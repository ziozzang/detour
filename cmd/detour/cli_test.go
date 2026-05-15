package main

// End-to-end test: stand up the real api.Server backed by linuxnat
// (with a fake iptables runner) and hostsfile (writing to a tmp file),
// expose it on a Unix-domain socket, then drive every CLI subcommand
// against it via the same run() the binary uses.
//
// This is the strongest test in the project: it exercises argv
// parsing, the http client transport, the JSON wire format, the API
// handlers, and the linuxnat/hostsfile state machines all in one
// process — without ever calling real iptables or touching /etc/hosts.

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"detour/internal/api"
	"detour/internal/hostsfile"
	"detour/internal/linuxnat"
)

// fakeRunner is the test seam for iptables. Records every invocation,
// returns success by default. Mirrors the one in
// internal/linuxnat/linuxnat_test.go but kept local so this test
// doesn't reach into internal package privates.
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (f *fakeRunner) Run(args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]string(nil), args...)
	f.calls = append(f.calls, cp)
	return nil, nil
}

// daemon spins up an in-process api.Server on a fresh Unix socket and
// returns the unix:// address plus a teardown func.
func daemon(t *testing.T) (addr string, teardown func()) {
	t.Helper()
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(dir, "detour.sock")

	natMgr, err := linuxnat.New(linuxnat.Options{
		Chain:  "TESTDETOUR",
		Runner: &fakeRunner{},
	})
	if err != nil {
		t.Fatalf("linuxnat.New: %v", err)
	}
	hostsMgr := hostsfile.New(hostsPath)
	apiSrv := api.New(natMgr, hostsMgr)

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: apiSrv.Handler(), ReadHeaderTimeout: 2 * time.Second}
	go srv.Serve(l)

	return "unix://" + sockPath, func() {
		_ = srv.Close()
		_ = l.Close()
		_ = hostsMgr.Close()
		_ = natMgr.Close()
	}
}

// runCLI calls the CLI's run() with the given argv and host, returning
// (exit code, stdout, stderr).
func runCLI(t *testing.T, host string, argv ...string) (int, string, string) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	full := append([]string{"--host", host, "--timeout", "5s"}, argv...)
	code := run(full, stdout, stderr)
	return code, stdout.String(), stderr.String()
}

func TestCLIVersion(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	// version is local — no daemon needed.
	code := run([]string{"version"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "detour ") {
		t.Errorf("stdout=%q", stdout.String())
	}
}

func TestCLINoArgsShowsUsage(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run(nil, stdout, stderr)
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr missing usage: %q", stderr.String())
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"--host", "unix:///tmp/nope.sock", "frobnicate"}, stdout, stderr)
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr=%q", stderr.String())
	}
}

func TestCLIInfoAgainstLiveDaemon(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()

	code, out, errOut := runCLI(t, host, "info")
	if code != 0 {
		t.Fatalf("info exit=%d stderr=%s", code, errOut)
	}
	for _, want := range []string{"ADDRESS", "HEALTHY", "true", "RULES", "HOSTS"} {
		if !strings.Contains(out, want) {
			t.Errorf("info output missing %q: %s", want, out)
		}
	}
}

func TestCLIRuleLifecycle(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()

	// Empty state.
	_, out, _ := runCLI(t, host, "rule", "list")
	if !strings.Contains(out, "no rules") {
		t.Errorf("expected 'no rules' in initial list:\n%s", out)
	}

	// Add.
	code, out, errOut := runCLI(t, host, "rule", "add",
		"--from", "0.0.0.0:1234", "--to", "127.0.0.1:2234", "--proto", "tcp")
	if code != 0 {
		t.Fatalf("add exit=%d stderr=%s", code, errOut)
	}
	id := strings.TrimSpace(out)
	if id == "" {
		t.Fatal("rule add printed empty ID")
	}

	// List should show the rule.
	_, out, _ = runCLI(t, host, "rule", "list")
	if !strings.Contains(out, id) {
		t.Errorf("list missing rule %s:\n%s", id, out)
	}
	if !strings.Contains(out, "0.0.0.0:1234") {
		t.Errorf("list missing from address:\n%s", out)
	}

	// JSON output.
	_, out, _ = runCLI(t, host, "--json", "rule", "list")
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("expected JSON array, got:\n%s", out)
	}
	if !strings.Contains(out, `"id"`) {
		t.Errorf("JSON missing id field:\n%s", out)
	}

	// Remove.
	code, out, errOut = runCLI(t, host, "rule", "rm", id)
	if code != 0 {
		t.Fatalf("rm exit=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "deleted") {
		t.Errorf("rm output: %s", out)
	}

	// Verify removed.
	_, out, _ = runCLI(t, host, "rule", "list")
	if strings.Contains(out, id) {
		t.Errorf("rule still listed after rm:\n%s", out)
	}
}

func TestCLIRuleAddRequiresFlags(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()

	code, _, errOut := runCLI(t, host, "rule", "add", "--from", "0.0.0.0:1")
	if code != 1 {
		t.Errorf("exit=%d want 1", code)
	}
	if !strings.Contains(errOut, "--from and --to are required") {
		t.Errorf("stderr=%q", errOut)
	}
}

func TestCLIRuleRmUnknown(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()

	code, _, errOut := runCLI(t, host, "rule", "rm", "nope")
	if code != 1 {
		t.Errorf("exit=%d want 1", code)
	}
	if !strings.Contains(errOut, "rule not found") {
		t.Errorf("stderr=%q", errOut)
	}
}

func TestCLIHostLifecycle(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()

	code, out, errOut := runCLI(t, host, "host", "add",
		"--hostname", "foo.example.com", "--ip", "10.2.3.4")
	if code != 0 {
		t.Fatalf("host add exit=%d stderr=%s", code, errOut)
	}
	id := strings.TrimSpace(out)
	if id == "" {
		t.Fatal("host add printed empty ID")
	}

	_, out, _ = runCLI(t, host, "host", "list")
	if !strings.Contains(out, "foo.example.com") || !strings.Contains(out, "10.2.3.4") {
		t.Errorf("host list missing entry:\n%s", out)
	}

	code, _, errOut = runCLI(t, host, "host", "rm", id)
	if code != 0 {
		t.Fatalf("host rm exit=%d stderr=%s", code, errOut)
	}

	_, out, _ = runCLI(t, host, "host", "list")
	if strings.Contains(out, id) {
		t.Errorf("host still listed after rm:\n%s", out)
	}
}

func TestCLIHostAddBadIP(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()

	code, _, errOut := runCLI(t, host, "host", "add",
		"--hostname", "foo.com", "--ip", "not-an-ip")
	if code != 1 {
		t.Errorf("exit=%d want 1", code)
	}
	if !strings.Contains(errOut, "invalid ip") {
		t.Errorf("stderr=%q", errOut)
	}
}

func TestCLIBadHostAddress(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"--host", "ftp://nope", "info"}, stdout, stderr)
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
	if !strings.Contains(stderr.String(), "unsupported address scheme") {
		t.Errorf("stderr=%q", stderr.String())
	}
}
