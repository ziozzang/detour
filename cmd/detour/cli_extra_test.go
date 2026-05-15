package main

// Additional CLI tests covering: ping, status, --token, completion
// scripts, service subcommands (with a fake systemctl), rule add
// --dry-run, alias dispatch, and the connect-failure UX path.

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
	"detour/internal/auth"
	"detour/internal/hostsfile"
	"detour/internal/linuxnat"
)

// httpDaemon stands up the same backend as daemon() but on a TCP
// listener wrapped with the auth middleware, so we can drive token
// flows end-to-end.
func httpDaemon(t *testing.T, tokens []string, enforceUnix bool) (addr string, teardown func()) {
	t.Helper()
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	natMgr, err := linuxnat.New(linuxnat.Options{Chain: "TESTAUTH", Runner: &fakeRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	hostsMgr := hostsfile.New(hostsPath)
	apiSrv := api.NewWithInfo(natMgr, hostsMgr, api.NewInfo("test", "abc", "now", "TESTAUTH", hostsPath, modeLabel(tokens, enforceUnix)))
	handler := auth.Middleware(apiSrv.Handler(), auth.Options{
		Tokens:               auth.New(tokens),
		EnforceOnUnix:        enforceUnix,
		AllowUnauthenticated: []string{"/healthz"},
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		BaseContext:       auth.BaseContextFor(l),
	}
	go srv.Serve(l)
	return "http://" + l.Addr().String(), func() {
		_ = srv.Close()
		_ = l.Close()
		_ = hostsMgr.Close()
		_ = natMgr.Close()
	}
}

func modeLabel(tokens []string, enforceUnix bool) string {
	if len(tokens) == 0 {
		return "none"
	}
	if enforceUnix {
		return "all"
	}
	return "tcp"
}

func TestCLIPing(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()
	code, out, errOut := runCLI(t, host, "ping")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "pong") {
		t.Errorf("expected pong, got %q", out)
	}
}

func TestCLIStatus(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()
	code, out, errOut := runCLI(t, host, "status")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
	for _, want := range []string{"ADDRESS", "VERSION", "CHAIN", "AUTH-MODE", "UPTIME"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in status output:\n%s", want, out)
		}
	}
}

func TestCLITokenRequiredOverHTTP(t *testing.T) {
	host, teardown := httpDaemon(t, []string{"secret"}, false)
	defer teardown()

	// Without a token: should fail with 401.
	code, _, errOut := runCLI(t, host, "rule", "list")
	if code != 1 {
		t.Errorf("exit=%d want 1 (operation failed)", code)
	}
	if !strings.Contains(errOut, "401") && !strings.Contains(errOut, "unauthorized") {
		t.Errorf("expected 401/unauthorized, got %q", errOut)
	}

	// With a token: succeeds, /healthz works regardless.
	code, _, errOut = runCLI(t, host, "--token", "secret", "rule", "list")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
	code, _, errOut = runCLI(t, host, "ping")
	if code != 0 {
		t.Fatalf("ping (no token, /healthz bypass) exit=%d stderr=%s", code, errOut)
	}
}

func TestCLITokenFromFile(t *testing.T) {
	host, teardown := httpDaemon(t, []string{"file-token"}, false)
	defer teardown()
	dir := t.TempDir()
	path := filepath.Join(dir, "tok")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, host, "--token-file", path, "rule", "list")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
}

func TestCLIBadTokenOverHTTP(t *testing.T) {
	host, teardown := httpDaemon(t, []string{"good"}, false)
	defer teardown()
	code, _, errOut := runCLI(t, host, "--token", "wrong", "rule", "list")
	if code != 1 {
		t.Errorf("exit=%d want 1", code)
	}
	if !strings.Contains(errOut, "401") {
		t.Errorf("stderr=%q", errOut)
	}
}

func TestCLIRuleAddDryRun(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()
	code, out, errOut := runCLI(t, host, "rule", "add",
		"--from", "0.0.0.0:1", "--to", "127.0.0.1:2", "--dry-run")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "dry-run ok") {
		t.Errorf("expected dry-run output, got %q", out)
	}
	// Verify nothing was added.
	_, out, _ = runCLI(t, host, "rule", "list")
	if !strings.Contains(out, "no rules") {
		t.Errorf("dry-run unexpectedly added a rule:\n%s", out)
	}
}

func TestCLIAliasRuleLs(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()
	code, _, errOut := runCLI(t, host, "rule", "ls")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
}

func TestCLIAliasHostDelete(t *testing.T) {
	host, teardown := daemon(t)
	defer teardown()
	code, out, _ := runCLI(t, host, "host", "add", "--hostname", "x.com", "--ip", "1.1.1.1")
	if code != 0 {
		t.Fatal("add failed")
	}
	id := strings.TrimSpace(out)
	code, _, errOut := runCLI(t, host, "host", "delete", id)
	if code != 0 {
		t.Errorf("exit=%d stderr=%s", code, errOut)
	}
}

func TestCLIConnectError(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	// Definitely unreachable.
	code := run([]string{"--host", "unix:///tmp/definitely-no-such-detour-sock", "--timeout", "1s", "ping"}, stdout, stderr)
	if code != 2 {
		t.Errorf("exit=%d want 2 (conn error), stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "hint:") {
		t.Errorf("expected friendly hint in stderr, got %q", stderr.String())
	}
}

func TestCLICompletionBash(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"completion", "bash"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"_detour()", "complete -F _detour", "rule", "host", "service"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("bash completion missing %q", want)
		}
	}
}

func TestCLICompletionZsh(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"completion", "zsh"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "#compdef detour") {
		t.Errorf("zsh completion missing #compdef header: %q", stdout.String()[:32])
	}
}

func TestCLICompletionFish(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"completion", "fish"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "complete -c detour") {
		t.Errorf("fish completion malformed: %q", stdout.String())
	}
}

func TestCLICompletionMissingShell(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"completion"}, stdout, stderr)
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
}

func TestCLICompletionUnknownShell(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"completion", "tcsh"}, stdout, stderr)
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
}

// --- service subcommand tests with a fake systemctl ---

type fakeSystemctl struct {
	mu       sync.Mutex
	calls    [][]string
	stdout   string
	stderr   string
	failArgs map[string]bool
}

func (f *fakeSystemctl) Run(args ...string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), args...))
	key := strings.Join(args, " ")
	if f.failArgs[key] {
		return "", "boom", &runErr{"forced failure"}
	}
	return f.stdout, f.stderr, nil
}

type runErr struct{ s string }

func (e *runErr) Error() string { return e.s }

func withFakeService(t *testing.T, env serviceEnv) func() {
	t.Helper()
	prev := serviceEnvOverride
	serviceEnvOverride = &env
	return func() { serviceEnvOverride = prev }
}

func TestCLIServiceInstallDryRun(t *testing.T) {
	defer withFakeService(t, serviceEnv{
		runner:     &fakeSystemctl{},
		writeFile:  func(string, []byte, os.FileMode) error { t.Fatal("writeFile must not be called in dry-run"); return nil },
		removeFile: func(string) error { return nil },
		hasSystemd: func() bool { return false }, // even without systemd, dry-run should work
	})()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"service", "install", "--dry-run"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "[Unit]") || !strings.Contains(stdout.String(), "ExecStart=/usr/local/bin/detourd") {
		t.Errorf("unit text missing from dry-run:\n%s", stdout.String())
	}
}

func TestCLIServiceInstallNoSystemd(t *testing.T) {
	defer withFakeService(t, serviceEnv{
		runner:     &fakeSystemctl{},
		writeFile:  func(string, []byte, os.FileMode) error { return nil },
		removeFile: func(string) error { return nil },
		hasSystemd: func() bool { return false },
	})()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"service", "install"}, stdout, stderr)
	if code != 1 {
		t.Errorf("exit=%d want 1 (no systemd)", code)
	}
	if !strings.Contains(stderr.String(), "systemd not detected") {
		t.Errorf("stderr=%q", stderr.String())
	}
}

func TestCLIServiceInstallWrites(t *testing.T) {
	dir := t.TempDir()
	unitPath := filepath.Join(dir, "detourd.service")
	var got struct {
		body []byte
		mode os.FileMode
	}
	sc := &fakeSystemctl{}
	defer withFakeService(t, serviceEnv{
		runner: sc,
		writeFile: func(p string, b []byte, m os.FileMode) error {
			if p != unitPath {
				t.Errorf("path=%s want %s", p, unitPath)
			}
			got.body = b
			got.mode = m
			return nil
		},
		removeFile: func(string) error { return nil },
		hasSystemd: func() bool { return true },
	})()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"service", "install",
		"--unit-path", unitPath,
		"--binary", "/usr/local/bin/detourd",
		"--http", ":9999",
		"--auth-token-file", "/var/lib/detour/auth.token",
		"--enable",
	}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(string(got.body), "--http=:9999") {
		t.Errorf("unit missing --http flag:\n%s", got.body)
	}
	if !strings.Contains(string(got.body), "--auth-token-file=/var/lib/detour/auth.token") {
		t.Errorf("unit missing --auth-token-file:\n%s", got.body)
	}
	if got.mode != 0o644 {
		t.Errorf("mode=%o want 0644", got.mode)
	}
	// Should have called daemon-reload and enable --now.
	if len(sc.calls) < 2 {
		t.Fatalf("expected at least 2 systemctl calls, got %v", sc.calls)
	}
	if strings.Join(sc.calls[0], " ") != "daemon-reload" {
		t.Errorf("calls[0]=%v want daemon-reload", sc.calls[0])
	}
	if strings.Join(sc.calls[1], " ") != "enable --now detourd" {
		t.Errorf("calls[1]=%v", sc.calls[1])
	}
}

func TestCLIServiceStatusJSON(t *testing.T) {
	sc := &fakeSystemctl{
		stdout: "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nUnitFileState=enabled\nActiveEnterTimestamp=Mon 2024-01-01 00:00:00 UTC\n",
	}
	defer withFakeService(t, serviceEnv{
		runner:     sc,
		writeFile:  func(string, []byte, os.FileMode) error { return nil },
		removeFile: func(string) error { return nil },
		hasSystemd: func() bool { return true },
	})()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"--json", "service", "status"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{`"active_state": "active"`, `"sub_state": "running"`, `"main_pid": 4242`, `"unit_file_state": "enabled"`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q in JSON:\n%s", want, stdout.String())
		}
	}
}

func TestCLIServiceStatusTable(t *testing.T) {
	sc := &fakeSystemctl{
		stdout: "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nUnitFileState=enabled\n",
	}
	defer withFakeService(t, serviceEnv{
		runner:     sc,
		writeFile:  func(string, []byte, os.FileMode) error { return nil },
		removeFile: func(string) error { return nil },
		hasSystemd: func() bool { return true },
	})()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"service", "status"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"detourd.service", "active", "running", "enabled", "4242"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q in table:\n%s", want, stdout.String())
		}
	}
}

func TestCLIServiceStatusNoSystemd(t *testing.T) {
	defer withFakeService(t, serviceEnv{
		runner:     &fakeSystemctl{},
		writeFile:  func(string, []byte, os.FileMode) error { return nil },
		removeFile: func(string) error { return nil },
		hasSystemd: func() bool { return false },
	})()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"service", "status"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "not detected") {
		t.Errorf("stdout=%q", stdout.String())
	}
}

func TestCLIServiceUninstallDryRun(t *testing.T) {
	sc := &fakeSystemctl{}
	called := false
	defer withFakeService(t, serviceEnv{
		runner:     sc,
		writeFile:  func(string, []byte, os.FileMode) error { return nil },
		removeFile: func(string) error { called = true; return nil },
		hasSystemd: func() bool { return true },
	})()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"service", "uninstall", "--dry-run", "--purge"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if called {
		t.Errorf("removeFile must not be invoked in dry-run")
	}
	if len(sc.calls) != 0 {
		t.Errorf("systemctl should not be invoked in dry-run, got %v", sc.calls)
	}
	for _, want := range []string{"would run: systemctl stop", "would remove", "/var/lib/detour"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q in dry-run output:\n%s", want, stdout.String())
		}
	}
}

// runErr satisfies error.
