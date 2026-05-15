package api_test

// End-to-end integration test: stand up the API with REAL
// *linuxnat.Manager and *hostsfile.Manager instances (the former wired
// to a fake iptables Runner so we don't touch the kernel) and exercise
// the whole flow that an operator following the README would use.
//
// Tests both lives in api_test (external) so we exercise the public
// surface — package api isn't allowed any private peeks.

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"detour/internal/api"
	"detour/internal/hostsfile"
	"detour/internal/linuxnat"
)

// recordingRunner is a minimal Runner that records iptables invocations
// and always succeeds. Good enough to drive the API end-to-end.
type recordingRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingRunner) Run(args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), args...))
	return nil, nil
}

func (r *recordingRunner) joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var sb strings.Builder
	for _, c := range r.calls {
		sb.WriteString(strings.Join(c, " "))
		sb.WriteByte('\n')
	}
	return sb.String()
}

func TestEndToEndAddRedirectAndHostAndShutdown(t *testing.T) {
	runner := &recordingRunner{}
	natMgr, err := linuxnat.New(linuxnat.Options{Runner: runner, Chain: "DETOUR_E2E"})
	if err != nil {
		t.Fatalf("linuxnat.New: %v", err)
	}

	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatalf("seed hosts: %v", err)
	}
	hostsMgr := hostsfile.New(hostsPath)

	srv := api.New(natMgr, hostsMgr)
	handler := srv.Handler()

	// 1. Create a port redirect 0.0.0.0:1234 -> 127.0.0.1:2234.
	post := func(target, body string) (int, []byte) {
		r := httptest.NewRequest("POST", target, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}

	code, body := post("/rules",
		`{"from":"0.0.0.0:1234","to":"127.0.0.1:2234","proto":"tcp"}`)
	if code != 201 {
		t.Fatalf("POST /rules: status=%d body=%s", code, body)
	}
	var ruleResp struct{ ID, From, To, Proto string }
	if err := json.Unmarshal(body, &ruleResp); err != nil {
		t.Fatalf("decode rule resp: %v", err)
	}
	if ruleResp.ID == "" {
		t.Fatalf("empty rule id; body=%s", body)
	}
	if !strings.Contains(runner.joined(), "-A DETOUR_E2E -p tcp --dport 1234") {
		t.Errorf("iptables -A call missing:\n%s", runner.joined())
	}
	if strings.Contains(runner.joined(), "-d 0.0.0.0") {
		t.Errorf("0.0.0.0 should have been omitted from -d:\n%s", runner.joined())
	}

	// 2. Pin foo.com -> 10.2.3.4 in /etc/hosts.
	code, body = post("/hosts", `{"hostname":"foo.com","ip":"10.2.3.4"}`)
	if code != 201 {
		t.Fatalf("POST /hosts: status=%d body=%s", code, body)
	}
	var hostResp struct{ ID, Hostname, IP string }
	_ = json.Unmarshal(body, &hostResp)
	if hostResp.ID == "" {
		t.Fatalf("empty host id; body=%s", body)
	}
	contents, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	if !strings.Contains(string(contents), "10.2.3.4\tfoo.com") {
		t.Errorf("hosts file missing entry:\n%s", contents)
	}
	if !strings.Contains(string(contents), "127.0.0.1 localhost") {
		t.Errorf("hosts file lost user content:\n%s", contents)
	}

	// 3. Listing surfaces both.
	listReq := httptest.NewRequest("GET", "/rules", nil)
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)
	if !strings.Contains(listW.Body.String(), ruleResp.ID) {
		t.Errorf("list missing rule id; body=%s", listW.Body.String())
	}

	// 4. Shut everything down — both backends should clean up after
	// themselves.
	if err := hostsMgr.Close(); err != nil {
		t.Fatalf("hosts close: %v", err)
	}
	if err := natMgr.Close(); err != nil {
		t.Fatalf("nat close: %v", err)
	}

	after, _ := os.ReadFile(hostsPath)
	if strings.Contains(string(after), "foo.com") {
		t.Errorf("hosts entry leaked after Close:\n%s", after)
	}
	if !strings.Contains(string(after), "127.0.0.1 localhost") {
		t.Errorf("Close clobbered user content:\n%s", after)
	}
	joined := runner.joined()
	for _, want := range []string{"-D OUTPUT -j DETOUR_E2E", "-D PREROUTING -j DETOUR_E2E", "-F DETOUR_E2E", "-X DETOUR_E2E"} {
		if !strings.Contains(joined, want) {
			t.Errorf("iptables cleanup missing %q:\n%s", want, joined)
		}
	}
}
