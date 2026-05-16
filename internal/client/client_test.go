package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI returns a tiny http.Handler that mimics detourd's JSON shape
// for the routes the client exercises. Captures the last request body
// so individual tests can assert on it.
type fakeAPI struct {
	lastBody atomic.Value // string
	notFound bool
	fail500  bool
}

func (f *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /rules", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, []Rule{{ID: "r1", From: "1.2.3.4:80", To: "127.0.0.1:80", Proto: "tcp"}})
	})
	mux.HandleFunc("POST /rules", func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		f.lastBody.Store(string(body))
		if f.fail500 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fake failure"})
			return
		}
		writeJSON(w, http.StatusCreated, Rule{ID: "new", From: "0.0.0.0:1234", To: "127.0.0.1:2234", Proto: "tcp"})
	})
	mux.HandleFunc("DELETE /rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		if f.notFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /hosts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, []Host{{ID: "h1", Hostname: "foo.com", IP: "10.0.0.1"}})
	})
	mux.HandleFunc("POST /hosts", func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		f.lastBody.Store(string(body))
		writeJSON(w, http.StatusCreated, Host{ID: "hnew", Hostname: "foo.com", IP: "10.2.3.4"})
	})
	mux.HandleFunc("DELETE /hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	return buf[:n], nil
}

// startUnixServer mounts h on a fresh Unix socket in t.TempDir() and
// returns the unix:// URL plus a cleanup func.
func startUnixServer(t *testing.T, h http.Handler) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 2 * time.Second}
	go srv.Serve(l)

	return "unix://" + sockPath, func() {
		_ = srv.Close()
		_ = l.Close()
		_ = os.Remove(sockPath)
	}
}

// ----------------------------------------------------------------------
// New() address parsing
// ----------------------------------------------------------------------

func TestNewParsesAddresses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"empty defaults to unix", "", false},
		{"explicit unix", "unix:///tmp/x.sock", false},
		{"bare absolute path → unix", "/tmp/x.sock", false},
		{"http", "http://127.0.0.1:8080", false},
		{"https", "https://example.com", false},
		{"unix without absolute path", "unix://relative.sock", true},
		{"unknown scheme", "ftp://foo", true},
		{"http no host", "http://", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.addr)
			if tc.wantErr && err == nil {
				t.Error("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected: %v", err)
			}
		})
	}
}

// ----------------------------------------------------------------------
// HTTP transport: full coverage against httptest.Server
// ----------------------------------------------------------------------

func TestHTTPTransportHappyPaths(t *testing.T) {
	api := &fakeAPI{}
	ts := httptest.NewServer(api.handler())
	defer ts.Close()

	c, err := New(ts.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	rules, err := c.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "r1" {
		t.Errorf("ListRules unexpected: %+v", rules)
	}

	added, err := c.AddRule(ctx, AddRuleRequest{From: "0.0.0.0:1234", To: "127.0.0.1:2234", Proto: "tcp"})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if added.ID != "new" {
		t.Errorf("AddRule resp: %+v", added)
	}
	bodyAny := api.lastBody.Load()
	if bodyAny == nil || !strings.Contains(bodyAny.(string), `"from":"0.0.0.0:1234"`) {
		t.Errorf("body not posted as JSON: %v", bodyAny)
	}

	if err := c.DeleteRule(ctx, "new"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}

	hosts, err := c.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Hostname != "foo.com" {
		t.Errorf("ListHosts unexpected: %+v", hosts)
	}
	if _, err := c.AddHost(ctx, AddHostRequest{Hostname: "foo.com", IP: "10.2.3.4"}); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if err := c.DeleteHost(ctx, "hnew"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
}

func TestHTTPTransport404Surface(t *testing.T) {
	api := &fakeAPI{notFound: true}
	ts := httptest.NewServer(api.handler())
	defer ts.Close()

	c, _ := New(ts.URL)
	err := c.DeleteRule(context.Background(), "ghost")
	if err == nil {
		t.Fatal("want error")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound = false; err = %v", err)
	}
	if !strings.Contains(err.Error(), "rule not found") {
		t.Errorf("error message should carry daemon's message: %v", err)
	}
}

func TestHTTPTransport500Surface(t *testing.T) {
	api := &fakeAPI{fail500: true}
	ts := httptest.NewServer(api.handler())
	defer ts.Close()

	c, _ := New(ts.URL)
	_, err := c.AddRule(context.Background(), AddRuleRequest{From: "1.2.3.4:80", To: "127.0.0.1:80", Proto: "tcp"})
	if err == nil {
		t.Fatal("want error")
	}
	if IsNotFound(err) {
		t.Error("500 should not be classified as NotFound")
	}
	if !strings.Contains(err.Error(), "fake failure") {
		t.Errorf("server message lost: %v", err)
	}
}

// ----------------------------------------------------------------------
// Unix transport: end-to-end against a Unix-socket server
// ----------------------------------------------------------------------

func TestUnixTransportHappyPath(t *testing.T) {
	api := &fakeAPI{}
	addr, cleanup := startUnixServer(t, api.handler())
	defer cleanup()

	c, err := New(addr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Addr() != addr {
		t.Errorf("Addr() = %q, want %q", c.Addr(), addr)
	}
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	added, err := c.AddRule(ctx, AddRuleRequest{From: "0.0.0.0:1234", To: "127.0.0.1:2234", Proto: "tcp"})
	if err != nil {
		t.Fatalf("AddRule over unix: %v", err)
	}
	if added.ID == "" {
		t.Error("empty rule id")
	}
}

func TestEmptyIDRejected(t *testing.T) {
	c, _ := New("http://127.0.0.1:1")
	if err := c.DeleteRule(context.Background(), ""); err == nil {
		t.Error("DeleteRule empty id should error")
	}
	if err := c.DeleteHost(context.Background(), ""); err == nil {
		t.Error("DeleteHost empty id should error")
	}
}
