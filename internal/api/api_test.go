package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"detour/internal/hostsfile"
	"detour/internal/linuxnat"
)

// --- fakes ---

type fakeNAT struct {
	mu      sync.Mutex
	rules   []linuxnat.Rule
	nextID  int
	addErr  error
	delErr  error
	missing string // id whose Remove returns os.ErrNotExist
}

func (f *fakeNAT) Add(from, to linuxnat.Endpoint, proto linuxnat.Protocol) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return "", f.addErr
	}
	f.nextID++
	id := "rule-" + intToStr(f.nextID)
	f.rules = append(f.rules, linuxnat.Rule{ID: id, From: from, To: to, Proto: proto})
	return id, nil
}

func (f *fakeNAT) Remove(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	if id == f.missing {
		return os.ErrNotExist
	}
	for i, r := range f.rules {
		if r.ID == id {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return os.ErrNotExist
}

func (f *fakeNAT) List() []linuxnat.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]linuxnat.Rule, len(f.rules))
	copy(out, f.rules)
	return out
}

type fakeHosts struct {
	mu      sync.Mutex
	entries []hostsfile.Entry
	nextID  int
	addErr  error
	delErr  error
	missing string
}

func (f *fakeHosts) Add(hostname, ip string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return "", f.addErr
	}
	f.nextID++
	id := "host-" + intToStr(f.nextID)
	// store the parsed lowercase hostname like the real one would
	e := hostsfile.Entry{ID: id, Hostname: strings.ToLower(strings.TrimSpace(hostname))}
	// Don't bother parsing the IP — handler validated it.
	e.IP = parseIP(ip)
	f.entries = append(f.entries, e)
	return id, nil
}

func (f *fakeHosts) Remove(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	if id == f.missing {
		return hostsfile.ErrNotFound
	}
	for i, e := range f.entries {
		if e.ID == id {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			return nil
		}
	}
	return hostsfile.ErrNotFound
}

func (f *fakeHosts) List() []hostsfile.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]hostsfile.Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

// --- helpers ---

func intToStr(i int) string {
	return strconv.Itoa(i)
}

func parseIP(s string) net.IP {
	return net.ParseIP(strings.TrimSpace(s))
}

func do(t *testing.T, h http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
		r = httptest.NewRequest(method, target, &buf)
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// --- tests ---

func TestHealthz(t *testing.T) {
	srv := New(&fakeNAT{}, &fakeHosts{})
	w := do(t, srv.Handler(), "GET", "/healthz", nil)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("body=%s", w.Body.String())
	}
}

func TestAddRuleHappyPath(t *testing.T) {
	nat := &fakeNAT{}
	srv := New(nat, &fakeHosts{})

	w := do(t, srv.Handler(), "POST", "/rules", map[string]string{
		"from":  "0.0.0.0:1234",
		"to":    "127.0.0.1:2234",
		"proto": "tcp",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp ruleResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID == "" || resp.Proto != "tcp" {
		t.Errorf("bad response: %+v", resp)
	}
	if len(nat.rules) != 1 {
		t.Fatalf("rule not stored: %+v", nat.rules)
	}
}

func TestAddRuleDefaultsProtoBoth(t *testing.T) {
	nat := &fakeNAT{}
	srv := New(nat, nil)
	w := do(t, srv.Handler(), "POST", "/rules", map[string]string{
		"from": "1.2.3.4:80", "to": "127.0.0.1:8080",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp ruleResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Proto != "both" {
		t.Errorf("proto default not 'both': %s", resp.Proto)
	}
}

func TestAddRuleValidationErrors(t *testing.T) {
	srv := New(&fakeNAT{}, nil)
	for _, tc := range []struct {
		name string
		body map[string]string
	}{
		{"bad from", map[string]string{"from": "nope", "to": "127.0.0.1:1"}},
		{"bad to", map[string]string{"from": "1.2.3.4:1", "to": "nope"}},
		{"bad proto", map[string]string{"from": "1.2.3.4:1", "to": "127.0.0.1:2", "proto": "icmp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, srv.Handler(), "POST", "/rules", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAddRuleBackendError(t *testing.T) {
	nat := &fakeNAT{addErr: errors.New("iptables boom")}
	srv := New(nat, nil)
	w := do(t, srv.Handler(), "POST", "/rules", map[string]string{
		"from": "1.2.3.4:1", "to": "127.0.0.1:2", "proto": "tcp",
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAddRuleUnknownFieldRejected(t *testing.T) {
	srv := New(&fakeNAT{}, nil)
	r := httptest.NewRequest("POST", "/rules", strings.NewReader(`{"foo":"bar"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestListRules(t *testing.T) {
	nat := &fakeNAT{}
	from, _ := linuxnat.ParseEndpoint("1.2.3.4:80")
	to, _ := linuxnat.ParseEndpoint("127.0.0.1:8080")
	_, _ = nat.Add(from, to, linuxnat.ProtoTCP)

	srv := New(nat, nil)
	w := do(t, srv.Handler(), "GET", "/rules", nil)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	var out []ruleResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0].From != "1.2.3.4:80" || out[0].To != "127.0.0.1:8080" {
		t.Errorf("unexpected list: %+v", out)
	}
}

func TestDeleteRule(t *testing.T) {
	nat := &fakeNAT{}
	from, _ := linuxnat.ParseEndpoint("1.2.3.4:80")
	to, _ := linuxnat.ParseEndpoint("127.0.0.1:8080")
	id, _ := nat.Add(from, to, linuxnat.ProtoTCP)
	srv := New(nat, nil)

	w := do(t, srv.Handler(), "DELETE", "/rules/"+id, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(nat.List()) != 0 {
		t.Errorf("rule not deleted")
	}
}

func TestDeleteRuleUnknown(t *testing.T) {
	nat := &fakeNAT{missing: "ghost"}
	srv := New(nat, nil)
	w := do(t, srv.Handler(), "DELETE", "/rules/ghost", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestNATBackendNil(t *testing.T) {
	srv := New(nil, &fakeHosts{})
	w := do(t, srv.Handler(), "GET", "/rules", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", w.Code)
	}
}

func TestAddHostHappyPath(t *testing.T) {
	h := &fakeHosts{}
	srv := New(nil, h)
	w := do(t, srv.Handler(), "POST", "/hosts", map[string]string{
		"hostname": "foo.com",
		"ip":       "10.2.3.4",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp hostResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ID == "" || resp.Hostname != "foo.com" || resp.IP != "10.2.3.4" {
		t.Errorf("bad response: %+v", resp)
	}
}

func TestAddHostValidation(t *testing.T) {
	srv := New(nil, &fakeHosts{})
	for _, tc := range []struct {
		name string
		body map[string]string
	}{
		{"empty hostname", map[string]string{"hostname": "", "ip": "1.2.3.4"}},
		{"bad ip", map[string]string{"hostname": "foo.com", "ip": "not-an-ip"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, srv.Handler(), "POST", "/hosts", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDeleteHost(t *testing.T) {
	h := &fakeHosts{}
	id, _ := h.Add("foo.com", "1.2.3.4")
	srv := New(nil, h)
	w := do(t, srv.Handler(), "DELETE", "/hosts/"+id, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(h.List()) != 0 {
		t.Errorf("host not deleted")
	}
}

func TestDeleteHostUnknown(t *testing.T) {
	h := &fakeHosts{missing: "ghost"}
	srv := New(nil, h)
	w := do(t, srv.Handler(), "DELETE", "/hosts/ghost", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestHostsBackendNil(t *testing.T) {
	srv := New(&fakeNAT{}, nil)
	w := do(t, srv.Handler(), "POST", "/hosts", map[string]string{"hostname": "f", "ip": "1.1.1.1"})
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", w.Code)
	}
}
