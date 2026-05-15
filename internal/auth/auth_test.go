package auth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenSetMatches(t *testing.T) {
	ts := New([]string{"alpha", "beta", "", "  ", "alpha" /* dup */, "  gamma  "})
	if ts.Len() != 3 {
		t.Fatalf("Len=%d want 3 (after dedup + trim + empties)", ts.Len())
	}
	for _, ok := range []string{"alpha", "beta", "gamma"} {
		if !ts.Matches(ok) {
			t.Errorf("Matches(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "delta", "Alpha", "alpha "} {
		if ts.Matches(bad) {
			t.Errorf("Matches(%q) = true, want false", bad)
		}
	}
}

func TestTokenSetNilSafe(t *testing.T) {
	var ts *TokenSet
	if ts.Len() != 0 {
		t.Errorf("nil Len = %d", ts.Len())
	}
	if ts.Matches("anything") {
		t.Errorf("nil Matches returned true")
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		hdr      string
		wantTok  string
		wantOK   bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER xyz", "xyz", true},
		{"Bearer   spaced  ", "spaced", true},
		{"Basic abc", "", false},
		{"abc", "", false},
		{"", "", false},
		{"Bearer ", "", false},
		{"  Bearer abc  ", "abc", true},
	}
	for _, c := range cases {
		tok, ok := extractBearer(c.hdr)
		if tok != c.wantTok || ok != c.wantOK {
			t.Errorf("extractBearer(%q) = (%q,%v), want (%q,%v)", c.hdr, tok, ok, c.wantTok, c.wantOK)
		}
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	})
}

func TestMiddlewareNoTokensIsTransparent(t *testing.T) {
	h := Middleware(okHandler(), Options{})
	r := httptest.NewRequest("GET", "/whatever", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMiddlewareUnixBypass(t *testing.T) {
	h := Middleware(okHandler(), Options{Tokens: New([]string{"secret"})})
	r := httptest.NewRequest("GET", "/rules", nil)
	r = r.WithContext(WithListenerKind(r.Context(), KindUnix))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("unix peer should bypass auth, got %d", w.Code)
	}
}

func TestMiddlewareUnixEnforce(t *testing.T) {
	h := Middleware(okHandler(), Options{
		Tokens:        New([]string{"secret"}),
		EnforceOnUnix: true,
	})
	r := httptest.NewRequest("GET", "/rules", nil)
	r = r.WithContext(WithListenerKind(r.Context(), KindUnix))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("with EnforceOnUnix, missing token should 401, got %d", w.Code)
	}
}

func TestMiddlewareTCPRequiresToken(t *testing.T) {
	h := Middleware(okHandler(), Options{Tokens: New([]string{"secret"})})
	// No listener kind tag -> treated as TCP (the safe default).
	r := httptest.NewRequest("GET", "/rules", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("status=%d want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate=%q", got)
	}
	if !strings.Contains(w.Body.String(), "unauthorized") {
		t.Errorf("body=%q", w.Body.String())
	}
}

func TestMiddlewareTCPGoodToken(t *testing.T) {
	h := Middleware(okHandler(), Options{Tokens: New([]string{"secret-A", "secret-B"})})
	for _, tok := range []string{"secret-A", "secret-B"} {
		r := httptest.NewRequest("GET", "/rules", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		r = r.WithContext(WithListenerKind(r.Context(), KindTCP))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("token=%q status=%d", tok, w.Code)
		}
	}
}

func TestMiddlewareTCPBadToken(t *testing.T) {
	h := Middleware(okHandler(), Options{Tokens: New([]string{"secret"})})
	r := httptest.NewRequest("GET", "/rules", nil)
	r.Header.Set("Authorization", "Bearer not-the-token")
	r = r.WithContext(WithListenerKind(r.Context(), KindTCP))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("status=%d want 401", w.Code)
	}
}

func TestMiddlewareAllowUnauthenticated(t *testing.T) {
	h := Middleware(okHandler(), Options{
		Tokens:               New([]string{"secret"}),
		AllowUnauthenticated: []string{"/healthz"},
	})
	r := httptest.NewRequest("GET", "/healthz", nil)
	r = r.WithContext(WithListenerKind(r.Context(), KindTCP))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("status=%d, expected 200 for bypassed path", w.Code)
	}
}

func TestLoadTokensFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens")
	content := "# comment\n\n  token-A  \ntoken-B\n# another comment\ntoken-C\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTokensFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"token-A", "token-B", "token-C"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestLoadTokensFromFileRejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens")
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokensFromFile(path); err == nil {
		t.Fatalf("expected error for 0644 token file")
	} else if !strings.Contains(err.Error(), "too permissive") {
		t.Errorf("error=%v", err)
	}
}

func TestLoadTokensFromFileMissing(t *testing.T) {
	if _, err := LoadTokensFromFile("/nonexistent/path/almost-certainly"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGenerateToken(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two consecutive tokens collided; entropy source broken")
	}
	if len(a) != 64 {
		t.Errorf("token len=%d, want 64 (hex of 32 bytes)", len(a))
	}
}

func TestBaseContextForUnix(t *testing.T) {
	dir := t.TempDir()
	l, err := net.Listen("unix", filepath.Join(dir, "sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f := BaseContextFor(l)
	ctx := f(l)
	if got := ListenerKind(ctx); got != KindUnix {
		t.Errorf("kind=%q want %q", got, KindUnix)
	}
}

func TestBaseContextForTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f := BaseContextFor(l)
	ctx := f(l)
	if got := ListenerKind(ctx); got != KindTCP {
		t.Errorf("kind=%q want %q", got, KindTCP)
	}
}

func TestBaseContextForNil(t *testing.T) {
	f := BaseContextFor(nil)
	ctx := f(nil)
	if got := ListenerKind(ctx); got != KindTCP {
		t.Errorf("nil listener kind=%q want %q", got, KindTCP)
	}
}

// Sanity: ListenerKind on a vanilla context returns "".
func TestListenerKindUnset(t *testing.T) {
	if got := ListenerKind(context.Background()); got != "" {
		t.Errorf("got %q", got)
	}
}
