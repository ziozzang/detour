package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handlerForWeb(t *testing.T) http.Handler {
	t.Helper()
	return New(nil, nil).Handler()
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestWebUIServesIndexHTMLOnRoot(t *testing.T) {
	w := get(t, handlerForWeb(t), "/")
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<title>detour</title>") {
		t.Errorf("body missing expected <title>: %q", body[:min(200, len(body))])
	}
	// Make sure the page references its assets and the JSON endpoints
	// it will call — protects against the embed silently breaking.
	for _, needle := range []string{
		`/static/app.js`,
		`/static/style.css`,
		`/healthz`,
		`/rules`,
		`/hosts`,
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("index.html missing %q reference", needle)
		}
	}
}

func TestWebUIServesStaticAssetsWithCorrectContentType(t *testing.T) {
	h := handlerForWeb(t)
	cases := []struct {
		path string
		ct   string
		find string
	}{
		{"/static/app.js", "application/javascript", "fetch"},
		{"/static/style.css", "text/css", "body"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			w := get(t, h, tc.path)
			if w.Code != 200 {
				t.Fatalf("status=%d", w.Code)
			}
			if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, tc.ct) {
				t.Errorf("Content-Type = %q, want prefix %q", got, tc.ct)
			}
			if !strings.Contains(w.Body.String(), tc.find) {
				t.Errorf("body missing %q", tc.find)
			}
		})
	}
}

func TestWebUIRejectsUnknownAsset(t *testing.T) {
	w := get(t, handlerForWeb(t), "/static/nope.txt")
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", w.Code)
	}
}

func TestWebUIRejectsPathTraversal(t *testing.T) {
	for _, p := range []string{
		"/static/..%2fapi.go",
		"/static/sub/file",
	} {
		t.Run(p, func(t *testing.T) {
			w := get(t, handlerForWeb(t), p)
			if w.Code != http.StatusNotFound {
				t.Errorf("status=%d, want 404 for %s", w.Code, p)
			}
		})
	}
}

func TestWebUIUnknownPath404(t *testing.T) {
	// Random non-API, non-static path must 404 — must NOT render
	// index.html, otherwise we'd shadow future API additions.
	w := get(t, handlerForWeb(t), "/no-such-thing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", w.Code)
	}
}

func TestWebUIDoesNotShadowJSONEndpoints(t *testing.T) {
	// With a nil NAT backend the API returns 503, not the HTML page.
	// This protects against accidentally registering a catch-all
	// handler that swallows /rules.
	w := get(t, handlerForWeb(t), "/rules")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d (want 503 when backends are nil)", w.Code)
	}
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("/rules served HTML; should be JSON")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
