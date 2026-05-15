package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// webAssets carries the static UI shipped with the daemon. The build
// tag-free embed.FS keeps the binary self-contained: there is no
// external "templates/" directory to deploy and no chance of a
// version mismatch between the daemon and its UI.
//
//go:embed web/index.html web/app.js web/style.css
var webAssets embed.FS

// indexHTML is loaded lazily so package init doesn't panic if the
// embed gets accidentally moved. We accept the tiny ReadFile cost on
// every request — the file is well under a kilobyte and the alternative
// (caching in a var with `init()`) makes test stubbing awkward.
func readIndexHTML() ([]byte, error) {
	return webAssets.ReadFile("web/index.html")
}

// staticSubFS returns the embedded /static FS rooted at "web". Used by
// the http.FileServer for /static/* routes; chrooting via fs.Sub keeps
// /static/web/index.html from leaking out via the file server's path
// rules.
func staticSubFS() fs.FS {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		// embed.FS.Sub only fails for a malformed path, which is a
		// compile-time string here — bug, not a runtime condition.
		panic("api: bad embed sub-path: " + err.Error())
	}
	return sub
}

// handleIndex serves the SPA entry point. Routed only on `GET /{$}`,
// so any path that hasn't been claimed by another handler falls
// through to ServeMux's default 404 — the API surface stays
// predictable and `GET /random/thing` doesn't accidentally render the
// HTML page.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	body, err := readIndexHTML()
	if err != nil {
		http.Error(w, "web UI unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// handleStatic serves /static/<file> from the embedded asset FS.
// http.FileServer would normally also serve directory listings; we
// pull the file name out of the path pattern manually and reject
// anything that isn't a flat file in the embed, so the daemon doesn't
// expose the embed directory layout.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" {
		// /static/{file...} requires at least one path segment, but
		// guard anyway.
		http.NotFound(w, r)
		return
	}
	if strings.ContainsRune(name, '/') || strings.Contains(name, "..") {
		// We deliberately don't recurse into subdirectories. Keeps the
		// surface auditable and prevents path-traversal foot guns.
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(staticSubFS(), name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	default:
		w.Header().Set("Content-Type", http.DetectContentType(data))
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}
