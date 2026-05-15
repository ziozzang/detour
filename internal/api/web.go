package api

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
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

// Compute the embedded asset table once at package init. Doing it
// lazily on every request would re-walk the embed FS for nothing — the
// files are immutable for the lifetime of the binary, so we read them
// once, derive an ETag from a SHA-256 prefix, and serve from the cache
// thereafter.
var (
	indexHTMLBytes []byte
	staticFiles    = map[string]staticAsset{}
)

type staticAsset struct {
	body []byte
	etag string // strong ETag; "..." quotes included
	ctype string
}

func init() {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic("api: bad embed sub-path: " + err.Error())
	}
	idx, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("api: index.html missing from embed: " + err.Error())
	}
	indexHTMLBytes = idx
	for _, name := range []string{"app.js", "style.css"} {
		body, err := fs.ReadFile(sub, name)
		if err != nil {
			panic("api: " + name + " missing from embed: " + err.Error())
		}
		sum := sha256.Sum256(body)
		staticFiles[name] = staticAsset{
			body:  body,
			etag:  `"` + hex.EncodeToString(sum[:8]) + `"`,
			ctype: contentTypeFor(name),
		}
	}
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	}
	return "application/octet-stream"
}

// handleIndex serves the SPA entry point. Routed only on `GET /{$}`,
// so any path that hasn't been claimed by another handler falls
// through to ServeMux's default 404 — the API surface stays
// predictable and `GET /random/thing` doesn't accidentally render the
// HTML page.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The HTML is tiny and may reference future API additions; keep
	// it uncached so operators see updates immediately after upgrades.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTMLBytes)
}

// handleStatic serves /static/<file> from the in-memory asset table.
// We intentionally don't use http.FileServer: that would expose
// directory listings, follow symlinks (irrelevant here but a habit
// worth keeping), and serve subdirectories. The single-level map keeps
// the surface auditable.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	if strings.ContainsRune(name, '/') || strings.Contains(name, "..") {
		// Defensive: ServeMux already strips the prefix and rejects
		// unmatched paths, but `..` in the file segment is still
		// possible if a client crafts it manually.
		http.NotFound(w, r)
		return
	}
	asset, ok := staticFiles[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Conditional GET: respect If-None-Match so repeat loads of the
	// admin pane don't re-ship the bytes every poll cycle.
	if match := r.Header.Get("If-None-Match"); match != "" && match == asset.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", asset.ctype)
	w.Header().Set("ETag", asset.etag)
	// Bytes are immutable for the binary's lifetime; allow long cache
	// but require revalidation so a binary upgrade is picked up on
	// next request without operator action.
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	_, _ = w.Write(asset.body)
}
