// Package auth implements the minimum security layer detourd applies
// to its HTTP control plane: a bearer-token middleware backed by a
// constant-time comparison against an in-memory token set.
//
// Threat model and what this is *not*:
//
//   - The Unix-domain socket is the trusted path. POSIX file
//     permissions (root:detour 0660 by default — see internal/socket)
//     decide who may speak to the daemon over the socket; reproducing
//     bearer-token auth there would be redundant and break the Docker-
//     style local UX users expect.
//
//   - When the daemon also exposes its API over TCP (`--http`), the
//     listener is by definition reachable by anyone who can route
//     packets to the port. Token auth is the single bar that gates
//     that surface. If you need stronger guarantees (mutual TLS, per-
//     user identity), front detourd with a reverse proxy.
//
// Token management is split into:
//
//   - Source resolution: CLI flag, env, file. The daemon's main()
//     calls LoadTokensFromFile and merges results.
//   - Enforcement: Middleware(handler, opts) wraps the API mux and
//     short-circuits unauthenticated TCP requests with HTTP 401.
//   - Identification: callers tag the request context with the
//     listener kind via WithListenerKind so the middleware can
//     distinguish Unix from TCP without inspecting raw connections.
package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// listenerKeyType is the context key under which we stash the listener
// network type when wrapping each accepted connection. Untyped string
// keys would clash with anything else in the request context.
type listenerKeyType struct{}

var listenerKey = listenerKeyType{}

// Listener kinds. Strings rather than ints so log lines and audit
// trails read naturally.
const (
	KindUnix = "unix"
	KindTCP  = "tcp"
)

// WithListenerKind returns a context that carries the listener kind
// for use by Middleware. Daemons should call this on every incoming
// request via http.Server.BaseContext when they accept the
// connection.
func WithListenerKind(ctx context.Context, kind string) context.Context {
	return context.WithValue(ctx, listenerKey, kind)
}

// ListenerKind reads the kind tagged via WithListenerKind. Returns
// empty string when the context wasn't tagged (e.g. tests that build
// requests without going through the listener wrapper).
func ListenerKind(ctx context.Context) string {
	v, _ := ctx.Value(listenerKey).(string)
	return v
}

// TokenSet stores raw tokens with constant-time membership testing.
// Membership is small (a handful at most), so a slice is fine and
// avoids the map iteration-order issue.
type TokenSet struct {
	tokens [][]byte
}

// New builds a TokenSet from a slice of strings. Empty strings and
// duplicates are silently dropped so callers can pass through optional
// flags without pre-filtering. The returned set is safe for
// concurrent reads.
func New(tokens []string) *TokenSet {
	ts := &TokenSet{}
	seen := map[string]struct{}{}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		// Store as []byte so subtle.ConstantTimeCompare can use it
		// without per-call allocation.
		ts.tokens = append(ts.tokens, []byte(t))
	}
	return ts
}

// Len reports how many tokens are loaded. 0 means "no auth configured".
func (ts *TokenSet) Len() int {
	if ts == nil {
		return 0
	}
	return len(ts.tokens)
}

// Matches reports whether candidate equals any configured token. Uses
// constant-time comparison; the length-mismatch fast path is
// considered acceptable since the token length itself is not a secret
// (it's a build-time choice).
func (ts *TokenSet) Matches(candidate string) bool {
	if ts == nil || len(ts.tokens) == 0 {
		return false
	}
	c := []byte(candidate)
	matched := 0
	for _, t := range ts.tokens {
		if len(t) == len(c) && subtle.ConstantTimeCompare(t, c) == 1 {
			matched = 1
		}
	}
	return matched == 1
}

// Options drives Middleware behaviour. The zero value is "no auth
// required anywhere", suitable for a daemon started without any token
// configured.
type Options struct {
	// Tokens are the accepted bearer tokens. nil/empty -> auth disabled
	// for any path that would otherwise be enforced.
	Tokens *TokenSet
	// EnforceOnUnix forces the middleware to validate the
	// Authorization header even for Unix-socket peers. Default is
	// false (rely on POSIX permissions).
	EnforceOnUnix bool
	// Realm appears in the WWW-Authenticate response header on 401s.
	// Empty -> "detour".
	Realm string
	// AllowUnauthenticated lists paths that bypass auth even on TCP.
	// `/healthz` is included by default by the daemon so external
	// uptime probes don't need a token.
	AllowUnauthenticated []string
}

// Middleware wraps h with bearer-token enforcement consistent with the
// Options provided. It is safe to wrap a nil token set: the middleware
// then passes all requests through unchanged.
func Middleware(h http.Handler, opts Options) http.Handler {
	realm := opts.Realm
	if realm == "" {
		realm = "detour"
	}
	bypass := map[string]struct{}{}
	for _, p := range opts.AllowUnauthenticated {
		bypass[p] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decide whether auth is required for *this* request:
		//   - if no tokens are loaded, auth is universally disabled
		//   - else, TCP requests always require a token
		//   - Unix requests only require a token when EnforceOnUnix
		//   - explicit bypass paths (e.g. /healthz) always pass
		if opts.Tokens == nil || opts.Tokens.Len() == 0 {
			h.ServeHTTP(w, r)
			return
		}
		if _, ok := bypass[r.URL.Path]; ok {
			h.ServeHTTP(w, r)
			return
		}
		kind := ListenerKind(r.Context())
		if kind == KindUnix && !opts.EnforceOnUnix {
			h.ServeHTTP(w, r)
			return
		}
		token, ok := extractBearer(r.Header.Get("Authorization"))
		if !ok || !opts.Tokens.Matches(token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: provide Authorization: Bearer <token>"}` + "\n"))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// extractBearer pulls the token out of an Authorization header value.
// We accept the canonical "Bearer <token>" form, case-insensitive on
// the scheme as per RFC 6750 §2.1. Returns (token, true) on success.
func extractBearer(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	sp := strings.IndexByte(header, ' ')
	if sp <= 0 {
		return "", false
	}
	if !strings.EqualFold(header[:sp], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(header[sp+1:])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// LoadTokensFromFile reads one token per line from path. Blank lines
// and `# ...` comment lines are ignored, the rest are returned
// verbatim (whitespace-trimmed). The file's mode must not be group-
// or world-readable to avoid silent token leakage; if it is, the
// function refuses with a clear error.
func LoadTokensFromFile(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("token file: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("token file %s: is a directory", path)
	}
	// On Linux a regular user file should be at most 0600.
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("token file %s: mode %o is too permissive (must not be group/world readable); chmod 600", path, mode)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open token file: %w", err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	// Tokens can plausibly be 256+ bytes (e.g. random 64-byte hex
	// strings); bump the scanner buffer to 64KiB to be safe.
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	return out, nil
}

// GenerateToken produces a cryptographically random 32-byte token,
// hex-encoded (64 ASCII chars). The format is deliberately benign
// (URL-safe, scriptable) and the entropy is well above what guessing
// can reach. Used for the auto-bootstrap path in detourd when --http
// is enabled without any token configured.
func GenerateToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// BaseContextFor returns a closure suitable for
// http.Server.BaseContext that tags every request with the listener
// kind inferred from l (unix vs tcp). Required so Middleware can tell
// trusted Unix-socket peers from anonymous TCP clients.
func BaseContextFor(l net.Listener) func(net.Listener) context.Context {
	kind := KindTCP
	if l != nil && l.Addr() != nil && l.Addr().Network() == "unix" {
		kind = KindUnix
	}
	return func(net.Listener) context.Context {
		return WithListenerKind(context.Background(), kind)
	}
}

// Errors.
var (
	// ErrNoToken is returned by helpers when the operator asked for
	// auth but provided no tokens. The daemon turns this into a fatal
	// startup error so misconfiguration never lands as "auth silently
	// disabled".
	ErrNoToken = errors.New("auth required but no tokens configured")
)
