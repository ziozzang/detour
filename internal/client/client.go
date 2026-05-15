// Package client is a thin Go wrapper over the detourd HTTP API. The
// CLI uses it for every command; external tools can vendor it to drive
// the daemon without re-implementing the wire format.
//
// Two transports are supported, chosen by the address prefix:
//
//	unix:///run/detour.sock   -> Unix-domain socket, the default for local CLIs
//	http://host:port          -> TCP loopback or remote daemons exposed via --http
//	https://host:port         -> same but over TLS (no client cert support yet)
//
// The Client keeps an http.Client with a custom Transport, so a single
// instance may be reused for many calls and is safe for concurrent
// use.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultSocketPath is where detourd places its Unix-domain control
// socket by default. Mirrors Docker's /var/run convention.
const DefaultSocketPath = "/run/detour.sock"

// Client talks to a single detourd instance. Construct via New.
type Client struct {
	addr    string // user-supplied address, kept for error messages
	baseURL string // URL we hand to http.NewRequest
	http    *http.Client
	token   string // Bearer token, attached via SetToken; empty by default
}

// Rule mirrors the JSON shape returned by the daemon. Kept in this
// package so callers don't have to import internal/api.
type Rule struct {
	ID    string `json:"id"`
	From  string `json:"from"`
	To    string `json:"to"`
	Proto string `json:"proto"`
}

// AddRuleRequest is the body for POST /rules.
type AddRuleRequest struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Proto string `json:"proto,omitempty"`
}

// Host mirrors a single managed /etc/hosts entry.
type Host struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// AddHostRequest is the body for POST /hosts.
type AddHostRequest struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// Error is returned by every Client method when the daemon replies
// with a non-2xx status. The HTTP status and the daemon's JSON error
// message are surfaced so the CLI can print something useful.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("daemon returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("daemon returned HTTP %d: %s", e.Status, e.Message)
}

// IsNotFound reports whether err is a 404 from the daemon.
func IsNotFound(err error) bool {
	var de *Error
	if errors.As(err, &de) {
		return de.Status == http.StatusNotFound
	}
	return false
}

// New builds a Client from a user-supplied address.
//
// Supported address forms:
//   - "unix:///path/to.sock"  (absolute path after unix://)
//   - "http://host:port"
//   - "https://host:port"
//   - "/path/to.sock"         (bare absolute path treated as unix://)
//   - ""                       (defaults to unix:///run/detour.sock)
//
// Each Client owns its own *http.Transport so independent Client
// instances don't share a connection pool. Per-request deadlines must
// be supplied via the context passed to each method; we deliberately
// do not set http.Client.Timeout, which would otherwise shadow
// callers' context-based cancellation.
func New(addr string) (*Client, error) {
	if addr == "" {
		addr = "unix://" + DefaultSocketPath
	}
	// Bare absolute path → unix.
	if strings.HasPrefix(addr, "/") {
		addr = "unix://" + addr
	}

	switch {
	case strings.HasPrefix(addr, "unix://"):
		sockPath := strings.TrimPrefix(addr, "unix://")
		if sockPath == "" || !strings.HasPrefix(sockPath, "/") {
			return nil, fmt.Errorf("unix socket path must be absolute, got %q", sockPath)
		}
		return &Client{
			addr:    addr,
			baseURL: "http://detour", // host portion is irrelevant for unix transport
			http: &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "unix", sockPath)
					},
					DisableCompression:    true,
					MaxIdleConns:          4,
					IdleConnTimeout:       90 * time.Second,
					ResponseHeaderTimeout: 30 * time.Second,
				},
			},
		}, nil
	case strings.HasPrefix(addr, "http://"), strings.HasPrefix(addr, "https://"):
		u, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", addr, err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("address %q has no host", addr)
		}
		return &Client{
			addr:    addr,
			baseURL: strings.TrimRight(addr, "/"),
			http: &http.Client{
				Transport: &http.Transport{
					Proxy:                 http.ProxyFromEnvironment,
					MaxIdleConns:          4,
					IdleConnTimeout:       90 * time.Second,
					ResponseHeaderTimeout: 30 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported address scheme: %q (use unix://, http://, or https://)", addr)
}

// Addr returns the address the client was constructed with. Useful for
// diagnostics.
func (c *Client) Addr() string { return c.addr }

// SetToken attaches a bearer token sent as `Authorization: Bearer ...`
// on every subsequent request. An empty string disables the header
// (default). Tokens may contain any non-control byte except the
// horizontal tab/newline that would terminate the HTTP header; we
// don't validate that here — the daemon's auth middleware does.
func (c *Client) SetToken(token string) { c.token = token }

// Token returns the bearer token currently configured. Empty when none
// has been set.
func (c *Client) Token() string { return c.token }

// VersionInfo mirrors GET /version. Fields may be empty when talking
// to an older daemon that doesn't yet implement the endpoint.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"date"`
	Chain     string `json:"chain"`
	UptimeSec int64  `json:"uptime_sec"`
	HostsFile string `json:"hosts_file"`
	AuthMode  string `json:"auth_mode"`
}

// Version fetches build/runtime metadata from the daemon.
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	var out VersionInfo
	err := c.do(ctx, http.MethodGet, "/version", nil, &out)
	return out, err
}

// Ping issues GET /healthz. Returns nil on a 200 response.
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", nil, nil)
}

// ListRules returns every DNAT rule currently installed.
func (c *Client) ListRules(ctx context.Context) ([]Rule, error) {
	var out []Rule
	if err := c.do(ctx, http.MethodGet, "/rules", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddRule installs a new DNAT rule.
func (c *Client) AddRule(ctx context.Context, req AddRuleRequest) (Rule, error) {
	var out Rule
	err := c.do(ctx, http.MethodPost, "/rules", req, &out)
	return out, err
}

// DeleteRule removes an installed rule by ID.
func (c *Client) DeleteRule(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("rule id is required")
	}
	return c.do(ctx, http.MethodDelete, "/rules/"+url.PathEscape(id), nil, nil)
}

// ListHosts returns every managed /etc/hosts entry.
func (c *Client) ListHosts(ctx context.Context) ([]Host, error) {
	var out []Host
	if err := c.do(ctx, http.MethodGet, "/hosts", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddHost adds a managed /etc/hosts entry.
func (c *Client) AddHost(ctx context.Context, req AddHostRequest) (Host, error) {
	var out Host
	err := c.do(ctx, http.MethodPost, "/hosts", req, &out)
	return out, err
}

// DeleteHost removes a managed /etc/hosts entry by ID.
func (c *Client) DeleteHost(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("host id is required")
	}
	return c.do(ctx, http.MethodDelete, "/hosts/"+url.PathEscape(id), nil, nil)
}

// do is the single HTTP path: encode the body if any, dispatch, then
// either decode the response into outPtr or return a typed *Error for
// the non-2xx case. outPtr may be nil for endpoints that return 204.
func (c *Client) do(ctx context.Context, method, path string, body, outPtr any) error {
	var reqBody io.Reader
	if body != nil {
		buf := &bytes.Buffer{}
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reqBody = buf
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call daemon at %s: %w", c.addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if outPtr == nil || resp.StatusCode == http.StatusNoContent {
			// Drain so the connection can be reused.
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil
		}
		if err := json.NewDecoder(resp.Body).Decode(outPtr); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	}

	// Non-2xx: try to surface the daemon's JSON error envelope.
	apiErr := &Error{Status: resp.StatusCode}
	var env struct {
		Error string `json:"error"`
	}
	body2, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body2, &env) == nil && env.Error != "" {
		apiErr.Message = env.Error
	} else if len(body2) > 0 {
		apiErr.Message = strings.TrimSpace(string(body2))
	}
	return apiErr
}
