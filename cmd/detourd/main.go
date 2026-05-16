// Command detourd is the detour daemon: a long-running Linux service
// that exposes a JSON HTTP API for managing iptables DNAT rules and
// on-the-fly /etc/hosts entries.
//
// The control plane is served over a Unix-domain socket by default
// (modeled on /var/run/docker.sock): owned by root, group-readable so
// members of a configured Unix group can drive the daemon with the
// `detour` CLI without elevation. An optional TCP listener can be
// enabled with --http for remote operation or scripting.
//
// On SIGINT/SIGTERM the daemon removes its iptables chain and managed
// /etc/hosts block, so a clean shutdown leaves no trace.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"detour/internal/api"
	"detour/internal/auth"
	"detour/internal/hostsfile"
	"detour/internal/linuxnat"
	"detour/internal/socket"
)

// Build metadata, populated at link time via -ldflags "-X main.version=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is the testable entry point. It accepts argv slice (without the
// program name) so tests can drive specific flag combinations. Returns
// the desired process exit code so callers don't have to wrap
// log.Fatal in defer-Close gymnastics.
func run(argv []string) int {
	fs := flag.NewFlagSet("detourd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		sockPath  = fs.String("socket", "/run/detour.sock", "Unix-domain socket path for the control plane")
		sockGroup = fs.String("socket-group", "detour", "Unix group that owns the socket (empty = leave at default)")
		sockMode  = fs.String("socket-mode", "0660", "Octal file mode applied to the socket (e.g. 0660, 0600)")
		httpAddr  = fs.String("http", "", "Also expose API on this TCP host:port (off by default)")
		hostsPath = fs.String("hosts-file", "/etc/hosts", "path to the hosts file managed on-the-fly")
		chain     = fs.String("chain", "DETOUR", "iptables chain name (nat table)")
		iptables  = fs.String("iptables", "iptables", "iptables binary path or name on $PATH")
		noHosts   = fs.Bool("no-hosts", false, "disable /etc/hosts management; /hosts endpoints return 503")
		authTok   = fs.String("auth-token", "", "single bearer token accepted on TCP (prefer --auth-token-file for production)")
		authFile  = fs.String("auth-token-file", "", "file with one bearer token per line; mode must be 0600")
		authReq   = fs.Bool("auth-required", false, "also require Authorization on the Unix socket (default: socket peers trusted via POSIX perms)")
		authState = fs.String("auth-state-dir", "/var/lib/detour", "directory for the auto-generated token when --http is set without tokens")
		showVer   = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: detourd [flags]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(argv); err != nil {
		// flag.ContinueOnError already printed the error.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVer {
		fmt.Printf("detourd %s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)

	// iptables(8) needs CAP_NET_ADMIN, which in practice means root.
	// Don't hard-fail though — a user with CAP_NET_ADMIN granted via
	// `setcap` is a perfectly valid operator. Just emit a warning so
	// the failure later is easier to debug.
	if os.Geteuid() != 0 {
		logger.Printf("warning: not running as root (euid=%d); iptables calls may fail unless CAP_NET_ADMIN is granted", os.Geteuid())
	}

	mode, err := parseOctalMode(*sockMode)
	if err != nil {
		logger.Printf("invalid --socket-mode: %v", err)
		return 2
	}

	natMgr, err := linuxnat.New(linuxnat.Options{
		Chain:        *chain,
		IptablesPath: *iptables,
	})
	if err != nil {
		logger.Printf("init iptables manager: %v", err)
		return 1
	}

	var hostsMgr *hostsfile.Manager
	if !*noHosts {
		hostsMgr = hostsfile.New(*hostsPath)
	}

	var hostsBackend api.HostsBackend
	if hostsMgr != nil {
		hostsBackend = hostsMgr
	}

	// ---- Resolve tokens ----------------------------------------------------
	tokens, authMode, err := resolveTokens(*authTok, *authFile, *httpAddr != "", *authReq, *authState, logger)
	if err != nil {
		_ = natMgr.Close()
		logger.Printf("auth setup: %v", err)
		return 1
	}

	info := api.NewInfo(
		version, commit, date, *chain,
		hostsPathOrDisabled(*hostsPath, *noHosts),
		authMode,
	)
	apiSrv := api.NewWithInfo(natMgr, hostsBackend, info)
	handler := auth.Middleware(apiSrv.Handler(), auth.Options{
		Tokens:        tokens,
		EnforceOnUnix: *authReq,
		AllowUnauthenticated: []string{
			// Health checks should never need a token; uptime probes
			// from monitoring systems are the entire point.
			"/healthz",
		},
	})

	// Unix socket: required.
	unixListener, err := socket.Listen(*sockPath, *sockGroup, mode)
	if err != nil {
		// Best-effort: tear down the iptables chain we just installed
		// so a flapping startup doesn't leave kernel state behind.
		_ = natMgr.Close()
		logger.Printf("socket setup: %v", err)
		return 1
	}

	// Optional TCP listener.
	var tcpListener net.Listener
	if *httpAddr != "" {
		tcpListener, err = net.Listen("tcp", *httpAddr)
		if err != nil {
			_ = unixListener.Close()
			_ = os.Remove(*sockPath)
			_ = natMgr.Close()
			logger.Printf("http listen: %v", err)
			return 1
		}
	}

	unixHTTP := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       auth.BaseContextFor(unixListener),
	}
	var tcpHTTP *http.Server
	if tcpListener != nil {
		tcpHTTP = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			BaseContext:       auth.BaseContextFor(tcpListener),
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = unixHTTP.Shutdown(shutdownCtx)
		if tcpHTTP != nil {
			_ = tcpHTTP.Shutdown(shutdownCtx)
		}
		// Always remove the socket file on the way out — Shutdown
		// doesn't unlink the inode and a stale 0660 socket on next
		// start would be confusing.
		_ = os.Remove(*sockPath)
		if hostsMgr != nil {
			if err := hostsMgr.Close(); err != nil {
				logger.Printf("hosts cleanup: %v", err)
			}
		}
		if err := natMgr.Close(); err != nil {
			logger.Printf("iptables cleanup: %v", err)
		}
	}

	// Serve in goroutines so we can react to either a signal or a
	// listener error from the main goroutine.
	listenErr := make(chan error, 2)
	go func() {
		logger.Printf("detourd listening on unix://%s (group=%s mode=%04o chain=%s hosts=%s auth=%s)",
			*sockPath, *sockGroup, mode, *chain,
			hostsPathOrDisabled(*hostsPath, *noHosts), authMode)
		listenErr <- unixHTTP.Serve(unixListener)
	}()
	if tcpHTTP != nil {
		go func() {
			logger.Printf("detourd also listening on http://%s", *httpAddr)
			listenErr <- tcpHTTP.Serve(tcpListener)
		}()
	}

	select {
	case <-ctx.Done():
		logger.Printf("signal received, cleaning up...")
	case err := <-listenErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("listener failed: %v", err)
		}
	}
	cleanup()
	return 0
}

// parseOctalMode accepts "0660", "660", or "0o660" style strings and
// returns the corresponding os.FileMode. Anything else is an error.
func parseOctalMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0, nil
	}
	// Allow Go-style 0o660 input, just in case operators are used to it.
	stripped := s
	if len(stripped) >= 2 && (stripped[:2] == "0o" || stripped[:2] == "0O") {
		stripped = stripped[2:]
	}
	var mode os.FileMode
	for _, r := range stripped {
		if r < '0' || r > '7' {
			return 0, fmt.Errorf("not a valid octal mode: %q", s)
		}
		mode = mode<<3 | os.FileMode(r-'0')
	}
	if mode > 0o7777 {
		return 0, fmt.Errorf("mode %q out of range", s)
	}
	return mode, nil
}

func hostsPathOrDisabled(path string, disabled bool) string {
	if disabled {
		return "disabled"
	}
	return path
}

// resolveTokens gathers tokens from the supplied flags, the
// DETOURD_AUTH_TOKEN environment variable, and (when needed) an
// auto-generated token persisted under stateDir. Returns the merged
// TokenSet (nil if no tokens are configured and none required) and a
// human-readable authMode label ("none" | "tcp" | "all").
//
// Bootstrap policy: if the operator enables --http without any token
// configured anywhere, we synthesise a random token and persist it at
// stateDir/auth.token (mode 0600). This is the "minimum security"
// posture: the daemon never accepts unauthenticated requests over TCP.
func resolveTokens(flagTok, flagFile string, httpEnabled, enforceUnix bool, stateDir string, logger *log.Logger) (*auth.TokenSet, string, error) {
	var collected []string
	if flagTok != "" {
		collected = append(collected, flagTok)
	}
	if env := strings.TrimSpace(os.Getenv("DETOURD_AUTH_TOKEN")); env != "" {
		collected = append(collected, env)
	}
	if flagFile != "" {
		ts, err := auth.LoadTokensFromFile(flagFile)
		if err != nil {
			return nil, "", fmt.Errorf("--auth-token-file: %w", err)
		}
		collected = append(collected, ts...)
	}

	if len(collected) == 0 && httpEnabled {
		// Auto-bootstrap: generate one and write it under stateDir so
		// the operator can read it back.
		tok, err := auth.GenerateToken()
		if err != nil {
			return nil, "", fmt.Errorf("auto-generate token: %w", err)
		}
		path := filepath.Join(stateDir, "auth.token")
		if err := writeTokenFile(path, tok); err != nil {
			return nil, "", fmt.Errorf("persist auto-generated token at %s: %w", path, err)
		}
		logger.Printf("auto-generated bearer token written to %s (mode 0600); use it as Authorization: Bearer <token>", path)
		collected = append(collected, tok)
	}

	if len(collected) == 0 {
		if enforceUnix {
			return nil, "", fmt.Errorf("--auth-required set but no tokens configured")
		}
		return nil, "none", nil
	}

	ts := auth.New(collected)
	if ts.Len() == 0 {
		// Everything we collected was blank — same outcome as "none".
		if enforceUnix {
			return nil, "", fmt.Errorf("--auth-required set but no usable tokens were found")
		}
		return nil, "none", nil
	}

	mode := "tcp"
	if enforceUnix {
		mode = "all"
	}
	return ts, mode, nil
}

// writeTokenFile writes token to path with restrictive permissions,
// creating intermediate directories as needed. The file is replaced
// atomically (write+rename) so a crashed daemon can't leave a half-
// written file behind. Existing tokens are overwritten only when the
// file mode is already 0600; otherwise we refuse and let the operator
// investigate.
func writeTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if st, err := os.Stat(path); err == nil {
		if st.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("refusing to overwrite %s with mode %o (must be <= 0600)", path, st.Mode().Perm())
		}
	}
	tmp, err := os.CreateTemp(dir, ".auth.token-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
