//go:build linux

// detour-linux is the Linux runtime for detour. It exposes an HTTP API
// for adding/removing iptables DNAT rules and ephemeral /etc/hosts
// entries. Both kinds of state are cleaned up on SIGINT/SIGTERM so
// quitting the daemon leaves no stale redirects behind.
//
// Typical operation:
//
//	# As root:
//	./detour-linux --listen :8080
//
//	# Redirect any local 0.0.0.0:1234 -> 127.0.0.1:2234:
//	curl -X POST localhost:8080/rules \
//	   -d '{"from":"0.0.0.0:1234","to":"127.0.0.1:2234","proto":"tcp"}'
//
//	# Pin foo.com -> 10.2.3.4 in /etc/hosts:
//	curl -X POST localhost:8080/hosts \
//	   -d '{"hostname":"foo.com","ip":"10.2.3.4"}'
//
//	# Ctrl+C: all rules and the managed /etc/hosts block disappear.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"detour/internal/api"
	"detour/internal/hostsfile"
	"detour/internal/linuxnat"
)

// Build metadata, populated at link time via -ldflags "-X main.version=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.SetFlags(log.Ltime)

	var (
		listen      = flag.String("listen", ":8080", "HTTP API listen address (host:port)")
		hostsPath   = flag.String("hosts-file", "/etc/hosts", "path to the hosts file managed on-the-fly")
		chain       = flag.String("chain", "DETOUR", "iptables chain name (nat table)")
		iptablesBin = flag.String("iptables", "iptables", "iptables binary path or name on $PATH")
		noHosts     = flag.Bool("no-hosts", false, "disable /etc/hosts management; /hosts endpoints return 503")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("detour-linux %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	// iptables(8) requires CAP_NET_ADMIN, which in practice means
	// running as root. Fail fast with a clear message rather than
	// surfacing the kernel's permission-denied later.
	if os.Geteuid() != 0 {
		log.Fatalf("must run as root (effective uid is %d) — iptables requires CAP_NET_ADMIN", os.Geteuid())
	}

	natMgr, err := linuxnat.New(linuxnat.Options{
		Chain:        *chain,
		IptablesPath: *iptablesBin,
	})
	if err != nil {
		log.Fatalf("init iptables manager: %v", err)
	}

	var hostsMgr *hostsfile.Manager
	if !*noHosts {
		hostsMgr = hostsfile.New(*hostsPath)
	}

	// The api.Server takes interface-typed backends; *hostsfile.Manager
	// satisfies HostsBackend, *linuxnat.Manager satisfies NATBackend.
	var hostsBackend api.HostsBackend
	if hostsMgr != nil {
		hostsBackend = hostsMgr
	}
	srv := api.New(natMgr, hostsBackend)

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Cleanup must run regardless of *how* we exit (signal, listener
	// error, panic). Pull it out into a function so every exit path
	// goes through the same code.
	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("http shutdown: %v", err)
		}
		if hostsMgr != nil {
			if err := hostsMgr.Close(); err != nil {
				log.Printf("hosts cleanup: %v", err)
			}
		}
		if err := natMgr.Close(); err != nil {
			log.Printf("iptables cleanup: %v", err)
		}
	}

	// Listen in a goroutine so we can react to either a signal or a
	// listener error from the main goroutine.
	listenErr := make(chan error, 1)
	go func() {
		log.Printf("detour-linux listening on %s (chain=%s hosts=%s)",
			*listen, *chain, hostsPathOrDisabled(*hostsPath, *noHosts))
		listenErr <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Printf("signal received, cleaning up...")
	case err := <-listenErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http listener failed: %v", err)
		}
	}
	cleanup()
}

func hostsPathOrDisabled(path string, disabled bool) string {
	if disabled {
		return "disabled"
	}
	return path
}
