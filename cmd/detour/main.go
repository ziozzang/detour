// Command detour is the command-line client for the detour daemon.
//
// Connects to the daemon's Unix-domain socket (default
// /run/detour.sock) by default. Override with --host or the
// DETOUR_HOST environment variable. http://host:port works too if the
// daemon is started with --http.
//
// Subcommand layout (Docker-style):
//
//	detour version
//	detour info
//	detour rule list
//	detour rule add  --from IP:PORT --to IP:PORT [--proto tcp|udp|both]
//	detour rule rm   <id>
//	detour host list
//	detour host add  --hostname H --ip IP
//	detour host rm   <id>
//
// Global flags:
//
//	--host ADDR     unix:///path | http://host:port  (env: DETOUR_HOST)
//	--json          print JSON instead of tables
//	--timeout DUR   per-call timeout (default 10s)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"detour/internal/client"
)

// Build metadata, populated at link time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. Returns the desired process exit
// code. stdout/stderr are passed in so tests can capture them with a
// bytes.Buffer.
func run(argv []string, stdout, stderr io.Writer) int {
	root := flag.NewFlagSet("detour", flag.ContinueOnError)
	root.SetOutput(stderr)

	defaultHost := os.Getenv("DETOUR_HOST")
	if defaultHost == "" {
		defaultHost = "unix://" + client.DefaultSocketPath
	}
	host := root.String("host", defaultHost, "daemon address: unix:///path | http://host:port (env: DETOUR_HOST)")
	asJSON := root.Bool("json", false, "print JSON instead of tables")
	timeout := root.Duration("timeout", 10*time.Second, "per-call timeout")

	root.Usage = func() {
		fmt.Fprintf(stderr, "Usage: detour [global flags] <command> [args]\n\n")
		fmt.Fprintf(stderr, "Global flags:\n")
		root.PrintDefaults()
		fmt.Fprintf(stderr, "\nCommands:\n")
		for _, c := range commands() {
			fmt.Fprintf(stderr, "  %-18s %s\n", c.name, c.short)
		}
		fmt.Fprintf(stderr, "\nRun any command with --help to see its flags.\n")
	}

	if err := root.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	args := repackTwoWord(root.Args())
	if len(args) == 0 {
		root.Usage()
		return 2
	}

	cmdName, cmdArgs := args[0], args[1:]

	// `version` doesn't need a daemon round-trip.
	if cmdName == "version" {
		fmt.Fprintf(stdout, "detour %s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	c, err := client.New(*host)
	if err != nil {
		fmt.Fprintf(stderr, "detour: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	cfg := runConfig{
		client: c,
		ctx:    ctx,
		stdout: stdout,
		stderr: stderr,
		asJSON: *asJSON,
	}

	cmd, ok := dispatch(cmdName)
	if !ok {
		fmt.Fprintf(stderr, "detour: unknown command %q\n", cmdName)
		root.Usage()
		return 2
	}
	if err := cmd.run(cfg, cmdArgs); err != nil {
		fmt.Fprintf(stderr, "detour: %v\n", err)
		return 1
	}
	return 0
}

// runConfig threads the resolved client, timeout context, and output
// streams through every subcommand without making each one re-parse
// the global flags.
type runConfig struct {
	client *client.Client
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
	asJSON bool
}

type command struct {
	name  string
	short string
	run   func(cfg runConfig, args []string) error
}

func commands() []command {
	return []command{
		{"version", "show client version", nil}, // handled inline in run()
		{"info", "show daemon health and basic info", cmdInfo},
		{"rule list", "list installed DNAT rules", cmdRuleList},
		{"rule add", "install a DNAT rule (--from --to [--proto])", cmdRuleAdd},
		{"rule rm", "remove a DNAT rule by ID", cmdRuleRm},
		{"host list", "list managed /etc/hosts entries", cmdHostList},
		{"host add", "add a managed /etc/hosts entry (--hostname --ip)", cmdHostAdd},
		{"host rm", "remove a managed /etc/hosts entry by ID", cmdHostRm},
	}
}

// dispatch resolves "rule add" / "host rm" / "info" style command
// names to their handlers. Returns false on miss.
func dispatch(name string) (command, bool) {
	for _, c := range commands() {
		if c.name == name && c.run != nil {
			return c, true
		}
	}
	return command{}, false
}

// repackTwoWord joins the first two args when they form a known
// compound command (e.g. "rule" "add" -> "rule add"), so flag.Parse
// can hand them to us split but dispatch can match the full name.
func repackTwoWord(args []string) []string {
	if len(args) >= 2 {
		joined := args[0] + " " + args[1]
		if _, ok := dispatch(joined); ok {
			out := make([]string, 0, len(args)-1)
			out = append(out, joined)
			out = append(out, args[2:]...)
			return out
		}
	}
	return args
}

// ---------------------------------------------------------------------------
// subcommand implementations
// ---------------------------------------------------------------------------

type infoRow struct {
	Address string `json:"address"`
	Healthy bool   `json:"healthy"`
	Rules   int    `json:"rules"`
	Hosts   int    `json:"hosts"`
}

func cmdInfo(cfg runConfig, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("info: unexpected arguments: %v", args)
	}
	row := infoRow{Address: cfg.client.Addr()}
	if err := cfg.client.Ping(cfg.ctx); err == nil {
		row.Healthy = true
		if rs, err := cfg.client.ListRules(cfg.ctx); err == nil {
			row.Rules = len(rs)
		}
		if hs, err := cfg.client.ListHosts(cfg.ctx); err == nil {
			row.Hosts = len(hs)
		}
	}
	if cfg.asJSON {
		return writeJSON(cfg.stdout, row)
	}
	tw := newTab(cfg.stdout)
	fmt.Fprintf(tw, "ADDRESS\t%s\n", row.Address)
	fmt.Fprintf(tw, "HEALTHY\t%v\n", row.Healthy)
	fmt.Fprintf(tw, "RULES\t%d\n", row.Rules)
	fmt.Fprintf(tw, "HOSTS\t%d\n", row.Hosts)
	return tw.Flush()
}

func cmdRuleList(cfg runConfig, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("rule list: unexpected arguments: %v", args)
	}
	rules, err := cfg.client.ListRules(cfg.ctx)
	if err != nil {
		return err
	}
	if cfg.asJSON {
		return writeJSON(cfg.stdout, rules)
	}
	tw := newTab(cfg.stdout)
	fmt.Fprintln(tw, "ID\tFROM\tTO\tPROTO")
	for _, r := range rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.From, r.To, r.Proto)
	}
	if len(rules) == 0 {
		fmt.Fprintln(tw, "(no rules)\t\t\t")
	}
	return tw.Flush()
}

func cmdRuleAdd(cfg runConfig, args []string) error {
	fs := flag.NewFlagSet("rule add", flag.ContinueOnError)
	fs.SetOutput(cfg.stderr)
	from := fs.String("from", "", "from IP:PORT (use 0.0.0.0 to match any local IP)")
	to := fs.String("to", "", "to IP:PORT")
	proto := fs.String("proto", "both", "protocol: tcp | udp | both")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		return errors.New("rule add: --from and --to are required")
	}
	got, err := cfg.client.AddRule(cfg.ctx, client.AddRuleRequest{
		From: *from, To: *to, Proto: *proto,
	})
	if err != nil {
		return err
	}
	if cfg.asJSON {
		return writeJSON(cfg.stdout, got)
	}
	fmt.Fprintln(cfg.stdout, got.ID)
	return nil
}

func cmdRuleRm(cfg runConfig, args []string) error {
	if len(args) != 1 {
		return errors.New("rule rm: exactly one rule ID required")
	}
	if err := cfg.client.DeleteRule(cfg.ctx, args[0]); err != nil {
		return err
	}
	if !cfg.asJSON {
		fmt.Fprintln(cfg.stdout, "deleted "+args[0])
	}
	return nil
}

func cmdHostList(cfg runConfig, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("host list: unexpected arguments: %v", args)
	}
	hosts, err := cfg.client.ListHosts(cfg.ctx)
	if err != nil {
		return err
	}
	if cfg.asJSON {
		return writeJSON(cfg.stdout, hosts)
	}
	tw := newTab(cfg.stdout)
	fmt.Fprintln(tw, "ID\tHOSTNAME\tIP")
	for _, h := range hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", h.ID, h.Hostname, h.IP)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(tw, "(no hosts)\t\t")
	}
	return tw.Flush()
}

func cmdHostAdd(cfg runConfig, args []string) error {
	fs := flag.NewFlagSet("host add", flag.ContinueOnError)
	fs.SetOutput(cfg.stderr)
	hostname := fs.String("hostname", "", "DNS hostname to override")
	ip := fs.String("ip", "", "IP address to point the hostname at")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hostname == "" || *ip == "" {
		return errors.New("host add: --hostname and --ip are required")
	}
	got, err := cfg.client.AddHost(cfg.ctx, client.AddHostRequest{Hostname: *hostname, IP: *ip})
	if err != nil {
		return err
	}
	if cfg.asJSON {
		return writeJSON(cfg.stdout, got)
	}
	fmt.Fprintln(cfg.stdout, got.ID)
	return nil
}

func cmdHostRm(cfg runConfig, args []string) error {
	if len(args) != 1 {
		return errors.New("host rm: exactly one host ID required")
	}
	if err := cfg.client.DeleteHost(cfg.ctx, args[0]); err != nil {
		return err
	}
	if !cfg.asJSON {
		fmt.Fprintln(cfg.stdout, "deleted "+args[0])
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newTab(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
}
