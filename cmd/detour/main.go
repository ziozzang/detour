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
//	detour ping
//	detour info | status
//	detour rule list                                       (alias: rule ls)
//	detour rule add  --from IP:PORT --to IP:PORT [--proto tcp|udp|both] [--dry-run]
//	detour rule rm   <id>                                  (alias: rule remove, rule delete)
//	detour host list                                       (alias: host ls)
//	detour host add  --hostname H --ip IP
//	detour host rm   <id>                                  (alias: host remove, host delete)
//	detour service install     [--unit-path PATH] [--user U] [--group G]
//	                           [--socket PATH] [--http ADDR] [--enable] [--dry-run]
//	detour service uninstall   [--purge] [--dry-run]
//	detour service status
//	detour service logs        [--tail N] [--follow]
//	detour completion bash|zsh|fish
//
// Global flags:
//
//	--host ADDR        unix:///path | http://host:port (env: DETOUR_HOST)
//	--token TOKEN      bearer token for HTTP auth     (env: DETOUR_TOKEN)
//	--token-file PATH  read bearer token from file    (env: DETOUR_TOKEN_FILE)
//	--json             print JSON instead of tables
//	--timeout DUR      per-call timeout (default 10s)
//
// Exit codes:
//
//	0   success
//	1   call succeeded to the daemon but the operation failed
//	2   usage error or could not reach the daemon
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
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
	token := root.String("token", os.Getenv("DETOUR_TOKEN"), "bearer token for HTTP auth (env: DETOUR_TOKEN)")
	tokenFile := root.String("token-file", os.Getenv("DETOUR_TOKEN_FILE"), "read bearer token from file (env: DETOUR_TOKEN_FILE)")
	asJSON := root.Bool("json", false, "print JSON instead of tables")
	timeout := root.Duration("timeout", 10*time.Second, "per-call timeout")

	root.Usage = func() {
		fmt.Fprintf(stderr, "Usage: detour [global flags] <command> [args]\n\n")
		fmt.Fprintf(stderr, "Global flags:\n")
		root.PrintDefaults()
		fmt.Fprintf(stderr, "\nCommands:\n")
		for _, c := range commands() {
			fmt.Fprintf(stderr, "  %-20s %s\n", c.name, c.short)
		}
		fmt.Fprintf(stderr, "\nRun any command with --help to see its flags.\n")
		fmt.Fprintf(stderr, "Exit codes: 0=ok, 1=operation failed, 2=usage / unreachable.\n")
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

	// `completion` writes a static shell-completion script. Doesn't
	// need a daemon round-trip either.
	if cmdName == "completion" {
		return cmdCompletion(cmdArgs, stdout, stderr)
	}

	c, err := client.New(*host)
	if err != nil {
		fmt.Fprintf(stderr, "detour: %v\n", err)
		return 2
	}

	// Resolve token: explicit --token wins, else --token-file, else env.
	if *token == "" && *tokenFile != "" {
		raw, ferr := os.ReadFile(*tokenFile)
		if ferr != nil {
			fmt.Fprintf(stderr, "detour: read --token-file: %v\n", ferr)
			return 2
		}
		*token = strings.TrimSpace(string(raw))
	}
	if *token != "" {
		c.SetToken(*token)
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
		fmt.Fprintf(stderr, "detour: %s\n", friendlyError(err, c.Addr()))
		// "could not connect" is a usage/environment error, not an
		// operation error — distinguish for scripts.
		if isConnError(err) {
			return 2
		}
		return 1
	}
	return 0
}

// friendlyError adds a hint when the error suggests the daemon is not
// reachable. We keep the original message verbatim so debugging info
// isn't lost.
func friendlyError(err error, addr string) string {
	if isConnError(err) {
		return fmt.Sprintf("%v\n  hint: is detourd running at %s? Try: sudo systemctl status detourd",
			err, addr)
	}
	return err.Error()
}

// isConnError reports whether the error looks like a transport-level
// failure (no daemon, refused, permission denied on socket). We don't
// want to depend on errors.Is over the net package's many sentinels,
// so a substring check is good enough for UX.
func isConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, k := range []string{"connection refused", "no such file", "permission denied", "connect: ", "dial unix"} {
		if strings.Contains(msg, k) {
			return true
		}
	}
	return false
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
		{"ping", "fast health probe (exit 0 = ok)", cmdPing},
		{"info", "show daemon health, build info, and counts", cmdInfo},
		{"status", "alias of info, with verbose layout", cmdStatus},
		{"rule list", "list installed DNAT rules", cmdRuleList},
		{"rule add", "install a DNAT rule (--from --to [--proto] [--dry-run])", cmdRuleAdd},
		{"rule rm", "remove a DNAT rule by ID", cmdRuleRm},
		{"host list", "list managed /etc/hosts entries", cmdHostList},
		{"host add", "add a managed /etc/hosts entry (--hostname --ip)", cmdHostAdd},
		{"host rm", "remove a managed /etc/hosts entry by ID", cmdHostRm},
		{"service install", "install the systemd unit and (optionally) start the daemon", cmdServiceInstall},
		{"service uninstall", "stop, disable, and remove the systemd unit", cmdServiceUninstall},
		{"service status", "show systemd status of the detourd service", cmdServiceStatus},
		{"service logs", "tail journal logs for the detourd service", cmdServiceLogs},
		{"completion", "print shell completion script (bash|zsh|fish)", nil}, // handled inline in run()
	}
}

// aliases maps the canonical command name to its accepted alternatives.
// Kept as a flat table so `dispatch` stays O(commands).
var aliases = map[string]string{
	"rule ls":     "rule list",
	"host ls":     "host list",
	"rule remove": "rule rm",
	"rule delete": "rule rm",
	"host remove": "host rm",
	"host delete": "host rm",
}

// dispatch resolves "rule add" / "host rm" / "info" style command
// names to their handlers. Honors aliases. Returns false on miss.
func dispatch(name string) (command, bool) {
	if canon, ok := aliases[name]; ok {
		name = canon
	}
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
		// Also collapse "completion" + arg into just "completion"
		// when args[0] is a known leaf with a sub-arg.
		if args[0] == "completion" {
			return args
		}
	}
	return args
}

// ---------------------------------------------------------------------------
// subcommand implementations
// ---------------------------------------------------------------------------

type infoRow struct {
	Address   string `json:"address"`
	Healthy   bool   `json:"healthy"`
	Error     string `json:"error,omitempty"`
	Version   string `json:"version,omitempty"`
	Chain     string `json:"chain,omitempty"`
	HostsFile string `json:"hosts_file,omitempty"`
	AuthMode  string `json:"auth_mode,omitempty"`
	UptimeSec int64  `json:"uptime_sec,omitempty"`
	Rules     int    `json:"rules"`
	Hosts     int    `json:"hosts"`
}

func gatherInfo(cfg runConfig) infoRow {
	row := infoRow{Address: cfg.client.Addr()}
	if err := cfg.client.Ping(cfg.ctx); err != nil {
		row.Error = err.Error()
		return row
	}
	row.Healthy = true
	if v, err := cfg.client.Version(cfg.ctx); err == nil {
		row.Version = v.Version
		row.Chain = v.Chain
		row.HostsFile = v.HostsFile
		row.AuthMode = v.AuthMode
		row.UptimeSec = v.UptimeSec
	}
	if rs, err := cfg.client.ListRules(cfg.ctx); err == nil {
		row.Rules = len(rs)
	}
	if hs, err := cfg.client.ListHosts(cfg.ctx); err == nil {
		row.Hosts = len(hs)
	}
	return row
}

func cmdPing(cfg runConfig, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("ping: unexpected arguments: %v", args)
	}
	if err := cfg.client.Ping(cfg.ctx); err != nil {
		return err
	}
	if !cfg.asJSON {
		fmt.Fprintln(cfg.stdout, "pong")
	} else {
		_ = writeJSON(cfg.stdout, map[string]string{"status": "ok"})
	}
	return nil
}

func cmdInfo(cfg runConfig, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("info: unexpected arguments: %v", args)
	}
	row := gatherInfo(cfg)
	if cfg.asJSON {
		return writeJSON(cfg.stdout, row)
	}
	tw := newTab(cfg.stdout)
	fmt.Fprintf(tw, "ADDRESS\t%s\n", row.Address)
	fmt.Fprintf(tw, "HEALTHY\t%v\n", row.Healthy)
	if row.Error != "" {
		fmt.Fprintf(tw, "ERROR\t%s\n", row.Error)
	}
	fmt.Fprintf(tw, "RULES\t%d\n", row.Rules)
	fmt.Fprintf(tw, "HOSTS\t%d\n", row.Hosts)
	return tw.Flush()
}

// cmdStatus is the verbose cousin of cmdInfo: surfaces the daemon's
// build metadata, auth mode, and uptime. Designed for "is this thing
// healthy and what version" at a glance.
func cmdStatus(cfg runConfig, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("status: unexpected arguments: %v", args)
	}
	row := gatherInfo(cfg)
	if cfg.asJSON {
		return writeJSON(cfg.stdout, row)
	}
	tw := newTab(cfg.stdout)
	fmt.Fprintf(tw, "ADDRESS\t%s\n", row.Address)
	fmt.Fprintf(tw, "HEALTHY\t%v\n", row.Healthy)
	if row.Error != "" {
		fmt.Fprintf(tw, "ERROR\t%s\n", row.Error)
	}
	fmt.Fprintf(tw, "VERSION\t%s\n", strOrDash(row.Version))
	fmt.Fprintf(tw, "CHAIN\t%s\n", strOrDash(row.Chain))
	fmt.Fprintf(tw, "HOSTS-FILE\t%s\n", strOrDash(row.HostsFile))
	fmt.Fprintf(tw, "AUTH-MODE\t%s\n", strOrDash(row.AuthMode))
	if row.UptimeSec > 0 {
		fmt.Fprintf(tw, "UPTIME\t%s\n", time.Duration(row.UptimeSec)*time.Second)
	} else {
		fmt.Fprintln(tw, "UPTIME\t-")
	}
	fmt.Fprintf(tw, "RULES\t%d\n", row.Rules)
	fmt.Fprintf(tw, "HOSTS\t%d\n", row.Hosts)
	return tw.Flush()
}

func strOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
	dryRun := fs.Bool("dry-run", false, "validate inputs locally without calling the daemon")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		return errors.New("rule add: --from and --to are required")
	}
	switch *proto {
	case "tcp", "udp", "both":
	default:
		return fmt.Errorf("rule add: invalid --proto %q (want tcp|udp|both)", *proto)
	}
	if *dryRun {
		// We don't try to re-implement endpoint parsing on the
		// client; just confirm the flag combination and exit 0.
		if cfg.asJSON {
			return writeJSON(cfg.stdout, map[string]any{
				"dry_run": true,
				"from":    *from,
				"to":      *to,
				"proto":   *proto,
			})
		}
		fmt.Fprintf(cfg.stdout, "dry-run ok: from=%s to=%s proto=%s\n", *from, *to, *proto)
		return nil
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
