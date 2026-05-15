package main

// service.go implements `detour service {install,uninstall,status,logs}`.
//
// The design assumption is straightforward: most Linux production
// hosts run systemd, and the operator wants one command to install
// detourd as a managed unit. We don't try to support OpenRC / runit /
// custom init; on those systems the user is expected to write a unit
// themselves and the CLI just refuses with a clear error.
//
// Every action accepts --dry-run, which prints the unit text and the
// shell commands that would run (with no side effects). That makes
// the subcommand easy to audit before running it as root.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// systemctlRunner is the seam between cmdService* and the real
// systemctl binary. Tests inject a recorder; production wires
// execRunner.
type systemctlRunner interface {
	Run(args ...string) (stdout string, stderr string, err error)
}

// fileWriter / fileRemover let tests intercept writes without actually
// touching /etc/systemd/system. mkdirAll/chmod follow the same
// pattern.
type fileWriter func(path string, body []byte, mode os.FileMode) error
type fileRemover func(path string) error

// serviceEnv carries the side-effect surfaces a service subcommand
// touches: the systemctl shim, file IO, and detection of systemd
// availability. Default production wiring is produced by
// defaultServiceEnv().
type serviceEnv struct {
	runner       systemctlRunner
	writeFile    fileWriter
	removeFile   fileRemover
	hasSystemd   func() bool
	lookupBinary func(name string) (string, error)
}

func defaultServiceEnv() serviceEnv {
	return serviceEnv{
		runner: execSystemctl{},
		writeFile: func(path string, body []byte, mode os.FileMode) error {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			return os.WriteFile(path, body, mode)
		},
		removeFile: os.Remove,
		hasSystemd: func() bool {
			_, err := os.Stat("/run/systemd/system")
			return err == nil
		},
		lookupBinary: exec.LookPath,
	}
}

type execSystemctl struct{}

func (execSystemctl) Run(args ...string) (string, string, error) {
	cmd := exec.Command("systemctl", args...)
	stdoutBuf := &strings.Builder{}
	stderrBuf := &strings.Builder{}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	err := cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

// serviceEnvOverride is set by tests via newServiceEnvForTest to
// inject a fake. nil in production.
var serviceEnvOverride *serviceEnv

func currentServiceEnv() serviceEnv {
	if serviceEnvOverride != nil {
		return *serviceEnvOverride
	}
	return defaultServiceEnv()
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

const defaultUnitPath = "/etc/systemd/system/detourd.service"

type installFlags struct {
	unitPath    string
	user        string
	group       string
	socket      string
	socketGroup string
	socketMode  string
	httpAddr    string
	chain       string
	hostsFile   string
	noHosts     bool
	authFile    string
	enable      bool
	exec        string
	dryRun      bool
}

func cmdServiceInstall(cfg runConfig, args []string) error {
	fs := flag.NewFlagSet("service install", flag.ContinueOnError)
	fs.SetOutput(cfg.stderr)
	f := installFlags{}
	fs.StringVar(&f.unitPath, "unit-path", defaultUnitPath, "where to write the systemd unit")
	fs.StringVar(&f.user, "user", "root", "User= for the unit (root required for iptables)")
	fs.StringVar(&f.group, "group", "root", "Group= for the unit")
	fs.StringVar(&f.socket, "socket", "/run/detour.sock", "detourd --socket")
	fs.StringVar(&f.socketGroup, "socket-group", "detour", "detourd --socket-group")
	fs.StringVar(&f.socketMode, "socket-mode", "0660", "detourd --socket-mode")
	fs.StringVar(&f.httpAddr, "http", "", "detourd --http (optional)")
	fs.StringVar(&f.chain, "chain", "DETOUR", "detourd --chain")
	fs.StringVar(&f.hostsFile, "hosts-file", "/etc/hosts", "detourd --hosts-file")
	fs.BoolVar(&f.noHosts, "no-hosts", false, "set if you want detourd --no-hosts")
	fs.StringVar(&f.authFile, "auth-token-file", "", "detourd --auth-token-file (optional)")
	fs.StringVar(&f.exec, "binary", "/usr/local/bin/detourd", "absolute path to the detourd binary")
	fs.BoolVar(&f.enable, "enable", false, "also enable and start the service after install")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print unit + commands, don't touch the system")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !filepath.IsAbs(f.exec) {
		return fmt.Errorf("service install: --binary must be an absolute path, got %q", f.exec)
	}
	env := currentServiceEnv()
	if !env.hasSystemd() && !f.dryRun {
		return errors.New("service install: systemd not detected (no /run/systemd/system); generate a unit manually or pass --dry-run to inspect one")
	}
	unit := renderUnit(f)
	if f.dryRun {
		fmt.Fprintf(cfg.stdout, "# would write %s (mode 0644):\n", f.unitPath)
		fmt.Fprintln(cfg.stdout, unit)
		fmt.Fprintf(cfg.stdout, "# would run: systemctl daemon-reload\n")
		if f.enable {
			fmt.Fprintf(cfg.stdout, "# would run: systemctl enable --now detourd\n")
		}
		return nil
	}
	if err := env.writeFile(f.unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", f.unitPath, err)
	}
	fmt.Fprintf(cfg.stdout, "wrote %s\n", f.unitPath)
	if err := runSystemctl(env.runner, cfg.stdout, "daemon-reload"); err != nil {
		return err
	}
	if f.enable {
		if err := runSystemctl(env.runner, cfg.stdout, "enable", "--now", "detourd"); err != nil {
			return err
		}
		fmt.Fprintln(cfg.stdout, "detourd enabled and started")
	} else {
		fmt.Fprintln(cfg.stdout, "service installed; start with: sudo systemctl enable --now detourd")
	}
	return nil
}

// renderUnit produces the systemd unit text for the supplied flags.
// Kept as a pure function so tests can assert the exact output.
func renderUnit(f installFlags) string {
	var execArgs []string
	execArgs = append(execArgs, f.exec)
	execArgs = append(execArgs, "--socket="+f.socket)
	execArgs = append(execArgs, "--socket-group="+f.socketGroup)
	execArgs = append(execArgs, "--socket-mode="+f.socketMode)
	if f.httpAddr != "" {
		execArgs = append(execArgs, "--http="+f.httpAddr)
	}
	execArgs = append(execArgs, "--chain="+f.chain)
	execArgs = append(execArgs, "--hosts-file="+f.hostsFile)
	if f.noHosts {
		execArgs = append(execArgs, "--no-hosts")
	}
	if f.authFile != "" {
		execArgs = append(execArgs, "--auth-token-file="+f.authFile)
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=detour iptables/hosts daemon\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + f.user + "\n")
	b.WriteString("Group=" + f.group + "\n")
	// CAP_NET_ADMIN lets detourd manage iptables even if the operator
	// later swaps User= to a non-root account; harmless when User=root.
	b.WriteString("AmbientCapabilities=CAP_NET_ADMIN\n")
	b.WriteString("CapabilityBoundingSet=CAP_NET_ADMIN\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("ExecStart=" + strings.Join(execArgs, " ") + "\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=2\n")
	// State dir for the auto-generated token; systemd will create
	// /var/lib/detour with the correct ownership.
	b.WriteString("StateDirectory=detour\n")
	b.WriteString("StateDirectoryMode=0700\n")
	b.WriteString("RuntimeDirectory=detour\n")
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

func runSystemctl(r systemctlRunner, out io.Writer, args ...string) error {
	stdout, stderr, err := r.Run(args...)
	if stdout != "" {
		fmt.Fprint(out, stdout)
	}
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr))
		}
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

func cmdServiceUninstall(cfg runConfig, args []string) error {
	fs := flag.NewFlagSet("service uninstall", flag.ContinueOnError)
	fs.SetOutput(cfg.stderr)
	unitPath := fs.String("unit-path", defaultUnitPath, "path of the unit to remove")
	purge := fs.Bool("purge", false, "also remove /var/lib/detour (auto-generated tokens etc.)")
	dryRun := fs.Bool("dry-run", false, "print commands without running them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env := currentServiceEnv()
	steps := [][]string{
		{"stop", "detourd"},
		{"disable", "detourd"},
	}
	if *dryRun {
		for _, s := range steps {
			fmt.Fprintf(cfg.stdout, "# would run: systemctl %s\n", strings.Join(s, " "))
		}
		fmt.Fprintf(cfg.stdout, "# would remove: %s\n", *unitPath)
		fmt.Fprintln(cfg.stdout, "# would run: systemctl daemon-reload")
		if *purge {
			fmt.Fprintln(cfg.stdout, "# would remove: /var/lib/detour")
		}
		return nil
	}
	if !env.hasSystemd() {
		return errors.New("service uninstall: systemd not detected; nothing to undo (or remove the unit manually)")
	}
	for _, s := range steps {
		// Don't abort if a step fails — `stop` on an already-stopped
		// unit returns non-zero on some systemd versions, and
		// `disable` on a missing unit too. We surface stderr instead.
		stdout, stderr, err := env.runner.Run(s...)
		if stdout != "" {
			fmt.Fprint(cfg.stdout, stdout)
		}
		if err != nil {
			fmt.Fprintf(cfg.stderr, "detour: systemctl %s: %s\n", strings.Join(s, " "), strings.TrimSpace(stderr))
		}
	}
	if err := env.removeFile(*unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", *unitPath, err)
	}
	fmt.Fprintf(cfg.stdout, "removed %s\n", *unitPath)
	_ = runSystemctl(env.runner, cfg.stdout, "daemon-reload")
	if *purge {
		if err := os.RemoveAll("/var/lib/detour"); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("purge /var/lib/detour: %w", err)
		}
		fmt.Fprintln(cfg.stdout, "purged /var/lib/detour")
	}
	return nil
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

type serviceStatusRow struct {
	Detected      bool   `json:"systemd_detected"`
	LoadState     string `json:"load_state,omitempty"`
	ActiveState   string `json:"active_state,omitempty"`
	SubState      string `json:"sub_state,omitempty"`
	MainPID       int    `json:"main_pid,omitempty"`
	Enabled       string `json:"unit_file_state,omitempty"`
	ActiveEnterTS string `json:"active_enter_timestamp,omitempty"`
}

func cmdServiceStatus(cfg runConfig, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("service status: unexpected arguments: %v", args)
	}
	env := currentServiceEnv()
	row := serviceStatusRow{Detected: env.hasSystemd()}
	if !row.Detected {
		if cfg.asJSON {
			return writeJSON(cfg.stdout, row)
		}
		fmt.Fprintln(cfg.stdout, "systemd not detected on this host.")
		return nil
	}
	// `systemctl show -p ...` outputs key=value lines, robust against
	// systemd version differences in `status` formatting.
	props := []string{
		"LoadState",
		"ActiveState",
		"SubState",
		"MainPID",
		"UnitFileState",
		"ActiveEnterTimestamp",
	}
	stdout, _, err := env.runner.Run(append([]string{"show", "-p", strings.Join(props, ",")}, "detourd")...)
	if err != nil {
		return fmt.Errorf("systemctl show detourd: %w", err)
	}
	for _, line := range strings.Split(stdout, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			row.LoadState = v
		case "ActiveState":
			row.ActiveState = v
		case "SubState":
			row.SubState = v
		case "MainPID":
			if n, err := strconv.Atoi(v); err == nil {
				row.MainPID = n
			}
		case "UnitFileState":
			row.Enabled = v
		case "ActiveEnterTimestamp":
			row.ActiveEnterTS = v
		}
	}
	if cfg.asJSON {
		return writeJSON(cfg.stdout, row)
	}
	tw := newTab(cfg.stdout)
	fmt.Fprintf(tw, "UNIT\tdetourd.service\n")
	fmt.Fprintf(tw, "LOADED\t%s\n", strOrDash(row.LoadState))
	fmt.Fprintf(tw, "ACTIVE\t%s (%s)\n", strOrDash(row.ActiveState), strOrDash(row.SubState))
	fmt.Fprintf(tw, "ENABLED\t%s\n", strOrDash(row.Enabled))
	if row.MainPID > 0 {
		fmt.Fprintf(tw, "PID\t%d\n", row.MainPID)
	}
	if row.ActiveEnterTS != "" {
		fmt.Fprintf(tw, "SINCE\t%s\n", row.ActiveEnterTS)
	}
	return tw.Flush()
}

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

func cmdServiceLogs(cfg runConfig, args []string) error {
	fs := flag.NewFlagSet("service logs", flag.ContinueOnError)
	fs.SetOutput(cfg.stderr)
	tail := fs.Int("tail", 100, "show last N lines (0 = all)")
	follow := fs.Bool("follow", false, "follow new log lines (Ctrl-C to stop)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env := currentServiceEnv()
	if !env.hasSystemd() {
		return errors.New("service logs: systemd not detected (no journalctl)")
	}
	bin, err := env.lookupBinary("journalctl")
	if err != nil {
		return fmt.Errorf("service logs: journalctl not found in PATH")
	}
	cmd := exec.Command(bin, "-u", "detourd")
	if *tail > 0 {
		cmd.Args = append(cmd.Args, "-n", strconv.Itoa(*tail))
	}
	if *follow {
		cmd.Args = append(cmd.Args, "-f")
	}
	cmd.Stdout = cfg.stdout
	cmd.Stderr = cfg.stderr
	return cmd.Run()
}
