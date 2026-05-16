// Package linuxnat implements destination-NAT redirection on Linux using
// iptables(8). Every Manager owns a dedicated chain in the `nat` table —
// `DETOUR` by default — that gets hooked from `OUTPUT` and `PREROUTING`,
// so rules apply both to packets originated locally and to packets
// forwarded through this host. Close() flushes and removes the chain so
// no stray DNAT rules survive the process.
//
// The package is build-tagged Linux because it shells out to iptables.
// To keep it unit-testable on every host, command execution is mediated
// by a Runner interface; tests inject a recording fake instead of
// actually invoking iptables.
package linuxnat

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Protocol enumerates the L4 protocols the manager understands. We
// purposefully mirror the names accepted by iptables so they go straight
// into command lines.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoBoth Protocol = "both" // expands to two iptables rules
)

// Valid reports whether p is one of the supported protocols.
func (p Protocol) Valid() bool {
	switch p {
	case ProtoTCP, ProtoUDP, ProtoBoth:
		return true
	}
	return false
}

// Endpoint is a literal IPv4 + port pair. We deliberately keep this
// package independent of detour/internal/cli.Endpoint so that pure-Go
// callers (the HTTP API, tests) don't drag in Windows-only build
// constraints transitively.
type Endpoint struct {
	IP   net.IP
	Port uint16
}

// String renders an endpoint as "IP:PORT" — what iptables expects.
func (e Endpoint) String() string {
	return net.JoinHostPort(e.IP.String(), strconv.Itoa(int(e.Port)))
}

// ParseEndpoint parses "IP:PORT" into an IPv4 Endpoint. IP `0.0.0.0` is
// permitted on the FROM side and is interpreted as "match any local
// destination address on the given port"; iptables expresses this by
// omitting the `--destination` match entirely.
func ParseEndpoint(s string) (Endpoint, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid IP:PORT %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return Endpoint{}, fmt.Errorf("invalid IP %q", host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return Endpoint{}, fmt.Errorf("only IPv4 supported, got %q", host)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || p == 0 {
		return Endpoint{}, fmt.Errorf("invalid port %q", portStr)
	}
	return Endpoint{IP: ip4, Port: uint16(p)}, nil
}

// Rule is the public view of one redirection currently installed.
type Rule struct {
	ID    string
	From  Endpoint
	To    Endpoint
	Proto Protocol
}

// Runner is the seam between Manager and the actual iptables binary.
// Production code wires in execRunner; tests inject a recorder that
// returns deterministic output without touching the kernel.
type Runner interface {
	// Run invokes iptables with the given arguments and returns its
	// combined stdout+stderr. Implementations must return a non-nil
	// error iff the process exits non-zero or fails to launch.
	Run(args ...string) ([]byte, error)
}

type execRunner struct {
	bin string
}

func (r execRunner) Run(args ...string) ([]byte, error) {
	out, err := exec.Command(r.bin, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (output: %s)",
			r.bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Options configures Manager. Zero values are sensible.
type Options struct {
	// Chain is the iptables chain Manager owns. Default "DETOUR".
	Chain string
	// IptablesPath overrides the binary used by the production runner.
	// Default "iptables" (looked up via $PATH).
	IptablesPath string
	// Runner overrides command execution entirely. Tests set this; in
	// production it's left nil and Manager builds an execRunner from
	// IptablesPath.
	Runner Runner
}

// Manager owns one iptables chain and the rules inside it. Safe for
// concurrent use.
type Manager struct {
	runner Runner
	chain  string

	mu              sync.Mutex
	rules           map[string]Rule
	closed          bool
	bootstrapped    bool
	enabledLocalNet bool // we toggled net.ipv4.conf.all.route_localnet on
}

// New constructs a Manager and installs the dedicated chain in the
// `nat` table, hooking it from OUTPUT and PREROUTING. If the chain
// already exists from a prior run it is reused and flushed so we start
// from a clean slate without disturbing concurrent rule sets.
func New(opts Options) (*Manager, error) {
	chain := opts.Chain
	if chain == "" {
		chain = "DETOUR"
	}
	if !validChainName(chain) {
		return nil, fmt.Errorf("invalid chain name %q", chain)
	}
	runner := opts.Runner
	if runner == nil {
		bin := opts.IptablesPath
		if bin == "" {
			bin = "iptables"
		}
		runner = execRunner{bin: bin}
	}
	m := &Manager{
		runner: runner,
		chain:  chain,
		rules:  map[string]Rule{},
	}
	if err := m.bootstrap(); err != nil {
		return nil, err
	}
	m.bootstrapped = true
	return m, nil
}

// Chain returns the iptables chain this Manager owns.
func (m *Manager) Chain() string { return m.chain }

// Add installs a DNAT rule mapping from -> to for the given protocol(s)
// and returns the assigned rule ID. For ProtoBoth two iptables rules
// (tcp and udp) are emitted under the same ID; Remove deletes them
// together. The whole call is best-effort transactional — if the second
// rule fails to install the first is rolled back before returning.
func (m *Manager) Add(from, to Endpoint, proto Protocol) (string, error) {
	if !proto.Valid() {
		return "", fmt.Errorf("invalid protocol %q", proto)
	}
	if from.Port == 0 || to.Port == 0 {
		return "", errors.New("ports must be non-zero")
	}
	if from.IP == nil || to.IP == nil {
		return "", errors.New("IP addresses must be set")
	}
	if to.IP.Equal(net.IPv4zero) {
		return "", errors.New("TO address must not be 0.0.0.0")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", errors.New("linuxnat: manager is closed")
	}

	id := newID()
	rule := Rule{ID: id, From: from, To: to, Proto: proto}

	// DNAT to 127.0.0.1 from a non-loopback interface only works if the
	// kernel has route_localnet enabled. We flip it on once per Manager
	// lifetime and restore it on Close.
	if isLoopback(to.IP) && !m.enabledLocalNet {
		if err := writeSysctl("net.ipv4.conf.all.route_localnet", "1"); err != nil {
			// Not fatal — the rule might still work for non-loopback
			// callers — but worth telling the user.
			fmt.Fprintf(os.Stderr, "detour: warning: could not enable route_localnet: %v\n", err)
		} else {
			m.enabledLocalNet = true
		}
	}

	protos := expandProto(proto)
	installed := make([]Protocol, 0, len(protos))
	for _, p := range protos {
		if _, err := m.runner.Run(addArgs(m.chain, id, p, from, to)...); err != nil {
			// Roll back any rules we already added under this ID before
			// surfacing the error.
			for _, done := range installed {
				_, _ = m.runner.Run(delArgs(m.chain, id, done, from, to)...)
			}
			return "", err
		}
		installed = append(installed, p)
	}
	m.rules[id] = rule
	return id, nil
}

// Remove deletes the rule(s) added under id. Returns os.ErrNotExist if
// the id is unknown.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("linuxnat: manager is closed")
	}
	r, ok := m.rules[id]
	if !ok {
		return os.ErrNotExist
	}
	var firstErr error
	for _, p := range expandProto(r.Proto) {
		if _, err := m.runner.Run(delArgs(m.chain, id, p, r.From, r.To)...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		// Even if delete failed, drop our bookkeeping for the rule so
		// the user isn't stuck with a phantom entry. On Close we'll
		// flush the chain anyway.
		delete(m.rules, id)
		return firstErr
	}
	delete(m.rules, id)
	return nil
}

// List returns a snapshot of the currently installed rules, ordered by
// ID for stable output.
func (m *Manager) List() []Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Rule, 0, len(m.rules))
	for _, r := range m.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Close undoes the chain bootstrap: unhooks our chain from OUTPUT and
// PREROUTING, flushes it, deletes it, and restores the route_localnet
// sysctl if we touched it. Subsequent calls are no-ops.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if !m.bootstrapped {
		return nil
	}
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Order matters: remove jumps first, then flush, then delete.
	// Ignore "rule does not exist" style errors — Close must be
	// idempotent if the kernel state has already partially gone away.
	_, err := m.runner.Run("-t", "nat", "-D", "OUTPUT", "-j", m.chain)
	if err != nil && !isMissingTargetErr(err) {
		record(err)
	}
	_, err = m.runner.Run("-t", "nat", "-D", "PREROUTING", "-j", m.chain)
	if err != nil && !isMissingTargetErr(err) {
		record(err)
	}
	if _, err := m.runner.Run("-t", "nat", "-F", m.chain); err != nil && !isMissingTargetErr(err) {
		record(err)
	}
	if _, err := m.runner.Run("-t", "nat", "-X", m.chain); err != nil && !isMissingTargetErr(err) {
		record(err)
	}
	m.rules = map[string]Rule{}

	if m.enabledLocalNet {
		if err := writeSysctl("net.ipv4.conf.all.route_localnet", "0"); err != nil {
			fmt.Fprintf(os.Stderr, "detour: warning: could not restore route_localnet: %v\n", err)
		}
		m.enabledLocalNet = false
	}
	return firstErr
}

// --- internals -------------------------------------------------------------

func (m *Manager) bootstrap() error {
	// Try to create the chain. If it already exists iptables exits 1; we
	// treat that as success and flush instead so a previous run's stale
	// rules don't accumulate.
	if _, err := m.runner.Run("-t", "nat", "-N", m.chain); err != nil {
		// Best-effort: flush in case it already exists.
		if _, ferr := m.runner.Run("-t", "nat", "-F", m.chain); ferr != nil {
			return fmt.Errorf("create/flush chain %s: %w", m.chain, err)
		}
	}
	// Hook from OUTPUT and PREROUTING — idempotently: check first.
	for _, hook := range []string{"OUTPUT", "PREROUTING"} {
		if _, err := m.runner.Run("-t", "nat", "-C", hook, "-j", m.chain); err != nil {
			if _, ierr := m.runner.Run("-t", "nat", "-I", hook, "-j", m.chain); ierr != nil {
				return fmt.Errorf("hook %s -> %s: %w", hook, m.chain, ierr)
			}
		}
	}
	return nil
}

// addArgs builds the iptables argv for adding a single DNAT rule.
// `0.0.0.0` on the FROM side is special: omit the --destination match
// so any local IP on that port qualifies, matching the user-facing
// "0.0.0.0:1234 -> upstream" semantics.
func addArgs(chain, id string, proto Protocol, from, to Endpoint) []string {
	args := []string{"-t", "nat", "-A", chain, "-p", string(proto)}
	if !from.IP.Equal(net.IPv4zero) {
		args = append(args, "-d", from.IP.String())
	}
	args = append(args,
		"--dport", strconv.Itoa(int(from.Port)),
		"-j", "DNAT",
		"--to-destination", to.String(),
		"-m", "comment", "--comment", "detour:"+id,
	)
	return args
}

// delArgs mirrors addArgs but with -D, so iptables removes the exact
// same rule we appended.
func delArgs(chain, id string, proto Protocol, from, to Endpoint) []string {
	args := []string{"-t", "nat", "-D", chain, "-p", string(proto)}
	if !from.IP.Equal(net.IPv4zero) {
		args = append(args, "-d", from.IP.String())
	}
	args = append(args,
		"--dport", strconv.Itoa(int(from.Port)),
		"-j", "DNAT",
		"--to-destination", to.String(),
		"-m", "comment", "--comment", "detour:"+id,
	)
	return args
}

func expandProto(p Protocol) []Protocol {
	if p == ProtoBoth {
		return []Protocol{ProtoTCP, ProtoUDP}
	}
	return []Protocol{p}
}

func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", os.Getpid())
	}
	return hex.EncodeToString(b[:])
}

func isLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 127
	}
	return ip.IsLoopback()
}

// validChainName mirrors the restrictions iptables itself enforces:
// printable ASCII without spaces, '-', '/', '!' or '"'. We're stricter
// than necessary and accept only [A-Za-z0-9_]{1,28} to keep things
// predictable.
func validChainName(s string) bool {
	if len(s) == 0 || len(s) > 28 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
			// ok
		default:
			return false
		}
	}
	return true
}

// isMissingTargetErr inspects an iptables error message for the
// well-known "No chain/target/match by that name" / "doesn't exist"
// phrases that mean "already gone" — i.e. cleanup-friendly errors we
// can safely swallow during Close.
func isMissingTargetErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no chain/target/match") ||
		strings.Contains(msg, "does a matching rule exist") ||
		strings.Contains(msg, "doesn't exist") ||
		strings.Contains(msg, "no such file or directory")
}

// writeSysctl pokes /proc/sys/<dotted-key>. Keeping this local (rather
// than exec()ing sysctl(8)) means the package has zero runtime
// dependencies beyond iptables itself.
func writeSysctl(key, value string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return os.WriteFile(path, []byte(value), 0o644)
}
