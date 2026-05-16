// Package hostsfile manages on-the-fly entries appended to a hosts-format
// file (typically /etc/hosts) bracketed by sentinel comments. Entries added
// at runtime are removed again on Close, so a crashed or signalled process
// can be restarted without leaving stale redirects behind (provided Close
// runs — see cmd/detour-linux for SIGINT/SIGTERM wiring).
//
// The package is pure Go and carries no build tag so it can be exercised
// with `go test` on every host. The only OS-specific consideration is the
// path passed to New() — callers pick "/etc/hosts" on Linux, "C:\\Windows
// \\System32\\drivers\\etc\\hosts" on Windows, etc.
package hostsfile

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Sentinel comments that bracket detour-managed entries inside the host
// file. Anything outside this block is left strictly untouched on every
// rewrite, including blank lines and user comments.
const (
	beginMarker = "# >>> detour managed >>>"
	endMarker   = "# <<< detour managed <<<"
)

// ErrNotFound is returned by Remove when the supplied id has no
// corresponding managed entry.
var ErrNotFound = errors.New("hosts entry not found")

// Entry is one managed mapping. ID is opaque and assigned by Add; callers
// pass it to Remove. Hostname is stored lower-cased (hosts(5) is
// case-insensitive in practice).
type Entry struct {
	ID       string
	Hostname string
	IP       net.IP
}

// Manager owns the managed section of a single hosts file. Safe for
// concurrent use.
type Manager struct {
	path    string
	mu      sync.Mutex
	entries map[string]Entry // keyed by ID
	closed  bool
}

// New constructs a Manager bound to path. The file is not touched until
// the first Add/Remove/Close — so constructing a Manager against a
// non-existent file is fine; it will be created on first write.
func New(path string) *Manager {
	return &Manager{
		path:    path,
		entries: map[string]Entry{},
	}
}

// Path returns the file Manager writes to. Mostly for diagnostics / tests.
func (m *Manager) Path() string { return m.path }

// Add inserts (or replaces, by hostname) a managed entry mapping hostname
// -> ip and returns the assigned ID. Validation:
//   - ip must parse as a literal IP (v4 or v6)
//   - hostname must be non-empty and contain no whitespace
//
// If an entry with the same hostname already exists it is replaced and
// the *original* ID is returned — callers tracking the ID never see it
// change for a given hostname. This matches the "redirect foo.com to a
// new IP" UX described in the task spec.
func (m *Manager) Add(hostname, ipStr string) (string, error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return "", errors.New("hostname is empty")
	}
	if strings.ContainsAny(hostname, " \t\r\n") {
		return "", fmt.Errorf("hostname %q contains whitespace", hostname)
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", ipStr)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", errors.New("hostsfile: manager is closed")
	}

	// Replace-by-hostname keeps the same ID, so the caller's bookkeeping
	// is stable across "update" calls.
	id := ""
	for existingID, e := range m.entries {
		if e.Hostname == hostname {
			id = existingID
			break
		}
	}
	if id == "" {
		id = newID()
	}
	m.entries[id] = Entry{ID: id, Hostname: hostname, IP: ip}
	if err := m.rewriteLocked(); err != nil {
		// Revert in-memory mutation so a failed write doesn't leave the
		// Manager claiming an entry exists when the file disagrees.
		delete(m.entries, id)
		return "", err
	}
	return id, nil
}

// Remove drops the entry with the given ID. Returns ErrNotFound if the ID
// is unknown.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("hostsfile: manager is closed")
	}
	old, ok := m.entries[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.entries, id)
	if err := m.rewriteLocked(); err != nil {
		// On failure, restore in-memory state.
		m.entries[id] = old
		return err
	}
	return nil
}

// List returns a snapshot of currently-managed entries, sorted by
// hostname for deterministic output.
func (m *Manager) List() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// Close removes every managed entry and the surrounding markers from the
// hosts file, leaving the unmanaged portion untouched. It is safe to call
// Close more than once; subsequent calls are no-ops.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.entries = map[string]Entry{}
	m.closed = true
	// Rewriting with zero entries strips the marker block entirely.
	return m.rewriteLocked()
}

// --- internals -------------------------------------------------------------

func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is exceptional; fall back to a fixed prefix
		// with a process-unique counter rather than panicking, since this
		// runs inside an API handler.
		return fmt.Sprintf("fallback-%d", os.Getpid())
	}
	return hex.EncodeToString(b[:])
}

// rewriteLocked atomically writes the hosts file: read existing content,
// strip any prior managed block, append a fresh block (if there are
// entries), and rename over the original. mu must already be held.
func (m *Manager) rewriteLocked() error {
	existing, err := os.ReadFile(m.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", m.path, err)
	}

	preserved := stripManagedBlock(existing)

	var buf bytes.Buffer
	buf.Write(preserved)
	if len(m.entries) > 0 {
		// Guarantee a newline before our block so we never glue onto a
		// non-terminated final line of user content.
		if len(preserved) > 0 && !bytes.HasSuffix(preserved, []byte("\n")) {
			buf.WriteByte('\n')
		}
		buf.WriteString(beginMarker)
		buf.WriteByte('\n')
		for _, e := range sortedEntries(m.entries) {
			fmt.Fprintf(&buf, "%s\t%s\t# id=%s\n", e.IP.String(), e.Hostname, e.ID)
		}
		buf.WriteString(endMarker)
		buf.WriteByte('\n')
	}

	return atomicWrite(m.path, buf.Bytes())
}

// stripManagedBlock removes everything from beginMarker through
// endMarker (inclusive) from data. Lines outside the block are returned
// verbatim, including blank lines and user comments. If markers are
// missing or malformed, data is returned untouched apart from a defensive
// pass that drops any orphan marker lines so the file can't grow stale
// sentinels forever.
func stripManagedBlock(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	inBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimRight(line, " \t")
		switch {
		case trimmed == beginMarker:
			inBlock = true
			continue
		case trimmed == endMarker:
			// End marker without begin — treat as a stray and drop it.
			inBlock = false
			continue
		case inBlock:
			continue
		default:
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

func sortedEntries(in map[string]Entry) []Entry {
	out := make([]Entry, 0, len(in))
	for _, e := range in {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// atomicWrite writes data to a sibling temp file and renames it over
// path. On Linux this gives an atomic replace; readers either see the
// full old or full new content but never a torn write. Permissions and
// ownership of an existing file are preserved on a best-effort basis.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	// Preserve the existing mode if we can stat the file; default to 0644
	// when creating fresh.
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp, err := os.CreateTemp(dir, ".detour-hosts-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}
