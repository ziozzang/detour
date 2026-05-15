package hostsfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: stand up a Manager on a tmp file pre-populated with content.
func newOn(t *testing.T, initial string) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if initial != "" {
		if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return New(path), path
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

func TestAddCreatesFileWithMarkers(t *testing.T) {
	m, path := newOn(t, "")
	id, err := m.Add("foo.com", "10.2.3.4")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if id == "" {
		t.Fatal("Add returned empty id")
	}
	got := read(t, path)
	if !strings.Contains(got, beginMarker) || !strings.Contains(got, endMarker) {
		t.Fatalf("markers missing:\n%s", got)
	}
	if !strings.Contains(got, "10.2.3.4\tfoo.com") {
		t.Fatalf("entry missing:\n%s", got)
	}
	if !strings.Contains(got, "id="+id) {
		t.Fatalf("id comment missing:\n%s", got)
	}
}

func TestAddPreservesExistingContent(t *testing.T) {
	pre := "127.0.0.1 localhost\n# user comment\n::1 ip6-localhost\n"
	m, path := newOn(t, pre)
	if _, err := m.Add("foo.com", "10.0.0.1"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got := read(t, path)
	if !strings.HasPrefix(got, pre) {
		t.Fatalf("user content not preserved verbatim at start:\n%q", got)
	}
}

func TestAddInvalidInputs(t *testing.T) {
	m, _ := newOn(t, "")
	cases := []struct {
		name string
		host string
		ip   string
	}{
		{"empty hostname", "", "1.2.3.4"},
		{"whitespace hostname", "foo bar", "1.2.3.4"},
		{"bad ip", "foo.com", "not-an-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.Add(tc.host, tc.ip); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestAddSameHostnameReusesID(t *testing.T) {
	m, path := newOn(t, "")
	id1, err := m.Add("foo.com", "10.0.0.1")
	if err != nil {
		t.Fatalf("Add1: %v", err)
	}
	id2, err := m.Add("FOO.COM", "10.0.0.2") // case-insensitive
	if err != nil {
		t.Fatalf("Add2: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("expected same ID on hostname update, got %s and %s", id1, id2)
	}
	got := read(t, path)
	if !strings.Contains(got, "10.0.0.2\tfoo.com") {
		t.Fatalf("entry not updated:\n%s", got)
	}
	if strings.Contains(got, "10.0.0.1") {
		t.Fatalf("old IP still present:\n%s", got)
	}
}

func TestRemoveDropsEntry(t *testing.T) {
	m, path := newOn(t, "127.0.0.1 localhost\n")
	id, err := m.Add("foo.com", "10.0.0.1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got := read(t, path)
	if strings.Contains(got, "foo.com") {
		t.Fatalf("entry still present:\n%s", got)
	}
	// With no entries the marker block must also be gone.
	if strings.Contains(got, beginMarker) {
		t.Fatalf("marker still present:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1 localhost") {
		t.Fatalf("user content lost:\n%s", got)
	}
}

func TestRemoveUnknownReturnsErrNotFound(t *testing.T) {
	m, _ := newOn(t, "")
	if err := m.Remove("does-not-exist"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestCloseRemovesAllManagedEntries(t *testing.T) {
	pre := "127.0.0.1 localhost\n"
	m, path := newOn(t, pre)
	if _, err := m.Add("foo.com", "10.0.0.1"); err != nil {
		t.Fatalf("Add foo: %v", err)
	}
	if _, err := m.Add("bar.com", "10.0.0.2"); err != nil {
		t.Fatalf("Add bar: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := read(t, path)
	if strings.Contains(got, "foo.com") || strings.Contains(got, "bar.com") {
		t.Fatalf("managed entries leaked after Close:\n%s", got)
	}
	if strings.Contains(got, beginMarker) || strings.Contains(got, endMarker) {
		t.Fatalf("markers leaked after Close:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1 localhost") {
		t.Fatalf("user content lost after Close:\n%s", got)
	}
	// Subsequent Add must fail; Manager is closed.
	if _, err := m.Add("baz.com", "10.0.0.3"); err == nil {
		t.Fatal("Add after Close should error")
	}
	// Second Close is a no-op.
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCloseStripsPreExistingMarkerBlock(t *testing.T) {
	// Simulate a previous detour run that crashed mid-flight: marker
	// block already present on disk before this process started.
	stale := "127.0.0.1 localhost\n" +
		beginMarker + "\n" +
		"9.9.9.9\tstale.example\t# id=abc\n" +
		endMarker + "\n" +
		"# trailing user comment\n"
	m, path := newOn(t, stale)
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := read(t, path)
	if strings.Contains(got, "stale.example") || strings.Contains(got, beginMarker) {
		t.Fatalf("stale block not cleaned up:\n%s", got)
	}
	if !strings.Contains(got, "trailing user comment") {
		t.Fatalf("trailing content lost:\n%s", got)
	}
}

func TestListSortedByHostname(t *testing.T) {
	m, _ := newOn(t, "")
	for _, e := range []struct{ h, ip string }{
		{"zeta.example", "1.1.1.1"},
		{"alpha.example", "2.2.2.2"},
		{"middle.example", "3.3.3.3"},
	} {
		if _, err := m.Add(e.h, e.ip); err != nil {
			t.Fatalf("Add %s: %v", e.h, err)
		}
	}
	got := m.List()
	want := []string{"alpha.example", "middle.example", "zeta.example"}
	if len(got) != len(want) {
		t.Fatalf("len got %d want %d", len(got), len(want))
	}
	for i, e := range got {
		if e.Hostname != want[i] {
			t.Fatalf("pos %d got %s want %s", i, e.Hostname, want[i])
		}
	}
}

func TestStripManagedBlockHandlesMissingNewlineAndOrphanEndMarker(t *testing.T) {
	// No trailing newline on user content; orphan end marker we should
	// also drop defensively.
	data := "127.0.0.1 localhost\n" + endMarker + "\nuser line"
	out := string(stripManagedBlock([]byte(data)))
	if strings.Contains(out, endMarker) {
		t.Fatalf("orphan end marker not dropped: %q", out)
	}
	if !strings.Contains(out, "user line") {
		t.Fatalf("user content lost: %q", out)
	}
}
