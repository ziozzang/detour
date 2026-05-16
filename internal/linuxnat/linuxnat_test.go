package linuxnat

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records every iptables invocation and lets tests script
// per-call return values. It is intentionally dumb: no semantic
// modelling of the iptables state, just enough to assert on the
// argument strings Manager produces.
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	// next time Run sees the predicate match, return this error and
	// advance the script. Allows simulating "rule already exists" / "no
	// such chain" responses without overfitting to one specific failure
	// mode.
	script []scriptedResp
}

type scriptedResp struct {
	match func(args []string) bool
	out   []byte
	err   error
}

func (f *fakeRunner) Run(args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]string(nil), args...)
	f.calls = append(f.calls, cp)
	for i, s := range f.script {
		if s.match(cp) {
			// Pop the scripted response so it fires once.
			f.script = append(f.script[:i], f.script[i+1:]...)
			return s.out, s.err
		}
	}
	return nil, nil
}

func (f *fakeRunner) snapshot() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = append([]string(nil), c...)
	}
	return out
}

func containsArgs(t *testing.T, calls [][]string, want ...string) bool {
	t.Helper()
outer:
	for _, c := range calls {
		joined := strings.Join(c, " ")
		for _, w := range want {
			if !strings.Contains(joined, w) {
				continue outer
			}
		}
		return true
	}
	return false
}

func mustEndpoint(t *testing.T, s string) Endpoint {
	t.Helper()
	e, err := ParseEndpoint(s)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q): %v", s, err)
	}
	return e
}

func TestParseEndpoint(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantErr bool
	}{
		{"1.2.3.4:80", false},
		{"0.0.0.0:1234", false},
		{"::1:80", true},     // IPv6 not supported
		{"foo:80", true},     // hostname not allowed
		{"1.2.3.4:0", true},  // port 0 rejected
		{"1.2.3.4", true},    // no port
		{"1.2.3.4:99999", true},
	} {
		_, err := ParseEndpoint(tc.in)
		if tc.wantErr && err == nil {
			t.Errorf("%q: want error, got nil", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%q: unexpected error: %v", tc.in, err)
		}
	}
}

func TestNewBootstrapsChainAndHooks(t *testing.T) {
	fr := &fakeRunner{}
	m, err := New(Options{Runner: fr, Chain: "DETOUR_TEST"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	calls := fr.snapshot()
	if !containsArgs(t, calls, "-N", "DETOUR_TEST") {
		t.Errorf("chain creation missing; calls=%v", calls)
	}
	// We try -C first (idempotent check), then -I if -C fails. fakeRunner
	// returns nil error by default for -C so -I shouldn't fire. But the
	// bootstrap must at least have invoked the check.
	if !containsArgs(t, calls, "-C", "OUTPUT", "-j", "DETOUR_TEST") {
		t.Errorf("OUTPUT hook check missing; calls=%v", calls)
	}
	if !containsArgs(t, calls, "-C", "PREROUTING", "-j", "DETOUR_TEST") {
		t.Errorf("PREROUTING hook check missing; calls=%v", calls)
	}
}

func TestNewInsertsHooksWhenMissing(t *testing.T) {
	fr := &fakeRunner{
		script: []scriptedResp{
			{match: func(a []string) bool {
				return len(a) >= 4 && a[2] == "-C" && a[3] == "OUTPUT"
			}, err: errors.New("iptables: Bad rule (does a matching rule exist in that chain?).")},
			{match: func(a []string) bool {
				return len(a) >= 4 && a[2] == "-C" && a[3] == "PREROUTING"
			}, err: errors.New("iptables: Bad rule (does a matching rule exist in that chain?).")},
		},
	}
	m, err := New(Options{Runner: fr, Chain: "DETOUR"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	calls := fr.snapshot()
	if !containsArgs(t, calls, "-I", "OUTPUT", "-j", "DETOUR") {
		t.Errorf("OUTPUT insert missing; calls=%v", calls)
	}
	if !containsArgs(t, calls, "-I", "PREROUTING", "-j", "DETOUR") {
		t.Errorf("PREROUTING insert missing; calls=%v", calls)
	}
}

func TestNewRejectsInvalidChainName(t *testing.T) {
	// Note: "" is intentionally not in this set — it triggers the
	// default-name fallback in New() rather than a validation error.
	for _, bad := range []string{"with space", "has-dash", "bang!", strings.Repeat("X", 40)} {
		if _, err := New(Options{Runner: &fakeRunner{}, Chain: bad}); err == nil {
			t.Errorf("chain %q: want error", bad)
		}
	}
}

func TestAddEmitsExpectedRule(t *testing.T) {
	fr := &fakeRunner{}
	m, err := New(Options{Runner: fr, Chain: "DETOUR"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	id, err := m.Add(mustEndpoint(t, "1.2.3.4:80"), mustEndpoint(t, "127.0.0.1:8080"), ProtoTCP)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if id == "" {
		t.Fatal("empty ID")
	}

	calls := fr.snapshot()
	if !containsArgs(t, calls,
		"-A", "DETOUR", "-p", "tcp",
		"-d", "1.2.3.4",
		"--dport", "80",
		"-j", "DNAT",
		"--to-destination", "127.0.0.1:8080",
		"detour:"+id,
	) {
		t.Errorf("expected DNAT add call not found; calls=%v", calls)
	}

	got := m.List()
	if len(got) != 1 || got[0].ID != id {
		t.Errorf("List: want one rule with id %q, got %+v", id, got)
	}
}

func TestAddZeroFromOmitsDestinationMatch(t *testing.T) {
	fr := &fakeRunner{}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})
	defer m.Close()

	_, err := m.Add(mustEndpoint(t, "0.0.0.0:1234"), mustEndpoint(t, "127.0.0.1:2234"), ProtoTCP)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	calls := fr.snapshot()
	for _, c := range calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "-A DETOUR") && strings.Contains(j, "-d 0.0.0.0") {
			t.Fatalf("0.0.0.0 should not appear as -d: %s", j)
		}
	}
	if !containsArgs(t, calls, "-A", "DETOUR", "--dport", "1234", "--to-destination", "127.0.0.1:2234") {
		t.Errorf("DNAT call missing; calls=%v", calls)
	}
}

func TestAddBothExpandsToTcpAndUdp(t *testing.T) {
	fr := &fakeRunner{}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})
	defer m.Close()

	id, err := m.Add(mustEndpoint(t, "1.2.3.4:53"), mustEndpoint(t, "8.8.8.8:53"), ProtoBoth)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	calls := fr.snapshot()
	if !containsArgs(t, calls, "-A", "DETOUR", "-p", "tcp", "detour:"+id) {
		t.Errorf("tcp variant missing; calls=%v", calls)
	}
	if !containsArgs(t, calls, "-A", "DETOUR", "-p", "udp", "detour:"+id) {
		t.Errorf("udp variant missing; calls=%v", calls)
	}
}

func TestAddRollsBackOnFailure(t *testing.T) {
	// Make the udp insert fail; the tcp insert that ran first must be
	// undone with a matching -D before Add returns.
	fr := &fakeRunner{
		script: []scriptedResp{
			{
				match: func(a []string) bool {
					j := strings.Join(a, " ")
					return strings.Contains(j, "-A DETOUR") && strings.Contains(j, "-p udp")
				},
				err: errors.New("iptables: simulated failure"),
			},
		},
	}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})
	defer m.Close()

	_, err := m.Add(mustEndpoint(t, "1.2.3.4:53"), mustEndpoint(t, "8.8.8.8:53"), ProtoBoth)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if len(m.List()) != 0 {
		t.Errorf("rule should not be tracked after rollback: %+v", m.List())
	}
	calls := fr.snapshot()
	// Look for a -D matching the tcp rule we rolled back.
	found := false
	for _, c := range calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "-D DETOUR") && strings.Contains(j, "-p tcp") && strings.Contains(j, "-d 1.2.3.4") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected rollback -D for tcp; calls=%v", calls)
	}
}

func TestAddValidates(t *testing.T) {
	fr := &fakeRunner{}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})
	defer m.Close()

	if _, err := m.Add(mustEndpoint(t, "1.2.3.4:80"), mustEndpoint(t, "1.2.3.4:80"), Protocol("sctp")); err == nil {
		t.Error("invalid protocol should error")
	}
	if _, err := m.Add(mustEndpoint(t, "1.2.3.4:80"), Endpoint{IP: nil, Port: 80}, ProtoTCP); err == nil {
		t.Error("nil TO IP should error")
	}
	// TO cannot be 0.0.0.0
	zero, _ := ParseEndpoint("0.0.0.0:80")
	if _, err := m.Add(mustEndpoint(t, "1.2.3.4:80"), zero, ProtoTCP); err == nil {
		t.Error("0.0.0.0 TO should error")
	}
}

func TestRemoveEmitsMatchingDeleteAndForgets(t *testing.T) {
	fr := &fakeRunner{}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})
	defer m.Close()

	id, err := m.Add(mustEndpoint(t, "1.2.3.4:80"), mustEndpoint(t, "127.0.0.1:8080"), ProtoTCP)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(m.List()) != 0 {
		t.Errorf("rule should be gone: %+v", m.List())
	}
	calls := fr.snapshot()
	if !containsArgs(t, calls, "-D", "DETOUR", "-p", "tcp", "-d", "1.2.3.4", "--dport", "80", "detour:"+id) {
		t.Errorf("matching -D missing; calls=%v", calls)
	}
}

func TestRemoveUnknown(t *testing.T) {
	fr := &fakeRunner{}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})
	defer m.Close()
	if err := m.Remove("nope"); err == nil {
		t.Error("Remove unknown should error")
	}
}

func TestCloseCleansUp(t *testing.T) {
	fr := &fakeRunner{}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})

	if _, err := m.Add(mustEndpoint(t, "1.2.3.4:80"), mustEndpoint(t, "127.0.0.1:8080"), ProtoTCP); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	calls := fr.snapshot()
	for _, want := range [][]string{
		{"-D", "OUTPUT", "-j", "DETOUR"},
		{"-D", "PREROUTING", "-j", "DETOUR"},
		{"-F", "DETOUR"},
		{"-X", "DETOUR"},
	} {
		if !containsArgs(t, calls, want...) {
			t.Errorf("Close missing call %v; calls=%v", want, calls)
		}
	}
	// Idempotent.
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Post-close mutations rejected.
	if _, err := m.Add(mustEndpoint(t, "1.2.3.4:80"), mustEndpoint(t, "127.0.0.1:8080"), ProtoTCP); err == nil {
		t.Error("Add after Close should error")
	}
}

func TestCloseSwallowsMissingTargetErrors(t *testing.T) {
	fr := &fakeRunner{
		script: []scriptedResp{
			{match: func(a []string) bool { return strings.Contains(strings.Join(a, " "), "-D OUTPUT") },
				err: errors.New("iptables: No chain/target/match by that name.")},
			{match: func(a []string) bool { return strings.Contains(strings.Join(a, " "), "-D PREROUTING") },
				err: errors.New("iptables: No chain/target/match by that name.")},
			{match: func(a []string) bool { return strings.Contains(strings.Join(a, " "), "-F DETOUR") },
				err: errors.New("iptables: No chain/target/match by that name.")},
			{match: func(a []string) bool { return strings.Contains(strings.Join(a, " "), "-X DETOUR") },
				err: errors.New("iptables: No chain/target/match by that name.")},
		},
	}
	m, _ := New(Options{Runner: fr, Chain: "DETOUR"})
	if err := m.Close(); err != nil {
		t.Fatalf("Close should swallow 'no chain' errors, got %v", err)
	}
}
