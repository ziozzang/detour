package main

// Lightweight tests for the daemon entry point. The real iptables
// requires CAP_NET_ADMIN, so we keep these focused on the bits that
// don't shell out: flag parsing, mode parsing, --version, and the
// failure path when the socket can't be bound.

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestParseOctalMode(t *testing.T) {
	cases := []struct {
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{"0660", 0o660, false},
		{"660", 0o660, false},
		{"0o660", 0o660, false},
		{"0o600", 0o600, false},
		{"0700", 0o700, false},
		{"", 0, false},
		{"8", 0, true},     // not octal
		{"abc", 0, true},   // garbage
		{"77777", 0, true}, // out of range
	}
	for _, tc := range cases {
		got, err := parseOctalMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseOctalMode(%q) want error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOctalMode(%q) unexpected err: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseOctalMode(%q) = %o, want %o", tc.in, got, tc.want)
		}
	}
}

func TestHostsPathOrDisabled(t *testing.T) {
	if got := hostsPathOrDisabled("/etc/hosts", false); got != "/etc/hosts" {
		t.Errorf("got %q", got)
	}
	if got := hostsPathOrDisabled("/etc/hosts", true); got != "disabled" {
		t.Errorf("got %q", got)
	}
}

func TestRunVersionFlag(t *testing.T) {
	// Redirect os.Stdout for the duration of run() and restore after.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w

	code := run([]string{"--version"})

	// Close the writer first so the read side EOFs, then restore.
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()

	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("detourd ")) {
		t.Errorf("stdout=%q", buf.String())
	}
}

func TestRunInvalidMode(t *testing.T) {
	// Silence the package logger writing to os.Stderr during test.
	log.SetOutput(&bytes.Buffer{})
	defer log.SetOutput(os.Stderr)

	code := run([]string{"--socket-mode", "garbage"})
	if code != 2 {
		t.Errorf("exit=%d, want 2", code)
	}
}

func TestRunBadSocketPath(t *testing.T) {
	log.SetOutput(&bytes.Buffer{})
	defer log.SetOutput(os.Stderr)

	// Use a path under a regular file so socket.Listen can't bind.
	dir := t.TempDir()
	blocking := filepath.Join(dir, "block")
	if err := os.WriteFile(blocking, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(blocking, "sub.sock") // parent is a regular file

	code := run([]string{"--socket", bad, "--socket-group", ""})
	if code != 1 {
		t.Errorf("exit=%d, want 1 (socket setup failure)", code)
	}
}
