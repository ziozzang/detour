// Package socket sets up the Unix-domain listener detourd exposes to its
// CLI clients. The model mirrors Docker's /var/run/docker.sock: the
// socket is owned by root, group is set to a specific Unix group (by
// default "detour"), and the file mode is 0660 so anyone in that group
// can talk to the daemon without elevation.
//
// Group-based access avoids two failure modes of HTTP-on-loopback:
//
//   - You don't accidentally expose the control plane to other users on
//     the box (the kernel enforces POSIX file permissions on the socket
//     inode every time a peer connects).
//   - You don't need to run the CLI as root just because the daemon
//     does.
//
// Listen() is small but covers the common edge cases (stale socket
// from a crashed prior run, group missing from /etc/group, parent dir
// missing) so the daemon's main() stays focused on plumbing.
package socket

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// Listen creates a Unix-domain stream listener at path. If group is
// non-empty the socket inode is chown'd to that group; if mode is
// non-zero the socket inode is chmod'd accordingly. A stale socket file
// from a previous run is removed before we bind. The parent directory
// is created with 0755 if it doesn't exist — daemons that run before
// /run/<name> is set up don't have to special-case that.
//
// On any error after the listener has been opened, Listen closes it
// and removes the file before returning, so callers never need a
// "partial listener cleanup" branch.
func Listen(path, group string, mode os.FileMode) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("socket path is empty")
	}
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}

	// From here on, on any error, close the listener and clean up the
	// socket file so we don't leave a 0777 stale entry behind.
	cleanup := func(err error) (net.Listener, error) {
		_ = l.Close()
		_ = os.Remove(path)
		return nil, err
	}

	if group != "" {
		gid, lerr := lookupGID(group)
		if lerr != nil {
			return cleanup(fmt.Errorf("lookup group %q: %w", group, lerr))
		}
		if cerr := os.Chown(path, -1, gid); cerr != nil {
			return cleanup(fmt.Errorf("chown %s to gid %d: %w", path, gid, cerr))
		}
	}
	if mode != 0 {
		if cerr := os.Chmod(path, mode); cerr != nil {
			return cleanup(fmt.Errorf("chmod %s to %o: %w", path, mode, cerr))
		}
	}
	return l, nil
}

// removeStale drops a leftover socket inode without disturbing other
// file types — if `path` exists and is *not* a socket we refuse to
// touch it (defensive, in case the operator points the daemon at a
// real file by mistake).
func removeStale(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refuse to overwrite non-socket file %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." || dir == "/" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create parent dir %s: %w", dir, err)
	}
	return nil
}

// lookupGID resolves a group name to its numeric gid. Accepts numeric
// strings directly so operators on systems with NSS quirks (or in
// containers without /etc/group) can pass a literal gid like "999".
func lookupGID(group string) (int, error) {
	if gid, err := strconv.Atoi(group); err == nil {
		return gid, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q: invalid gid %q: %w", group, g.Gid, err)
	}
	return gid, nil
}
