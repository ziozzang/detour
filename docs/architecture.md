# Architecture

`detour` is split into a privileged daemon (`detourd`) and an
unprivileged CLI (`detour`). They share an HTTP/JSON wire format
served either over a Unix-domain socket (default) or TCP. The same
HTTP handler also serves a small embedded browsable web UI.

## Process model

```
                 +-----------------------------+
                 |          operator           |
                 |  (in `detour` Unix group)   |
                 +--+-----+------------+-------+
                    |     |            |
              CLI   |     | browser    | curl / scripts
                    v     v            v
              +-----------------------------+
              |       /run/detour.sock      |   <-- POSIX permissions
              |     root:detour 0660        |       are the auth layer
              +--------------+--------------+
                             |
                             v
              +-----------------------------+
              |           detourd            |  runs as root (or
              |                              |  with CAP_NET_ADMIN)
              |  +-------------------------+ |
              |  |   internal/api.Server   | |  HTTP/JSON + embedded
              |  |   handler (one mux)     | |  static UI
              |  +-----+-------------+-----+ |
              |        |             |       |
              |        v             v       |
              | +---------------+  +-------+ |
              | | internal/     |  | int./ | |
              | | linuxnat      |  | hosts | |
              | | (iptables)    |  | file  | |
              | +-------+-------+  +---+---+ |
              +---------|--------------|-----+
                        v              v
                  iptables(8)      /etc/hosts
                  (nat table,      (sentinel
                   DETOUR chain)    block)
```

## Components

### `internal/api`

A `net/http` ServeMux built on the Go 1.22 `METHOD PATH` pattern syntax.
The Server type takes two interfaces (`NATBackend`, `HostsBackend`)
which keeps the HTTP layer trivially mockable.

Endpoints:

| Method | Path | Description |
|---|---|---|
| GET    | `/healthz`     | liveness probe |
| GET    | `/rules`        | list DNAT rules |
| POST   | `/rules`        | add a rule |
| DELETE | `/rules/{id}`   | remove a rule |
| GET    | `/hosts`        | list managed `/etc/hosts` entries |
| POST   | `/hosts`        | add a hosts entry |
| DELETE | `/hosts/{id}`   | remove a hosts entry |
| GET    | `/`             | web UI entry point |
| GET    | `/static/{file}` | embedded JS/CSS |

When a backend is `nil` (e.g. the operator started `detourd --no-hosts`)
the corresponding endpoints return `503`. The HTTP layer never
touches kernel state directly; everything is delegated to the
backends.

### `internal/linuxnat`

Owns a dedicated iptables chain (default `DETOUR`) in the `nat` table.
On `New()` it creates the chain, flushes any leftovers from a previous
run, and hooks it from both `OUTPUT` (for traffic originating on this
host) and `PREROUTING` (for traffic transiting through it).

The implementation hides `exec.Command` behind a `Runner` interface:

```go
type Runner interface { Run(args ...string) ([]byte, error) }
```

Tests inject a recording fake; production wires in an `execRunner`
that invokes the iptables binary.

`Close()` flushes and deletes the chain, removes the OUTPUT/PREROUTING
jumps, and restores `net.ipv4.conf.all.route_localnet` if the manager
had to flip it on.

### `internal/hostsfile`

A pure-Go `/etc/hosts` editor. All managed lines live in a sentinel
block:

```
# >>> detour managed >>>
10.2.3.4    foo.com  # detour-id=a1b2c3
# <<< detour managed <<<
```

This makes it possible to:

- audit what `detourd` owns by `grep "detour managed"`
- recover manually by deleting the block if the daemon ever crashes
- preserve the rest of `/etc/hosts` byte-for-byte across `Add`/`Remove`

Writes are atomic: we write a `<path>.detour.tmp` next to the target
and `rename(2)` it into place. The file mode and SELinux context of
the original file are preserved.

### `internal/socket`

A thin helper around `net.Listen("unix", ...)`:

- removes stale socket inodes from previous runs (and refuses to
  overwrite a regular file at the same path)
- creates the parent directory with `0755` if missing
- `chown`s the socket to a configurable Unix group (`detour` by
  default, accepts numeric gids too)
- `chmod`s to a configurable mode (`0660` by default)
- on any failure after `Listen`, closes the listener and removes
  the socket file so retries don't have to clean up partial state

### `internal/client`

A Go client library used by the CLI. Speaks both
`unix:///path/to.sock` and `http://host:port` transparently via a
custom `http.Transport.DialContext`.

Surfaces typed errors:

```go
var e *client.Error
errors.As(err, &e)  // e.Status == 404, e.Message == "rule not found"
client.IsNotFound(err) // convenience
```

The library is the canonical contract between CLI and daemon. Third
parties can import it (`detour/internal/client`) — modulo the
internal/ visibility marker — to drive `detourd` from their own Go
programs.

### `cmd/detourd`

The daemon entry point. Wires together `linuxnat`, `hostsfile`,
`api`, and `socket`, then serves the same handler on:

- the Unix-domain socket (always)
- an optional TCP listener (`--http :8080`)

`os/signal.NotifyContext` watches for `SIGINT` and `SIGTERM`; on
either, the daemon:

1. shuts down both HTTP servers with a 5s deadline,
2. removes the socket inode,
3. calls `hostsfile.Manager.Close()` to delete the managed block,
4. calls `linuxnat.Manager.Close()` to flush and remove the chain.

If any step fails the others are still attempted, so a misbehaving
backend can't keep the others from cleaning up.

### `cmd/detour`

The CLI. Uses `flag` (no third-party dependency) and a tiny
two-word-subcommand resolver so `detour rule add` works the same way
`docker volume create` does.

The CLI is **stateless**: every invocation builds a fresh
`client.Client`, makes one or two API calls, prints, and exits. There
is no config file to keep in sync with the daemon.

## Wire format

JSON over HTTP/1.1. No streaming, no chunked transfer in either
direction — the API is request/response with small payloads, so the
default `net/http` defaults are fine.

`Content-Type: application/json` on inputs, `Accept: application/json`
expected for typed responses. The web UI sends the same JSON the CLI
does.

## State management

`detourd` is **stateless across restarts** by design: a fresh daemon
has no rules and no hosts entries, because both `Close()` and `New()`
flush their respective slices of state. If you need rules to survive
a daemon restart, drive `detourd` from a script that re-issues the
`detour rule add` calls on each boot (or use the `Restart=on-failure`
systemd unit in the README — that *preserves* rules across CR-aaSHes
only if the daemon was killed hard enough not to run `Close()`,
which is fragile and intentionally not relied upon).

## Threading

- The `linuxnat.Manager` and `hostsfile.Manager` are guarded by a
  `sync.Mutex`. Concurrent API requests are safe.
- `http.Server.Serve` already dispatches each request on its own
  goroutine; nothing in the handlers blocks longer than the
  iptables/file-write call.
- The race detector is run in CI (`go test -race ./...`).
