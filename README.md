# detour

> A Linux daemon + CLI for **on-the-fly traffic redirection** using
> `iptables` DNAT and managed `/etc/hosts` entries — with a JSON HTTP
> API, a Docker-style Unix-socket control plane, and a small web UI.

`detour` lets you redirect traffic that was meant for one
host/port to another without modifying the application, like:

| Intent | Mechanism |
|---|---|
| `0.0.0.0:1234 → 127.0.0.1:2234` (port-level rewire) | iptables `nat/OUTPUT` and `nat/PREROUTING` DNAT into a dedicated `DETOUR` chain |
| `foo.com → 10.2.3.4`  (hostname-level rewire)       | Managed entry in `/etc/hosts` inside a sentinel block |

Everything is **ephemeral**: when the daemon stops, the iptables
chain is flushed and removed and the managed `/etc/hosts` block is
deleted. A clean shutdown leaves the host as it found it.

---

## Architecture

```
                   ┌────────────────────────────────────┐
   detour CLI  ────►       /run/detour.sock (0660)      │
   browser     ───►│       (Unix-domain socket)          │
   curl,jq     ───►│                                     │
                   │  ┌───────────────────────────────┐  │
                   │  │     detourd (HTTP API)        │  │
                   │  │  /healthz /rules /hosts        │  │
                   │  │  /  /static/* (web UI)         │  │
                   │  └────────┬──────────┬────────────┘  │
                   │           │          │              │
                   │  ┌────────▼──┐  ┌────▼──────────┐   │
                   │  │ linuxnat  │  │  hostsfile     │   │
                   │  │ iptables  │  │  /etc/hosts    │   │
                   │  └───────────┘  └────────────────┘   │
                   └────────────────────────────────────┘
```

- **detourd** runs as root (or with `CAP_NET_ADMIN` + write access to
  `/etc/hosts`) and serves the API.
- **detour** (the CLI) is unprivileged. It talks to `detourd` over the
  Unix socket; access is gated by the POSIX group of the socket file
  (default `detour`, mode `0660`) — the same model Docker uses for
  `/var/run/docker.sock`.
- The **web UI** is mounted on the same handler, so `http://detourd/`
  (or whatever you configure with `--http`) serves a browsable
  dashboard for the rules and host entries.

See [`docs/architecture.md`](docs/architecture.md) for a deeper
walk-through.

---

## Quick start

### Build

Requires Go 1.23+.

```sh
go build -o detourd ./cmd/detourd
go build -o detour  ./cmd/detour
```

Zero non-stdlib runtime dependencies. The web UI is embedded into the
`detourd` binary via `embed.FS`.

### Run the daemon

```sh
# Create the access group (one-time):
sudo groupadd --system detour
sudo usermod -aG detour "$USER"   # log out & back in for it to take effect

# Run it:
sudo ./detourd \
    --socket /run/detour.sock \
    --socket-group detour \
    --socket-mode 0660
```

Now anyone in the `detour` group can drive it without `sudo`:

```sh
detour info
detour rule list
```

### Add a port redirect

Redirect every `0.0.0.0:1234` packet to `127.0.0.1:2234`, TCP only:

```sh
detour rule add --from 0.0.0.0:1234 --to 127.0.0.1:2234 --proto tcp
```

Equivalent over the API:

```sh
curl --unix-socket /run/detour.sock \
     -H 'Content-Type: application/json' \
     -d '{"from":"0.0.0.0:1234","to":"127.0.0.1:2234","proto":"tcp"}' \
     http://detour/rules
```

### Override a hostname

Pin `foo.com` to `10.2.3.4` via `/etc/hosts`:

```sh
detour host add --hostname foo.com --ip 10.2.3.4
```

### Browse the UI

Expose HTTP too (optional):

```sh
sudo ./detourd --http 127.0.0.1:8080
```

Then open <http://127.0.0.1:8080/>.

---

## CLI reference

```
Usage: detour [global flags] <command> [args]

Global flags:
  --host ADDR        daemon address: unix:///path | http://host:port
                     (env: DETOUR_HOST; default unix:///run/detour.sock)
  --token TOKEN      bearer token for HTTP auth (env: DETOUR_TOKEN)
  --token-file PATH  read bearer token from file (env: DETOUR_TOKEN_FILE)
  --json             print JSON instead of tables
  --timeout DUR      per-call timeout (default 10s)

Commands:
  version              show client version
  ping                 fast health probe (exit 0 = ok)
  info                 show daemon health and counts
  status               verbose layout (version, chain, auth-mode, uptime)
  rule list            list installed DNAT rules            (alias: rule ls)
  rule add             install a DNAT rule (--from --to [--proto] [--dry-run])
  rule rm <id>         remove a DNAT rule by ID             (aliases: remove, delete)
  host list            list managed /etc/hosts entries      (alias: host ls)
  host add             add an /etc/hosts entry (--hostname --ip)
  host rm <id>         remove a host entry by ID            (aliases: remove, delete)
  service install      install the systemd unit (writes /etc/systemd/system/detourd.service)
  service uninstall    stop, disable, and remove the unit
  service status       show systemctl status of detourd
  service logs         tail journalctl -u detourd
  completion {bash|zsh|fish}   print shell-completion script
```

### Examples

```sh
# Talk to a remote daemon:
detour --host http://10.0.0.5:8080 info

# Use a different socket path:
detour --host unix:///tmp/test.sock rule list

# Machine-readable output:
detour --json rule list | jq '.[] | select(.proto=="tcp")'
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | the daemon responded with a non-2xx status, or the operation otherwise failed |
| `2` | user error: bad flags, unknown command, malformed --host |

---

## Authentication (token auth)

The Unix-domain socket is gated by POSIX group permissions (same model
Docker uses), so on the local box you don't need a token. **As soon as
you expose the daemon over TCP with `--http`, a bearer token is
required.** detourd will refuse to serve TCP requests that don't carry
`Authorization: Bearer <token>`.

You have three ways to configure tokens (any combination works; they
are merged):

```sh
# 1. Single token on the command line (visible in /proc — prefer the file).
sudo ./detourd --http 127.0.0.1:8080 --auth-token 'my-secret-token'

# 2. Token via environment variable (e.g. systemd EnvironmentFile=).
DETOURD_AUTH_TOKEN='my-secret-token' sudo -E ./detourd --http :8080

# 3. One token per line in a file mode 0600 — the recommended option.
sudo install -m 0600 /dev/stdin /etc/detour/tokens <<EOF
# operators
e7a4...64hex
# CI bot
9f2b...64hex
EOF
sudo ./detourd --http :8080 --auth-token-file /etc/detour/tokens
```

If you start `detourd --http` **without** any token configured, the
daemon refuses to silently leave the listener unauthenticated:
instead, it auto-generates a 64-character random token, writes it to
`/var/lib/detour/auth.token` (mode `0600`), logs the path, and uses
that token for the lifetime of the process. Look for a line like:

```
auto-generated bearer token written to /var/lib/detour/auth.token (mode 0600); ...
```

On the client side, point the CLI at the token (env var, flag, or
file):

```sh
export DETOUR_TOKEN="$(sudo cat /var/lib/detour/auth.token)"
detour --host http://10.0.0.5:8080 status

# Or:
detour --host http://10.0.0.5:8080 --token-file ~/.config/detour/token rule list
```

The web UI has a token input in the top bar — paste the token once and
it's saved in `localStorage` (never sent anywhere except as the
`Authorization` header).

`GET /healthz` always bypasses auth so external uptime probes work
without a credential. Everything else (including `/version`) needs
the token on TCP.

If you want to enforce token auth on the Unix socket too (e.g. a
shared host where simply being in the `detour` group isn't enough),
add `--auth-required`.

> **Threat model**: this is a single-secret bearer token — anyone who
> can read it can drive the daemon. It protects against unauthenticated
> network attackers and casual scans. If you need richer guarantees
> (per-user identity, mTLS, audit trails), front detourd with a
> reverse proxy.

---

## Service installation (systemd)

The CLI can write a systemd unit for you, run `daemon-reload`, and
optionally `enable --now`:

```sh
sudo detour service install \
    --binary /usr/local/bin/detourd \
    --http 127.0.0.1:8080 \
    --auth-token-file /etc/detour/tokens \
    --enable
```

Inspect the unit it would produce without touching the system:

```sh
detour service install --dry-run --http :8080 | less
```

Check the live unit state at any time (machine-readable with `--json`):

```sh
detour service status
# UNIT     detourd.service
# LOADED   loaded
# ACTIVE   active (running)
# ENABLED  enabled
# PID      4242
# SINCE    Sat 2026-05-15 22:30:00 UTC

detour service logs --tail 50 --follow   # journalctl -u detourd
```

Uninstall (optionally purging `/var/lib/detour`):

```sh
sudo detour service uninstall --purge
```

If systemd isn't present on the host, `detour service install` and
`status` refuse with a clear error; `--dry-run` still works.

---

## 한국어 매뉴얼

자세한 한국어 사용 설명서는 [`docs/manual.ko.md`](docs/manual.ko.md)
파일을 참고하세요. 빠른 시작부터 데몬/CLI 옵션, 토큰 인증, systemd
서비스 등록, 트러블슈팅, 전체 API 레퍼런스까지 깊이 있게 다룹니다.

---

## HTTP API

All endpoints accept and return JSON. Errors come as
`{"error": "<message>"}` with the appropriate HTTP status.

### `GET /healthz`

```json
{"status": "ok", "uptime_sec": 3600}
```

### `GET /version`

```json
{
  "version":    "1.2.3",
  "commit":     "abcdef0",
  "date":       "2026-05-15T00:00:00Z",
  "chain":      "DETOUR",
  "hosts_file": "/etc/hosts",
  "auth_mode":  "tcp",
  "uptime_sec": 3600
}
```

`auth_mode` is one of `none`, `tcp` (auth enforced on TCP only), or
`all` (auth enforced everywhere).

### `POST /rules`

Request:

```json
{ "from": "0.0.0.0:1234", "to": "127.0.0.1:2234", "proto": "tcp" }
```

`proto` is one of `tcp`, `udp`, or `both` (default).
`from` may use `0.0.0.0` to match any local address.

Response: `201 Created`

```json
{ "id": "a1b2c3", "from": "0.0.0.0:1234", "to": "127.0.0.1:2234", "proto": "tcp" }
```

### `GET /rules`

Array of rule objects.

### `DELETE /rules/{id}`

`204 No Content` on success, `404` if the ID is unknown.

### `POST /hosts`

```json
{ "hostname": "foo.com", "ip": "10.2.3.4" }
```

Response: `201 Created` with `{id, hostname, ip}`.

### `GET /hosts` & `DELETE /hosts/{id}`

Symmetric with `/rules`. When `detourd` is started with `--no-hosts`,
all `/hosts*` endpoints return `503`.

### Web UI

- `GET /` — `text/html`, the SPA entry point.
- `GET /static/app.js` and `GET /static/style.css` — assets served
  out of the embedded FS. No external CDNs, no JS frameworks.

---

## Permissions & security

- The daemon's only privileged surface is the iptables rule
  installation and the write to `/etc/hosts`. Both can be granted to
  a non-root user by combining `CAP_NET_ADMIN` (`setcap`) with
  filesystem ACLs on `/etc/hosts`, but the safe default is to run
  `detourd` as root and constrain *clients* via socket group
  ownership.

- The socket is created `root:detour 0660` by default. Use
  `--socket-group ""` to disable the chown, or pass a numeric gid
  (`--socket-group 999`) for environments without `/etc/group`.

- The control plane has **no authentication on top of the socket
  permissions**. If you enable `--http` you are exposing the API to
  whoever can reach that port: bind it to loopback and put a TLS
  reverse-proxy in front for anything else.

- All managed `/etc/hosts` entries live inside a single sentinel
  block:

  ```
  # >>> detour managed >>>
  10.2.3.4    foo.com  # detour-id=a1b2c3
  # <<< detour managed <<<
  ```

  This makes it easy to audit what the daemon owns and to recover
  manually if it ever crashes mid-write (it writes atomically via
  `rename(2)`, so partial files don't happen).

---

## systemd unit

`/etc/systemd/system/detourd.service`:

```ini
[Unit]
Description=detour daemon (iptables/DNAT and /etc/hosts manager)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/detourd \
    --socket /run/detour.sock \
    --socket-group detour \
    --socket-mode 0660
Restart=on-failure
# CAP_NET_ADMIN is enough for iptables; running as root is simpler.
AmbientCapabilities=CAP_NET_ADMIN
ProtectSystem=full
ReadWritePaths=/etc/hosts /run

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now detourd
```

---

## Development

```sh
# All tests, race detector on:
go test -race ./...

# Vet:
go vet ./...

# Run the daemon locally on a non-root path (skips the root warning):
mkdir -p /tmp/detour
./detourd \
    --socket /tmp/detour/sock \
    --socket-group ""        \
    --iptables /bin/true     # <-- only for `--version`-style smoke tests
```

The package layout:

| Package | Purpose |
|---|---|
| `cmd/detourd` | the daemon binary |
| `cmd/detour`  | the CLI binary |
| `internal/api` | HTTP handlers + embedded web UI |
| `internal/client` | Go client library used by the CLI |
| `internal/hostsfile` | `/etc/hosts` editor with sentinel block |
| `internal/linuxnat` | iptables DNAT manager (mockable runner) |
| `internal/socket` | Unix-socket listener with group/mode |

Every package above ships with unit tests; `cmd/detour/cli_test.go`
runs the CLI end-to-end against a real in-process daemon on a Unix
socket, with the iptables runner stubbed out — so the test suite
works on any Linux host without root.

---

## Troubleshooting

- **`socket setup: lookup group "detour"`** — create the group with
  `sudo groupadd --system detour`, or pass `--socket-group ""` to
  disable group ownership entirely.
- **`iptables: Permission denied`** — `detourd` needs root or
  `CAP_NET_ADMIN`. The daemon will only warn on startup; the actual
  failure surfaces the first time you `rule add`.
- **DNAT to `127.0.0.1` doesn't work for traffic arriving on
  non-loopback** — the daemon enables `net.ipv4.conf.all.route_localnet=1`
  for the duration of its lifetime when needed. If you see a warning
  about it on stderr, run as root (sysctl is privileged).
- **`detour` CLI says `connect: permission denied`** — your user
  isn't in the socket's group, or you haven't logged out/in since
  joining it.

---

## License

MIT — see [`LICENSE`](LICENSE).
