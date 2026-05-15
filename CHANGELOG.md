# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — auth, service management, deeper CLI/UX

- **Bearer-token authentication** (`internal/auth`). The Unix-domain
  socket stays gated by POSIX permissions (Docker-style trust); TCP
  always requires `Authorization: Bearer <token>`. If `--http` is
  enabled without any token, the daemon auto-generates a 64-char
  random token and persists it to `/var/lib/detour/auth.token` (mode
  0600) — token-less TCP exposure is now impossible. Constant-time
  comparison via `crypto/subtle`. `--auth-required` flips Unix-socket
  enforcement on for shared hosts.
- New daemon flags: `--auth-token`, `--auth-token-file` (mode-0600
  enforced, one token per line, `#` comments), `--auth-required`,
  `--auth-state-dir`. Env var `DETOURD_AUTH_TOKEN` supported.
- New CLI flags: `--token`, `--token-file`. Env vars `DETOUR_TOKEN`,
  `DETOUR_TOKEN_FILE`.
- **`GET /version`** endpoint returns build metadata, chain name,
  hosts-file path, auth mode, and uptime. `GET /healthz` now also
  reports `uptime_sec`. `/healthz` bypasses auth so external probes
  keep working.
- **`detour service {install,uninstall,status,logs}`** subcommands.
  Renders a hardened systemd unit (`CAP_NET_ADMIN`,
  `NoNewPrivileges=true`, `StateDirectory=detour`,
  `RuntimeDirectory=detour`) and drives `systemctl` for install/
  enable/disable. `--dry-run` everywhere prints the unit + commands
  without touching the system; works even when systemd is absent.
- **`detour status`** — verbose cousin of `info` with version, chain,
  auth-mode, uptime, rule/host counts.
- **`detour ping`** — minimal health probe for scripts.
- **`detour completion {bash|zsh|fish}`** — static shell-completion
  scripts (subcommands, common flags, no third-party dep).
- **`detour rule add --dry-run`** — validate flag combination
  without calling the daemon.
- Friendlier error messages: connection failures now hint
  "`is detourd running? Try: sudo systemctl status detourd`" and exit 2
  (vs 1 for operation failures).
- Aliases: `rule ls`, `host ls`, `rule remove`/`rule delete`,
  `host remove`/`host delete`.
- Web UI gains a token input persisted to `localStorage`; the JS
  helper now attaches `Authorization: Bearer …` on every request.
- Korean manual: [`docs/manual.ko.md`](docs/manual.ko.md) — deep
  end-to-end guide (quick start, daemon/CLI flag reference, auth
  model, systemd integration, web UI, internals, security, FAQ, API).

### Fixed (small code-review nits)

- `internal/api`: `handleAddHost` normalizes the parsed IP in the
  response so callers see the canonical form regardless of input
  whitespace.

## [0.1.0]

### Changed — major rewrite

`detour` has been rewritten from a single-binary Windows tool (built
on WinDivert) into a Linux daemon + CLI pair with a JSON HTTP API and
a browsable web UI. All Windows-specific code has been removed.

### Added

- **`detourd`** — long-running daemon that exposes a JSON HTTP API on
  a Unix-domain socket (default `/run/detour.sock`, `root:detour 0660`)
  and, optionally, a TCP listener (`--http`).
- **`detour`** — Docker-style CLI with subcommands `info`, `version`,
  `rule {list,add,rm}`, `host {list,add,rm}`. Supports `--json`
  output, `--host` / `DETOUR_HOST` for address selection.
- **Embedded web UI** at `GET /` — single-page HTML/JS, no
  frameworks, no external CDNs, served from `embed.FS`.
- **`internal/api`** — backend-agnostic HTTP handlers driven by two
  small interfaces (`NATBackend`, `HostsBackend`).
- **`internal/linuxnat`** — iptables DNAT manager with a mockable
  `Runner` interface; owns a dedicated `DETOUR` chain in the `nat`
  table; flushes and removes it on shutdown.
- **`internal/hostsfile`** — pure-Go `/etc/hosts` editor with
  sentinel block, atomic writes, and full cleanup on `Close`.
- **`internal/socket`** — Unix-socket listener helper handling
  stale-socket recovery, parent-dir creation, and group/mode
  application.
- **`internal/client`** — Go client library used by the CLI; speaks
  both `unix://` and `http(s)://`.
- Full test suite (`go test -race ./...`) covering every package,
  including an in-process end-to-end test driving the CLI against a
  real Unix-socket daemon with the iptables runner stubbed.
- New `README.md` and `docs/architecture.md`.

### Removed

- All Windows code: `main.go`, `cmd/detour-gui/`, `internal/admin/`,
  `internal/cli/`, `internal/dnat/`, `internal/rules/`,
  `internal/runtime/`, `internal/wdembed/`, `winres/`.
- Bundled WinDivert driver assets.
- `go-winres` build dependency, `.goreleaser.yaml`, and the goreleaser
  release pipeline (replaced by a simple `go build` workflow producing
  linux/amd64 + linux/arm64 archives).

[Unreleased]: https://github.com/ziozzang/detour/compare/v0.0.0...HEAD
