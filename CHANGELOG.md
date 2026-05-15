# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
