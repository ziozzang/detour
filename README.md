# detour

[![CI](https://github.com/LeeJeKyun/detour/actions/workflows/ci.yml/badge.svg)](https://github.com/LeeJeKyun/detour/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/LeeJeKyun/detour)](https://github.com/LeeJeKyun/detour/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Reference](https://pkg.go.dev/badge/github.com/LeeJeKyun/detour.svg)](https://pkg.go.dev/github.com/LeeJeKyun/detour)

A Windows CLI that transparently redirects TCP/UDP traffic destined for one `IP:PORT` to another. Uses [WinDivert](https://github.com/basil00/WinDivert) to intercept packets at the kernel level and perform destination NAT in userspace.

`WinDivert.dll` and `WinDivert64.sys` are embedded in the binary, so **`detour.exe` ships as a single self-contained file** — no installer, no separate driver setup.

## Requirements

- Windows 7+ (x64)
- Go 1.23+ (build only)
- Administrator privileges (run only — required to load the WinDivert driver). The binary embeds a UAC manifest, so launching it from a non-elevated shell or by double-clicking automatically triggers the elevation prompt — no need to spawn an Administrator PowerShell yourself.

## Build

The binaries embed a UAC manifest via [`go-winres`](https://github.com/tc-hib/go-winres). One-time setup:

```sh
go install github.com/tc-hib/go-winres@latest
```

Then build both the CLI and the GUI:

```powershell
go-winres make --arch amd64
Copy-Item rsrc_windows_amd64.syso cmd\detour-gui\
go build -ldflags "-s -w" -o detour.exe .
go build -ldflags "-s -w -H=windowsgui" -o detour-gui.exe .\cmd\detour-gui
```

Cross-compile from macOS/Linux:

```sh
go-winres make --arch amd64
cp rsrc_windows_amd64.syso cmd/detour-gui/
GOOS=windows go build -ldflags "-s -w" -o detour.exe .
GOOS=windows go build -ldflags "-s -w -H=windowsgui" -o detour-gui.exe ./cmd/detour-gui
```

`go-winres make` reads `winres/winres.json` and produces `rsrc_windows_amd64.syso`, which `go build` automatically links into the executable. The `.syso` is build output (gitignored) — regenerate it whenever `winres/winres.json` changes. Each `main` package directory (`.` and `cmd/detour-gui/`) needs its own copy so the manifest is linked into both binaries.

Released zip archives include both binaries; you can grab them from the [Releases page](../../releases) instead of building from source.

## Usage

### CLI — `detour.exe`

```powershell
.\detour.exe --from 1.2.3.4:5000 --to 127.0.0.1:5001
```

A UAC prompt appears the first time the binary tries to load the WinDivert driver — accept it once per launch. After the prompt, the rule is active until you press `Ctrl+C`.

| Flag | Description |
|---|---|
| `--from <IP:PORT>` | original destination to intercept (required) |
| `--to <IP:PORT>` | new destination (required) |
| `--protocol tcp\|udp\|both` | default `both` |
| `-v` | verbose logging — prints filter expressions and drop reasons |
| `--version` | print version and exit |

Press `Ctrl+C` to stop. Both WinDivert handles close cleanly and traffic returns to its normal path.

### GUI — `detour-gui.exe`

A small native window for users who prefer not to keep an Administrator console open. Double-click to launch — the same UAC prompt appears, then a window listing your saved rules in a table.

Behavior:
- **Multi-rule** — every row is an independent rule with its own packet counters; multiple rules can run at the same time.
- **Checkbox = selection, buttons = action.** Tick the leftmost (`All`) checkbox on one or more rows, then press **Start** / **Stop** in the footer to activate or deactivate the checked rules. Click the `All` column **header** to toggle every row's checkbox at once (handy for bulk Start/Stop/Delete). Edit applies to a single checked row; Delete works on any number of checked rows. Button enable state is driven by the checkboxes, not row focus — clicking around the table to tick boxes never disables Edit or Delete.
- **Add / Edit / Delete** open a small modal dialog with `From` / `To` / `Protocol` fields. Inputs are validated live; **OK** stays disabled until both endpoints parse as valid IPv4:Port. A rule must be stopped before it can be edited. Double-clicking a row is a shortcut for editing that specific row.
- **Auto-saved** to `%APPDATA%\detour\rules.json`. Every Add/Edit/Delete writes the file atomically; the next launch restores the same list.
- **Live packet counts** (`Forward` / `Reverse`) refresh every second per row, plus a footer aggregate (`Active: N   Forward: M   Reverse: M`).
- **Tray icon** in the system notification area — gray when idle, green when at least one rule is running. Hover for the aggregate tooltip; left-click to reopen the window; right-click for **Open / Quit**.
- **Closing the window** with the X button (or Alt+F4) hides to the tray as long as any rule is running; only **Quit** (or X with everything stopped) terminates the process. The first hide triggers a balloon notification so you know the app is still alive.
- **Conflict detection** — two rules with the same `From IP:Port` and overlapping protocols (e.g. one `tcp`, another `both`) are rejected at Add/Edit time so the WinDivert filters never fight.

The CLI and GUI share the same packet-handling core (`internal/runtime`), so per-rule behavior with respect to traffic is identical — choose whichever interface is more convenient.

## How it works

- **Forward handle**: receives outbound packets matching `ip.DstAddr == FROM_IP` + `DstPort == FROM_PORT`, rewrites the destination to `TO`, recalculates checksums, and reinjects the packet.
- **Reverse handle**: receives inbound packets matching `ip.SrcAddr == TO_IP` + `SrcPort == TO_PORT`, rewrites the source back to `FROM`, so the calling application sees responses as coming from the address it originally dialed.
- Applies system-wide (no PID filtering). The CLI runs one rule per process; the GUI multiplexes multiple rules within a single process, each with its own pair of WinDivert handles.

## Runtime layout

On first run, the embedded WinDivert files are extracted to a content-hashed runtime directory:

```
%PROGRAMDATA%\detour\runtime-<sha256-prefix>\
  ├── WinDivert.dll
  └── WinDivert64.sys
```

Subsequent runs of the same binary reuse this cache. A different build (different file hashes) gets its own directory.

## Limitations (v1)

- IPv4 only (IPv6 not supported)
- Loopback (`127.0.0.1`) targets may behave inconsistently — Windows networking treats local-to-local traffic specially.
- No TCP MSS clamping — fragmentation may occur if the redirected path has a smaller MTU.

## License

`detour` is released under the **GPLv3** license. See [LICENSE](LICENSE) for details.

The runtime dependency [WinDivert](https://github.com/basil00/WinDivert) is dual-licensed **LGPLv3 / GPLv2**; this project relies on the LGPLv3 terms. When distributing builds, include the WinDivert license text alongside (the upstream copy lives at `third_party/WinDivert-2.2.2-A/LICENSE`).

## Linux runtime — `detour-linux`

A separate Linux daemon under [`cmd/detour-linux`](cmd/detour-linux) offers the same conceptual feature set (transparent destination redirection + ad-hoc hostname overrides) using kernel mechanisms native to Linux:

- **`iptables`** rules in the `nat` table (a dedicated `DETOUR` chain hooked from `OUTPUT` and `PREROUTING`) replace WinDivert. Add, remove, and list rules at runtime; the chain is flushed and removed on shutdown.
- **`/etc/hosts`** entries can be added on the fly, bracketed by sentinel comments, and are stripped automatically when the daemon exits (SIGINT/SIGTERM).
- A small **JSON-over-HTTP API** is the control surface — set rules and host overrides with `curl`, no GUI.

### Requirements

- Linux with `iptables` (legacy or `iptables-nft` — both speak the same CLI)
- Go 1.23+ to build
- `root` (CAP_NET_ADMIN) at runtime

### Build

```sh
GOOS=linux CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o detour-linux ./cmd/detour-linux
```

### Run

```sh
sudo ./detour-linux --listen :8080
```

| Flag | Default | Description |
|---|---|---|
| `--listen` | `:8080` | HTTP API listen address |
| `--hosts-file` | `/etc/hosts` | path of the hosts file managed on-the-fly |
| `--chain` | `DETOUR` | iptables chain (created in the `nat` table) |
| `--iptables` | `iptables` | iptables binary path / name on `$PATH` |
| `--no-hosts` | — | disable `/etc/hosts` management; `/hosts` returns 503 |
| `--version` | — | print version and exit |

### API examples

The two scenarios from the original feature spec, expressed as `curl` calls:

```sh
# 0.0.0.0:1234 -> 127.0.0.1:2234 (any local IP, port 1234 -> upstream)
curl -sS -X POST localhost:8080/rules \
  -H 'content-type: application/json' \
  -d '{"from":"0.0.0.0:1234","to":"127.0.0.1:2234","proto":"tcp"}'

# foo.com -> 10.2.3.4 (transient /etc/hosts entry, removed on shutdown)
curl -sS -X POST localhost:8080/hosts \
  -H 'content-type: application/json' \
  -d '{"hostname":"foo.com","ip":"10.2.3.4"}'

# Inspect / remove
curl -sS localhost:8080/rules
curl -sS localhost:8080/hosts
curl -sS -X DELETE localhost:8080/rules/<id>
curl -sS -X DELETE localhost:8080/hosts/<id>
curl -sS localhost:8080/healthz
```

| Verb / path | Body | Result |
|---|---|---|
| `GET /healthz` | — | `{"status":"ok"}` |
| `GET /rules` | — | array of installed DNAT rules |
| `POST /rules` | `{"from":"IP:PORT","to":"IP:PORT","proto":"tcp\|udp\|both"}` | `201` with `{id,...}`. `proto` defaults to `both`. |
| `DELETE /rules/{id}` | — | `204`; `404` if id unknown |
| `GET /hosts` | — | array of managed hosts entries |
| `POST /hosts` | `{"hostname":"...","ip":"..."}` | `201` with `{id,...}` |
| `DELETE /hosts/{id}` | — | `204`; `404` if id unknown |

`from` is a literal `IP:PORT`. `0.0.0.0` on the `from` side is special: it matches *any* local destination IP on the given port, so the rule covers traffic targeted at any of the machine's interfaces.

### How it works

- Every rule becomes an `iptables -t nat -A DETOUR -p <proto> [-d <from-ip>] --dport <from-port> -j DNAT --to-destination <to>` invocation. Rules also carry an `iptables` comment (`detour:<id>`) so manual inspection (`iptables -t nat -S DETOUR`) is straightforward.
- For `tcp+udp` (`proto:"both"`) the daemon installs two rules under the same id and removes them atomically.
- DNAT to `127.0.0.1` only works for traffic that arrives on a non-loopback interface if `net.ipv4.conf.all.route_localnet=1`. The daemon flips this sysctl when needed and restores the previous value on shutdown.
- Host overrides land between sentinel comments inside the hosts file (`# >>> detour managed >>>` / `# <<< detour managed <<<`). The file is rewritten atomically (temp file + `rename`); content outside the managed block is preserved verbatim.

### Cleanup guarantees

On `SIGINT`/`SIGTERM` the daemon:

1. Stops accepting new HTTP requests.
2. Removes the managed `/etc/hosts` block (and only that block).
3. Unhooks `DETOUR` from `OUTPUT` and `PREROUTING`, flushes the chain, and deletes it.
4. Restores `route_localnet` if it was changed.

If the process is killed with `SIGKILL` instead, the next clean restart re-uses (and flushes) the existing chain and strips any leftover managed `/etc/hosts` block — so a hard kill is recoverable but cleanup is deferred until the next start.

### Limitations

- IPv4 only (matches the rest of detour).
- DNAT only — there's no kernel-level reverse-mapping for stateful TCP that originates from the daemon's host *to* the original `from` address; this is the same redirect model as the Windows side.
- Requires Linux kernel `iptables` (legacy or nftables-backed CLI). Pure-`nft` mode is not implemented.

