package main

// completion.go writes shell-completion scripts for bash, zsh, and
// fish. Three goals shape the implementation:
//
//   1. No third-party dependency: we embed the script bodies as plain
//      strings, parameterising only what each shell needs.
//   2. No code generation step: the scripts are valid for the current
//      binary; running `detour completion` always produces a script
//      that reflects today's command surface.
//   3. Pragmatic completion depth: we complete subcommand names, the
//      common flags (--host, --token, --json, ...), and accept any
//      argument after that. We don't try to emulate `detour rule rm`
//      ID lookup (that'd need a live daemon and is a footgun in
//      pipelines).

import (
	"fmt"
	"io"
	"strings"
)

func cmdCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "completion: exactly one of bash|zsh|fish required")
		return 2
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(stdout, completionBash(commandNames(), globalFlagNames()))
		return 0
	case "zsh":
		fmt.Fprint(stdout, completionZsh(commandNames(), globalFlagNames()))
		return 0
	case "fish":
		fmt.Fprint(stdout, completionFish(commandNames(), globalFlagNames()))
		return 0
	}
	fmt.Fprintf(stderr, "completion: unsupported shell %q (want bash|zsh|fish)\n", args[0])
	return 2
}

func globalFlagNames() []string {
	return []string{"--host", "--token", "--token-file", "--json", "--timeout"}
}

// commandNames produces the flat list of top-level + compound command
// tokens for completion. "rule" / "host" / "service" appear once, and
// the subcommand words ("list", "add", "rm", ...) appear under them.
// Aliases are deliberately omitted from completion to keep the output
// uncluttered.
func commandNames() []string {
	out := []string{"version", "ping", "info", "status", "completion", "rule", "host", "service"}
	return out
}

func completionBash(_, flags []string) string {
	// Statically know the per-noun verbs.
	return `# bash completion for detour. Source from /etc/bash_completion.d/ or
# add to your ~/.bashrc: source <(detour completion bash)
_detour() {
  local cur prev words cword
  _init_completion -n = || return
  case "${COMP_CWORD}" in
    1)
      COMPREPLY=( $(compgen -W "version ping info status rule host service completion ` + strings.Join(flags, " ") + `" -- "$cur") )
      return 0 ;;
    2)
      case "${COMP_WORDS[1]}" in
        rule)        COMPREPLY=( $(compgen -W "list ls add rm remove delete" -- "$cur") ) ;;
        host)        COMPREPLY=( $(compgen -W "list ls add rm remove delete" -- "$cur") ) ;;
        service)     COMPREPLY=( $(compgen -W "install uninstall status logs" -- "$cur") ) ;;
        completion)  COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
      esac
      return 0 ;;
  esac
  case "$prev" in
    --from|--to|--ip|--hostname|--host|--token|--token-file|--unit-path|--binary|--socket|--http|--chain|--hosts-file|--auth-token-file|--user|--group|--proto|--timeout|--tail)
      COMPREPLY=() ; return 0 ;;
  esac
  COMPREPLY=( $(compgen -W "--from --to --proto --ip --hostname --json --dry-run --enable --purge --follow --tail --host --token --token-file --timeout" -- "$cur") )
}
complete -F _detour detour
`
}

func completionZsh(_, _ []string) string {
	return `#compdef detour
# zsh completion for detour. To use, drop in $fpath as _detour or eval:
#   eval "$(detour completion zsh)"
_detour() {
  local -a cmds
  cmds=(
    'version:show client version'
    'ping:fast health probe'
    'info:show daemon health'
    'status:show daemon status (verbose)'
    'rule:manage iptables DNAT rules'
    'host:manage /etc/hosts entries'
    'service:manage the detourd systemd unit'
    'completion:print shell completion script'
  )
  if (( CURRENT == 2 )); then
    _describe 'detour command' cmds
    return
  fi
  case "$words[2]" in
    rule)
      if (( CURRENT == 3 )); then
        _values 'rule subcommand' list ls add rm remove delete
      fi ;;
    host)
      if (( CURRENT == 3 )); then
        _values 'host subcommand' list ls add rm remove delete
      fi ;;
    service)
      if (( CURRENT == 3 )); then
        _values 'service subcommand' install uninstall status logs
      fi ;;
    completion)
      if (( CURRENT == 3 )); then
        _values 'shell' bash zsh fish
      fi ;;
  esac
  _arguments \
    '--host[daemon address]:address:' \
    '--token[bearer token]:token:' \
    '--token-file[bearer token file]:_files' \
    '--timeout[per-call timeout]:duration:' \
    '--json[JSON output]' \
    '--from[from IP:PORT]:endpoint:' \
    '--to[to IP:PORT]:endpoint:' \
    '--proto[protocol]:proto:(tcp udp both)' \
    '--ip[IP address]:ip:' \
    '--hostname[hostname]:host:' \
    '--dry-run[validate without applying]'
}
_detour "$@"
`
}

func completionFish(_, _ []string) string {
	return `# fish completion for detour. Save as ~/.config/fish/completions/detour.fish
function __detour_no_subcommand
  set -l cmd (commandline -opc)
  if test (count $cmd) -lt 2
    return 0
  end
  return 1
end

complete -c detour -f
complete -c detour -n __detour_no_subcommand -a 'version ping info status rule host service completion'
complete -c detour -n '__fish_seen_subcommand_from rule'    -a 'list ls add rm remove delete'
complete -c detour -n '__fish_seen_subcommand_from host'    -a 'list ls add rm remove delete'
complete -c detour -n '__fish_seen_subcommand_from service' -a 'install uninstall status logs'
complete -c detour -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c detour -l host       -d 'daemon address'
complete -c detour -l token      -d 'bearer token'
complete -c detour -l token-file -d 'token file' -r
complete -c detour -l json       -d 'JSON output'
complete -c detour -l timeout    -d 'per-call timeout'
complete -c detour -l from       -d 'from IP:PORT'
complete -c detour -l to         -d 'to IP:PORT'
complete -c detour -l proto      -d 'protocol' -a 'tcp udp both'
complete -c detour -l ip         -d 'IP address'
complete -c detour -l hostname   -d 'hostname'
complete -c detour -l dry-run    -d 'validate without applying'
`
}
