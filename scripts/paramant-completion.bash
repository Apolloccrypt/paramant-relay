# Bash completion for all paramant-* commands
# Installed to /etc/bash_completion.d/paramant by scripts.nix

# ── List of all paramant-* commands ───────────────────────────────────────────
_PARAMANT_COMMANDS=(
  paramant-backup
  paramant-cron
  paramant-dashboard
  paramant-doctor
  paramant-export
  paramant-help
  paramant-info
  paramant-ip
  paramant-key-add
  paramant-key-revoke
  paramant-keys
  paramant-license
  paramant-logs
  paramant-ports
  paramant-restart
  paramant-restore
  paramant-scan
  paramant-sector-add
  paramant-security
  paramant-setup
  paramant-status
  paramant-test
  paramant-update
  paramant-verify
  paramant-wifi
)

# ── Generic completer — used when no specific flags are defined ────────────────
_paramant_generic() {
  # No arguments → nothing to complete
  COMPREPLY=()
}

# ── Per-command completers with flags ─────────────────────────────────────────
_paramant_setup() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "--force" -- "$cur") )
}

_paramant_logs() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  if [[ "$prev" == "-n" ]]; then
    COMPREPLY=( $(compgen -W "20 50 100 200 500" -- "$cur") )
  else
    COMPREPLY=( $(compgen -W "-n" -- "$cur") )
  fi
}

_paramant_cron() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "install-backup install-watchdog install-license list remove" -- "$cur") )
}

_paramant_sector_add() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "health finance legal iot custom" -- "$cur") )
}

_paramant_verify() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "--list --clear --help" -- "$cur") )
}

# ── Tab-complete "paramant-<Tab>" to list all commands ────────────────────────
_paramant_prefix() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "${_PARAMANT_COMMANDS[*]}" -- "$cur") )
}

# ── Register completions ───────────────────────────────────────────────────────
complete -F _paramant_setup       paramant-setup
complete -F _paramant_logs        paramant-logs
complete -F _paramant_cron        paramant-cron
complete -F _paramant_sector_add  paramant-sector-add
complete -F _paramant_verify      paramant-verify

# All other commands: no-arg completer
for _cmd in paramant-backup paramant-dashboard paramant-doctor \
            paramant-export paramant-help paramant-info paramant-ip \
            paramant-key-add paramant-key-revoke paramant-keys \
            paramant-license paramant-ports paramant-restart \
            paramant-restore paramant-scan paramant-security \
            paramant-status paramant-test paramant-update paramant-wifi; do
  complete -F _paramant_generic "$_cmd"
done
unset _cmd

# ── "paramant-<Tab>" prefix completion ────────────────────────────────────────
# Allows: paramant-<Tab><Tab> to show all commands
# This works because bash tries to complete the current word against commands
# in PATH. Since all paramant-* are in PATH via Nix, this works automatically.
# The function below adds completion within a bare "paramant" word (no dash yet).
_paramant_bare() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "${_PARAMANT_COMMANDS[*]}" -- "paramant${cur}") )
  # Trim the "paramant" prefix that compgen adds back
  COMPREPLY=( "${COMPREPLY[@]#paramant}" )
}
