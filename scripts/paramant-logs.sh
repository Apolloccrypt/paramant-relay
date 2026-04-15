#!/usr/bin/env bash
# paramant-logs — live relay log stream (Ctrl-C to stop)

BOLD='\033[1m'; CYAN='\033[0;36m'; RESET='\033[0m'

echo -e "${CYAN}${BOLD}Paramant relay logs — Ctrl-C to stop${RESET}\n"

# If -n flag given, show last N lines and exit
if [[ "${1:-}" == "-n" ]] && [[ -n "${2:-}" ]]; then
  journalctl -u paramant-relay -n "$2" --no-pager
else
  journalctl -u paramant-relay -f --no-pager
fi
