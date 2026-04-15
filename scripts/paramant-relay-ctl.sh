#!/usr/bin/env bash
# paramant-relay-ctl — privileged relay service control (H1: sudo wildcard fix)
#
# Validates the service name before calling systemctl so the sudoers entry
# cannot be abused to start arbitrary services.
# Valid names: paramant-relay  OR  paramant-relay-<1-32 char slug>
#
# Called as root via sudo (NOPASSWD in configuration.nix sudoers).
# Usage:
#   sudo paramant-relay-ctl <action> [service-name]
#   sudo paramant-relay-ctl daemon-reload

set -euo pipefail

ACTION="${1:-}"
SERVICE="${2:-paramant-relay}"

case "$ACTION" in
  daemon-reload)
    exec systemctl daemon-reload
    ;;
  start|stop|restart|enable|disable|status) ;;
  *)
    printf 'Usage: paramant-relay-ctl <start|stop|restart|enable|disable|status|daemon-reload> [service]\n' >&2
    exit 1
    ;;
esac

# Strict service name validation — prevents wildcard abuse
if [[ ! "$SERVICE" =~ ^paramant-relay(-[a-z][a-z0-9-]{0,31})?$ ]]; then
  printf 'Error: invalid service name "%s"\n' "$SERVICE" >&2
  exit 1
fi

exec systemctl "$ACTION" "$SERVICE"
