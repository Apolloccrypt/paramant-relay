#!/usr/bin/env bash
# paramant-data-ctl — privileged relay data-dir management (H2: sudo wildcard fix)
#
# Validates the target path before creating/owning/chmoding so the sudoers
# entry cannot be abused to manipulate arbitrary directories.
# Valid paths: /var/lib/paramant-relay  OR  /var/lib/paramant-relay-<slug>
#
# Called as root via sudo (NOPASSWD in configuration.nix sudoers).
# Usage:
#   sudo paramant-data-ctl mkdir  <path>
#   sudo paramant-data-ctl chown  <path>
#   sudo paramant-data-ctl chmod  <path>

set -euo pipefail

ACTION="${1:-}"
TARGET="${2:-}"

# Strict path validation — must be /var/lib/paramant-relay or /var/lib/paramant-relay-<slug>
if [[ ! "$TARGET" =~ ^/var/lib/paramant-relay(-[a-z][a-z0-9-]{0,31})?$ ]]; then
  printf 'Error: invalid path "%s"\n' "$TARGET" >&2
  exit 1
fi

case "$ACTION" in
  mkdir)
    exec mkdir -p "$TARGET"
    ;;
  chown)
    exec chown paramant-relay:paramant-relay "$TARGET"
    ;;
  chmod)
    exec chmod 750 "$TARGET"
    ;;
  *)
    printf 'Usage: paramant-data-ctl <mkdir|chown|chmod> <path>\n' >&2
    exit 1
    ;;
esac
