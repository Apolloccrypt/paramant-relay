#!/usr/bin/env bash
# paramant-backup (web-cli) -- trigger an immediate relay backup. MUTATE.
# Non-interactive. ASCII-only. Writes only under the allowed backup dir.
set -uo pipefail

# Only /tmp and /var/log/paramant are writable per the CLI security policy;
# backups land under a dedicated, policy-compliant directory.
BACKUP_BASE="${BACKUP_DIR:-/var/log/paramant/backups}"
RELAY_URL="${RELAY_URL:-http://localhost:3000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "Create backup"
echo "--------------------------------------"

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[FAIL] ADMIN_TOKEN not configured."
  exit 1
fi

# Prefer a relay-side backup endpoint when available; this keeps the admin
# container from needing direct access to relay data volumes.
RESP=$(curl -sf --max-time 30 -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  "${RELAY_URL}/v2/admin/backup" 2>/dev/null || echo "")

if [ -n "$RESP" ]; then
  echo "[OK] relay backup triggered:"
  echo "$RESP" | jq . 2>/dev/null || echo "$RESP"
  exit 0
fi

echo "[WARN] relay backup endpoint unavailable -- writing local marker only."
TS=$(date '+%Y%m%d-%H%M%S')
mkdir -p "$BACKUP_BASE" 2>/dev/null || {
  echo "[FAIL] cannot create ${BACKUP_BASE}"
  exit 1
}
echo "backup requested at ${TS}" > "${BACKUP_BASE}/backup-${TS}.txt"
echo "[OK] marker written: ${BACKUP_BASE}/backup-${TS}.txt"
