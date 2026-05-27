#!/usr/bin/env bash
# paramant-audit-recent (web-cli) -- show recent relay audit-log entries.
# Non-interactive, read-only. ASCII-only.
# Positional args:
#   $1 = limit (integer, default 50)
set -uo pipefail

LIMIT="${1:-50}"
RELAY_URL="${RELAY_URL:-http://localhost:3000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "Recent audit entries (limit ${LIMIT})"
echo "--------------------------------------"

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[FAIL] ADMIN_TOKEN not configured."
  exit 1
fi

RESP=$(curl -sf --max-time 5 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  "${RELAY_URL}/v2/admin/audit?limit=${LIMIT}" 2>/dev/null || echo "")

if [ -z "$RESP" ]; then
  echo "[FAIL] could not reach relay audit endpoint."
  exit 1
fi

echo "$RESP" | jq -r '
  (if type == "object" then (.events // .entries // []) else . end) as $ev
  | if ($ev | length) == 0 then "  (no entries)"
    else $ev[]
      | "  " + ((.ts // .time // "?") | tostring) + "  " + (.event_type // .event // "?") + "  " + ((.user_id // .admin_id // "") | tostring)
    end
' 2>/dev/null || { echo "$RESP"; }
