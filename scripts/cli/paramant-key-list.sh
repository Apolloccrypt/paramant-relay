#!/usr/bin/env bash
# paramant-key-list (web-cli) -- list active API keys, masked.
# Non-interactive, read-only. ASCII-only.
set -uo pipefail

RELAY_URL="${RELAY_URL:-http://localhost:3000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "Active API keys"
echo "--------------------------------------"

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[FAIL] ADMIN_TOKEN not configured."
  exit 1
fi

RESP=$(curl -sf --max-time 5 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  "${RELAY_URL}/v2/admin/keys" 2>/dev/null || echo "")

if [ -z "$RESP" ]; then
  echo "[FAIL] could not reach relay at ${RELAY_URL}/v2/admin/keys"
  exit 1
fi

# Normalize {keys:[...]} or bare [...]; mask the key body to a short prefix.
echo "$RESP" | jq -r '
  (if type == "object" then (.keys // []) else . end) as $keys
  | if ($keys | length) == 0 then "  (no keys)"
    else $keys[]
      | ((.key // .api_key // .id // "????????") | tostring) as $k
      | "  " + ($k[0:8]) + "...  " + (.label // "unlabeled") + "  [" + (.plan // "?") + "]"
    end
' 2>/dev/null || { echo "[FAIL] unexpected response format"; exit 1; }
