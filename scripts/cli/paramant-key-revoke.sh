#!/usr/bin/env bash
# paramant-key-revoke (web-cli) -- revoke an API key by hash-prefix. MUTATE.
# Non-interactive (no whiptail). ASCII-only.
# Positional args:
#   $1 = key_prefix (>= 8 chars, validated)
set -uo pipefail

PREFIX="${1:?key_prefix required}"

RELAY_URL="${RELAY_URL:-http://localhost:3000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "Revoke API key"
echo "--------------------------------------"
echo "  prefix: ${PREFIX:0:8}..."

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[FAIL] ADMIN_TOKEN not configured."
  exit 1
fi

PAYLOAD=$(jq -n --arg p "$PREFIX" '{key_prefix: $p}')

RESP=$(curl -sf --max-time 8 -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "${RELAY_URL}/v2/admin/keys/revoke" 2>/dev/null || echo "")

if [ -z "$RESP" ]; then
  echo "[FAIL] relay did not accept the revoke request."
  exit 1
fi

OK=$(echo "$RESP" | jq -r '.ok // .revoked // empty' 2>/dev/null || echo "")
if [ -n "$OK" ]; then
  echo "[OK] key(s) matching prefix revoked."
else
  echo "[OK] request accepted:"
  echo "$RESP" | jq . 2>/dev/null || echo "$RESP"
fi
