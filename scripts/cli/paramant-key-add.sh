#!/usr/bin/env bash
# paramant-key-add (web-cli) -- add a new API key. MUTATE (TOTP-gated server-side).
# Non-interactive (no whiptail). ASCII-only.
# Positional args:
#   $1 = email (validated)
#   $2 = plan  (free|pro|enterprise, default free)
set -uo pipefail

EMAIL="${1:?email required}"
PLAN="${2:-free}"

RELAY_URL="${RELAY_URL:-http://localhost:3000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "Add API key"
echo "--------------------------------------"
echo "  email: ${EMAIL}"
echo "  plan:  ${PLAN}"

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[FAIL] ADMIN_TOKEN not configured."
  exit 1
fi

PAYLOAD=$(jq -n --arg email "$EMAIL" --arg plan "$PLAN" \
  '{label: ("cli-" + $email), plan: $plan, email: $email}')

RESP=$(curl -sf --max-time 8 -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "${RELAY_URL}/v2/admin/keys" 2>/dev/null || echo "")

if [ -z "$RESP" ]; then
  echo "[FAIL] relay did not accept the request."
  exit 1
fi

NEWKEY=$(echo "$RESP" | jq -r '.key // .api_key // ""' 2>/dev/null || echo "")
if [ -n "$NEWKEY" ]; then
  echo "[OK] key created: ${NEWKEY:0:8}... (full key shown once in relay response)"
else
  echo "[OK] request accepted:"
  echo "$RESP" | jq . 2>/dev/null || echo "$RESP"
fi
