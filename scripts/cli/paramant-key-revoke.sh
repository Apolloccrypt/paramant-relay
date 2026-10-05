#!/usr/bin/env bash
# paramant-key-revoke (web-cli) -- revoke an API key by prefix. MUTATE.
# Non-interactive (no whiptail). ASCII-only.
# Positional args:
#   $1 = key_prefix (>= 8 chars, validated)
#
# The relay's revoke route takes the exact key, not a prefix. This script used
# to post {key_prefix} and every revoke failed with 404 while the key stayed
# valid (ADMIN-45), and it only ever reached one relay. Now it resolves the
# prefix to exactly one key first, and revokes that key on every sector the
# admin knows (RELAY_SECTORS, set by admin/lib/cli-commands.js).
set -uo pipefail

PREFIX="${1:?key_prefix required}"

RELAY_URL="${RELAY_URL:-http://localhost:3000}"
RELAY_SECTORS="${RELAY_SECTORS:-health=${RELAY_URL}}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "Revoke API key"
echo "--------------------------------------"
echo "  prefix: ${PREFIX:0:8}..."

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[FAIL] ADMIN_TOKEN not configured."
  exit 1
fi

KEYS=$(curl -sf --max-time 8 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  "${RELAY_URL}/v2/admin/keys?reveal=1" 2>/dev/null || echo "")
if [ -z "$KEYS" ]; then
  echo "[FAIL] could not list keys on ${RELAY_URL}."
  exit 1
fi

MATCHES=$(echo "$KEYS" | jq -r --arg p "$PREFIX" '[.keys[]? | select(.key != null and (.key | startswith($p)) and .active != false) | .key] | unique | .[]' 2>/dev/null || echo "")
COUNT=$(printf '%s' "$MATCHES" | grep -c . || true)
if [ "$COUNT" -eq 0 ]; then
  echo "[FAIL] no active key starts with that prefix."
  exit 1
fi
if [ "$COUNT" -gt 1 ]; then
  echo "[FAIL] ${COUNT} keys start with that prefix. Give a longer prefix."
  exit 1
fi
KEY="$MATCHES"
PAYLOAD=$(jq -n --arg k "$KEY" '{key: $k}')

OKS=0; TOTAL=0
IFS=',' read -r -a PAIRS <<< "$RELAY_SECTORS"
for pair in "${PAIRS[@]}"; do
  NAME="${pair%%=*}"; URL="${pair#*=}"
  [ -z "$URL" ] && continue
  TOTAL=$((TOTAL + 1))
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-Admin-Token: ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "${URL}/v2/admin/keys/revoke" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ]; then
    OKS=$((OKS + 1)); echo "  [ok]   ${NAME}"
  elif [ "$CODE" = "404" ]; then
    echo "  [--]   ${NAME} (key not on this sector)"
  else
    echo "  [FAIL] ${NAME} (HTTP ${CODE})"
  fi
done

if [ "$OKS" -gt 0 ]; then
  echo "[OK] key ${KEY:0:12}... revoked on ${OKS} of ${TOTAL} sector(s)."
else
  echo "[FAIL] no sector revoked the key."
  exit 1
fi
