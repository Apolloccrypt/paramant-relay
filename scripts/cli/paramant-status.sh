#!/usr/bin/env bash
# paramant-status (web-cli) -- relay health, version, edition.
# Non-interactive. Reads RELAY_URL + ADMIN_TOKEN from env. ASCII-only.
set -uo pipefail

RELAY_URL="${RELAY_URL:-http://localhost:3000}"

echo "Paramant Relay Status"
echo "--------------------------------------"

HEALTH=$(curl -sf --max-time 4 "${RELAY_URL}/health" 2>/dev/null || echo "")
if [ -n "$HEALTH" ]; then
  VERSION=$(echo "$HEALTH" | jq -r '.version // "?"' 2>/dev/null || echo "?")
  EDITION=$(echo "$HEALTH" | jq -r '.edition // "?"' 2>/dev/null || echo "?")
  MAX=$(echo "$HEALTH"     | jq -r '.max_keys // "?"' 2>/dev/null || echo "?")
  SECTOR=$(echo "$HEALTH"  | jq -r '.sector // "?"'  2>/dev/null || echo "?")
  echo "  Health:   [OK] reachable"
  echo "  Version:  v${VERSION}"
  echo "  Edition:  ${EDITION}"
  echo "  Max keys: ${MAX}"
  echo "  Sector:   ${SECTOR}"
else
  echo "  Health:   [FAIL] unreachable at ${RELAY_URL}/health"
  exit 1
fi
