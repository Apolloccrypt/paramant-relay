#!/usr/bin/env bash
# paramant-relay-list (web-cli) -- list configured sector relays and probe them.
# Non-interactive, read-only. ASCII-only.
set -uo pipefail

SECTORS_RAW="${RELAY_SECTORS:-primary=${RELAY_URL:-http://localhost:3000}}"

echo "Configured sector relays"
echo "--------------------------------------"

IFS=',' read -ra PAIRS <<< "$SECTORS_RAW"
for pair in "${PAIRS[@]}"; do
  name="${pair%%=*}"
  url="${pair#*=}"
  [ -z "$name" ] && continue
  R=$(curl -sf --max-time 3 "${url}/health" 2>/dev/null || echo "")
  if [ -n "$R" ]; then
    echo "  ${name}  ->  ${url}  [up]"
  else
    echo "  ${name}  ->  ${url}  [down]"
  fi
done
