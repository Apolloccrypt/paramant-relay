#!/usr/bin/env bash
# paramant-doctor (web-cli) -- deep health check across sector relays.
# Non-interactive. ASCII-only. Probes the configured sector health endpoints.
set -uo pipefail

# Sector base URLs are injected by the admin server (SECTORS map). Fall back to
# the primary relay if none are provided.
SECTORS_RAW="${RELAY_SECTORS:-primary=${RELAY_URL:-http://localhost:3000}}"

echo "paramant-doctor -- service health"
echo "--------------------------------------"

FAIL=0
# RELAY_SECTORS format: "name=url,name=url,..."
IFS=',' read -ra PAIRS <<< "$SECTORS_RAW"
for pair in "${PAIRS[@]}"; do
  name="${pair%%=*}"
  url="${pair#*=}"
  [ -z "$name" ] && continue
  R=$(curl -sf --max-time 3 "${url}/health" 2>/dev/null || echo "")
  if [ -n "$R" ]; then
    VER=$(echo "$R" | jq -r '.version // "?"' 2>/dev/null || echo "?")
    echo "  [OK]   ${name} (${url}) -- v${VER}"
  else
    echo "  [FAIL] ${name} (${url}) -- no response"
    FAIL=$((FAIL+1))
  fi
done

echo "--------------------------------------"
if [ "$FAIL" -eq 0 ]; then
  echo "All probed services healthy."
else
  echo "${FAIL} service(s) unreachable."
  exit 1
fi
