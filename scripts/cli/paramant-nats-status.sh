#!/usr/bin/env bash
# paramant-nats-status (web-cli) -- NATS JetStream connectivity check.
# Non-interactive, read-only. ASCII-only.
set -uo pipefail

# NATS monitoring endpoint (HTTP) -- localhost/internal only, no egress.
NATS_MON="${NATS_MONITOR_URL:-http://nats:8222}"

echo "NATS JetStream status"
echo "--------------------------------------"

VARZ=$(curl -sf --max-time 4 "${NATS_MON}/varz" 2>/dev/null || echo "")
if [ -z "$VARZ" ]; then
  echo "[FAIL] NATS monitoring unreachable at ${NATS_MON}/varz"
  exit 1
fi

SERVER=$(echo "$VARZ" | jq -r '.server_name // "?"' 2>/dev/null || echo "?")
VER=$(echo "$VARZ"    | jq -r '.version // "?"'     2>/dev/null || echo "?")
CONNS=$(echo "$VARZ"  | jq -r '.connections // "?"' 2>/dev/null || echo "?")
echo "  Server:      ${SERVER}"
echo "  Version:     ${VER}"
echo "  Connections: ${CONNS}"

JSZ=$(curl -sf --max-time 4 "${NATS_MON}/jsz" 2>/dev/null || echo "")
if [ -n "$JSZ" ]; then
  STREAMS=$(echo "$JSZ" | jq -r '.streams // "?"'   2>/dev/null || echo "?")
  MSGS=$(echo "$JSZ"    | jq -r '.messages // "?"'  2>/dev/null || echo "?")
  echo "  JetStream:   [OK] streams=${STREAMS} messages=${MSGS}"
else
  echo "  JetStream:   [WARN] /jsz not available"
fi
