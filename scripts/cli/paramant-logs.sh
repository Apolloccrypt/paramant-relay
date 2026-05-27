#!/usr/bin/env bash
# paramant-logs (web-cli) -- last N log lines for a service.
# Non-interactive (no -f follow, no pager). ASCII-only.
# Positional args (validated by server against the whitelist schema):
#   $1 = service  (relay|admin|nats|frontend)
#   $2 = tail     (integer, default 100)
set -uo pipefail

SERVICE="${1:?service required}"
TAIL="${2:-100}"

# Map logical service name to a docker compose service.
case "$SERVICE" in
  relay)    SVC="relay-health" ;;
  admin)    SVC="admin" ;;
  nats)     SVC="nats" ;;
  frontend) SVC="frontend" ;;
  *) echo "[FAIL] unknown service: ${SERVICE}"; exit 1 ;;
esac

COMPOSE="${COMPOSE_CMD:-docker compose}"

echo "Logs: ${SERVICE} (${SVC}) -- last ${TAIL} lines"
echo "--------------------------------------"

if ! command -v docker >/dev/null 2>&1; then
  echo "[FAIL] docker not available in this container."
  echo "       (logs require the docker socket to be mounted into admin)"
  exit 1
fi

# --no-color and --tail keep output deterministic and bounded.
$COMPOSE logs --no-color --tail "$TAIL" "$SVC" 2>&1 || {
  echo "[FAIL] could not read logs for ${SVC}"
  exit 1
}
