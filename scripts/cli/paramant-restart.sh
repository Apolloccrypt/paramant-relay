#!/usr/bin/env bash
# paramant-restart (web-cli) -- restart a service via docker compose. MUTATE.
# Non-interactive. ASCII-only.
# Positional args:
#   $1 = service (relay|admin|frontend|all)
set -uo pipefail

SERVICE="${1:?service required}"
COMPOSE="${COMPOSE_CMD:-docker compose}"

echo "Restart service: ${SERVICE}"
echo "--------------------------------------"

if ! command -v docker >/dev/null 2>&1; then
  echo "[FAIL] docker not available in this container."
  echo "       (restart requires the docker socket to be mounted into admin)"
  exit 1
fi

case "$SERVICE" in
  relay)    TARGETS="relay-health" ;;
  admin)    TARGETS="admin" ;;
  frontend) TARGETS="frontend" ;;
  all)      TARGETS="" ;;  # empty = all services
  *) echo "[FAIL] unknown service: ${SERVICE}"; exit 1 ;;
esac

# shellcheck disable=SC2086
if $COMPOSE restart $TARGETS 2>&1; then
  echo "[OK] restart issued for: ${SERVICE}"
else
  echo "[FAIL] restart failed for: ${SERVICE}"
  exit 1
fi
