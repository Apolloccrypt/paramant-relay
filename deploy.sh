#!/usr/bin/env bash
# Safe deploy with pre- and post-deploy checks.
# Usage: ./deploy.sh [container]   (default: admin)
#
# Flow:
#   1. Static sanity → blocks deploy on syntax errors / undefined refs
#   2. docker compose up -d --build
#   3. Wait for container healthy
#   4. Auth smoke tests → if any fail, prints warning (does not rollback)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER="${1:-admin}"
MAX_WAIT=60

echo "═══════════════════════════════════"
echo "  PARAMANT SAFE DEPLOY"
echo "  Container: $CONTAINER"
echo "═══════════════════════════════════"
echo ""

# ── 1. Pre-deploy static sanity ──────────────────────────────────────────────
echo "Step 1/4: Static sanity check..."
if ! "$ROOT/tests/static-sanity.sh"; then
  echo ""
  echo "Deploy blocked — fix static sanity failures first."
  exit 1
fi
echo ""

# ── 2. Build and start container ─────────────────────────────────────────────
echo "Step 2/4: Rebuilding $CONTAINER..."
docker compose up -d --build "$CONTAINER"
echo ""

# ── 3. Wait for healthy ───────────────────────────────────────────────────────
echo "Step 3/4: Waiting for container to become healthy (max ${MAX_WAIT}s)..."
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' "paramant-relay-${CONTAINER}" 2>/dev/null || echo 'unknown')
  if [ "$STATUS" = 'healthy' ]; then
    echo "  Container healthy after ${WAITED}s"
    break
  fi
  if [ "$STATUS" = 'unhealthy' ]; then
    echo "  Container unhealthy after ${WAITED}s — deploy may have failed"
    echo "  Logs:"
    docker logs "paramant-relay-${CONTAINER}" 2>&1 | tail -20
    echo ""
    echo "Running smoke tests anyway to confirm impact..."
    break
  fi
  sleep 5
  WAITED=$((WAITED + 5))
  printf "  ...%ds\n" "$WAITED"
done
echo ""

# ── 4. Post-deploy smoke test ────────────────────────────────────────────────
echo "Step 4/4: Auth smoke tests..."
if "$ROOT/tests/auth-smoke.sh"; then
  echo ""
  echo "═══════════════════════════════════"
  echo "  Deploy verified ✓"
  echo "═══════════════════════════════════"
  exit 0
else
  echo ""
  echo "═══════════════════════════════════"
  echo "  Smoke tests FAILED after deploy."
  echo "  Check logs: docker logs paramant-relay-$CONTAINER"
  echo "  Rollback: git revert HEAD && ./deploy.sh $CONTAINER"
  echo "═══════════════════════════════════"
  exit 1
fi
