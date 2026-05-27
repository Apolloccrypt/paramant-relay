#!/bin/bash
# Emergency rollback for the paramant 3.0.0 deploy.
# Run ONLY after a failed deploy + a CRITICAL FAIL signal from
# scripts/post-deploy-verify.sh. Mick runs this manually (with sudo if the
# docker socket needs it).
#
# MODEL: relays are built from source (docker-compose `build: ./relay`); there
# is no registry image to re-pull. So rollback restores the PREVIOUS LOCALLY
# BUILT images that the pre-deploy backup step tagged, then recreates the
# containers from those images WITHOUT rebuilding. It does NOT touch git.
#
# It relies on a manifest written by the backup step (see RUNBOOK Step 1):
#   /home/paramant/backups/rollback-images-latest.txt
# with lines:  <service>|<compose-image-name>|<rollback-tag>
#
# Env overrides:
#   COMPOSE_DIR   directory containing docker-compose.yml (default /home/paramant/app)
#   MANIFEST      explicit manifest path (default: newest rollback-images-*.txt)
#   BACKUP_DIR    where backups/manifests live (default /home/paramant/backups)

set -uo pipefail

COMPOSE_DIR="${COMPOSE_DIR:-/home/paramant/app}"
BACKUP_DIR="${BACKUP_DIR:-/home/paramant/backups}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:3000/health}"

echo "PARAMANT 3.0.0 ROLLBACK"
echo "======================="
echo "Compose dir: $COMPOSE_DIR"
echo ""
echo "This restores the previously-built relay/admin images (last good deploy)"
echo "and recreates the containers. It does NOT revert git or rebuild."
echo ""
read -r -p "Confirm rollback (yes/no): " confirm
[ "$confirm" = "yes" ] || { echo "Aborted."; exit 1; }

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found."
  exit 1
fi

cd "$COMPOSE_DIR" 2>/dev/null || { echo "ERROR: cannot cd to $COMPOSE_DIR"; exit 1; }
if [ ! -f docker-compose.yml ] && [ ! -f compose.yml ]; then
  echo "ERROR: no docker-compose.yml in $COMPOSE_DIR"
  exit 1
fi

# Locate the manifest produced by the backup step.
MANIFEST="${MANIFEST:-}"
if [ -z "$MANIFEST" ]; then
  if [ -f "$BACKUP_DIR/rollback-images-latest.txt" ]; then
    MANIFEST="$BACKUP_DIR/rollback-images-latest.txt"
  else
    MANIFEST=$(ls -t "$BACKUP_DIR"/rollback-images-*.txt 2>/dev/null | head -1)
  fi
fi

if [ -z "$MANIFEST" ] || [ ! -f "$MANIFEST" ]; then
  echo "ERROR: no rollback manifest found in $BACKUP_DIR."
  echo "The pre-deploy backup step (RUNBOOK Step 1) did not run, or backups are gone."
  echo "Manual rollback:"
  echo "  docker images | grep paramant-rollback     # find a saved tag"
  echo "  docker tag paramant-rollback/relay-main:<TS> <compose-image-name>"
  echo "  docker compose up -d --no-deps --force-recreate relay-main"
  exit 1
fi

echo "Using manifest: $MANIFEST"
echo ""

SERVICES=""
RESTORED=0
MISSING=0
while IFS='|' read -r svc image rbtag; do
  [ -z "${svc:-}" ] && continue
  case "$svc" in \#*) continue;; esac
  if ! docker image inspect "$rbtag" >/dev/null 2>&1; then
    echo "  WARN: rollback image missing for $svc ($rbtag) - skipping"
    MISSING=$((MISSING+1))
    continue
  fi
  echo "  restoring $svc: $rbtag -> $image"
  docker tag "$rbtag" "$image"
  SERVICES="$SERVICES $svc"
  RESTORED=$((RESTORED+1))
done < "$MANIFEST"

if [ "$RESTORED" -eq 0 ]; then
  echo "ERROR: no rollback images could be restored. Aborting."
  exit 1
fi

echo ""
echo "Recreating services (no rebuild):$SERVICES"
# --force-recreate picks up the retagged image; NO --build so source is ignored.
# shellcheck disable=SC2086
docker compose up -d --no-deps --force-recreate $SERVICES

echo ""
echo "Waiting for relay health at $HEALTH_URL ..."
HEALTHY=no
for _ in $(seq 1 30); do
  if curl -fs --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
    echo "  relay healthy after rollback"
    HEALTHY=yes
    break
  fi
  sleep 2
done
[ "$HEALTHY" = "yes" ] || echo "  WARN: relay not healthy after 60s - check 'docker compose logs relay-main'"

# Optional .env restore.
LATEST_ENV=$(ls -t "$BACKUP_DIR"/.env-pre-* 2>/dev/null | head -1)
if [ -n "${LATEST_ENV:-}" ]; then
  echo ""
  read -r -p "Restore .env from $LATEST_ENV ? (yes/no): " restore_env
  if [ "$restore_env" = "yes" ]; then
    cp "$LATEST_ENV" "$COMPOSE_DIR/.env"
    echo "  .env restored; recreating relay-main to apply"
    docker compose up -d --no-deps --force-recreate relay-main
  fi
fi

echo ""
echo "Rollback complete: restored=$RESTORED missing=$MISSING"
echo "Re-run: scripts/post-deploy-verify.sh https://paramant.app"
[ "$MISSING" -eq 0 ] && [ "$HEALTHY" = "yes" ] && exit 0 || exit 1
