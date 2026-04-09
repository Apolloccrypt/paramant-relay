#!/usr/bin/env bash
# scripts/deploy.sh — deploy frontend + relay stack to production server
#
# Usage (run from repo root on LOCAL machine):
#   ./scripts/deploy.sh [user@]host
#
# What it does:
#   1. git pull on server (stashes local changes if needed)
#   2. Copies frontend/ to /home/paramant/app/ (excluding dev files)
#   3. Copies frontend/pkg/ (WASM + JS glue) to /home/paramant/app/pkg/
#   4. Rebuilds Docker images and restarts services
#
# Secrets stay on server only (.env, users.json, ct-log.json).
# WASM binaries are committed to git (no secrets) and deployed via this script.

set -euo pipefail

HOST="${1:-paramant@paramant.app}"
REMOTE_REPO="/home/paramant/paramant-master"   # git repo on server
REMOTE_APP="/home/paramant/app"                 # nginx root

echo "==> Deploying to ${HOST}"

ssh "${HOST}" bash -s <<'REMOTE'
set -euo pipefail
cd /home/paramant/paramant-master

echo "--- git pull"
# Stash any local edits (e.g. debug leftovers) before pulling
git stash --quiet 2>/dev/null || true
git pull --ff-only

echo "--- sync frontend to app dir"
rsync -av --delete \
  --exclude='*.md' \
  --exclude='.git' \
  --exclude='node_modules' \
  frontend/ /home/paramant/app/

echo "--- reload nginx (config unchanged, just content)"
sudo nginx -t && sudo systemctl reload nginx

echo "--- rebuild + restart Docker relay stack"
cd /home/paramant/paramant-master
docker compose pull 2>/dev/null || true
docker compose up -d --build --remove-orphans

echo "--- health check"
sleep 5
docker compose ps
curl -sf http://127.0.0.1:3000/health  && echo "relay-main OK"   || echo "relay-main FAIL"
curl -sf http://127.0.0.1:3001/health  && echo "relay-health OK" || echo "relay-health FAIL"
curl -sf http://127.0.0.1:3002/health  && echo "relay-finance OK"|| echo "relay-finance FAIL"
curl -sf http://127.0.0.1:3003/health  && echo "relay-legal OK"  || echo "relay-legal FAIL"
curl -sf http://127.0.0.1:3004/health  && echo "relay-iot OK"    || echo "relay-iot FAIL"

echo "--- deploy complete"
REMOTE

echo "==> Done."
