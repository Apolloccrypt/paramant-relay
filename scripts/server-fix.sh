#!/usr/bin/env bash
# scripts/server-fix.sh — run this on the server to fix all current issues:
#   1. git pull latest code
#   2. Deploy frontend files
#   3. Fix nginx port mapping
#   4. Restart relay containers (picks up MAX_KEYS=50 from .env)
#
# Usage (as paramant user or with sudo):
#   cd /home/paramant/paramant-master && bash scripts/server-fix.sh

set -euo pipefail
REPO=/home/paramant/paramant-master
APP=/home/paramant/app

echo "=== 1. git pull ==="
cd "$REPO"
git stash 2>/dev/null || true
git pull --ff-only

echo ""
echo "=== 2. Deploy frontend ==="
rsync -a --delete "$REPO/frontend/" "$APP/"
echo "Frontend synced to $APP"

echo ""
echo "=== 3. Fix nginx ports ==="
sudo python3 "$REPO/scripts/fix-nginx-ports.py"

echo ""
echo "=== 4. Ensure MAX_KEYS in .env ==="
if ! grep -q "^MAX_KEYS=" "$REPO/.env" 2>/dev/null; then
    echo "MAX_KEYS=50" >> "$REPO/.env"
    echo "Added MAX_KEYS=50 to .env"
else
    echo "MAX_KEYS already set: $(grep '^MAX_KEYS=' $REPO/.env)"
fi

echo ""
echo "=== 5. Restart relay containers ==="
cd "$REPO"
docker compose up -d --build --remove-orphans

echo ""
echo "=== 6. Health check (wait 8s for containers) ==="
sleep 8
for port in 3000 3001 3002 3003 3004; do
    result=$(curl -sf http://127.0.0.1:$port/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sector'])" 2>/dev/null || echo "FAIL")
    echo "  port $port → $result"
done

echo ""
echo "=== 7. Verify domain routing ==="
for domain in relay health finance legal iot; do
    result=$(curl -s https://$domain.paramant.app/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sector'])" 2>/dev/null || echo "FAIL/502")
    echo "  $domain.paramant.app → $result"
done

echo ""
echo "=== Done. ==="
