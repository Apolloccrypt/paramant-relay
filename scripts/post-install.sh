#!/bin/bash
# PARAMANT post-install verification
# Run after: docker compose up -d
# Usage: bash scripts/post-install.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓  ${*}${NC}"; }
warn() { echo -e "${YELLOW}⚠  ${*}${NC}"; }
err()  { echo -e "${RED}✗  ${*}${NC}"; }
info() { echo -e "${CYAN}   ${*}${NC}"; }

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   PARAMANT Post-Install Verification  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# ── Load .env ─────────────────────────────────────────────────────────────────
[ -f .env ] && export $(grep -v '^#' .env | grep -v '^$' | xargs) 2>/dev/null

# ── Check docker compose is running ───────────────────────────────────────────
if ! docker compose ps --services 2>/dev/null | grep -q .; then
    err "No docker compose stack found in this directory."
    echo "   Run: docker compose up -d"
    exit 1
fi

# ── Get actual ports from running containers (not from .env) ──────────────────
HTTP_PORT_LIVE=$(docker compose port nginx 80 2>/dev/null | cut -d: -f2)
HTTPS_PORT_LIVE=$(docker compose port nginx 443 2>/dev/null | cut -d: -f2)

if [ -z "$HTTP_PORT_LIVE" ] || [ -z "$HTTPS_PORT_LIVE" ]; then
    err "nginx container is not running or ports are not mapped."
    echo ""
    docker compose ps
    exit 1
fi

# Detect port mismatch between .env and running containers
ENV_HTTP=${HTTP_PORT:-80}
ENV_HTTPS=${HTTPS_PORT:-443}
if [ "$HTTP_PORT_LIVE" != "$ENV_HTTP" ] || [ "$HTTPS_PORT_LIVE" != "$ENV_HTTPS" ]; then
    warn "Port mismatch: .env says ${ENV_HTTP}/${ENV_HTTPS} but containers run on ${HTTP_PORT_LIVE}/${HTTPS_PORT_LIVE}"
    info "Fixing .env to match running containers..."
    sed -i '/^HTTP_PORT=/d' .env 2>/dev/null; echo "HTTP_PORT=${HTTP_PORT_LIVE}" >> .env
    sed -i '/^HTTPS_PORT=/d' .env 2>/dev/null; echo "HTTPS_PORT=${HTTPS_PORT_LIVE}" >> .env
    ok ".env updated: HTTP_PORT=${HTTP_PORT_LIVE} HTTPS_PORT=${HTTPS_PORT_LIVE}"
fi

BASE_URL="https://localhost:${HTTPS_PORT_LIVE}"
echo -e "   Using: ${CYAN}${BASE_URL}${NC}"
echo ""

# ── Wait for healthy containers ───────────────────────────────────────────────
echo "Waiting for containers..."
MAX_WAIT=30
WAITED=0
while true; do
    ALL_UP=true
    for svc in relay-health relay-legal relay-finance relay-iot nginx; do
        state=$(docker compose ps --format '{{.State}}' "$svc" 2>/dev/null | head -1)
        [ "$state" != "running" ] && ALL_UP=false && break
    done
    $ALL_UP && break
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        warn "Some containers not running after ${MAX_WAIT}s:"
        docker compose ps
        echo ""
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    echo -ne "   ${WAITED}s...\r"
done
ok "All containers running"
echo ""

# ── Test all 4 sectors ────────────────────────────────────────────────────────
echo "Testing sectors..."
SECTORS=(health legal finance iot)
ALL_OK=true

for sector in "${SECTORS[@]}"; do
    result=$(curl -sk --max-time 5 \
        -H "Host: ${sector}.localhost" \
        "${BASE_URL}/health" 2>/dev/null)
    sector_val=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sector','?'))" 2>/dev/null)
    version=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version','?'))" 2>/dev/null)
    edition=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('edition','?'))" 2>/dev/null)
    if [ "$sector_val" = "$sector" ] || [ -n "$version" ]; then
        ok "${sector:<8} v${version}  edition=${edition}"
    else
        err "${sector}: no response or wrong sector (got: ${sector_val:-empty})"
        ALL_OK=false
    fi
done
echo ""

if ! $ALL_OK; then
    warn "Some sectors failed. Check logs: docker compose logs nginx"
    echo ""
fi

# ── Show access URL ───────────────────────────────────────────────────────────
echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Your relay is live                   ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""
info "HTTPS (sector via Host header):"
echo "   https://localhost:${HTTPS_PORT_LIVE}    ← default (health sector)"
echo "   Use Host: health.localhost for health sector"
echo "   Use Host: legal.localhost  for legal sector"
echo "   Use Host: finance.localhost for finance sector"
echo "   Use Host: iot.localhost    for IoT sector"
echo ""
info "HTTP redirect:"
echo "   http://localhost:${HTTP_PORT_LIVE} → redirects to HTTPS"
echo ""

# ── ADMIN_TOKEN status ────────────────────────────────────────────────────────
if [ -n "$ADMIN_TOKEN" ]; then
    ok "ADMIN_TOKEN is set"
    echo ""
else
    warn "ADMIN_TOKEN not found in .env"
    info "Generate one: openssl rand -hex 32 >> .env # add ADMIN_TOKEN=<value>"
    echo ""
fi

# ── First API key creation instructions ──────────────────────────────────────
echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Next step: create your first API key ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""
info "Using the admin CLI:"
echo "   export ADMIN_TOKEN=${ADMIN_TOKEN:-<your-token>}"
echo "   export RELAY_BASE_URL=https://localhost:${HTTPS_PORT_LIVE}"
echo ""
echo "   python3 scripts/paramant-admin.py add-key \\"
echo "       --sector health \\"
echo "       --label 'my-first-device' \\"
echo "       --plan pro"
echo ""
info "Or directly via the API:"
echo "   curl -sk -X POST ${BASE_URL}/v2/keys \\"
echo "       -H 'X-Admin-Token: \${ADMIN_TOKEN}' \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"label\":\"my-device\",\"plan\":\"pro\"}'"
echo ""
info "Docs: https://github.com/Apolloccrypt/paramant-relay/blob/main/docs/self-hosting.md"
echo ""
