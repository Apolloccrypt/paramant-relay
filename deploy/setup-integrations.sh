#!/usr/bin/env bash
# setup-integrations.sh — run once before docker compose up with integrations
# Usage: bash deploy/setup-integrations.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env"
TOKEN_FILE="$SCRIPT_DIR/prometheus-token"

# ── Load .env ─────────────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: .env not found at $ENV_FILE"
  echo "       Run: cp deploy/.env.example .env && nano .env"
  exit 1
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

# ── Check required vars ───────────────────────────────────────────────────────
missing=()
[[ -z "${ADMIN_TOKEN:-}" ]]    && missing+=("ADMIN_TOKEN")
[[ -z "${N8N_PASSWORD:-}" ]]   && missing+=("N8N_PASSWORD")
[[ -z "${GRAFANA_PASSWORD:-}" ]] && missing+=("GRAFANA_PASSWORD")

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "ERROR: Missing required .env vars: ${missing[*]}"
  echo "       Edit .env and set these values."
  exit 1
fi

# ── Write Prometheus bearer token ─────────────────────────────────────────────
printf '%s' "$ADMIN_TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
echo "✓ prometheus-token written to $TOKEN_FILE"

# ── Register n8n webhook with relay (after relay is up) ───────────────────────
register_webhook() {
  local sector="$1"
  local port="$2"
  local relay_url="http://127.0.0.1:${port}"

  echo -n "  Registering n8n webhook on $sector relay... "

  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${relay_url}/v2/webhook" \
    -H "X-Api-Key: ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"http://n8n:5678/webhook/paramant-burn\",\"secret\":\"${N8N_PASSWORD}\"}" \
    --connect-timeout 3 2>/dev/null || echo "000")

  if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
    echo "done (HTTP $http_code)"
  elif [[ "$http_code" == "000" ]]; then
    echo "skipped (relay not running yet — run this script again after 'docker compose up -d')"
  else
    echo "HTTP $http_code (may already be registered)"
  fi
}

echo ""
echo "Registering n8n burn-webhook on all relay sectors..."
register_webhook "health"  "3005"
register_webhook "legal"   "3002"
register_webhook "finance" "3003"
register_webhook "iot"     "3004"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Setup complete. Start the full stack:"
echo ""
echo "    docker compose -f docker-compose.yml \\"
echo "                   -f docker-compose.integrations.yml up -d"
echo ""
echo "  Access:"
echo "    Grafana  → https://\${DOMAIN}/grafana/  (admin / \$GRAFANA_PASSWORD)"
echo "    n8n      → ssh -L 5678:127.0.0.1:5678 root@<server>  →  http://localhost:5678"
echo "    Prometheus→ ssh -L 9090:127.0.0.1:9090 root@<server>  →  http://localhost:9090"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
