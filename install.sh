#!/usr/bin/env bash
# PARAMANT relay installer
# Usage: curl -fsSL https://get.paramant.app/install.sh | bash
# Docs:  https://github.com/Apolloccrypt/paramant-relay#self-hosting
# BUSL-1.1 — free for Community Edition (up to 5 API keys)
# Commercial license: https://paramant.app/pricing

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
C='\033[0;36m'; W='\033[1;37m'; D='\033[2m'; E='\033[0m'
BOLD='\033[1m'

ok()   { echo -e "${G}✓${E}  $*"; }
err()  { echo -e "${R}✗${E}  $*" >&2; }
warn() { echo -e "${Y}⚠${E}  $*"; }
info() { echo -e "${B}·${E}  $*"; }
step() { echo -e "\n${BOLD}${W}$*${E}"; }
dim()  { echo -e "${D}$*${E}"; }

INSTALL_DIR="${PARAMANT_DIR:-/opt/paramant}"
REPO="https://github.com/Apolloccrypt/paramant-relay"
VERSION="v2.2.0"
MIN_RAM_MB=512
MIN_DISK_GB=4

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "
${C}${BOLD}  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗ █████╗ ███╗  ██╗████████╗${E}
${C}${BOLD}  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔══██╗████╗ ██║╚══██╔══╝${E}
${C}${BOLD}  ██████╔╝███████║██████╔╝███████║██╔████╔██║███████║██╔██╗██║   ██║   ${E}
${C}${BOLD}  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║╚████║   ██║   ${E}
${C}${BOLD}  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██║ ╚███║   ██║   ${E}
${C}${BOLD}  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝   ${E}

  ${D}Post-Quantum Relay Installer ${VERSION}${E}
  ${D}ML-KEM-768 · Burn-on-read · Community Edition${E}

  ${Y}License: BUSL-1.1 — free for up to 5 API keys.${E}
  ${D}Commercial use with more keys: https://paramant.app/pricing${E}
"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Run as root or with sudo:"
  echo "  sudo bash install.sh"
  exit 1
fi

# ── OS detection ─────────────────────────────────────────────────────────────
step "Step 1/8 — Detecting system"

OS_ID=""
OS_VERSION=""
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION="${VERSION_ID:-}"
fi

case "$OS_ID" in
  ubuntu|debian|linuxmint|pop)
    PKG_MGR="apt-get"
    PKG_UPDATE="apt-get update -qq"
    PKG_INSTALL="apt-get install -y -qq"
    ok "Detected Debian-family OS: ${OS_ID} ${OS_VERSION}"
    ;;
  rhel|centos|rocky|almalinux|fedora)
    PKG_MGR="dnf"
    PKG_UPDATE="dnf check-update -q || true"
    PKG_INSTALL="dnf install -y -q"
    ok "Detected RHEL-family OS: ${OS_ID} ${OS_VERSION}"
    ;;
  *)
    warn "Unknown OS '${OS_ID}' — assuming Debian-compatible"
    PKG_MGR="apt-get"
    PKG_UPDATE="apt-get update -qq"
    PKG_INSTALL="apt-get install -y -qq"
    ;;
esac

# ── System requirements ──────────────────────────────────────────────────────
step "Step 2/8 — Checking requirements"

# RAM
TOTAL_RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
if (( TOTAL_RAM_MB < MIN_RAM_MB )); then
  err "Insufficient RAM: ${TOTAL_RAM_MB}MB (minimum ${MIN_RAM_MB}MB)"
  exit 1
fi
ok "RAM: ${TOTAL_RAM_MB}MB"

# Disk
AVAIL_DISK_GB=$(df / --output=avail -BG | tail -1 | tr -d 'G ')
if (( AVAIL_DISK_GB < MIN_DISK_GB )); then
  err "Insufficient disk: ${AVAIL_DISK_GB}GB free (minimum ${MIN_DISK_GB}GB)"
  exit 1
fi
ok "Disk: ${AVAIL_DISK_GB}GB available"

# Swap — relay uses RAM-only storage, swap can cause data leakage
if swapon --show 2>/dev/null | grep -q .; then
  warn "Swap is active. Disabling (relay uses RAM-only storage)..."
  swapoff -a
  # Persist across reboots
  sed -i '/\sswap\s/d' /etc/fstab 2>/dev/null || true
  ok "Swap disabled"
else
  ok "Swap already disabled"
fi

# Ports 80 + 443
for port in 80 443; do
  if ss -tlnp 2>/dev/null | grep -q ":${port} " ; then
    warn "Port ${port} already in use — make sure nginx can bind to it"
  fi
done
ok "Port check complete"

# ── Install dependencies ──────────────────────────────────────────────────────
step "Step 3/8 — Installing dependencies"

$PKG_UPDATE >/dev/null 2>&1
$PKG_INSTALL curl git openssl ca-certificates gnupg >/dev/null 2>&1
ok "Base packages installed"

# Docker
if command -v docker &>/dev/null; then
  DOCKER_VERSION=$(docker --version | grep -oP '[\d.]+' | head -1)
  ok "Docker already installed (${DOCKER_VERSION})"
else
  info "Installing Docker..."
  case "$PKG_MGR" in
    apt-get)
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/${OS_ID}/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
      chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/${OS_ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
      ;;
    dnf)
      dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo -q
      dnf install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
      ;;
  esac
  systemctl enable --now docker >/dev/null 2>&1
  ok "Docker installed"
fi

# Certbot
if ! command -v certbot &>/dev/null; then
  info "Installing Certbot..."
  $PKG_INSTALL certbot >/dev/null 2>&1
  ok "Certbot installed"
else
  ok "Certbot already installed"
fi

# ── Interactive setup ─────────────────────────────────────────────────────────
step "Step 4/8 — Configuration"
echo ""

# Domain
while true; do
  read -rp "  $(echo -e "${W}Domain name${E}") (e.g. relay.example.com): " DOMAIN
  DOMAIN="${DOMAIN// /}"
  [[ -n "$DOMAIN" ]] && break
  warn "Domain cannot be empty"
done

# Email for Let's Encrypt
while true; do
  read -rp "  $(echo -e "${W}Email address${E}") (for SSL certificate): " LE_EMAIL
  [[ "$LE_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]] && break
  warn "Enter a valid email address"
done

# Admin token
echo ""
AUTO_TOKEN=$(openssl rand -hex 32)
read -rp "  $(echo -e "${W}Admin token${E}") [press Enter to auto-generate]: " ADMIN_TOKEN_INPUT
if [[ -z "$ADMIN_TOKEN_INPUT" ]]; then
  ADMIN_TOKEN="$AUTO_TOKEN"
  info "Generated admin token"
else
  ADMIN_TOKEN="$ADMIN_TOKEN_INPUT"
fi

# Sectors
echo ""
echo -e "  ${W}Sectors to enable${E} ${D}(space-separated, default: health legal finance iot)${E}"
read -rp "  Sectors [Enter for all]: " SECTORS_INPUT
SECTORS="${SECTORS_INPUT:-health legal finance iot}"

# Optional: license key
echo ""
read -rp "  $(echo -e "${W}License key${E}") ${D}(plk_... for Pro, Enter to skip)${E}: " LICENSE_KEY

echo ""
ok "Configuration complete"
dim "  Domain:  ${DOMAIN}"
dim "  Email:   ${LE_EMAIL}"
dim "  Sectors: ${SECTORS}"
dim "  Token:   ${ADMIN_TOKEN:0:8}...${ADMIN_TOKEN: -4}"

echo ""
read -rp "  Proceed with installation? [Y/n] " CONFIRM
CONFIRM="${CONFIRM:-Y}"
[[ "${CONFIRM,,}" =~ ^y ]] || { info "Aborted."; exit 0; }

# ── Clone repository ──────────────────────────────────────────────────────────
step "Step 5/8 — Downloading PARAMANT relay"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  info "Existing install found at ${INSTALL_DIR} — pulling latest..."
  git -C "$INSTALL_DIR" pull --ff-only -q
  ok "Updated to latest"
else
  info "Cloning ${REPO}..."
  git clone --depth 1 --branch "${VERSION}" "$REPO" "$INSTALL_DIR" -q 2>/dev/null \
    || git clone --depth 1 "$REPO" "$INSTALL_DIR" -q
  ok "Cloned to ${INSTALL_DIR}"
fi

cd "$INSTALL_DIR"

# ── Write .env ────────────────────────────────────────────────────────────────
step "Step 6/8 — Writing configuration"

cat > "${INSTALL_DIR}/.env" <<ENV
# Generated by PARAMANT installer $(date -u +%Y-%m-%dT%H:%M:%SZ)
ADMIN_TOKEN=${ADMIN_TOKEN}
RELAY_MODE=ghost_pipe
RAM_RESERVE_MB=256
RAM_LIMIT_MB=1024
RESEND_API_KEY=
TOTP_SECRET=
${LICENSE_KEY:+PARAMANT_LICENSE=${LICENSE_KEY}}
ENV

chmod 600 "${INSTALL_DIR}/.env"
ok ".env written (chmod 600)"

# ── TLS certificates via Let's Encrypt ───────────────────────────────────────
step "Step 7/8 — Obtaining TLS certificate"

mkdir -p "${INSTALL_DIR}/deploy/certs"

# Stop anything on port 80 temporarily for standalone challenge
info "Obtaining certificate for ${DOMAIN}..."
certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --email "${LE_EMAIL}" \
  --domain "${DOMAIN}" \
  --pre-hook  "docker compose -f ${INSTALL_DIR}/docker-compose.yml stop nginx 2>/dev/null || true" \
  --post-hook "docker compose -f ${INSTALL_DIR}/docker-compose.yml start nginx 2>/dev/null || true" \
  2>&1 | grep -E 'Congratulations|error|Error|certificate' || true

CERT_PATH="/etc/letsencrypt/live/${DOMAIN}"
if [[ -f "${CERT_PATH}/fullchain.pem" ]]; then
  ln -sf "${CERT_PATH}/fullchain.pem" "${INSTALL_DIR}/deploy/certs/cert.pem"
  ln -sf "${CERT_PATH}/privkey.pem"   "${INSTALL_DIR}/deploy/certs/key.pem"
  ok "Certificate obtained and linked"

  # Auto-renewal hook
  cat > /etc/letsencrypt/renewal-hooks/deploy/paramant-reload.sh <<'HOOK'
#!/bin/bash
DOMAIN=$(basename $RENEWED_LINEAGE)
ln -sf "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" /opt/paramant/deploy/certs/cert.pem
ln -sf "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"   /opt/paramant/deploy/certs/key.pem
docker compose -f /opt/paramant/docker-compose.yml exec nginx nginx -s reload 2>/dev/null || true
HOOK
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/paramant-reload.sh
  ok "Auto-renewal hook installed"
else
  warn "Could not obtain certificate for ${DOMAIN}"
  warn "Make sure the domain points to this server's IP and port 80 is reachable"
  warn "Re-run after DNS is configured: certbot certonly --standalone -d ${DOMAIN}"
  info "Continuing with self-signed certificate for now..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${INSTALL_DIR}/deploy/certs/key.pem" \
    -out "${INSTALL_DIR}/deploy/certs/cert.pem" \
    -subj "/CN=${DOMAIN}" 2>/dev/null
  warn "Self-signed cert installed — replace with Let's Encrypt when DNS is ready"
fi

# ── Launch stack ──────────────────────────────────────────────────────────────
step "Step 8/8 — Launching relay stack"

cd "$INSTALL_DIR"

info "Building Docker images (first run may take ~2 minutes)..."
docker compose build --quiet 2>&1 | grep -v '^#' | tail -3 || true

info "Starting services..."
docker compose up -d --remove-orphans 2>&1 | tail -5

# Wait for health
info "Waiting for relays to become healthy..."
MAX_WAIT=60
WAITED=0
HEALTHY=false
while (( WAITED < MAX_WAIT )); do
  STATUS=$(docker compose ps --format json 2>/dev/null \
    | python3 -c "import sys,json; data=sys.stdin.read(); rows=[json.loads(l) for l in data.strip().splitlines() if l]; print(sum(1 for r in rows if r.get('Health','')=='healthy'))" 2>/dev/null || echo "0")
  if [[ "$STATUS" -ge 1 ]]; then
    HEALTHY=true
    break
  fi
  sleep 3
  (( WAITED+=3 ))
  printf "."
done
echo ""

if $HEALTHY; then
  ok "Stack healthy"
else
  warn "Healthcheck timed out — services may still be starting"
fi

# Final healthcheck
echo ""
HEALTH_RESP=$(curl -sk "https://${DOMAIN}/health" 2>/dev/null || curl -sk "http://127.0.0.1/health" 2>/dev/null || echo '{}')
HEALTH_OK=$(echo "$HEALTH_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ok','false'))" 2>/dev/null || echo "false")
HEALTH_VER=$(echo "$HEALTH_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version','?'))" 2>/dev/null || echo "?")
HEALTH_EDI=$(echo "$HEALTH_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('edition','?'))" 2>/dev/null || echo "?")

if [[ "$HEALTH_OK" == "True" || "$HEALTH_OK" == "true" ]]; then
  ok "Relay is live: version=${HEALTH_VER} edition=${HEALTH_EDI}"
else
  warn "Could not reach relay via HTTPS yet (DNS may need to propagate)"
fi

# ── Install paramant CLI ──────────────────────────────────────────────────────
cat > /usr/local/bin/paramant <<CLISCRIPT
#!/usr/bin/env bash
# PARAMANT relay management CLI
INSTALL_DIR="${INSTALL_DIR}"
ADMIN_TOKEN="\$(grep ADMIN_TOKEN \${INSTALL_DIR}/.env | cut -d= -f2)"

case "\${1:-help}" in
  status)
    echo "=== Relay status ==="
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" ps
    echo ""
    echo "=== Health ==="
    for port in 3005 3002 3003 3004; do
      resp=\$(curl -s http://127.0.0.1:\$port/health 2>/dev/null || echo '{}')
      ok=\$(echo "\$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ok','?'))" 2>/dev/null)
      ver=\$(echo "\$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version','?'))" 2>/dev/null)
      edi=\$(echo "\$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('edition','?'))" 2>/dev/null)
      sec=\$(echo "\$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sector','?'))" 2>/dev/null)
      echo "  :\$port  ok=\$ok  v\$ver  \$sec  [\$edi]"
    done
    ;;
  logs)
    SERVICE="\${2:-}"
    if [[ -n "\$SERVICE" ]]; then
      docker compose -f "\${INSTALL_DIR}/docker-compose.yml" logs -f "relay-\${SERVICE}"
    else
      docker compose -f "\${INSTALL_DIR}/docker-compose.yml" logs -f
    fi
    ;;
  reload)
    echo "Reloading API keys (zero downtime)..."
    for port in 3005 3002 3003 3004; do
      resp=\$(curl -s -X POST http://127.0.0.1:\$port/v2/reload-users \
        -H "X-Api-Key: \${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" -d '{}' 2>/dev/null || echo '{"error":"unreachable"}')
      loaded=\$(echo "\$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('loaded','err'))" 2>/dev/null)
      echo "  :\$port  \$loaded keys loaded"
    done
    ;;
  upgrade)
    echo "Pulling latest release..."
    git -C "\${INSTALL_DIR}" pull --ff-only
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" build --quiet
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" up -d --remove-orphans
    echo "Done. Run 'paramant status' to verify."
    ;;
  stop)
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" stop
    ;;
  start)
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" up -d
    ;;
  restart)
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" restart "\${2:-}"
    ;;
  token)
    echo "\${ADMIN_TOKEN}"
    ;;
  *)
    echo "PARAMANT relay CLI"
    echo ""
    echo "Usage: paramant <command> [args]"
    echo ""
    echo "Commands:"
    echo "  status           Show relay health and container status"
    echo "  logs [sector]    Tail logs (sector: health|legal|finance|iot)"
    echo "  reload           Reload API keys without downtime"
    echo "  upgrade          Pull latest release and restart"
    echo "  start            Start all services"
    echo "  stop             Stop all services"
    echo "  restart [svc]    Restart all or one service"
    echo "  token            Print admin token"
    ;;
esac
CLISCRIPT

chmod +x /usr/local/bin/paramant
ok "paramant CLI installed → /usr/local/bin/paramant"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${C}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
echo -e "${G}${BOLD}  PARAMANT installed successfully!${E}"
echo -e "${C}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
echo ""
echo -e "  ${W}Relay URL:${E}    https://${DOMAIN}/health"
echo -e "  ${W}Admin token:${E}  ${ADMIN_TOKEN:0:8}...${ADMIN_TOKEN: -4}  (stored in ${INSTALL_DIR}/.env)"
echo -e "  ${W}Install dir:${E}  ${INSTALL_DIR}"
echo -e "  ${W}Edition:${E}      Community (up to 5 API keys)"
echo ""
echo -e "  ${D}Manage your relay:${E}"
echo -e "  ${C}paramant status${E}       — check health"
echo -e "  ${C}paramant logs${E}         — tail all logs"
echo -e "  ${C}paramant reload${E}       — reload API keys (zero downtime)"
echo -e "  ${C}paramant upgrade${E}      — update to latest version"
echo ""
echo -e "  ${D}Add your first API key:${E}"
echo -e "  ${C}python3 ${INSTALL_DIR}/scripts/paramant-admin.py add --label myuser --plan pro${E}"
echo -e "  ${C}ADMIN_TOKEN=\$(paramant token) python3 ${INSTALL_DIR}/scripts/paramant-admin.py sync${E}"
echo ""
echo -e "  ${D}Docs:${E} https://github.com/Apolloccrypt/paramant-relay#self-hosting"
echo -e "  ${D}License: BUSL-1.1 — free for ≤5 API keys${E}"
echo ""
