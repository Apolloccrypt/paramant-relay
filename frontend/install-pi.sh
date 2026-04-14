#!/usr/bin/env bash
# PARAMANT relay installer — Raspberry Pi edition
# Usage: curl -fsSL https://paramant.app/install-pi.sh | sudo bash
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
VERSION="v2.4.5"
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

  ${D}Post-Quantum Relay Installer ${VERSION} — Raspberry Pi Edition${E}
  ${D}ML-KEM-768 · Burn-on-read · Community Edition${E}

  ${Y}License: BUSL-1.1 — free for up to 5 API keys.${E}
  ${D}Commercial use with more keys: https://paramant.app/pricing${E}
"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Run as root or with sudo:"
  echo "  curl -fsSL https://paramant.app/install-pi.sh | sudo bash"
  exit 1
fi

# ── Architecture check ───────────────────────────────────────────────────────
step "Step 1/8 — Detecting system"

ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64)
    DOCKER_ARCH="arm64"
    ok "Architecture: arm64 (64-bit Pi OS)"
    ;;
  armv7l|armhf)
    err "32-bit Raspberry Pi OS detected (armhf)."
    err "PARAMANT relay requires 64-bit OS. Flash Raspberry Pi OS (64-bit) and retry."
    exit 1
    ;;
  x86_64)
    DOCKER_ARCH="amd64"
    warn "x86_64 detected — use the standard installer for non-Pi servers:"
    warn "  curl -fsSL https://paramant.app/install.sh | sudo bash"
    read -rp "  Continue anyway? [y/N] " C; [[ "${C,,}" == "y" ]] || exit 0
    ;;
  *)
    err "Unsupported architecture: ${ARCH}"
    exit 1
    ;;
esac

# OS detection — Pi OS is Debian-based
OS_ID=""
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION="${VERSION_ID:-}"
fi
ok "OS: ${OS_ID:-unknown} ${OS_VERSION:-}"

# ── System requirements ──────────────────────────────────────────────────────
step "Step 2/8 — Checking requirements"

TOTAL_RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
if (( TOTAL_RAM_MB < MIN_RAM_MB )); then
  err "Insufficient RAM: ${TOTAL_RAM_MB}MB (minimum ${MIN_RAM_MB}MB — Pi 3B+ or newer required)"
  exit 1
fi
ok "RAM: ${TOTAL_RAM_MB}MB"

AVAIL_DISK_GB=$(df / --output=avail -BG | tail -1 | tr -d 'G ')
if (( AVAIL_DISK_GB < MIN_DISK_GB )); then
  err "Insufficient disk: ${AVAIL_DISK_GB}GB free (minimum ${MIN_DISK_GB}GB)"
  exit 1
fi
ok "Disk: ${AVAIL_DISK_GB}GB available"

# SD card warning
if lsblk -d -o NAME,TRAN 2>/dev/null | grep -qE 'mmcblk.*'; then
  warn "Running from SD card — for production use an SSD via USB 3.0 for better I/O."
fi

# Disable swap — relay uses RAM-only storage
if swapon --show 2>/dev/null | grep -q .; then
  warn "Swap is active. Disabling (relay uses RAM-only storage)..."
  swapoff -a
  sed -i '/\sswap\s/d' /etc/fstab 2>/dev/null || true
  # Disable dphys-swapfile on Pi OS
  systemctl disable dphys-swapfile 2>/dev/null || true
  ok "Swap disabled"
else
  ok "Swap already disabled"
fi

for port in 80 443; do
  if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
    warn "Port ${port} already in use — make sure nginx can bind to it"
  fi
done
ok "Port check complete"

# ── Install dependencies ──────────────────────────────────────────────────────
step "Step 3/8 — Installing dependencies"

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl git openssl ca-certificates gnupg >/dev/null 2>&1
ok "Base packages installed"

# Docker — use official Docker install script (handles Pi OS arm64 correctly)
if command -v docker &>/dev/null; then
  DOCKER_VERSION=$(docker --version | grep -oP '[\d.]+' | head -1)
  ok "Docker already installed (${DOCKER_VERSION})"
else
  info "Installing Docker (arm64)..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
  chmod a+r /etc/apt/keyrings/docker.gpg
  CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-bookworm}")
  echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
  systemctl enable --now docker >/dev/null 2>&1
  ok "Docker installed (arm64)"
fi

# Certbot
if ! command -v certbot &>/dev/null; then
  info "Installing Certbot..."
  apt-get install -y -qq certbot >/dev/null 2>&1
  ok "Certbot installed"
else
  ok "Certbot already installed"
fi

# ── Interactive setup ─────────────────────────────────────────────────────────
step "Step 4/8 — Configuration"
echo ""

while true; do
  read -rp "  $(echo -e "${W}Domain name${E}") (e.g. relay.example.com): " DOMAIN
  DOMAIN="${DOMAIN// /}"
  [[ -n "$DOMAIN" ]] && break
  warn "Domain cannot be empty"
done

while true; do
  read -rp "  $(echo -e "${W}Email address${E}") (for SSL certificate): " LE_EMAIL
  [[ "$LE_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]] && break
  warn "Enter a valid email address"
done

echo ""
AUTO_TOKEN=$(openssl rand -hex 32)
read -rp "  $(echo -e "${W}Admin token${E}") [press Enter to auto-generate]: " ADMIN_TOKEN_INPUT
ADMIN_TOKEN="${ADMIN_TOKEN_INPUT:-$AUTO_TOKEN}"
[[ -z "$ADMIN_TOKEN_INPUT" ]] && info "Generated admin token"

echo ""
echo -e "  ${W}Sectors to enable${E} ${D}(space-separated, default: health legal finance iot)${E}"
read -rp "  Sectors [Enter for all]: " SECTORS_INPUT
SECTORS="${SECTORS_INPUT:-health legal finance iot}"

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

TOTP_SECRET=$(python3 -c "
import secrets, base64
raw = secrets.token_bytes(20)
print(base64.b32encode(raw).decode().rstrip('='))
" 2>/dev/null || openssl rand -base64 15 | tr -d '/+=' | tr '[:lower:]' '[:upper:]' | head -c 32)

cat > "${INSTALL_DIR}/.env" <<ENV
# Generated by PARAMANT installer $(date -u +%Y-%m-%dT%H:%M:%SZ)
ADMIN_TOKEN=${ADMIN_TOKEN}
RELAY_MODE=ghost_pipe
RAM_RESERVE_MB=128
RAM_LIMIT_MB=512
RESEND_API_KEY=
TOTP_SECRET=${TOTP_SECRET}
${LICENSE_KEY:+PARAMANT_LICENSE=${LICENSE_KEY}}
ENV

chmod 600 "${INSTALL_DIR}/.env"
ok ".env written (chmod 600)"

# ── TLS certificates via Let's Encrypt ───────────────────────────────────────
step "Step 7/8 — Obtaining TLS certificate"

mkdir -p "${INSTALL_DIR}/deploy/certs"

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

  cat > /etc/letsencrypt/renewal-hooks/deploy/paramant-reload.sh <<HOOK
#!/bin/bash
DOMAIN=\$(basename \$RENEWED_LINEAGE)
ln -sf "/etc/letsencrypt/live/\${DOMAIN}/fullchain.pem" "${INSTALL_DIR}/deploy/certs/cert.pem"
ln -sf "/etc/letsencrypt/live/\${DOMAIN}/privkey.pem"   "${INSTALL_DIR}/deploy/certs/key.pem"
docker compose -f "${INSTALL_DIR}/docker-compose.yml" exec nginx nginx -s reload 2>/dev/null || true
HOOK
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/paramant-reload.sh
  ok "Auto-renewal hook installed"
else
  warn "Could not obtain certificate for ${DOMAIN} — using self-signed cert"
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${INSTALL_DIR}/deploy/certs/key.pem" \
    -out "${INSTALL_DIR}/deploy/certs/cert.pem" \
    -subj "/CN=${DOMAIN}" 2>/dev/null
  warn "Replace with Let's Encrypt when DNS is ready: certbot certonly --standalone -d ${DOMAIN}"
fi

# ── Launch stack ──────────────────────────────────────────────────────────────
step "Step 8/8 — Launching relay stack"

cd "$INSTALL_DIR"

info "Pulling arm64 image from Docker Hub..."
docker pull mtty001/relay:latest --platform linux/arm64 2>&1 | tail -3 || true

info "Starting services..."
docker compose up -d --remove-orphans 2>&1 | tail -5

info "Waiting for relays to become healthy..."
MAX_WAIT=90
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

$HEALTHY && ok "Stack healthy" || warn "Healthcheck timed out — services may still be starting (Pi first boot is slow)"

# Install paramant CLI
cat > /usr/local/bin/paramant <<CLISCRIPT
#!/usr/bin/env bash
INSTALL_DIR="${INSTALL_DIR}"
ADMIN_TOKEN="\$(grep ADMIN_TOKEN \${INSTALL_DIR}/.env | cut -d= -f2)"
case "\${1:-help}" in
  status)
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" ps
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
    for port in 3000 3001 3002 3003 3004; do
      resp=\$(curl -s -X POST http://127.0.0.1:\$port/v2/reload-users \
        -H "X-Api-Key: \${ADMIN_TOKEN}" -H "Content-Type: application/json" -d '{}' 2>/dev/null || echo '{}')
      loaded=\$(echo "\$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('loaded','err'))" 2>/dev/null)
      echo "  :\$port  \$loaded keys loaded"
    done
    ;;
  upgrade)
    git -C "\${INSTALL_DIR}" pull --ff-only
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" pull
    docker compose -f "\${INSTALL_DIR}/docker-compose.yml" up -d --remove-orphans
    ;;
  stop)   docker compose -f "\${INSTALL_DIR}/docker-compose.yml" stop ;;
  start)  docker compose -f "\${INSTALL_DIR}/docker-compose.yml" up -d ;;
  restart) docker compose -f "\${INSTALL_DIR}/docker-compose.yml" restart "\${2:-}" ;;
  token)  echo "\${ADMIN_TOKEN}" ;;
  *)
    echo "Usage: paramant <status|logs [sector]|reload|upgrade|start|stop|restart|token>"
    ;;
esac
CLISCRIPT
chmod +x /usr/local/bin/paramant
ok "paramant CLI installed → /usr/local/bin/paramant"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${C}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
echo -e "${G}${BOLD}  PARAMANT installed successfully on Raspberry Pi!${E}"
echo -e "${C}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
echo ""
TOTP_URI="otpauth://totp/PARAMANT%20Admin?secret=${TOTP_SECRET}&issuer=PARAMANT&algorithm=SHA1&digits=6&period=30"
echo -e "  ${W}Relay URL:${E}    https://${DOMAIN}/health"
echo -e "  ${W}Admin token:${E}  ${ADMIN_TOKEN:0:8}...${ADMIN_TOKEN: -4}  (stored in ${INSTALL_DIR}/.env)"
echo -e "  ${W}Install dir:${E}  ${INSTALL_DIR}"
echo -e "  ${W}Edition:${E}      Community (up to 5 API keys)"
echo ""
echo -e "  ${Y}${BOLD}MFA (TOTP) instellen — vereist voor admin panel:${E}"
echo -e "  ${C}${TOTP_URI}${E}"
echo -e "  Scan bovenstaande URI in je Authenticator app (Google Authenticator, Aegis, etc.)"
echo -e "  ${D}Secret: ${TOTP_SECRET}  Algoritme: SHA1  Cijfers: 6  Periode: 30s${E}"
echo ""
echo -e "  ${C}paramant status${E}    — check health"
echo -e "  ${C}paramant logs${E}      — tail all logs"
echo -e "  ${C}paramant upgrade${E}   — update to latest version"
echo ""
echo -e "  ${D}Docs: https://github.com/Apolloccrypt/paramant-relay#self-hosting${E}"
echo ""
