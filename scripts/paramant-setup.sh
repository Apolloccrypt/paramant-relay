#!/usr/bin/env bash
set -euo pipefail

SETUP_DONE_FILE="/etc/paramant/.setup-done"
LICENSE_FILE="/etc/paramant/license"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[•]${RESET} $*"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
heading() { echo -e "\n${BOLD}$*${RESET}"; }

# ── Skip unless interactive or forced ──────────────────────────────────────────
if [[ ! -t 0 ]] && [[ "${1:-}" != "--force" ]]; then
  exit 0
fi

# ── Skip if already done (first-boot auto-run only) ───────────────────────────
if [[ -f "$SETUP_DONE_FILE" ]] && [[ "${1:-}" != "--force" ]]; then
  exit 0
fi

clear
echo ""
echo -e "${GREEN}            *   *   *   *   *   *   *"
echo "         *                           *"
echo "       *                               *"
echo "      *                                 *"
echo "     *         P A R A M A N T           *"
echo "     *       Post-Quantum Ghost Pipe       *"
echo "     *         EU/DE  ·  BUSL-1.1         *"
echo "      *                                 *"
echo "       *                               *"
echo "         *                           *"
echo -e "            *   *   *   *   *   *   *${RESET}"
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗"
echo "║              ParamantOS Setup Wizard                 ║"
echo "║      Post-Quantum Ghost Pipe Relay — v2.4.5          ║"
echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "This wizard walks you through first-boot configuration."
echo "Press Ctrl-C at any time to skip the remaining steps."
echo ""

# ── Step 1: Change password ────────────────────────────────────────────────────
heading "Step 1/4 — Change your password"

# Detect if the default password is still active (M1: force password change)
_DEFAULT_HASH='$6$salt$8G8PuKNnYlxBriFm7BSgm6IKsTJLXpVSGGJRklJqpN8K2.2HJGt3L5sFCXCxGNsyPO.ysZgREq4ZaQJHH9Pq/'
_CURRENT_HASH=$(getent shadow paramant 2>/dev/null | cut -d: -f2)
_DEFAULT_ACTIVE=false
# Check if default password 'paramant123' still works by comparing shadow hash
if echo 'paramant123' | openssl passwd -6 -stdin 2>/dev/null | grep -q '^\$'; then
  # Use chpasswd dry-check: if the stored hash is not the locked/unusable marker, check
  if [[ "$_CURRENT_HASH" != '!' ]] && [[ "$_CURRENT_HASH" != '*' ]] && [[ "$_CURRENT_HASH" != '' ]]; then
    if python3 -c 'import crypt,sys; h=sys.argv[1]; sys.exit(0 if crypt.crypt("paramant123",h)==h else 1)' "$_CURRENT_HASH" 2>/dev/null; then
      _DEFAULT_ACTIVE=true
    fi
  fi
fi

if [[ "$_DEFAULT_ACTIVE" == "true" ]]; then
  warn "Default password 'paramant123' detected — you MUST change it now."
  echo ""
  until passwd paramant; do
    warn "Password change failed — try again."
  done
  ok "Password updated."
else
  echo "Password for 'paramant' is already customised."
  if whiptail --title "Change Password?" --yesno "Change the password for user 'paramant' now?" 10 60; then
    until passwd paramant; do
      warn "Password change failed — try again."
    done
    ok "Password updated."
  else
    info "Password unchanged."
  fi
fi

# ── Step 2: Set hostname ───────────────────────────────────────────────────────
heading "Step 2/4 — Hostname"
CURRENT_HOST=$(hostname)
NEW_HOST=$(whiptail --title "Set Hostname" \
  --inputbox "Enter hostname for this relay node:\n(current: $CURRENT_HOST)" \
  10 60 "$CURRENT_HOST" 3>&1 1>&2 2>&3) || true

if [[ -n "$NEW_HOST" ]] && [[ "$NEW_HOST" != "$CURRENT_HOST" ]]; then
  hostnamectl set-hostname "$NEW_HOST"
  ok "Hostname set to: $NEW_HOST"
else
  info "Hostname unchanged: $CURRENT_HOST"
fi

# ── Step 3: License key ────────────────────────────────────────────────────────
heading "Step 3/4 — License key"
echo "Community Edition supports up to 5 API keys."
echo "Add a license key (PLK_...) to unlock unlimited keys."
echo ""

CURRENT_KEY=""
if [[ -f "$LICENSE_FILE" ]]; then
  CURRENT_KEY=$(sed -n 's/^PLK_KEY=//p' "$LICENSE_FILE" 2>/dev/null | grep -m1 '^plk_' || true)
fi

if [[ -n "$CURRENT_KEY" ]]; then
  info "Current key: ${CURRENT_KEY:0:12}..."
  PROMPT="Update the license key? (leave blank to keep current)"
else
  PROMPT="Enter your license key (PLK_...) or leave blank for Community Edition:"
fi

PLK_KEY=$(whiptail --title "License Key" \
  --inputbox "$PROMPT" 10 70 "" 3>&1 1>&2 2>&3) || true

# ── Auto-generate ADMIN_TOKEN if not present ───────────────────────────────────
if [[ ! -f "$LICENSE_FILE" ]] || ! grep -q "ADMIN_TOKEN=" "$LICENSE_FILE" 2>/dev/null; then
  ADMIN_TOKEN=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 40)
  info "Generated ADMIN_TOKEN for admin panel access."
else
  ADMIN_TOKEN=$(sed -n 's/^ADMIN_TOKEN=//p' "$LICENSE_FILE" 2>/dev/null | head -1 || true)
fi

mkdir -p /etc/paramant
chmod 750 /etc/paramant

if [[ -n "$PLK_KEY" ]]; then
  if [[ "$PLK_KEY" == plk_* ]]; then
    printf 'PLK_KEY=%s\nADMIN_TOKEN=%s\n' "$PLK_KEY" "$ADMIN_TOKEN" > "$LICENSE_FILE"
    chmod 640 "$LICENSE_FILE"
    sudo paramant-relay-ctl restart paramant-relay 2>/dev/null || true
    sleep 2
    EDITION=$(curl -sf http://localhost:3000/health 2>/dev/null | jq -r '.edition // "unknown"' 2>/dev/null || echo "unknown")
    ok "License applied — edition: ${EDITION}"
  else
    warn "Key must start with 'plk_' — skipped."
    if [[ -n "$ADMIN_TOKEN" ]]; then
      printf 'ADMIN_TOKEN=%s\n' "$ADMIN_TOKEN" > "$LICENSE_FILE"
      [[ -n "$CURRENT_KEY" ]] && printf 'PLK_KEY=%s\n' "$CURRENT_KEY" >> "$LICENSE_FILE"
      chmod 640 "$LICENSE_FILE"
    fi
  fi
else
  # Write ADMIN_TOKEN even without PLK key
  if [[ -n "$ADMIN_TOKEN" ]]; then
    if [[ -n "$CURRENT_KEY" ]]; then
      printf 'PLK_KEY=%s\nADMIN_TOKEN=%s\n' "$CURRENT_KEY" "$ADMIN_TOKEN" > "$LICENSE_FILE"
    else
      printf 'ADMIN_TOKEN=%s\n' "$ADMIN_TOKEN" > "$LICENSE_FILE"
    fi
    chmod 640 "$LICENSE_FILE"
  fi
  info "No license key — running Community Edition (max 5 keys)."
fi

# ── Step 4: SSH public key ─────────────────────────────────────────────────────
heading "Step 4/4 — SSH public key"
echo "Paste your SSH public key to enable key-based login."
echo "(Password auth is disabled — you need this for remote access)"
echo ""

SSH_KEY=$(whiptail --title "SSH Public Key" \
  --inputbox "Paste your SSH public key (ssh-ed25519 / ssh-rsa ...):\n(leave blank to skip)" \
  12 80 "" 3>&1 1>&2 2>&3) || true

if [[ -n "$SSH_KEY" ]]; then
  # M2: validate SSH key format before appending (prevents garbage in authorized_keys)
  _KEY_TYPE=$(echo "$SSH_KEY" | awk '{print $1}')
  if [[ "$_KEY_TYPE" =~ ^(ssh-ed25519|ssh-rsa|ssh-ecdsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)$ ]]; then
    mkdir -p /home/paramant/.ssh
    chmod 700 /home/paramant/.ssh
    echo "$SSH_KEY" >> /home/paramant/.ssh/authorized_keys
    chmod 600 /home/paramant/.ssh/authorized_keys
    chown -R paramant:users /home/paramant/.ssh
    ok "SSH key added."
  else
    warn "Invalid SSH key format (expected ssh-ed25519/ssh-rsa/ecdsa-sha2-*) — key not added."
    warn "You can add it manually later: echo 'YOUR_KEY' >> /home/paramant/.ssh/authorized_keys"
  fi
else
  warn "No SSH key added — you can only access this node from the console."
fi

# ── Done ───────────────────────────────────────────────────────────────────────
mkdir -p /etc/paramant
touch "$SETUP_DONE_FILE"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║              Setup complete!                         ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "Relay status: systemctl status paramant-relay"
echo "Health check: curl -s http://localhost:3000/health"
echo "All commands: paramant-help"
if [[ -n "${ADMIN_TOKEN:-}" ]]; then
  echo "Admin token:  $(sed -n 's/^ADMIN_TOKEN=//p' "$LICENSE_FILE" 2>/dev/null | head -1 || echo "(see /etc/paramant/license)")"
fi
echo ""
