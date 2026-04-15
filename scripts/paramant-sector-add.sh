#!/usr/bin/env bash
# paramant-sector-add — add a new relay sector (systemd service + data dir)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║          paramant-sector-add                     ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}\n"

# ── Pre-defined sectors ────────────────────────────────────────────────────────
PRESET_NAMES=("health" "finance" "legal" "iot" "custom")
PRESET_PORTS=(3001      3002      3003   3004   0)

# ── Check existing sectors ─────────────────────────────────────────────────────
echo -e "  ${CYAN}Currently active relay services:${RESET}"
systemctl list-units 'paramant-relay*' --no-legend --state=active 2>/dev/null \
  | awk '{print "    " $1}' || echo "    (none)"
echo ""

# ── Sector selection ───────────────────────────────────────────────────────────
MENU_ITEMS=()
for i in "${!PRESET_NAMES[@]}"; do
  name="${PRESET_NAMES[$i]}"
  port="${PRESET_PORTS[$i]}"
  if systemctl is-active "paramant-relay-${name}" >/dev/null 2>&1; then
    MENU_ITEMS+=("$name" "port ${port} (already running)" "OFF")
  elif [[ "$name" == "custom" ]]; then
    MENU_ITEMS+=("$name" "custom name + port" "OFF")
  else
    MENU_ITEMS+=("$name" "port ${port}" "OFF")
  fi
done

CHOICE=$(whiptail --title "Add Sector" \
  --radiolist "Select sector to add:" 16 60 6 \
  "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3) || exit 0

if [[ -z "$CHOICE" ]]; then
  echo "Cancelled."
  exit 0
fi

# ── Determine name and port ────────────────────────────────────────────────────
if [[ "$CHOICE" == "custom" ]]; then
  SECTOR_NAME=$(whiptail --title "Custom Sector Name" \
    --inputbox "Enter sector name (lowercase, no spaces):" 10 60 "" 3>&1 1>&2 2>&3) || exit 0
  SECTOR_NAME=$(echo "$SECTOR_NAME" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')
  if [[ -z "$SECTOR_NAME" ]]; then
    echo -e "${RED}Empty name — aborted.${RESET}"
    exit 1
  fi
  SECTOR_PORT=$(whiptail --title "Custom Sector Port" \
    --inputbox "Enter port number (e.g. 3005):" 10 60 "3005" 3>&1 1>&2 2>&3) || exit 0
  if ! [[ "$SECTOR_PORT" =~ ^[0-9]+$ ]] || [[ "$SECTOR_PORT" -lt 1024 ]] || [[ "$SECTOR_PORT" -gt 65535 ]]; then
    echo -e "${RED}Invalid port — aborted.${RESET}"
    exit 1
  fi
else
  SECTOR_NAME="$CHOICE"
  for i in "${!PRESET_NAMES[@]}"; do
    if [[ "${PRESET_NAMES[$i]}" == "$CHOICE" ]]; then
      SECTOR_PORT="${PRESET_PORTS[$i]}"
      break
    fi
  done
fi

SERVICE_NAME="paramant-relay-${SECTOR_NAME}"
DATA_DIR="/var/lib/${SERVICE_NAME}"

echo ""
echo -e "  Sector: ${BOLD}${SECTOR_NAME}${RESET}"
echo -e "  Port:   ${BOLD}${SECTOR_PORT}${RESET}"
echo -e "  Unit:   ${BOLD}/etc/systemd/system/${SERVICE_NAME}.service${RESET}"
echo ""

if ! whiptail --title "Confirm" \
  --yesno "Create and start sector '${SECTOR_NAME}' on port ${SECTOR_PORT}?" 10 60; then
  echo "Cancelled."
  exit 0
fi

# ── Find relay binary from existing unit ──────────────────────────────────────
RELAY_BIN=$(systemctl cat paramant-relay 2>/dev/null \
  | awk -F= '/^ExecStart=/{print $2}' | head -1 \
  | awk '{print $1}')

if [[ -z "$RELAY_BIN" ]] || [[ ! -x "$RELAY_BIN" ]]; then
  # Fallback: search in nix store
  RELAY_BIN=$(find /nix/store -name "paramant-relay" -type f -executable 2>/dev/null | head -1 || true)
fi

if [[ -z "$RELAY_BIN" ]]; then
  echo -e "${RED}Cannot find relay binary. Is paramant-relay installed?${RESET}"
  exit 1
fi

echo -e "  ${CYAN}Relay binary: ${RELAY_BIN}${RESET}"

# ── Get existing unit environment ────────────────────────────────────────────
LICENSE_FILE="/etc/paramant/license"
ENV_FILE_LINE=""
if [[ -f "$LICENSE_FILE" ]]; then
  ENV_FILE_LINE="EnvironmentFile=-${LICENSE_FILE}"
fi

# ── Write unit file to /run/paramant-tmp then install ────────────────────────
# /run/paramant-tmp is created by systemd-tmpfiles (module.nix) with 0750 paramant:paramant
# Using /run instead of /tmp avoids the /tmp/* sudo wildcard privilege escalation risk.
mkdir -p /run/paramant-tmp
TMPUNIT=$(mktemp /run/paramant-tmp/paramant-sector-XXXXXX.service)
cat > "$TMPUNIT" << UNIT
[Unit]
Description=Paramant Ghost Pipe Relay — sector: ${SECTOR_NAME}
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${RELAY_BIN}
Restart=on-failure
RestartSec=5
User=paramant-relay
Group=paramant-relay
${ENV_FILE_LINE}
Environment="PORT=${SECTOR_PORT}"
Environment="SECTOR=${SECTOR_NAME}"
Environment="DATA_DIR=${DATA_DIR}"
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
PrivateTmp=true
PrivateDevices=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
UNIT

# Install unit, create data dir, enable + start
# H1/H2: use validated wrapper scripts instead of direct sudo systemctl/mkdir/chown/chmod
echo -e "  Creating data directory..."
sudo paramant-data-ctl mkdir "$DATA_DIR"
sudo paramant-data-ctl chown "$DATA_DIR"
sudo paramant-data-ctl chmod "$DATA_DIR"

echo -e "  Installing unit file..."
sudo install -m 644 -o root -g root "$TMPUNIT" "/etc/systemd/system/${SERVICE_NAME}.service"
rm -f "$TMPUNIT"

echo -e "  Reloading systemd..."
sudo paramant-relay-ctl daemon-reload

echo -e "  Enabling and starting ${SERVICE_NAME}..."
sudo paramant-relay-ctl enable "$SERVICE_NAME"
sudo paramant-relay-ctl start  "$SERVICE_NAME"

sleep 2

STATUS=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "unknown")
if [[ "$STATUS" == "active" ]]; then
  echo -e "\n  ${GREEN}✓${RESET}  ${SERVICE_NAME} is ${STATUS}"
  HEALTH=$(curl -sf --max-time 3 "http://localhost:${SECTOR_PORT}/health" 2>/dev/null || echo "")
  if [[ -n "$HEALTH" ]]; then
    echo -e "  ${GREEN}✓${RESET}  Health: ${HEALTH}"
  fi
else
  echo -e "\n  ${RED}✗${RESET}  Service is ${STATUS}"
  echo -e "  Check: ${YELLOW}journalctl -u ${SERVICE_NAME} -n 20${RESET}"
fi

echo ""
echo -e "  ${YELLOW}Note: add port ${SECTOR_PORT} to your firewall if accessing externally.${RESET}"
echo ""
