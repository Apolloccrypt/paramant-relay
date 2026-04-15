#!/usr/bin/env bash
# paramant-wifi — interactive WiFi manager

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; RESET='\033[0m'

# Check NetworkManager
if ! systemctl is-active NetworkManager >/dev/null 2>&1; then
  echo -e "${RED}NetworkManager is not running.${RESET}"
  echo "Start: sudo systemctl start NetworkManager"
  exit 1
fi

echo -e "\n${BOLD}WiFi Manager${RESET}"
echo "──────────────────────────────────────"

ACTION=$(whiptail --title "WiFi" \
  --menu "Select action:" 14 60 5 \
  "scan"       "Scan for networks" \
  "connect"    "Connect to a network" \
  "status"     "Show connection status" \
  "disconnect" "Disconnect current WiFi" \
  "list"       "List saved connections" \
  3>&1 1>&2 2>&3) || exit 0

case "$ACTION" in
  scan)
    echo -e "  ${GREEN}Scanning (max 8s)...${RESET}"
    # --rescan yes can hang; cap it with timeout
    timeout 8 nmcli dev wifi list --rescan yes 2>/dev/null \
      || nmcli dev wifi list 2>/dev/null \
      || echo -e "${YELLOW}No networks found.${RESET}"
    ;;

  connect)
    echo -e "  ${GREEN}Scanning for networks (max 8s)...${RESET}"
    timeout 8 nmcli dev wifi list --rescan yes >/dev/null 2>&1 || true

    # Build list of visible SSIDs
    NETWORKS=$(nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list 2>/dev/null \
      | grep -v '^:' | sort -t: -k2 -rn | head -20 || echo "")

    if [[ -z "$NETWORKS" ]]; then
      echo -e "${YELLOW}No networks found. Move closer to an access point and try again.${RESET}"
      exit 0
    fi

    MENU_ITEMS=()
    while IFS=: read -r ssid signal security; do
      [[ -z "$ssid" ]] && continue
      MENU_ITEMS+=("$ssid" "${signal}% ${security}")
    done <<< "$NETWORKS"

    SSID=$(whiptail --title "Select Network" \
      --menu "Available networks:" 20 60 12 \
      "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3) || exit 0

    # Check if open or secured
    SECURITY=$(nmcli -t -f SSID,SECURITY dev wifi list 2>/dev/null \
      | grep "^${SSID}:" | head -1 | cut -d: -f2 || echo "")

    if [[ -z "$SECURITY" ]] || [[ "$SECURITY" == "--" ]]; then
      echo -e "  ${YELLOW}Open network — connecting...${RESET}"
      timeout 20 nmcli dev wifi connect "$SSID" \
        && echo -e "${GREEN}[+] Connected to ${SSID}${RESET}" \
        || echo -e "${RED}[!] Connection failed${RESET}"
    else
      PASS=$(whiptail --title "WiFi Password" \
        --passwordbox "Password for '${SSID}':" 10 60 "" 3>&1 1>&2 2>&3) || exit 0
      echo -e "  ${YELLOW}Connecting...${RESET}"
      timeout 20 nmcli dev wifi connect "$SSID" password "$PASS" \
        && echo -e "${GREEN}[+] Connected to ${SSID}${RESET}" \
        || echo -e "${RED}[!] Connection failed — check password${RESET}"
    fi
    ;;

  status)
    echo ""
    nmcli dev status 2>/dev/null
    echo ""
    nmcli con show --active 2>/dev/null | head -10
    ;;

  disconnect)
    ACTIVE=$(nmcli -t -f NAME,TYPE con show --active 2>/dev/null \
      | grep ':wifi' | head -1 | cut -d: -f1 || echo "")
    if [[ -z "$ACTIVE" ]]; then
      echo "No active WiFi connection."
    else
      nmcli con down "$ACTIVE" \
        && echo -e "${GREEN}[+] Disconnected from ${ACTIVE}${RESET}" \
        || echo -e "${RED}[!] Disconnect failed${RESET}"
    fi
    ;;

  list)
    echo ""
    nmcli con show 2>/dev/null
    ;;
esac

echo ""
