#!/usr/bin/env bash
# paramant-update — check for relay updates and show upgrade path

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'

echo -e "\n${BOLD}Paramant Update Check${RESET}"
echo "──────────────────────────────────────"

# Current version
HEALTH=$(curl -sf --max-time 3 http://localhost:3000/health 2>/dev/null || echo "")
CURRENT=$(echo "$HEALTH" | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
echo -e "  Current version: ${GREEN}v${CURRENT}${RESET}"

# Latest GitHub release
echo -e "  ${CYAN}Checking latest release...${RESET}"
LATEST_JSON=$(curl -sf --max-time 5 \
  https://api.github.com/repos/Apolloccrypt/ParamantOS/releases/latest 2>/dev/null || echo "")

if [[ -n "$LATEST_JSON" ]]; then
  LATEST_TAG=$(echo "$LATEST_JSON" | jq -r '.tag_name // "?"' 2>/dev/null || echo "?")
  LATEST_URL=$(echo "$LATEST_JSON" | jq -r '.html_url // "?"' 2>/dev/null || echo "?")
  echo -e "  Latest release:  ${GREEN}${LATEST_TAG}${RESET}"
  echo -e "  Release URL:     ${LATEST_URL}"
else
  echo -e "  ${YELLOW}Could not reach GitHub API${RESET}"
fi

echo ""

# Is this a live ISO or disk install?
if grep -q 'tmpfs / tmpfs' /proc/mounts 2>/dev/null; then
  echo -e "${CYAN}Running from live ISO${RESET}"
  echo ""
  echo "To update: download the latest ISO and flash to USB:"
  echo ""
  echo "  1. Download: https://github.com/Apolloccrypt/ParamantOS/releases/latest"
  echo "  2. Flash: sudo dd if=ParamantOS.iso of=/dev/sdX bs=4M status=progress && sync"
  echo ""
  echo -e "${YELLOW}Note: Live ISO is RAM-only — no data persists across reboots.${RESET}"
  echo "      Back up keys first: paramant-backup  then  paramant-export"
else
  echo -e "${CYAN}Running from disk install${RESET}"
  echo ""
  echo "To update the relay on a disk-installed NixOS system:"
  echo ""
  echo "  1. Edit paramant-relay.nix with the new rev + hash"
  echo "  2. nixos-rebuild switch"
  echo ""
  echo "Or pull the latest ParamantOS flake:"
  echo "  nix flake update && nixos-rebuild switch"
fi

echo ""
