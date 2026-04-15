#!/usr/bin/env bash
# paramant-info — system overview

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; DIM='\033[2m'; RESET='\033[0m'

pager() {
  local buf; buf=$(cat)
  local lines; lines=$(echo "$buf" | wc -l)
  local height; height=$(tput lines 2>/dev/null || echo 24)
  if [ -t 1 ] && [ "$lines" -gt "$((height - 2))" ]; then
    echo "$buf" | less -R
  else
    echo "$buf"
  fi
}

{
echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║              ParamantOS System Info              ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}\n"

# Relay
HEALTH=$(curl -sf --max-time 2 http://localhost:3000/health 2>/dev/null || echo "")
VERSION=$(echo "$HEALTH" | jq -r '.version // "?"' 2>/dev/null || echo "?")
EDITION=$(echo "$HEALTH" | jq -r '.edition // "?"' 2>/dev/null || echo "?")

echo -e "  ${CYAN}Relay${RESET}"
echo -e "    Version:    v${VERSION}"
echo -e "    Edition:    ${EDITION}"
echo -e "    Service:    $(systemctl is-active paramant-relay 2>/dev/null || echo unknown)"
echo ""

# System
echo -e "  ${CYAN}System${RESET}"
echo -e "    Hostname:   $(hostname)"
echo -e "    OS:         $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo NixOS)"
echo -e "    Kernel:     $(uname -r)"
echo -e "    Uptime:     $(uptime -p 2>/dev/null || uptime)"
echo ""

# Hardware
echo -e "  ${CYAN}Hardware${RESET}"
CPU=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "?")
echo -e "    CPU:        ${CPU}"
echo -e "    RAM:        $(free -h 2>/dev/null | awk '/^Mem/{print $2 " total, " $7 " available"}')"
echo -e "    Disk:       $(df -h / 2>/dev/null | awk 'NR==2{print $2 " total, " $4 " free"}')"
echo ""

# Network
IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet )[0-9.]+' | head -1 || echo "none")
echo -e "  ${CYAN}Network${RESET}"
echo -e "    IP:         ${IP}"
echo -e "    NM:         $(systemctl is-active NetworkManager 2>/dev/null)"
echo ""

echo -e "  ${DIM}paramant-help for all commands${RESET}\n"
} | pager
