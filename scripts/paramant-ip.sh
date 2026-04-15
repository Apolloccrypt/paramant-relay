#!/usr/bin/env bash
# paramant-ip — show IP addresses, interfaces, and relay accessibility

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'

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
echo -e "\n${BOLD}Network Addresses${RESET}"
echo "──────────────────────────────────────"

# All interfaces
ip -4 addr show 2>/dev/null | awk '
/^[0-9]+:/ { iface=$2; gsub(/:$/,"",iface) }
/inet /     { print "  " iface "\t" $2 }
' | grep -v '127\.0\.0\.1' | column -t

echo ""

# Default gateway
GW=$(ip route 2>/dev/null | awk '/default/{print $3}' | head -1 || echo "none")
echo -e "  Gateway:  ${GW}"

# DNS
DNS=$(grep -oP '(?<=nameserver )\S+' /etc/resolv.conf 2>/dev/null | head -2 | tr '\n' ' ' || echo "unknown")
echo -e "  DNS:      ${DNS}"

echo ""

# Relay accessibility
for port in 3000 3001 3002 3003 3004; do
  R=$(curl -sf --max-time 1 "http://localhost:${port}/health" 2>/dev/null | \
      jq -r '"v" + (.version // "?") + "  " + (.sector // "?")' 2>/dev/null || echo "")
  if [[ -n "$R" ]]; then
    echo -e "  :${port}  ${GREEN}●${RESET}  ${R}"
  else
    echo -e "  :${port}  ${YELLOW}○${RESET}  (not responding)"
  fi
done

echo ""

# Public IP (best-effort)
PUBLIC=$(curl -sf --max-time 3 https://ifconfig.me 2>/dev/null || curl -sf --max-time 3 https://api.ipify.org 2>/dev/null || echo "")
[[ -n "$PUBLIC" ]] && echo -e "  Public IP: ${PUBLIC}\n"
} | pager
