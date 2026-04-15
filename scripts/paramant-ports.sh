#!/usr/bin/env bash
# paramant-ports — show firewall rules and listening ports

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
echo -e "\n${BOLD}Ports & Firewall${RESET}"
echo "──────────────────────────────────────"

echo -e "\n${CYAN}Listening ports:${RESET}"
ss -tlnp 2>/dev/null | awk 'NR==1 || /LISTEN/' | head -30 || \
  netstat -tlnp 2>/dev/null | grep LISTEN | head -30

echo -e "\n${CYAN}Firewall allowed TCP ports (nftables):${RESET}"
nft list ruleset 2>/dev/null | grep -A1 'tcp dport' | grep -v '^--$' || \
  echo "  (could not read nftables rules)"

echo -e "\n${CYAN}Expected relay ports:${RESET}"
for port in 22 3000 3001 3002 3003 3004; do
  LABEL=""
  case $port in
    22)   LABEL="SSH" ;;
    3000) LABEL="relay-main" ;;
    3001) LABEL="relay-health" ;;
    3002) LABEL="relay-finance" ;;
    3003) LABEL="relay-legal" ;;
    3004) LABEL="relay-iot" ;;
  esac
  if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
    echo -e "  ${GREEN}●${RESET}  :${port}  ${LABEL}"
  else
    echo -e "  ${YELLOW}○${RESET}  :${port}  ${LABEL}  (not listening)"
  fi
done

echo ""
} | pager
