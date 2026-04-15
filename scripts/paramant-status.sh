#!/usr/bin/env bash
# paramant-status — relay health, version, edition

LICENSE_FILE="/etc/paramant/license"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}Paramant Relay Status${RESET}"
echo "──────────────────────────────────────"

# systemd state
STATUS=$(systemctl is-active paramant-relay 2>/dev/null || echo "unknown")
if [[ "$STATUS" == "active" ]]; then
  echo -e "  Service:  ${GREEN}${STATUS}${RESET}"
else
  echo -e "  Service:  ${RED}${STATUS}${RESET}"
fi

UPTIME=$(systemctl show paramant-relay --property=ActiveEnterTimestamp 2>/dev/null \
  | sed 's/ActiveEnterTimestamp=//' || echo "")
[[ -n "$UPTIME" ]] && echo "  Since:    $UPTIME"

# health endpoint
HEALTH=$(curl -sf --max-time 3 http://localhost:3000/health 2>/dev/null || echo "")
if [[ -n "$HEALTH" ]]; then
  VERSION=$(echo "$HEALTH" | jq -r '.version // "?"' 2>/dev/null || echo "?")
  EDITION=$(echo "$HEALTH" | jq -r '.edition // "?"' 2>/dev/null || echo "?")
  MAX=$(echo "$HEALTH"     | jq -r '.max_keys // "?"'  2>/dev/null || echo "?")
  SECTOR=$(echo "$HEALTH"  | jq -r '.sector // "?"'   2>/dev/null || echo "?")
  echo -e "  Version:  ${GREEN}v${VERSION}${RESET}"
  echo    "  Edition:  ${EDITION}"
  echo    "  Max keys: ${MAX}"
  echo    "  Sector:   ${SECTOR}"
else
  echo -e "  Health:   ${RED}unreachable (port 3000)${RESET}"
fi

# license
if [[ -f "$LICENSE_FILE" ]]; then
  PLK=$(grep -oP '(?<=PLK_KEY=)plk_\S+' "$LICENSE_FILE" 2>/dev/null || true)
  if [[ -n "$PLK" ]]; then
    echo "  License:  ${PLK:0:14}..."
  else
    echo -e "  License:  ${YELLOW}Community (no key)${RESET}"
  fi
else
  echo -e "  License:  ${YELLOW}Community (no key file)${RESET}"
fi

echo ""
