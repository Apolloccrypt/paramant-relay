#!/usr/bin/env bash
# paramant-license — show license status and upgrade instructions

LICENSE_FILE="/etc/paramant/license"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}License Status${RESET}"
echo "──────────────────────────────────────"

# Health endpoint
HEALTH=$(curl -sf --max-time 3 http://localhost:3000/health 2>/dev/null || echo "")
if [[ -n "$HEALTH" ]]; then
  EDITION=$(echo "$HEALTH" | jq -r '.edition // "?"' 2>/dev/null || echo "?")
  MAX=$(echo "$HEALTH"     | jq -r '.max_keys // "?"'  2>/dev/null || echo "?")
  EXPIRES=$(echo "$HEALTH" | jq -r '.license_expires // ""' 2>/dev/null || true)

  if [[ "$EDITION" == "community" ]]; then
    echo -e "  Edition:  ${YELLOW}Community${RESET}  (max ${MAX} API keys)"
  else
    echo -e "  Edition:  ${GREEN}Licensed / ${EDITION}${RESET}  (max ${MAX} keys)"
  fi

  if [[ -n "$EXPIRES" ]]; then
    DAYS=$(( ( $(date -d "$EXPIRES" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
    [[ "$DAYS" -lt 0 ]] 2>/dev/null && DAYS=0
    if [[ "$DAYS" == "?" ]]; then
      echo "  Expires:  ${EXPIRES}"
    elif [[ "$DAYS" -lt 14 ]] 2>/dev/null; then
      echo -e "  Expires:  ${RED}in ${DAYS} day(s) — renew soon!${RESET}"
    else
      echo -e "  Expires:  ${GREEN}in ${DAYS} day(s)${RESET}  (${EXPIRES})"
    fi
  fi
fi

echo ""

# File
if [[ -f "$LICENSE_FILE" ]]; then
  PLK=$(grep -oP '(?<=PLK_KEY=)plk_\S+' "$LICENSE_FILE" 2>/dev/null || true)
  if [[ -n "$PLK" ]]; then
    echo -e "  Key file: ${GREEN}${PLK:0:16}...${RESET}"
  else
    echo -e "  Key file: ${YELLOW}exists, no PLK_KEY${RESET}"
  fi
else
  echo -e "  Key file: ${YELLOW}not configured${RESET}"
fi

echo ""

if [[ "$EDITION" == "community" ]] || [[ -z "$HEALTH" ]]; then
  echo -e "${CYAN}To unlock unlimited API keys:${RESET}"
  echo "  1. Get a license key: https://paramant.app/pricing"
  echo "  2. Run: paramant-setup --force  (step 3 adds the key)"
  echo "  3. Or manually:"
  echo "     echo 'PLK_KEY=plk_your_key' >> /etc/paramant/license"
  echo "     systemctl restart paramant-relay"
fi

echo ""
