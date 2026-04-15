#!/usr/bin/env bash
# paramant-restart — restart the relay service

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "${YELLOW}Restarting paramant-relay...${RESET}"
sudo paramant-relay-ctl restart paramant-relay

sleep 2

STATUS=$(systemctl is-active paramant-relay 2>/dev/null || echo "unknown")
if [[ "$STATUS" == "active" ]]; then
  HEALTH=$(curl -sf --max-time 3 http://localhost:3000/health 2>/dev/null || echo "")
  VERSION=$(echo "$HEALTH" | jq -r '.version // "?"' 2>/dev/null || echo "?")
  echo -e "${GREEN}✓ paramant-relay restarted — v${VERSION}${RESET}"
else
  echo -e "${RED}✗ restart failed — status: ${STATUS}${RESET}"
  echo "Check logs: journalctl -u paramant-relay -n 20"
  exit 1
fi
