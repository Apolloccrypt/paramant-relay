#!/usr/bin/env bash
# paramant-scan — discover Paramant relay nodes via registry and local network

PEERS_FILE="/etc/paramant/peers"
PRIMARY_RELAY="${PARAMANT_PRIMARY:-https://health.paramant.app}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║            paramant-scan                         ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}\n"

# ── Step 1: Query relay registry ──────────────────────────────────────────────
echo -e "  ${CYAN}Querying relay registry at ${PRIMARY_RELAY}…${RESET}"
REGISTRY=$(curl -sf --max-time 5 "${PRIMARY_RELAY}/v2/relays" 2>/dev/null || echo "")
REGISTRY_OK=0

if [[ -n "$REGISTRY" ]]; then
  COUNT=$(echo "$REGISTRY" | jq -r '.count // 0' 2>/dev/null || echo "0")
  if [[ "$COUNT" -gt 0 ]]; then
    echo -e "\n  ${GREEN}${BOLD}Registry: ${COUNT} verified relay(s)${RESET}\n"
    echo "$REGISTRY" | jq -r '.relays[]? |
      "    \u001b[32m✓\u001b[0m  \(.url)",
      "       sector=\(.sector // "?")  v\(.version // "?")  [\(.edition // "community")]",
      "       verified_since: \(.verified_since // "—" | .[0:16])  |  last_seen: \(.last_seen // "—" | .[0:16])",
      "       pk_hash: \(.pk_hash // "" | .[0:32])…  ct_index: \(.ct_index // "?")",
      ""
    ' 2>/dev/null
    REGISTRY_OK=1
  fi
fi

if [[ "$REGISTRY_OK" -eq 0 ]]; then
  echo -e "  ${YELLOW}Registry unavailable or empty — falling back to local network scan${RESET}\n"
fi

# ── Step 2: Local network scan (nmap) ─────────────────────────────────────────
echo -e "  ${CYAN}Local network scan…${RESET}"

# ── Detect subnet ──────────────────────────────────────────────────────────────
SUBNET=$(ip route 2>/dev/null \
  | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' \
  | grep -v '^169\.' \
  | head -1 || echo "")

if [[ -z "$SUBNET" ]]; then
  echo -e "${RED}Could not detect local subnet. Is the network up?${RESET}"
  echo "Try: ip route"
  exit 1
fi

echo -e "  ${CYAN}Subnet:${RESET} ${SUBNET}"
echo -e "  ${CYAN}Scanning for open port 3000 (relay-main)...${RESET}"
echo -e "  ${YELLOW}This may take 30–60 seconds depending on subnet size.${RESET}\n"

# ── nmap scan ─────────────────────────────────────────────────────────────────
TMPFILE=$(mktemp /tmp/paramant-scan-XXXXXX)
nmap -p 3000 --open -T4 -oG "$TMPFILE" "$SUBNET" 2>/dev/null || {
  echo -e "${RED}nmap failed. Is nmap installed?${RESET}"
  rm -f "$TMPFILE"
  exit 1
}

FOUND_IPS=$(grep -oP '(\d{1,3}\.){3}\d{1,3}(?=.*3000/open)' "$TMPFILE" 2>/dev/null || true)
rm -f "$TMPFILE"

if [[ -z "$FOUND_IPS" ]]; then
  echo -e "  ${YELLOW}No relay nodes found on ${SUBNET}${RESET}"
  echo ""
  exit 0
fi

echo -e "  ${GREEN}${BOLD}Found relay nodes:${RESET}\n"
PEER_LIST=()

while IFS= read -r ip; do
  # Probe health endpoint
  HEALTH=$(curl -sf --max-time 2 "http://${ip}:3000/health" 2>/dev/null || echo "")
  if [[ -n "$HEALTH" ]]; then
    VERSION=$(echo "$HEALTH" | jq -r '.version // "?"' 2>/dev/null || echo "?")
    SECTOR=$(echo  "$HEALTH" | jq -r '.sector // "?"'  2>/dev/null || echo "?")
    EDITION=$(echo "$HEALTH" | jq -r '.edition // ""'  2>/dev/null || true)
    echo -e "    ${GREEN}✓${RESET}  ${ip}  v${VERSION}  sector=${SECTOR}${EDITION:+  [${EDITION}]}"
    PEER_LIST+=("${ip}  v${VERSION}  sector=${SECTOR}")
  else
    echo -e "    ${YELLOW}?${RESET}  ${ip}  (port 3000 open, no /health response)"
    PEER_LIST+=("${ip}  unknown")
  fi
done <<< "$FOUND_IPS"

# ── Save to peers file ────────────────────────────────────────────────────────
if [[ ${#PEER_LIST[@]} -gt 0 ]]; then
  echo ""
  echo -e "  ${CYAN}Save peer list to ${PEERS_FILE}? [y/N]${RESET}"
  read -r -t 10 CONFIRM || CONFIRM="n"
  if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    mkdir -p /etc/paramant
    {
      echo "# Paramant peer scan — $(date '+%Y-%m-%d %H:%M:%S')"
      echo "# Subnet: ${SUBNET}"
      for p in "${PEER_LIST[@]}"; do echo "$p"; done
    } > "$PEERS_FILE"
    chmod 644 "$PEERS_FILE"
    echo -e "  ${GREEN}Saved to ${PEERS_FILE}${RESET}"
  fi
fi

echo ""
