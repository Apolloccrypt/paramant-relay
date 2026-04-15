#!/usr/bin/env bash
# paramant-hybrid-check — verify that a relay advertises hybrid-mode crypto support
# Usage: paramant-hybrid-check [relay-url]
# Default relay: https://relay.paramant.app

set -euo pipefail

G='\033[92m'; Y='\033[93m'; R='\033[91m'; B='\033[94m'; E='\033[0m'

RELAY="${1:-https://relay.paramant.app}"

echo -e "${B}Paramant Hybrid-Mode Check${E}"
echo "Relay: $RELAY"
echo "---"

HEADERS=$(curl -sI --max-time 10 "$RELAY/health" 2>&1) || {
  echo -e "${R}✗ Relay niet bereikbaar${E}"
  exit 1
}

get_header() {
  echo "$HEADERS" | grep -i "^${1}:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'
}

SECTOR=$(get_header "X-Paramant-Sector")
CRYPTO=$(get_header "X-Crypto-Version")
HYBRID=$(get_header "X-Hybrid-Mode")

# X-Paramant-Sector
if [[ -n "$SECTOR" ]]; then
  echo -e "${G}✓ Sector:          ${SECTOR}${E}"
else
  echo -e "${Y}? Sector:          (geen header)${E}"
fi

# X-Crypto-Version
if [[ "$CRYPTO" == "ML-KEM-768+AES-256-GCM" ]]; then
  echo -e "${G}✓ Crypto-versie:   ${CRYPTO}${E}"
elif [[ -n "$CRYPTO" ]]; then
  echo -e "${Y}? Crypto-versie:   ${CRYPTO} (onbekend formaat)${E}"
else
  echo -e "${R}✗ Crypto-versie:   (geen X-Crypto-Version header — relay te oud?)${E}"
fi

# X-Hybrid-Mode
if [[ "$HYBRID" == "available" ]]; then
  echo -e "${G}✓ Hybrid-modus:    beschikbaar${E}"
else
  echo -e "${R}✗ Hybrid-modus:    NIET beschikbaar (X-Hybrid-Mode: $HYBRID)${E}"
fi

echo "---"
if [[ "$CRYPTO" == "ML-KEM-768+AES-256-GCM" && "$HYBRID" == "available" ]]; then
  echo -e "${G}Relay ondersteunt hybride post-quantum encryptie.${E}"
  echo "Gebruik: paramant-sender --hybrid --relay ... --key ... --file ..."
  exit 0
else
  echo -e "${Y}Relay ondersteunt hybride modus nog niet. Update relay of gebruik standaard encryptie.${E}"
  exit 2
fi
