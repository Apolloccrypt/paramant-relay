#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Laad .env als die bestaat
[ -f .env ] && export $(grep -v '^#' .env | grep -v '^$' | xargs)

echo -e "\n${GREEN}PARAMANT pre-flight check${NC}"
echo "─────────────────────────"

HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}

echo -e "HTTP_PORT=${HTTP_PORT}  HTTPS_PORT=${HTTPS_PORT}"
echo ""

CONFLICT=0
for port in $HTTP_PORT $HTTPS_PORT; do
    if ss -tlnp 2>/dev/null | grep -q " :${port} "; then
        proc=$(ss -tlnp 2>/dev/null | grep " :${port} " | sed 's/.*users:(("//' | cut -d'"' -f1)
        echo -e "${YELLOW}⚠ Poort ${port} in gebruik door: ${proc:-onbekend}${NC}"
        CONFLICT=1
    else
        echo -e "${GREEN}✓ Poort ${port} vrij${NC}"
    fi
done

if ! command -v docker &>/dev/null; then
    echo -e "${RED}✗ Docker niet gevonden${NC}"; exit 1
else
    echo -e "${GREEN}✓ Docker $(docker --version | cut -d' ' -f3 | tr -d ',')${NC}"
fi

if swapon --show 2>/dev/null | grep -q .; then
    echo -e "${YELLOW}⚠ Swap actief — sudo swapoff -a${NC}"
else
    echo -e "${GREEN}✓ Swap uitgeschakeld${NC}"
fi

if [ "$CONFLICT" = "1" ]; then
    echo -e "\n${RED}✗ Poortconflict op poorten die al in .env staan — iets anders bezet deze poorten.${NC}"
    exit 1
fi

echo -e "\n${GREEN}✓ Klaar voor docker compose up -d${NC}\n"
