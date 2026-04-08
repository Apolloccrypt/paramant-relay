#!/bin/bash
# PARAMANT pre-flight check
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "\n${GREEN}PARAMANT pre-flight check${NC}"
echo "─────────────────────────"

HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}

# Check poorten
for port in $HTTP_PORT $HTTPS_PORT; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        proc=$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oP 'users:\(\("\K[^"]+')
        echo -e "${YELLOW}⚠ Poort $port in gebruik door: $proc${NC}"
        echo -e "  Voeg toe aan .env: HTTP_PORT=8080 / HTTPS_PORT=8443"
        echo -e "  Of stop $proc: sudo systemctl stop $proc"
        CONFLICT=1
    else
        echo -e "${GREEN}✓ Poort $port vrij${NC}"
    fi
done

# Check Docker
if ! command -v docker &>/dev/null; then
    echo -e "${RED}✗ Docker niet gevonden — installeer via: curl -fsSL https://get.docker.com | sh${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Docker $(docker --version | cut -d' ' -f3 | tr -d ',')${NC}"
fi

# Check swap
if swapon --show 2>/dev/null | grep -q .; then
    echo -e "${YELLOW}⚠ Swap actief — aanbevolen: sudo swapoff -a${NC}"
else
    echo -e "${GREEN}✓ Swap uitgeschakeld${NC}"
fi

if [ "$CONFLICT" = "1" ]; then
    echo -e "\n${YELLOW}Poortconflict gevonden. Zet HTTP_PORT en HTTPS_PORT in .env en probeer opnieuw.${NC}"
    exit 1
fi

echo -e "\n${GREEN}✓ Systeem klaar voor docker compose up -d${NC}\n"
