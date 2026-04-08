#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

[ -f .env ] && export $(grep -v '^#' .env | grep -v '^$' | xargs)

echo -e "\n${GREEN}PARAMANT pre-flight check${NC}"
echo "─────────────────────────"

HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}
echo -e "HTTP_PORT=${HTTP_PORT}  HTTPS_PORT=${HTTPS_PORT}\n"

CONFLICT=0

for port in $HTTP_PORT $HTTPS_PORT; do
    if ss -tlnp 2>/dev/null | grep -q " :${port} "; then
        proc=$(ss -tlnp 2>/dev/null | grep " :${port} " | sed 's/.*users:(("//' | cut -d'"' -f1)
        echo -e "${YELLOW}⚠  Port ${port} in use by: ${proc:-unknown}${NC}"
        echo -e "   Add to .env: HTTP_PORT=8080 / HTTPS_PORT=8443"
        CONFLICT=1
    else
        echo -e "${GREEN}✓  Port ${port} free${NC}"
    fi
done

if ! command -v docker &>/dev/null; then
    echo -e "${RED}✗  Docker not found — install via: curl -fsSL https://get.docker.com | sh${NC}"
    exit 1
else
    echo -e "${GREEN}✓  Docker $(docker --version | cut -d' ' -f3 | tr -d ',')${NC}"
fi

DISK_SWAP=$(swapon --show=TYPE,SIZE --noheadings 2>/dev/null | grep -v zram || true)
ZRAM_SWAP=$(swapon --show=TYPE,SIZE --noheadings 2>/dev/null | grep zram || true)

if [ -n "$DISK_SWAP" ]; then
    echo -e "${RED}✗  Disk swap is active — security risk for RAM-only storage${NC}"
    echo -e "   Disable: sudo swapoff -a && sudo sed -i '/swap/d' /etc/fstab"
    CONFLICT=1
elif [ -n "$ZRAM_SWAP" ]; then
    echo -e "${GREEN}✓  Swap: only zram (RAM-based, acceptable)${NC}"
else
    echo -e "${GREEN}✓  Swap disabled${NC}"
fi

if ! docker compose version &>/dev/null; then
    echo -e "${RED}✗  Docker Compose not found${NC}"
    exit 1
else
    echo -e "${GREEN}✓  Docker Compose $(docker compose version --short 2>/dev/null)${NC}"
fi

if [ "$CONFLICT" = "1" ]; then
    echo -e "\n${RED}✗  Issues found — fix before continuing${NC}\n"
    exit 1
fi

echo -e "\n${GREEN}✓  All checks passed — ready for docker compose up -d${NC}\n"
