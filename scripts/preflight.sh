#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# Load .env if present
[ -f .env ] && export $(grep -v '^#' .env | grep -v '^$' | xargs) 2>/dev/null

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     PARAMANT Pre-flight Check         ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}
ISSUES=0

# ── Port check ────────────────────────────────────────────────────────────────
check_port() {
    local port=$1
    local var=$2
    if ss -tlnp 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"; then
        local proc=$(ss -tlnp 2>/dev/null | grep ":${port} " | \
            grep -oP 'users:\(\("\K[^"]+' | head -1)
        echo -e "${YELLOW}⚠  Port ${port} is in use${proc:+ by $proc}${NC}"
        echo ""
        echo "   Options:"
        echo "   1) Use alternate ports (recommended)"
        echo "   2) Stop $proc manually, then re-run"
        echo "   3) Skip (may cause startup failure)"
        echo ""
        if [ -t 0 ]; then
            read -p "   Choose [1/2/3]: " choice
        else
            choice=1
            echo "   (non-interactive: auto-selecting option 1)"
        fi
        case ${choice:-1} in
            1)
                local alt_http=8080
                local alt_https=8443
                # Find free ports
                while ss -tlnp 2>/dev/null | awk '{print $4}' | grep -q ":${alt_http}$"; do
                    alt_http=$((alt_http + 1))
                done
                while ss -tlnp 2>/dev/null | awk '{print $4}' | grep -q ":${alt_https}$"; do
                    alt_https=$((alt_https + 1))
                done
                echo "HTTP_PORT=${alt_http}" >> .env
                echo "HTTPS_PORT=${alt_https}" >> .env
                export HTTP_PORT=${alt_http}
                export HTTPS_PORT=${alt_https}
                echo -e "${GREEN}✓  Will use ports ${alt_http}/${alt_https} — saved to .env${NC}"
                ;;
            2)
                echo -e "${YELLOW}   Stop ${proc} and re-run this script${NC}"
                exit 1
                ;;
            3)
                echo -e "${YELLOW}   Skipping — startup may fail${NC}"
                ISSUES=$((ISSUES + 1))
                ;;
        esac
    else
        echo -e "${GREEN}✓  Port ${port} free${NC}"
    fi
}

echo "Checking ports..."
check_port $HTTP_PORT HTTP_PORT
check_port $HTTPS_PORT HTTPS_PORT
echo ""

# ── Docker check ──────────────────────────────────────────────────────────────
echo "Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo -e "${RED}✗  Docker not found${NC}"
    echo ""
    read -p "   Install Docker now? [y/N]: " install_docker
    if [[ "$install_docker" =~ ^[Yy]$ ]]; then
        echo "   Installing Docker..."
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker $USER
        echo -e "${GREEN}✓  Docker installed — you may need to log out and back in${NC}"
    else
        echo -e "${RED}   Docker is required. Install from https://docs.docker.com/get-docker/${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓  Docker $(docker --version | cut -d' ' -f3 | tr -d ',')${NC}"
fi

if ! docker compose version &>/dev/null; then
    echo -e "${RED}✗  Docker Compose not found${NC}"
    exit 1
else
    echo -e "${GREEN}✓  Docker Compose $(docker compose version --short 2>/dev/null)${NC}"
fi
echo ""

# ── Swap check ────────────────────────────────────────────────────────────────
echo "Checking swap..."
DISK_SWAP=$(swapon --show=TYPE,NAME --noheadings 2>/dev/null | grep -v zram | grep -v "^$" || true)
ZRAM_SWAP=$(swapon --show=TYPE,NAME --noheadings 2>/dev/null | grep zram || true)

if [ -n "$DISK_SWAP" ]; then
    echo -e "${RED}✗  Disk swap is active — security risk for RAM-only storage${NC}"
    echo "   $DISK_SWAP"
    echo ""
    read -p "   Disable disk swap now? [Y/n]: " disable_swap
    if [[ ! "$disable_swap" =~ ^[Nn]$ ]]; then
        if sudo swapoff -a 2>/dev/null && sudo sed -i '/swap/d' /etc/fstab 2>/dev/null; then
            echo -e "${GREEN}✓  Disk swap disabled${NC}"
        else
            echo -e "${YELLOW}⚠  Could not disable swap (sudo required)${NC}"
            echo -e "${YELLOW}   Run manually: sudo swapoff -a && sudo sed -i '/swap/d' /etc/fstab${NC}"
            ISSUES=$((ISSUES + 1))
        fi
    else
        echo -e "${YELLOW}   Warning: RAM blobs may be paged to disk${NC}"
        ISSUES=$((ISSUES + 1))
    fi
elif [ -n "$ZRAM_SWAP" ]; then
    echo -e "${GREEN}✓  Swap: zram only (RAM-based, safe)${NC}"
else
    echo -e "${GREEN}✓  Swap disabled${NC}"
fi
echo ""

# ── ADMIN_TOKEN check ─────────────────────────────────────────────────────────
echo "Checking configuration..."
if [ -f .env ] && grep -q "^ADMIN_TOKEN=.\+" .env; then
    echo -e "${GREEN}✓  ADMIN_TOKEN configured${NC}"
else
    echo -e "${YELLOW}⚠  ADMIN_TOKEN not set${NC}"
    echo ""
    if [ -t 0 ]; then
        read -p "   Generate a secure ADMIN_TOKEN now? [Y/n]: " gen_token
    else
        gen_token="y"
        echo "   (non-interactive: auto-generating token)"
    fi
    if [[ ! "$gen_token" =~ ^[Nn]$ ]]; then
        TOKEN=$(openssl rand -hex 32)
        if [ ! -f .env ]; then
            cp .env.example .env
        fi
        # Remove existing empty ADMIN_TOKEN line and add new one
        sed -i 's/^ADMIN_TOKEN=$//' .env
        echo "ADMIN_TOKEN=${TOKEN}" >> .env
        echo ""
        echo -e "${GREEN}✓  ADMIN_TOKEN generated and saved to .env${NC}"
        echo -e "${YELLOW}   Save this token securely — you need it to manage API keys:${NC}"
        echo ""
        echo "   ADMIN_TOKEN=${TOKEN}"
        echo ""
    fi
fi
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
if [ "$ISSUES" -gt 0 ]; then
    echo -e "${YELLOW}⚠  Pre-flight complete with ${ISSUES} warning(s)${NC}"
    echo -e "   Proceeding may cause issues."
    echo ""
    read -p "   Continue anyway? [y/N]: " cont
    [[ "$cont" =~ ^[Yy]$ ]] || exit 1
else
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓  All checks passed                 ║${NC}"
    echo -e "${GREEN}║     Ready: docker compose up -d       ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
fi
echo ""
