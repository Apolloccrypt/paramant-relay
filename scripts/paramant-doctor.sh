#!/usr/bin/env bash
# paramant-doctor — automated health check for ParamantOS relay

LICENSE_FILE="/etc/paramant/license"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# Smart pager: pipe to less -R only when output exceeds terminal height
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

run_checks() {
pass() { echo -e "  ${GREEN}✓${RESET}  $*"; }
fail() { echo -e "  ${RED}✗${RESET}  $*"; FAILURES=$((FAILURES+1)); }
warn() { echo -e "  ${YELLOW}!${RESET}  $*"; WARNINGS=$((WARNINGS+1)); }
FAILURES=0; WARNINGS=0

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║            paramant-doctor                       ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}\n"

# ── 1. Relay service running ───────────────────────────────────────────────────
echo -e "${CYAN}[1] Relay service${RESET}"
STATUS=$(systemctl is-active paramant-relay 2>/dev/null || echo "unknown")
if [[ "$STATUS" == "active" ]]; then
  pass "paramant-relay is active"
else
  fail "paramant-relay is ${STATUS}"
  echo -e "      Fix: ${YELLOW}sudo systemctl start paramant-relay${RESET}"
fi

# ── 2. Relay health endpoint (port 3000) ──────────────────────────────────────
echo -e "\n${CYAN}[2] Health endpoint${RESET}"
HEALTH=$(curl -sf --max-time 3 http://localhost:3000/health 2>/dev/null || echo "")
if [[ -n "$HEALTH" ]]; then
  VERSION=$(echo "$HEALTH" | jq -r '.version // "?"' 2>/dev/null || echo "?")
  EDITION=$(echo "$HEALTH" | jq -r '.edition // ""' 2>/dev/null || true)
  pass "Relay responding — v${VERSION}${EDITION:+  [${EDITION}]}"
else
  fail "No response from http://localhost:3000/health"
  echo -e "      Fix: ${YELLOW}sudo systemctl restart paramant-relay${RESET}"
fi

# ── 3. Sector ports (3000 is required; 3001-3004 are optional add-ons) ────────
echo -e "\n${CYAN}[3] Sector ports${RESET}"
declare -A SECTORS=([3000]="main" [3001]="health" [3002]="finance" [3003]="legal" [3004]="iot")
for port in 3000 3001 3002 3003 3004; do
  name="${SECTORS[$port]}"
  R=$(curl -sf --max-time 2 "http://localhost:${port}/health" 2>/dev/null || echo "")
  if [[ -n "$R" ]]; then
    pass "Port ${port} (${name}) — OK"
  elif [[ "$port" -eq 3000 ]]; then
    fail "Port ${port} (${name}) — no response (primary relay must be running)"
    echo -e "      Fix: ${YELLOW}sudo systemctl restart paramant-relay${RESET}"
  else
    warn "Port ${port} (${name}) — not active (optional sector)"
    echo -e "      Add:  ${YELLOW}paramant-sector-add${RESET}"
  fi
done

# ── 4. Firewall ────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[4] Firewall${RESET}"
if nft list ruleset 2>/dev/null | grep -q "3000"; then
  pass "Firewall active, port 3000 present"
else
  warn "Could not verify firewall rules"
fi

# ── 5. SSH key configured ─────────────────────────────────────────────────────
echo -e "\n${CYAN}[5] SSH access${RESET}"
if [[ -s /home/paramant/.ssh/authorized_keys ]]; then
  COUNT=$(wc -l < /home/paramant/.ssh/authorized_keys)
  pass "SSH authorized_keys: ${COUNT} key(s)"
else
  warn "No SSH keys configured — console-only access"
  echo -e "      Fix: ${YELLOW}paramant-setup --force${RESET} (step 4)"
fi

# ── 6. Default password check ──────────────────────────────────────────────────
echo -e "\n${CYAN}[6] Default password${RESET}"
SHADOW=$(getent shadow paramant 2>/dev/null | cut -d: -f2 || echo "")
if [[ -z "$SHADOW" ]] || [[ "$SHADOW" == "!" ]] || [[ "$SHADOW" == "*" ]]; then
  pass "Password auth locked (good)"
elif [[ "$SHADOW" =~ ^\$([0-9a-z]+)\$([^\$]+)\$ ]]; then
  _SALT="${BASH_REMATCH[2]}"
  _COMPUTED=$(openssl passwd -6 -salt "$_SALT" "paramant123" 2>/dev/null || echo "x")
  if [[ "$_COMPUTED" == "$SHADOW" ]]; then
    fail "Default password 'paramant123' still active — change it!"
    echo -e "      Fix: ${YELLOW}passwd paramant${RESET}"
  else
    pass "Password has been changed"
  fi
else
  pass "Password has been changed"
fi

# ── 7. License file ────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[7] License${RESET}"
if [[ -f "$LICENSE_FILE" ]]; then
  PLK=$(grep -oP '(?<=PLK_KEY=)plk_\S+' "$LICENSE_FILE" 2>/dev/null || true)
  ADMIN=$(grep -oP '(?<=ADMIN_TOKEN=)\S+' "$LICENSE_FILE" 2>/dev/null || true)
  if [[ -n "$PLK" ]]; then
    pass "License key present: ${PLK:0:14}..."
  else
    warn "No PLK_KEY — Community Edition (max 5 keys)"
  fi
  if [[ -n "$ADMIN" ]]; then
    pass "ADMIN_TOKEN configured"
  else
    warn "No ADMIN_TOKEN — run paramant-setup to generate"
  fi
else
  warn "No license file — Community Edition, no ADMIN_TOKEN"
  echo -e "      Fix: ${YELLOW}paramant-setup --force${RESET} (step 3)"
fi

# ── 8. Disk space ─────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[8] Disk space${RESET}"
ROOT_USE=$(df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %' || echo "0")
if [[ "$ROOT_USE" -lt 80 ]]; then
  pass "Root filesystem: ${ROOT_USE}% used"
elif [[ "$ROOT_USE" -lt 90 ]]; then
  warn "Root filesystem: ${ROOT_USE}% used — getting full"
else
  fail "Root filesystem: ${ROOT_USE}% used — critically full"
fi

# ── 9. Network connectivity ────────────────────────────────────────────────────
echo -e "\n${CYAN}[9] Network${RESET}"
IP=$(ip -4 addr show scope global | grep -oP '(?<=inet )[0-9.]+' | head -1 || echo "")
if [[ -n "$IP" ]]; then
  pass "Network active — IP: ${IP}"
else
  fail "No global IP address found"
  echo -e "      WiFi: ${YELLOW}paramant-wifi${RESET}"
fi
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
  pass "Internet reachable"
else
  warn "No internet connectivity"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
if [[ $FAILURES -eq 0 ]] && [[ $WARNINGS -eq 0 ]]; then
  echo -e "  ${GREEN}${BOLD}All checks passed!${RESET}"
elif [[ $FAILURES -eq 0 ]]; then
  echo -e "  ${YELLOW}${BOLD}${WARNINGS} warning(s) — no critical failures${RESET}"
else
  echo -e "  ${RED}${BOLD}${FAILURES} failure(s), ${WARNINGS} warning(s)${RESET}"
fi
echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
echo ""
}

run_checks | pager
