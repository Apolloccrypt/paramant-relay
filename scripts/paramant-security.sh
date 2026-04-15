#!/usr/bin/env bash
# paramant-security — show firewall, SSH, kernel hardening status

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; RESET='\033[0m'

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

pass() { echo -e "  ${GREEN}✓${RESET}  $*"; }
fail() { echo -e "  ${RED}✗${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $*"; }

{
echo -e "\n${BOLD}Security Status${RESET}"
echo "──────────────────────────────────────"

# ── SSH ────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}SSH${RESET}"

if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
  pass "SSH service running"
else
  warn "SSH service not running"
fi

CFG_FILE=$(sshd -T 2>/dev/null | grep -c '.' > /dev/null && echo "sshd -T" || echo "/etc/ssh/sshd_config")

PERMIT_ROOT=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}' || grep -i PermitRootLogin /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | awk '{print $2}' || echo "?")
[[ "$PERMIT_ROOT" =~ ^(no|prohibit-password)$ ]] && pass "PermitRootLogin: ${PERMIT_ROOT}" || fail "PermitRootLogin: ${PERMIT_ROOT} (should be no)"

PASSWD_AUTH=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}' || grep -i PasswordAuthentication /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | awk '{print $2}' || echo "?")
[[ "$PASSWD_AUTH" == "no" ]] && pass "PasswordAuthentication: no" || warn "PasswordAuthentication: ${PASSWD_AUTH}"

X11=$(sshd -T 2>/dev/null | awk '/^x11forwarding/{print $2}' || echo "?")
[[ "$X11" == "no" ]] && pass "X11Forwarding: no" || warn "X11Forwarding: ${X11}"

TCP_FWD=$(sshd -T 2>/dev/null | awk '/^allowtcpforwarding/{print $2}' || echo "?")
[[ "$TCP_FWD" == "no" ]] && pass "AllowTcpForwarding: no" || warn "AllowTcpForwarding: ${TCP_FWD} (should be no)"

AGENT_FWD=$(sshd -T 2>/dev/null | awk '/^allowagentforwarding/{print $2}' || echo "?")
[[ "$AGENT_FWD" == "no" ]] && pass "AllowAgentForwarding: no" || warn "AllowAgentForwarding: ${AGENT_FWD} (should be no)"

AUTH_METHODS=$(sshd -T 2>/dev/null | awk '/^authenticationmethods/{print $2}' || echo "?")
[[ "$AUTH_METHODS" == "publickey" ]] && pass "AuthenticationMethods: publickey" || warn "AuthenticationMethods: ${AUTH_METHODS} (should be publickey)"

KEX=$(sshd -T 2>/dev/null | awk '/^kexalgorithms/{print $2}' || echo "?")
if echo "$KEX" | grep -q "mlkem768x25519"; then
  pass "Post-quantum KEX: mlkem768x25519 active"
else
  warn "Post-quantum KEX: mlkem768x25519 not detected — run paramant-setup or apply hardened config"
fi

KEY_COUNT=$(wc -l < /home/paramant/.ssh/authorized_keys 2>/dev/null || echo 0)
[[ "$KEY_COUNT" -gt 0 ]] && pass "SSH keys: ${KEY_COUNT} key(s) authorized" || warn "No SSH keys — console-only access"

# ── Firewall ─────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}Firewall${RESET}"

if nft list ruleset 2>/dev/null | grep -q 'filter'; then
  pass "nftables active"
  ALLOWED=$(nft list ruleset 2>/dev/null | grep -oP '\d{2,5}' | grep -E '^(22|3000|3001|3002|3003|3004)$' | sort -u | tr '\n' ' ')
  [[ -n "$ALLOWED" ]] && pass "Allowed ports: ${ALLOWED}" || warn "Could not parse allowed ports"
else
  warn "nftables rules not detected"
fi

# ── Kernel hardening ──────────────────────────────────────────────────────────
echo -e "\n${CYAN}Kernel Hardening${RESET}"

check_sysctl() {
  local key=$1 want=$2
  local val
  val=$(sysctl -n "$key" 2>/dev/null || echo "?")
  if [[ "$val" == "$want" ]]; then
    pass "${key} = ${val}"
  else
    fail "${key} = ${val} (expected ${want})"
  fi
}

check_sysctl "kernel.unprivileged_bpf_disabled" "1"
check_sysctl "kernel.kptr_restrict"             "2"
check_sysctl "net.core.bpf_jit_harden"          "2"

# ── Default password ──────────────────────────────────────────────────────────
echo -e "\n${CYAN}Credentials${RESET}"

SHADOW=$(getent shadow paramant 2>/dev/null | cut -d: -f2 || echo "")
if [[ -z "$SHADOW" ]] || [[ "$SHADOW" == "!" ]] || [[ "$SHADOW" == "*" ]]; then
  pass "Password locked"
elif [[ "$SHADOW" =~ ^\$([0-9a-z]+)\$([^\$]+)\$ ]]; then
  _SALT="${BASH_REMATCH[2]}"
  _COMPUTED=$(openssl passwd -6 -salt "$_SALT" "paramant123" 2>/dev/null || echo "x")
  if [[ "$_COMPUTED" == "$SHADOW" ]]; then
    fail "Default password 'paramant123' still active — run: passwd paramant"
  else
    pass "Password changed from default"
  fi
else
  pass "Password changed from default"
fi

echo ""
} | pager
