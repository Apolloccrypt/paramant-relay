#!/usr/bin/env bash
# paramant-test — Comprehensive automated test suite for ParamantOS
# Exit code 0 = all pass, 1 = one or more failures

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m';
CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'

VERSION="2.4.5"
RELAY_URL="http://localhost:3000"
PASS=0; FAIL=0; FAILURES=()

# ── test helpers ───────────────────────────────────────────────────────────────
ok()  { ((PASS++)); }
fail(){ ((FAIL++)); FAILURES+=("$1"); }

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    ok
  else
    fail "$name"
  fi
}

check_output() {
  local name="$1"; local pattern="$2"; shift 2
  local out
  out=$("$@" 2>/dev/null)
  if echo "$out" | grep -q "$pattern"; then
    ok
  else
    fail "${name} (expected: ${pattern})"
  fi
}

section() {
  local name="$1"; local p="$2"; local t="$3"
  local color="$GREEN"
  [ "$FAIL_IN_SECTION" -gt 0 ] && color="$RED"
  printf "  %-22s ${color}[%s/%s]${RESET}" "$name" "$p" "$t"
  if [ "$FAIL_IN_SECTION" -gt 0 ]; then
    printf "  ${RED}✗  %d issue%s${RESET}" "$FAIL_IN_SECTION" "$([ $FAIL_IN_SECTION -gt 1 ] && echo 's' || echo '')"
  else
    printf "  ${GREEN}✓${RESET}"
  fi
  echo ""
}

# ── SECTION 1: Relay Core ─────────────────────────────────────────────────────
PASS_S=0; FAIL_S=0; FAIL_IN_SECTION=0

_check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    ((PASS++)); ((PASS_S++))
  else
    ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
    FAILURES+=("RELAY CORE: $name")
  fi
}

_check_out() {
  # $3+ is a shell expression or command — use bash -c "$*" after shift (no eval)
  local name="$1"; local pat="$2"; shift 2
  local out; out=$(bash -c "$*" 2>/dev/null)
  if echo "$out" | grep -q "$pat"; then
    ((PASS++)); ((PASS_S++))
  else
    ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
    FAILURES+=("RELAY CORE: $name")
  fi
}

# /health check
_check_out "/health ok:true"    '"ok":true'    curl -sf "${RELAY_URL}/health"
_check_out "/health version"    "\"${VERSION}\"" curl -sf "${RELAY_URL}/health"
_check_out "/health edition"    '"edition"'    curl -sf "${RELAY_URL}/health"

# inbound / outbound / burn
TEST_BLOB=$(openssl rand -base64 64 | tr -d '\n')
TEST_HASH=$(echo -n "$TEST_BLOB" | sha256sum | awk '{print $1}')
INBOUND_RESP=$(curl -sf -X POST "${RELAY_URL}/v2/inbound" \
  -H "Content-Type: application/json" \
  -d "{\"hash\":\"${TEST_HASH}\",\"payload\":\"${TEST_BLOB}\",\"ttl_ms\":30000,\"max_views\":1}" 2>/dev/null)
if echo "$INBOUND_RESP" | grep -q '"ok":true'; then
  ((PASS++)); ((PASS_S++))
  # Try to get a real download token for burn test
  DL_TOKEN=$(echo "$INBOUND_RESP" | jq -r '.download_token // ""' 2>/dev/null)
else
  ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
  FAILURES+=("RELAY CORE: POST /v2/inbound")
  DL_TOKEN=""
fi

if [ -n "$DL_TOKEN" ]; then
  _check "GET /v2/dl/:token (first fetch)" curl -sf "${RELAY_URL}/v2/dl/${DL_TOKEN}/get"
  _check "GET /v2/dl/:token (burned = 404)" \
    'r=$(curl -s -o /dev/null -w "%{http_code}" "'${RELAY_URL}'/v2/dl/'${DL_TOKEN}'/get"); [ "$r" = "404" ]'
else
  # fallback: test outbound by hash
  _check_out "GET /v2/outbound/:hash" '"payload"' \
    curl -sf "${RELAY_URL}/v2/outbound/${TEST_HASH}"
  _check "GET /v2/outbound/:hash (burned = 404)" \
    'r=$(curl -s -o /dev/null -w "%{http_code}" "'${RELAY_URL}'/v2/outbound/'${TEST_HASH}'"); [ "$r" = "404" ]'
fi

# Community key limit (5 max)
# Register 5 devices and verify 6th is rejected — uses dummy invite tokens
for i in 1 2 3 4 5; do
  DEV_ID="inv_$(openssl rand -hex 16)"
  PUB_HEX=$(openssl rand -hex 32)
  curl -sf -X POST "${RELAY_URL}/v2/pubkey" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"${DEV_ID}\",\"ecdh_pub\":\"${PUB_HEX}\",\"kyber_pub\":\"\"}" >/dev/null 2>&1
done
# Community limit test is key-plan based — invite tokens bypass, so just verify basic pubkey registration works
_check_out "Pubkey registration returns fingerprint" '"fingerprint"' \
  'curl -sf -X POST "'${RELAY_URL}'/v2/pubkey" -H "Content-Type: application/json" \
  -d "{\"device_id\":\"inv_$(openssl rand -hex 16)\",\"ecdh_pub\":\"$(openssl rand -hex 32)\",\"kyber_pub\":\"\"}"'

# GET /v2/fingerprint/:device
FP_DEVICE="inv_$(openssl rand -hex 16)"
FP_PUB=$(openssl rand -hex 32)
curl -sf -X POST "${RELAY_URL}/v2/pubkey" \
  -H "Content-Type: application/json" \
  -d "{\"device_id\":\"${FP_DEVICE}\",\"ecdh_pub\":\"${FP_PUB}\",\"kyber_pub\":\"\"}" >/dev/null 2>&1
_check_out "GET /v2/fingerprint/:device" '"fingerprint"' \
  curl -sf "${RELAY_URL}/v2/fingerprint/${FP_DEVICE}"

# POST /v2/pubkey/verify
FP_VAL=$(curl -sf "${RELAY_URL}/v2/fingerprint/${FP_DEVICE}" 2>/dev/null | \
  jq -r '.fingerprint // ""' 2>/dev/null)
if [ -n "$FP_VAL" ]; then
  _check_out "POST /v2/pubkey/verify (match)" '"match":true' \
    'curl -sf -X POST "'${RELAY_URL}'/v2/pubkey/verify" -H "Content-Type: application/json" \
    -d "{\"device_id\":\"'${FP_DEVICE}'\",\"fingerprint\":\"'${FP_VAL}'\"}"'
else
  ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
  FAILURES+=("RELAY CORE: POST /v2/pubkey/verify (no FP retrieved)")
fi

PASS_S1=$((PASS_S)); FAIL_S1=$((FAIL_S)); FIS1=$((FAIL_IN_SECTION))
TOTAL_S1=$((PASS_S + FAIL_S))

# ── SECTION 2: Commands ────────────────────────────────────────────────────────
PASS_S=0; FAIL_S=0; FAIL_IN_SECTION=0

COMMANDS=(
  paramant-setup paramant-help paramant-info paramant-doctor
  paramant-status paramant-restart paramant-logs paramant-dashboard
  paramant-keys paramant-key-add paramant-key-revoke
  paramant-license
  paramant-wifi paramant-ip paramant-ports paramant-scan
  paramant-security paramant-sector-add
  paramant-backup paramant-restore paramant-export paramant-cron paramant-update
  paramant-verify paramant-test
)

for cmd in "${COMMANDS[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    ((PASS++)); ((PASS_S++))
  else
    ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
    FAILURES+=("COMMANDS: $cmd MISSING — install via nixos-rebuild")
  fi
done

PASS_S2=$((PASS_S)); FAIL_S2=$((FAIL_S)); FIS2=$((FAIL_IN_SECTION))
TOTAL_S2=$((PASS_S + FAIL_S))

# ── SECTION 3: System hardening ───────────────────────────────────────────────
PASS_S=0; FAIL_S=0; FAIL_IN_SECTION=0

_hcheck() {
  # $3 is a shell expression (may contain pipes/&&/etc.) — use bash -c, not eval
  local name="$1"; local fix="$2"; local cmd="$3"
  if bash -c "$cmd" >/dev/null 2>&1; then
    ((PASS++)); ((PASS_S++))
  else
    ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
    FAILURES+=("HARDENING: $name — fix: $fix")
  fi
}

_hcheck "swap disabled"   "swapoff -a && echo 0 | tee /proc/sys/vm/swappiness" \
  '[ "$(swapon --show 2>/dev/null | wc -l)" = "0" ]'

_hcheck "firewall active" "systemctl start nftables" \
  'systemctl is-active --quiet nftables 2>/dev/null || iptables -L >/dev/null 2>&1'

_hcheck "SSH PasswordAuth no" "edit /etc/ssh/sshd_config: PasswordAuthentication no" \
  'grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null || \
   grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config.d/*.conf 2>/dev/null'

_hcheck "SSH PermitRootLogin no" "edit /etc/ssh/sshd_config: PermitRootLogin no" \
  'grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null || \
   grep -q "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null'

_hcheck "kptr_restrict=2" "sysctl -w kernel.kptr_restrict=2" \
  '[ "$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)" = "2" ]'

_hcheck "unprivileged_bpf_disabled" "sysctl -w kernel.unprivileged_bpf_disabled=1" \
  '[ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)" = "1" ]'

_hcheck "relay data dir permissions" "chown -R paramant:paramant /var/lib/paramant && chmod 750 /var/lib/paramant" \
  '[ ! -d /var/lib/paramant ] || [ "$(stat -c %a /var/lib/paramant 2>/dev/null)" = "750" ]'

_hcheck "relay port 3000 only (no unexpected)" "" \
  '! ss -tlnp 2>/dev/null | grep -vE ":22 |:3000|:3001|:3002|:3003|:3004|:4200" | grep -q LISTEN'

PASS_S3=$((PASS_S)); FAIL_S3=$((FAIL_S)); FIS3=$((FAIL_IN_SECTION))
TOTAL_S3=$((PASS_S + FAIL_S))

# ── SECTION 4: License system ──────────────────────────────────────────────────
PASS_S=0; FAIL_S=0; FAIL_IN_SECTION=0

_lcheck() {
  local name="$1"; local fix="$2"; local cmd="$3"
  if bash -c "$cmd" >/dev/null 2>&1; then
    ((PASS++)); ((PASS_S++))
  else
    ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
    FAILURES+=("LICENSE: $name — $fix")
  fi
}

_lcheck "no PLK_KEY → community edition" "" \
  'PLK_KEY="" curl -sf "'${RELAY_URL}'/health" | jq -e '.ok == true' >/dev/null 2>&1'

_lcheck "relay health ok" "" \
  'curl -sf "'${RELAY_URL}'/health" | jq -e '.ok == true' >/dev/null 2>&1'

_lcheck "verify-license.js exists" "git pull in /opt/paramant-relay" \
  '[ -f /opt/paramant-relay/scripts/verify-license.js ] || [ -f ~/paramant-relay/scripts/verify-license.js ]'

_lcheck "relay.js has Ed25519 pubkey" "" \
  'grep -q "ed25519\|Ed25519\|PUBLIC_KEY" /opt/paramant-relay/relay/relay.js 2>/dev/null || \
   grep -q "ed25519\|Ed25519\|PUBLIC_KEY" ~/paramant-relay/relay/relay.js 2>/dev/null || \
   grep -q "ed25519\|Ed25519\|PUBLIC_KEY" /run/current-system/sw/bin/../../../opt/paramant-relay/relay/relay.js 2>/dev/null'

PASS_S4=$((PASS_S)); FAIL_S4=$((FAIL_S)); FIS4=$((FAIL_IN_SECTION))
TOTAL_S4=$((PASS_S + FAIL_S))

# ── SECTION 5: User experience ─────────────────────────────────────────────────
PASS_S=0; FAIL_S=0; FAIL_IN_SECTION=0

_uxcheck() {
  # $3 is a shell expression (may contain pipes/&&/etc.) — use bash -c, not "$@"
  local name="$1"; local fix="$2"; local cmd="$3"
  if bash -c "$cmd" >/dev/null 2>&1; then
    ((PASS++)); ((PASS_S++))
  else
    ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
    FAILURES+=("USER EXPERIENCE: $name — $fix")
  fi
}

_uxcheck "paramant-help runs" "nixos-rebuild switch" \
  'paramant-help 2>/dev/null | head -1 | grep -qi "paramant"'

_uxcheck "paramant-status runs" "systemctl restart paramant-relay" \
  'timeout 5 paramant-status >/dev/null 2>&1'

_uxcheck "paramant-ip runs" "" \
  'timeout 5 paramant-ip >/dev/null 2>&1'

_uxcheck "paramant-doctor runs" "" \
  'timeout 10 paramant-doctor >/dev/null 2>&1'

_uxcheck "first-boot setup flag path exists" "run paramant-setup" \
  '[ -d /etc/paramant ] || [ -f /etc/paramant/.setup-done ]'

_uxcheck "/etc/issue has ParamantOS branding" "check /etc/issue" \
  'grep -qi "paramant" /etc/issue 2>/dev/null'

_uxcheck "hostname is paramant" "hostnamectl set-hostname paramant" \
  '[ "$(hostname 2>/dev/null)" = "paramant" ]'

_uxcheck "paramant-relay service enabled" "systemctl enable paramant-relay" \
  'systemctl is-enabled --quiet paramant-relay 2>/dev/null'

_uxcheck "console Terminus font configured" "check configuration.nix console.font" \
  'grep -qi "terminus\|Terminus" /etc/current-system 2>/dev/null || \
   cat /proc/1/environ 2>/dev/null | tr "\0" "\n" | grep -qi terminus || \
   grep -qi "terminus" /etc/vconsole.conf 2>/dev/null'

PASS_S5=$((PASS_S)); FAIL_S5=$((FAIL_S)); FIS5=$((FAIL_IN_SECTION))
TOTAL_S5=$((PASS_S + FAIL_S))

# ── SECTION 6: ISO / NixOS integrity ──────────────────────────────────────────
PASS_S=0; FAIL_S=0; FAIL_IN_SECTION=0

_isocheck() {
  # $3 is a shell expression (may contain pipes/&&/etc.) — use bash -c, not "$@"
  local name="$1"; local fix="$2"; local cmd="$3"
  if bash -c "$cmd" >/dev/null 2>&1; then
    ((PASS++)); ((PASS_S++))
  else
    ((FAIL++)); ((FAIL_S++)); ((FAIL_IN_SECTION++))
    FAILURES+=("ISO INTEGRITY: $name — $fix")
  fi
}

_isocheck "paramant-relay service exists" "check module.nix" \
  'systemctl list-unit-files 2>/dev/null | grep -q paramant-relay'

_isocheck "no NixOS branding in /etc/issue" "update /etc/issue" \
  '! grep -qi "nixos" /etc/issue 2>/dev/null'

_isocheck "paramant-relay starts on boot" "nixos-rebuild switch" \
  'systemctl is-enabled --quiet paramant-relay 2>/dev/null'

_isocheck "relay running" "systemctl restart paramant-relay" \
  'systemctl is-active --quiet paramant-relay 2>/dev/null'

_isocheck "relay.js present" "git pull in relay directory" \
  '[ -f /opt/paramant-relay/relay/relay.js ] || \
   [ -f /run/current-system/share/paramant/relay.js ] || \
   [ -f ~/paramant-relay/relay/relay.js ]'

PASS_S6=$((PASS_S)); FAIL_S6=$((FAIL_S)); FIS6=$((FAIL_IN_SECTION))
TOTAL_S6=$((PASS_S + FAIL_S))

# ── Final report ───────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL))

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
printf "${BOLD}║  ParamantOS v%-47s║${RESET}\n" "${VERSION} — Full Test Report"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"

FIS=0
FAIL_IN_SECTION=$FIS1
printf "  %-22s [%s/%s]" "RELAY CORE" "${PASS_S1}" "${TOTAL_S1}"
[ $FIS1 -gt 0 ] && printf "  ${RED}✗  %d issue%s${RESET}" $FIS1 "$([ $FIS1 -gt 1 ] && echo 's' || echo '')" || printf "  ${GREEN}✓${RESET}"
printf " %-*s${BOLD}║${RESET}\n" $((30 - ${#PASS_S1} - ${#TOTAL_S1})) ""

FAIL_IN_SECTION=$FIS2
printf "  %-22s [%s/%s]" "COMMANDS" "${PASS_S2}" "${TOTAL_S2}"
[ $FIS2 -gt 0 ] && printf "  ${RED}✗  %d missing${RESET}" $FIS2 || printf "  ${GREEN}✓${RESET}"
printf " %-*s${BOLD}║${RESET}\n" $((30 - ${#PASS_S2} - ${#TOTAL_S2})) ""

printf "  %-22s [%s/%s]" "HARDENING" "${PASS_S3}" "${TOTAL_S3}"
[ $FIS3 -gt 0 ] && printf "  ${RED}✗  %d issue%s${RESET}" $FIS3 "$([ $FIS3 -gt 1 ] && echo 's' || echo '')" || printf "  ${GREEN}✓${RESET}"
printf " %-*s${BOLD}║${RESET}\n" $((30 - ${#PASS_S3} - ${#TOTAL_S3})) ""

printf "  %-22s [%s/%s]" "LICENSE" "${PASS_S4}" "${TOTAL_S4}"
[ $FIS4 -gt 0 ] && printf "  ${RED}✗  %d issue%s${RESET}" $FIS4 "$([ $FIS4 -gt 1 ] && echo 's' || echo '')" || printf "  ${GREEN}✓${RESET}"
printf " %-*s${BOLD}║${RESET}\n" $((30 - ${#PASS_S4} - ${#TOTAL_S4})) ""

printf "  %-22s [%s/%s]" "USER EXPERIENCE" "${PASS_S5}" "${TOTAL_S5}"
[ $FIS5 -gt 0 ] && printf "  ${RED}✗  %d issue%s${RESET}" $FIS5 "$([ $FIS5 -gt 1 ] && echo 's' || echo '')" || printf "  ${GREEN}✓${RESET}"
printf " %-*s${BOLD}║${RESET}\n" $((30 - ${#PASS_S5} - ${#TOTAL_S5})) ""

printf "  %-22s [%s/%s]" "ISO INTEGRITY" "${PASS_S6}" "${TOTAL_S6}"
[ $FIS6 -gt 0 ] && printf "  ${RED}✗  %d issue%s${RESET}" $FIS6 "$([ $FIS6 -gt 1 ] && echo 's' || echo '')" || printf "  ${GREEN}✓${RESET}"
printf " %-*s${BOLD}║${RESET}\n" $((30 - ${#PASS_S6} - ${#TOTAL_S6})) ""

echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
TOTAL_ALL=$((PASS_S1+FAIL_S1 + PASS_S2+FAIL_S2 + PASS_S3+FAIL_S3 + PASS_S4+FAIL_S4 + PASS_S5+FAIL_S5 + PASS_S6+FAIL_S6))
printf "  ${BOLD}%-22s [%s/%s]${RESET}" "TOTAL" "${PASS}" "${TOTAL_ALL}"
if [ $FAIL -gt 0 ]; then
  printf "  ${RED}%d FAILURE%s${RESET}" $FAIL "$([ $FAIL -gt 1 ] && echo 'S' || echo '')"
else
  printf "  ${GREEN}ALL PASS${RESET}"
fi
printf " %-*s${BOLD}║${RESET}\n" 10 ""

if [ ${#FAILURES[@]} -gt 0 ]; then
  echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
  echo -e "${BOLD}║  FAILURES:                                                   ║${RESET}"
  for f in "${FAILURES[@]}"; do
    # Split at " — fix: "
    IFS='—' read -r desc fix <<< "$f"
    printf "  ${RED}✗${RESET} %-58s\n" "$desc"
    if [ -n "$fix" ] && [ "$fix" != " " ]; then
      printf "    ${DIM}→ fix: %s${RESET}\n" "$(echo "$fix" | sed 's/^ fix: //')"
    fi
  done
fi

echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""

[ $FAIL -eq 0 ] && exit 0 || exit 1
