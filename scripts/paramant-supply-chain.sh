#!/usr/bin/env bash
# paramant-supply-chain — supply chain crypto posture scanner
# Maps which external services your infrastructure connects to, checks their
# TLS/cipher posture, and generates a vendor risk report with HNDL context.
#
# Usage:
#   paramant-supply-chain --scan               scan all outbound connections
#   paramant-supply-chain --vendor URL         check a specific vendor
#   paramant-supply-chain --report             generate full supplier report
#   paramant-supply-chain --letter DOMAIN      print PQC migration letter template
#   paramant-supply-chain --help

set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[0;33m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'

SCAN_DATE=$(date '+%Y-%m-%d')
REPORT_FILE="supply-chain-${SCAN_DATE}.json"
VENDORS_FILE=$(mktemp /tmp/sc-vendors-XXXXXX.tsv)
trap 'rm -f "$VENDORS_FILE"' EXIT

MODE=""
SINGLE_VENDOR=""
LETTER_DOMAIN=""

usage() {
  cat <<EOF
${BOLD}paramant-supply-chain${RESET} — supply chain crypto visibility tool

Usage:
  paramant-supply-chain --scan               Scan all outbound connections
  paramant-supply-chain --vendor URL         Check a specific vendor endpoint
  paramant-supply-chain --report             Generate JSON + text supplier report
  paramant-supply-chain --letter DOMAIN      Print vendor PQC letter template
  paramant-supply-chain --help

Output: human-readable table + ${REPORT_FILE}
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan)    MODE="scan" ;;
    --report)  MODE="report" ;;
    --vendor)  MODE="vendor"; SINGLE_VENDOR="$2"; shift ;;
    --letter)  MODE="letter"; LETTER_DOMAIN="$2"; shift ;;
    --help|-h) usage ;;
    *) echo -e "${RED}Unknown option: $1${RESET}" >&2; usage ;;
  esac; shift
done

[[ -z "$MODE" ]] && MODE="scan"

# ── TLS inspector ─────────────────────────────────────────────────────────────
check_tls() {
  local host="$1" port="${2:-443}"
  local result algo keybits tls_ver expiry qs risk

  result=$(echo Q | timeout 8 openssl s_client \
    -connect "${host}:${port}" \
    -servername "${host}" \
    -brief 2>&1) || { echo "TIMEOUT"; return; }

  # TLS version
  tls_ver=$(echo "$result" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1)
  [[ -z "$tls_ver" ]] && tls_ver=$(echo "$result" | grep -oP 'TLS\S+' | head -1)

  # Certificate info via full output
  local cert_text
  cert_text=$(echo Q | timeout 8 openssl s_client \
    -connect "${host}:${port}" \
    -servername "${host}" 2>/dev/null | openssl x509 -noout -text 2>/dev/null) || cert_text=""

  algo=$(echo "$cert_text" | grep -oP '(rsaEncryption|id-ecPublicKey|ECDSA|ML-KEM|Dilithium)' | head -1)
  keybits=$(echo "$cert_text" | grep -oP 'Public-Key: \(\K[0-9]+' | head -1)
  expiry=$(echo Q | timeout 8 openssl s_client \
    -connect "${host}:${port}" -servername "${host}" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 | cut -c1-11)

  # Normalize algorithm name
  case "$algo" in
    rsaEncryption)  algo="RSA-${keybits:-2048}"; qs="false"; risk="HIGH" ;;
    id-ecPublicKey) algo="ECDSA-${keybits:-256}"; qs="partial"; risk="MEDIUM" ;;
    ML-KEM*)        algo="ML-KEM (PQC)"; qs="true"; risk="OK" ;;
    Dilithium*)     algo="ML-DSA (PQC)"; qs="true"; risk="OK" ;;
    *)              algo="ECDSA-256"; qs="partial"; risk="MEDIUM" ;;  # modern default
  esac

  # Downgrade risk for old TLS
  if echo "$tls_ver" | grep -qE 'TLSv1\.(0|1)'; then
    risk="HIGH"; qs="false"
    algo="${algo}+TLS1.0/1.1"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$host" "${tls_ver:-unknown}" "$algo" "$qs" "$risk" "${expiry:-unknown}"
}

# ── discover outbound connections ─────────────────────────────────────────────
discover_vendors() {
  echo -e "  ${DIM}Discovering outbound connections...${RESET}"
  local seen=()
  local hosts=()

  # Method 1: active TCP connections (ss)
  while IFS= read -r line; do
    local peer; peer=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
    [[ "$peer" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    # skip private/loopback
    echo "$peer" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)' && continue
    hosts+=("$peer")
  done < <(ss -tnp state established 2>/dev/null | tail -n +2)

  # Method 2: /etc/hosts and configured remotes
  for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* \
              /etc/apache2/sites-enabled/* \
              /etc/postfix/main.cf \
              /opt/paramant/docker-compose.yml \
              ~/paramant-master/docker-compose.yml; do
    [[ -f "$conf" ]] || continue
    grep -oP 'https?://\K[a-zA-Z0-9._-]+' "$conf" 2>/dev/null \
      | grep -vE '^(localhost|127\.0\.0\.1|0\.0\.0\.0)$' >> /tmp/sc-hosts-$$ 2>/dev/null || true
  done

  # Method 3: DNS resolver config
  grep -oP 'nameserver\s+\K\S+' /etc/resolv.conf 2>/dev/null >> /tmp/sc-hosts-$$ || true

  # Method 4: docker network peers
  if command -v docker >/dev/null 2>&1; then
    docker ps -q 2>/dev/null | while read -r cid; do
      docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
        | grep -oP 'https?://\K[a-zA-Z0-9._-]+' >> /tmp/sc-hosts-$$ 2>/dev/null || true
    done
  fi

  # Resolve IPs to hostnames and deduplicate
  if [[ -f /tmp/sc-hosts-$$ ]]; then
    while IFS= read -r h; do
      [[ -z "$h" ]] && continue
      hosts+=("$h")
    done < /tmp/sc-hosts-$$
  fi
  rm -f /tmp/sc-hosts-$$

  # Resolve IPs → hostnames
  for h in "${hosts[@]}"; do
    if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      local resolved; resolved=$(host "$h" 2>/dev/null | grep -oP 'pointer \K\S+' | sed 's/\.$//' | head -1)
      [[ -n "$resolved" ]] && h="$resolved"
    fi
    # deduplicate
    local dupe=0
    for s in "${seen[@]:-}"; do [[ "$s" == "$h" ]] && dupe=1 && break; done
    [[ $dupe -eq 1 ]] && continue
    seen+=("$h")
    echo "$h"
  done
}

# ── package manager crypto check ──────────────────────────────────────────────
check_packages() {
  echo -e "\n${BOLD}PACKAGE CRYPTO DEPENDENCIES${RESET}"
  local found=0

  # npm
  if command -v npm >/dev/null 2>&1; then
    echo -e "  ${DIM}npm packages...${RESET}"
    local vulns; vulns=$(npm audit --json 2>/dev/null | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  vulns=[v for v in d.get('vulnerabilities',{}).values()
         if any(k in v.get('name','').lower() for k in ['crypto','ssl','tls','rsa','openssl'])]
  [print(f\"  [npm] {v['name']}: {v.get('severity','?').upper()}\") for v in vulns]
except: pass
" 2>/dev/null) || true
    [[ -n "$vulns" ]] && echo "$vulns" && found=1
  fi

  # pip
  if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
    echo -e "  ${DIM}Python crypto packages...${RESET}"
    local pipcmd; pipcmd=$(command -v pip3 || command -v pip)
    "$pipcmd" list 2>/dev/null | grep -iE 'cryptography|pyopenssl|pycrypto|paramiko|ssl' \
      | while read -r pkg ver; do
          echo -e "  ${CYAN}[pip]${RESET} ${pkg} ${ver} — verify is up-to-date"
        done
    found=1
  fi

  # apt
  if command -v dpkg >/dev/null 2>&1; then
    echo -e "  ${DIM}System crypto packages...${RESET}"
    dpkg -l 2>/dev/null | awk '/^ii/{print $2,$3}' \
      | grep -iE '^(openssl|libssl|gnutls|nss|libgcrypt|libsodium|bouncycastle|python3-crypto)' \
      | while read -r pkg ver; do
          local color="$DIM"
          # Flag old openssl
          echo "$ver" | grep -qE '^1\.[01]\.' && color="$YELLOW"
          echo -e "  ${color}[apt]${RESET} ${pkg} ${ver}"
        done
    found=1
  fi

  [[ $found -eq 0 ]] && echo -e "  ${DIM}No package managers found${RESET}"
}

# ── scan mode ─────────────────────────────────────────────────────────────────
do_scan() {
  echo -e "\n${BOLD}=== SUPPLY CHAIN CRYPTO SCAN ===${RESET}"
  echo -e "Date: ${SCAN_DATE}"
  echo -e "Discovering outbound connections...\n"

  local vendor_list=()
  while IFS= read -r vendor; do
    [[ -z "$vendor" ]] && continue
    vendor_list+=("$vendor")
  done < <(discover_vendors)

  local total=${#vendor_list[@]}
  echo -e "Found ${BOLD}${total}${RESET} external endpoints. Checking TLS posture...\n"

  local high_count=0 medium_count=0 ok_count=0

  printf "%-35s %-10s %-22s %-10s\n" "ENDPOINT" "TLS" "CERT ALGORITHM" "RISK"
  printf '%s\n' "$(printf '─%.0s' {1..80})"

  for vendor in "${vendor_list[@]}"; do
    echo -e "  ${DIM}Checking ${vendor}...${RESET}" >&2
    local result; result=$(check_tls "$vendor" 2>/dev/null) || result="ERROR	unknown	unknown	false	ERROR	unknown"
    local host tls_ver algo qs risk expiry
    IFS=$'\t' read -r host tls_ver algo qs risk expiry <<< "$result"

    local color="$GREEN"
    case "$risk" in
      HIGH)    color="$RED";    ((high_count++)) ;;
      MEDIUM)  color="$YELLOW"; ((medium_count++)) ;;
      OK)      color="$GREEN";  ((ok_count++)) ;;
      ERROR)   color="$DIM" ;;
      TIMEOUT) color="$DIM" ;;
    esac

    printf "${color}%-35s %-10s %-22s %-10s${RESET}\n" \
      "${vendor:0:34}" "${tls_ver:0:9}" "${algo:0:21}" "$risk"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$vendor" "$tls_ver" "$algo" "$qs" "$risk" "$expiry" >> "$VENDORS_FILE"
  done

  printf '%s\n' "$(printf '─%.0s' {1..80})"
  echo ""

  # HNDL context
  if [[ $high_count -gt 0 ]]; then
    echo -e "${RED}${BOLD}⚠  HARVEST-NOW-DECRYPT-LATER: SUPPLY CHAIN RISK${RESET}"
    echo -e "   ${RED}${high_count} suppliers use RSA/weak TLS. Encrypted data exchanged with these"
    echo -e "   vendors is being harvested by state actors TODAY and will be decrypted"
    echo -e "   when Q-Day arrives (~2029). This includes file transfers, API calls, and"
    echo -e "   authentication tokens.${RESET}"
    echo ""
  fi

  echo -e "SUMMARY:"
  echo -e "  ${RED}HIGH risk (RSA/TLS1.0):${RESET}      ${high_count} vendors"
  echo -e "  ${YELLOW}MEDIUM risk (ECDSA, no PQC):${RESET} ${medium_count} vendors"
  echo -e "  ${GREEN}OK (ECDSA/PQC transitional):${RESET} ${ok_count} vendors"
  echo ""
  [[ $high_count -gt 0 ]] && \
    echo -e "ACTION: Contact ${RED}${BOLD}${high_count}${RESET} vendors about their PQC migration timeline."
  echo -e "Template letter: ${CYAN}paramant-supply-chain --letter <domain>${RESET}"
  echo ""

  check_packages
  generate_json_report "$total" "$high_count" "$medium_count" "$ok_count"
}

# ── single vendor check ────────────────────────────────────────────────────────
do_vendor() {
  local url="$1"
  local host; host=$(echo "$url" | sed 's|^https\?://||' | cut -d/ -f1 | cut -d: -f1)
  local port; port=$(echo "$url" | grep -oP ':\K[0-9]+' | head -1); port="${port:-443}"

  echo -e "\n${BOLD}=== VENDOR TLS CHECK ===${RESET}"
  echo -e "Endpoint: ${CYAN}${host}:${port}${RESET}\n"

  local result; result=$(check_tls "$host" "$port")
  local h tls_ver algo qs risk expiry
  IFS=$'\t' read -r h tls_ver algo qs risk expiry <<< "$result"

  echo -e "TLS version:      ${tls_ver:-unknown}"
  echo -e "Cert algorithm:   ${algo:-unknown}"
  echo -e "Expiry:           ${expiry:-unknown}"

  case "$risk" in
    HIGH)
      echo -e "Risk:             ${RED}${BOLD}HIGH — RSA or TLS 1.0/1.1 detected${RESET}"
      echo -e "\n${RED}⚠  HNDL RISK: All data exchanged with this vendor is potentially being"
      echo -e "   harvested now. RSA key exchange allows retroactive decryption once"
      echo -e "   sufficiently large quantum computers exist (~2029 estimate).${RESET}"
      echo -e "\nAction: Contact vendor — use: ${CYAN}paramant-supply-chain --letter ${host}${RESET}"
      ;;
    MEDIUM)
      echo -e "Risk:             ${YELLOW}MEDIUM — ECDSA (harvest risk exists, not PQC-safe)${RESET}"
      echo -e "\nECDSA is safer than RSA but not quantum-resistant. Harvested data remains"
      echo -e "at risk. Request PQC migration timeline from vendor."
      ;;
    OK)
      echo -e "Risk:             ${GREEN}OK — PQC or strong ECDSA detected${RESET}"
      ;;
    *)
      echo -e "Risk:             ${DIM}Could not connect or determine algorithm${RESET}"
      ;;
  esac
}

# ── vendor letter template ─────────────────────────────────────────────────────
do_letter() {
  local domain="$1"
  cat <<EOF

${BOLD}=== PQC MIGRATION INQUIRY — TEMPLATE LETTER ===${RESET}
Send to: security@${domain} or privacy@${domain}

Subject: Post-Quantum Cryptography Migration — Inquiry re TLS/API Security

Dear ${domain} security team,

We are conducting a supply chain cryptography assessment as required under NIS2
Directive (EU 2022/2555) and our internal NCSC PQC migration policy.

Our scan of your endpoints (${domain}) indicates you are currently using
RSA-based or non-post-quantum-safe TLS certificates. Under the
"Harvest Now, Decrypt Later" (HNDL) threat model, encrypted data exchanged
between our systems is potentially being collected by state-level adversaries
today, with the intent to decrypt it when cryptographically relevant quantum
computers become available (estimated 2029–2031).

We request the following information:

1. Do you have a PQC migration roadmap? If so, what is your target date?
2. Are you planning to implement ML-KEM-768 (NIST FIPS 203) or hybrid
   post-quantum TLS for your API endpoints?
3. Does your organisation have a NCSC or BSI-aligned PQC migration plan?

We may need to restrict data exchange with vendors who cannot provide a
credible PQC migration timeline, as required by our compliance obligations.

We would appreciate a response within 30 days.

References:
- NIST FIPS 203 (ML-KEM-768): https://csrc.nist.gov/pubs/fips/203/final
- NCSC PQC migration: https://english.ncsc.nl
- NIS2 supply chain security: Article 21(2)(d)

Regards,
[Your name / security team]
[Organisation]
[Contact]

---
Generated by: paramant-supply-chain --letter ${domain}
Date: ${SCAN_DATE}
EOF
}

# ── JSON report ────────────────────────────────────────────────────────────────
generate_json_report() {
  local total="$1" high="$2" medium="$3" ok="$4"
  python3 - "$VENDORS_FILE" "$REPORT_FILE" "$SCAN_DATE" "$total" "$high" "$medium" "$ok" <<'PYEOF'
import json, sys

vendors_path, report_path, scan_date, total, high, medium, ok = sys.argv[1:]
vendors = []

with open(vendors_path) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) < 6: continue
        host, tls_ver, algo, qs, risk, expiry = parts[:6]
        vendors.append({
            "host": host, "tls_version": tls_ver, "algorithm": algo,
            "quantum_safe": qs == "true", "risk": risk, "cert_expiry": expiry
        })

vendors.sort(key=lambda x: {"HIGH": 0, "MEDIUM": 1, "OK": 2, "ERROR": 3, "TIMEOUT": 3}.get(x["risk"], 4))

report = {
    "scan_date": scan_date,
    "summary": {
        "total_vendors": int(total),
        "high_risk": int(high),
        "medium_risk": int(medium),
        "ok": int(ok),
        "hndl_risk": int(high) > 0
    },
    "vendors": vendors
}

with open(report_path, 'w') as f:
    json.dump(report, f, indent=2)

print(f"\nReport written: {report_path}")
PYEOF
}

# ── dispatch ───────────────────────────────────────────────────────────────────
case "$MODE" in
  scan)   do_scan ;;
  report) do_scan ;;
  vendor) do_vendor "$SINGLE_VENDOR" ;;
  letter) do_letter "$LETTER_DOMAIN" ;;
esac
