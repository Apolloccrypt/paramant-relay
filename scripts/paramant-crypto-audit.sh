#!/usr/bin/env bash
# paramant-crypto-audit — crypto inventory scanner + Harvest-Now-Decrypt-Later risk assessment
# Usage: paramant-crypto-audit [--remote HOST] [--report pdf] [--compare]

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[0;33m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'

SCAN_DATE=$(date '+%Y-%m-%d')
HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)
REMOTE=""; REPORT_FORMAT="text"; DO_COMPARE=0; LOCAL_MODE=0
FINDINGS_FILE=$(mktemp /tmp/crypto-audit-XXXXXX.tsv)
REPORT_FILE="crypto-audit-${SCAN_DATE}.json"
trap 'rm -f "$FINDINGS_FILE"' EXIT

usage() {
  echo -e "${BOLD}paramant-crypto-audit${RESET} — crypto inventory + HNDL risk scanner
Usage: paramant-crypto-audit [options]
  --remote HOST   Scan remote host via SSH (requires key auth)
  --compare       Compare to last scan, show new risks
  --report pdf    Generate PDF report (requires wkhtmltopdf)
  --help          Show this message
Output: human-readable summary + ${REPORT_FILE}"
  exit 0
}

# ── finding accumulator ────────────────────────────────────────────────────────
# Format: severity TAB category TAB item TAB algorithm TAB quantum_safe TAB action
add_finding() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$FINDINGS_FILE"
}

# ── 1. TLS certificates ────────────────────────────────────────────────────────
scan_tls() {
  echo -e "  ${DIM}Scanning TLS certificates...${RESET}"
  local ports
  ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -un | grep -E '^(443|465|587|993|995|8443|8080|4430)$')
  [[ -z "$ports" ]] && ports="443"
  while IFS= read -r port; do
    local info algo expiry qs sev action
    info=$(echo Q | timeout 5 openssl s_client -connect "localhost:${port}" 2>/dev/null | openssl x509 -noout -text 2>/dev/null) || continue
    algo=$(echo "$info" | grep -oP '(RSA|ECDSA|id-ecPublicKey|rsaEncryption)' | head -1)
    expiry=$(echo Q | timeout 5 openssl s_client -connect "localhost:${port}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    keybits=$(echo "$info" | grep -oP 'Public-Key: \(\K[0-9]+' | head -1)
    case "$algo" in
      RSA*|rsaEncryption)
        qs="false"; sev="HIGH"
        action="Replace with ECDSA P-256 + PQC hybrid before 2027 (NIST FIPS 203)"
        algo="RSA-${keybits:-2048}" ;;
      ECDSA*|id-ecPublicKey)
        qs="false"; sev="MEDIUM"
        action="Add post-quantum hybrid extension (ML-KEM-768) — harvest risk remains"
        algo="ECDSA-${keybits:-256}" ;;
      *) qs="true"; sev="INFO"; action="Quantum-safe — no action required"; algo="PQC/hybrid" ;;
    esac
    [[ -n "$expiry" ]] && action="${action}. Expires: ${expiry}"
    add_finding "$sev" "TLS" "TLS cert on port ${port}" "$algo" "$qs" "$action"
  done <<< "$ports"
}

# ── 2. SSH host keys ───────────────────────────────────────────────────────────
scan_ssh() {
  echo -e "  ${DIM}Scanning SSH host keys...${RESET}"
  for pubkey in /etc/ssh/ssh_host_*_key.pub; do
    [[ -f "$pubkey" ]] || continue
    local type algo sev qs action
    type=$(awk '{print $1}' "$pubkey")
    case "$type" in
      ssh-rsa)     algo="RSA"; sev="HIGH"; qs="false"; action="Replace with Ed25519: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key" ;;
      ecdsa-*)     algo="ECDSA"; sev="MEDIUM"; qs="false"; action="ECDSA safe for now but not PQC — plan ML-KEM migration" ;;
      ssh-ed25519) algo="Ed25519"; sev="LOW"; qs="false"; action="Ed25519 is safe today but not PQC — add ML-KEM config when available" ;;
      *)           algo="$type"; sev="INFO"; qs="true"; action="Verify algorithm is quantum-safe" ;;
    esac
    add_finding "$sev" "SSH" "SSH host key: $(basename "$pubkey")" "$algo" "$qs" "$action"
  done
}

# ── 3. Running services ────────────────────────────────────────────────────────
scan_services() {
  echo -e "  ${DIM}Scanning running services...${RESET}"
  local procs
  procs=$(ps -eo comm 2>/dev/null | sort -u)
  # nginx/apache/postfix/dovecot/mysql/postgres are covered by scan_tls/scan_email/scan_database
  declare -A SERVICE_RISK=(
    ["redis-server"]="MEDIUM|Redis: TLS disabled by default|None|false|Enable tls-port and tls-cert-file in redis.conf"
    ["mongod"]="MEDIUM|MongoDB: verify TLS config|RSA typical|false|Set net.tls.mode=requireTLS and use ECDSA cert in mongod.conf"
    ["haproxy"]="MEDIUM|HAProxy TLS termination|RSA typical|false|Check bind ssl crt directive; replace cert with ECDSA P-256"
    ["stunnel4"]="MEDIUM|stunnel TLS proxy|RSA typical|false|Check cert= in stunnel.conf; replace with ECDSA"
  )
  for svc in "${!SERVICE_RISK[@]}"; do
    echo "$procs" | grep -qx "$svc" || continue
    IFS='|' read -r sev item algo qs action <<< "${SERVICE_RISK[$svc]}"
    add_finding "$sev" "Service" "${item} (${svc})" "$algo" "$qs" "$action"
  done
}

# ── 4. Docker containers ───────────────────────────────────────────────────────
scan_docker() {
  command -v docker >/dev/null 2>&1 || return
  echo -e "  ${DIM}Scanning Docker containers...${RESET}"
  while IFS='|' read -r cid name image; do
    [[ -z "$cid" ]] && continue
    local created age_days
    created=$(docker inspect --format '{{.Created}}' "$cid" 2>/dev/null | cut -c1-10)
    age_days=$(( ( $(date +%s) - $(date -d "$created" +%s 2>/dev/null || echo 0) ) / 86400 ))
    if [[ $age_days -gt 365 ]]; then
      add_finding "MEDIUM" "Docker" "Container ${name} (${image})" "Unknown" "false" \
        "Image is ${age_days} days old — rebuild with current base image to pick up crypto library updates"
    fi
    # Check for known vulnerable base patterns
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
      | grep -qi "openssl_1\|ssl_version=TLS1_0\|ssl_version=TLS1_1" && \
      add_finding "HIGH" "Docker" "Container ${name}: legacy TLS env var" "TLS1.0/1.1" "false" \
        "Remove legacy TLS version pins from container environment"
  done < <(docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}' 2>/dev/null)
}

# ── 5. Cron jobs with long-retention data ─────────────────────────────────────
scan_cron() {
  echo -e "  ${DIM}Scanning cron jobs for HNDL risk...${RESET}"
  local cron_files=()
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do [[ -f "$f" ]] && cron_files+=("$f"); done
  for f in "${cron_files[@]}"; do
    if grep -qiE 'backup|dump|archive|tar|pg_dump|mysqldump|rsync' "$f" 2>/dev/null; then
      grep -qiE 'gpg|age|openssl|borgbackup|restic' "$f" 2>/dev/null \
        && add_finding "LOW" "Cron" "Cron job in $(basename "$f"): backup with encryption" "Encrypted" "false" "Verify backup encryption uses AES-256 or better" \
        || add_finding "HIGH" "Cron/HNDL" "Cron job in $(basename "$f"): unencrypted backup" "None" "false" \
             "HNDL risk: backup data can be harvested now, decrypted after Q-Day. Add encryption immediately."
    fi
  done
}

# ── 6. Files older than 5 years (HNDL risk) ───────────────────────────────────
scan_old_files() {
  echo -e "  ${DIM}Scanning for long-retention files (HNDL risk)...${RESET}" >&2
  local count=0
  for dir in /home /var/lib /var/backups /opt /srv /data; do
    [[ -d "$dir" ]] || continue
    local n
    n=$(find "$dir" -xdev -maxdepth 6 -type f -mtime +1825 2>/dev/null | wc -l)
    count=$(( count + n ))
  done
  if [[ $count -gt 0 ]]; then
    local sev="MEDIUM"; [[ $count -gt 1000 ]] && sev="HIGH"; [[ $count -gt 10000 ]] && sev="CRITICAL"
    add_finding "$sev" "HNDL" "${count} files older than 5 years detected" "Unknown" "false" \
      "HARVEST-NOW-DECRYPT-LATER: Sensitive files are at risk from Q-Day (est. 2029-2030). Re-encrypt with paramant or AES-256 now."
  fi
  echo "$count"
}

# ── 7. Email configuration ────────────────────────────────────────────────────
scan_email() {
  echo -e "  ${DIM}Scanning email configuration...${RESET}"
  if [[ -f /etc/postfix/main.cf ]]; then
    local cert algo
    cert=$(postconf -h smtpd_tls_cert_file 2>/dev/null)
    if [[ -n "$cert" && -f "$cert" ]]; then
      algo=$(openssl x509 -noout -text -in "$cert" 2>/dev/null | grep -oP '(rsaEncryption|id-ecPublicKey|ECDSA)' | head -1)
      [[ "$algo" == "rsaEncryption" ]] && \
        add_finding "HIGH" "Email" "Postfix SMTP TLS certificate" "RSA" "false" \
          "HNDL risk: STARTTLS with RSA exposes email metadata. Migrate to ECDSA + consider DANE/MTA-STS." || \
        add_finding "MEDIUM" "Email" "Postfix SMTP TLS certificate" "${algo:-unknown}" "false" \
          "Verify algorithm and plan post-quantum migration"
    else
      add_finding "HIGH" "Email" "Postfix: no TLS cert configured" "None" "false" "Enable STARTTLS with at minimum ECDSA certificate"
    fi
  fi
  for conf in /etc/dovecot/dovecot.conf /etc/dovecot/conf.d/10-ssl.conf; do
    [[ -f "$conf" ]] || continue
    grep -q 'ssl = yes\|ssl = required' "$conf" 2>/dev/null || \
      add_finding "HIGH" "Email" "Dovecot IMAP/POP3: SSL not enforced" "None" "false" "Set ssl = required in dovecot.conf"
  done
}

# ── 8. VPN configuration ──────────────────────────────────────────────────────
scan_vpn() {
  echo -e "  ${DIM}Scanning VPN configuration...${RESET}"
  if command -v wg >/dev/null 2>&1 || compgen -G '/etc/wireguard/*.conf' >/dev/null 2>&1; then
    add_finding "LOW" "VPN" "WireGuard VPN detected" "Curve25519+ChaCha20" "false" \
      "WireGuard is safe today but not PQC — monitor NIST WireGuard PQC extension (draft)"
  fi
  # Use find instead of ** glob (globstar not enabled by default)
  while IFS= read -r conf; do
    [[ -f "$conf" ]] || continue
    local cert; cert=$(grep -oP '(?<=cert\s)[^\s]+' "$conf" | head -1)
    if [[ -n "$cert" && -f "$cert" ]]; then
      local algo; algo=$(openssl x509 -noout -text -in "$cert" 2>/dev/null | grep -oP '(rsaEncryption|id-ecPublicKey)' | head -1)
      [[ "$algo" == "rsaEncryption" ]] && \
        add_finding "HIGH" "VPN" "OpenVPN config: $(basename "$conf")" "RSA" "false" \
          "Replace RSA OpenVPN cert with ECDSA P-256. RSA TLS handshakes are harvestable." || \
        add_finding "MEDIUM" "VPN" "OpenVPN config: $(basename "$conf")" "${algo:-unknown}" "false" \
          "Verify cipher suite and plan post-quantum migration"
    fi
  done < <(find /etc/openvpn -name '*.conf' 2>/dev/null)
}

# ── 9. Database encryption ────────────────────────────────────────────────────
scan_database() {
  echo -e "  ${DIM}Scanning database encryption...${RESET}"
  for pgconf in /etc/postgresql/*/main/postgresql.conf; do
    [[ -f "$pgconf" ]] || continue
    grep -q '^ssl = on' "$pgconf" 2>/dev/null || \
      add_finding "HIGH" "Database" "PostgreSQL: SSL disabled" "None" "false" "Enable ssl = on and configure ssl_cert_file with ECDSA cert"
    grep -q 'ssl_cert_file' "$pgconf" 2>/dev/null && \
      add_finding "MEDIUM" "Database" "PostgreSQL: SSL enabled" "RSA/ECDSA" "false" "Verify certificate algorithm and upgrade to ECDSA if RSA"
  done
  for mycnf in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf; do
    [[ -f "$mycnf" ]] || continue
    grep -qi 'ssl-ca\|ssl-cert\|require_secure_transport' "$mycnf" 2>/dev/null || \
      add_finding "HIGH" "Database" "MySQL/MariaDB: TLS not configured" "None" "false" "Enable require_secure_transport=ON and configure ssl-cert (ECDSA)"
  done
}

# ── 10. Backup encryption ─────────────────────────────────────────────────────
scan_backup() {
  echo -e "  ${DIM}Scanning backup encryption...${RESET}"
  # BorgBackup
  for borgdir in ~/.config/borg /etc/borgbackup /root/.config/borg; do
    [[ -d "$borgdir" ]] || continue
    add_finding "LOW" "Backup" "BorgBackup config found: ${borgdir}" "AES-256-CTR" "false" \
      "BorgBackup uses AES-256 — safe today. No PQC backup encryption standard exists yet."
  done
  command -v borg >/dev/null 2>&1 && [[ -z "$(ls ~/.config/borg 2>/dev/null)" ]] && \
    add_finding "INFO" "Backup" "BorgBackup installed but no repo configured" "None" "false" "Configure encrypted BorgBackup repository"
  # Restic
  command -v restic >/dev/null 2>&1 && \
    add_finding "LOW" "Backup" "Restic detected" "AES-256-CTR" "false" \
      "Restic uses AES-256-CTR with Poly1305-AES — safe today, no PQC equivalent yet."
  # Unencrypted tar/gz in cron
  grep -r 'tar.*\-cz\|tar.*\-czf' /etc/cron* /var/spool/cron 2>/dev/null | grep -v 'gpg\|age\|encrypt' | grep -q . && \
    add_finding "HIGH" "Backup" "Unencrypted tar backup found in cron" "None" "false" \
      "HNDL RISK: unencrypted tar archives are harvestable. Pipe through: | age -r <pubkey> or | gpg --encrypt"
}

# ── JSON + report generation ──────────────────────────────────────────────────
generate_report() {
  local old_file_count="$1"
python3 - "$FINDINGS_FILE" "$REPORT_FILE" "$SCAN_DATE" "$HOSTNAME_FQDN" "$old_file_count" <<'PYEOF'
import json, sys, os

findings_path, report_path, scan_date, hostname, old_count = sys.argv[1:]
findings = []
severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

with open(findings_path) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) < 6: continue
        sev, cat, item, algo, qs, action = parts[:6]
        findings.append({"category": cat, "item": item, "algorithm": algo,
                          "quantum_safe": qs == "true", "severity": sev, "action": action})
        if sev in counts: counts[sev] += 1

findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
total = len(findings)
qs_count = sum(1 for f in findings if f["quantum_safe"])
qs_pct = round(qs_count / total * 100) if total else 0
harvest_risk = any("HNDL" in f.get("category", "") or int(old_count or 0) > 0 for f in findings)

risk = "LOW"
if counts["CRITICAL"] > 0: risk = "CRITICAL"
elif counts["HIGH"] > 2: risk = "HIGH"
elif counts["HIGH"] > 0: risk = "MEDIUM"

report = {
    "scan_date": scan_date,
    "hostname": hostname,
    "risk_level": risk,
    "harvest_risk": harvest_risk,
    "findings": findings,
    "summary": {
        "total_findings": total,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
        "quantum_safe_percentage": qs_pct
    }
}
with open(report_path, 'w') as out:
    json.dump(report, out, indent=2)
print(json.dumps({"risk": risk, "total": total, "qs_pct": qs_pct,
                  "critical": counts["CRITICAL"], "high": counts["HIGH"],
                  "medium": counts["MEDIUM"], "low": counts["LOW"]}, indent=0))
PYEOF
}

# ── human-readable output ─────────────────────────────────────────────────────
print_report() {
  local summary="$1" old_count="$2"
  local risk total critical high medium low qs_pct
  read -r risk total critical high medium low qs_pct < <(echo "$summary" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d['risk'], d['total'], d['critical'], d['high'], d['medium'], d['low'], d['qs_pct'])
" 2>/dev/null)

  local risk_color="$GREEN"
  [[ "$risk" == "MEDIUM" ]] && risk_color="$YELLOW"
  [[ "$risk" == "HIGH" || "$risk" == "CRITICAL" ]] && risk_color="$RED"

  echo ""
  echo -e "${BOLD}=== PARAMANT CRYPTO AUDIT ===${RESET}"
  echo -e "Host: ${BOLD}${HOSTNAME_FQDN}${RESET}"
  echo -e "Date: ${SCAN_DATE}"
  echo -e "Risk level: ${risk_color}${BOLD}${risk}${RESET}"
  echo -e "Quantum-safe: ${qs_pct}%"
  echo ""

  # Check HNDL risk: old files OR sensitive-data indicators in findings
  local hndl_risk=0
  [[ "$old_count" -gt 0 ]] && hndl_risk=1
  grep -qiE 'medical|dicom|patient|legal|financial|backup.*unencrypt|HNDL' "$FINDINGS_FILE" 2>/dev/null && hndl_risk=1

  if [[ $hndl_risk -eq 1 ]]; then
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║  ⚠  HARVEST-NOW-DECRYPT-LATER RISK DETECTED                 ║${RESET}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    [[ "$old_count" -gt 0 ]] && \
      echo -e "  ${RED}${BOLD}${old_count} files older than 5 years found on this system.${RESET}"
    echo -e "  Sensitive data indicators found in this scan."
    echo ""
    echo -e "  ${BOLD}What is happening RIGHT NOW:${RESET}"
    echo -e "  ${DIM}State actors systematically intercept + store encrypted traffic."
    echo -e "  When quantum computers arrive (~2029), all RSA-encrypted data"
    echo -e "  becomes retroactively readable. Medical records, legal documents,"
    echo -e "  and financial data are primary collection targets.${RESET}"
    echo ""
    echo -e "  ${BOLD}Immediate actions required:${RESET}"
    echo -e "  ${CYAN}1.${RESET} Enroll sensitive files in paramant relay: ${CYAN}paramant-sender --watch /sensitive/${RESET}"
    echo -e "  ${CYAN}2.${RESET} Re-encrypt unprotected backups:           ${CYAN}paramant-migrate --backup${RESET}"
    echo -e "  ${CYAN}3.${RESET} Check supplier chain TLS posture:         ${CYAN}paramant-supply-chain --scan${RESET}"
    echo ""
    echo -e "  More info: ${CYAN}https://paramant.app/hndl${RESET}"
    echo ""
    echo -e "${RED}$(printf '─%.0s' {1..64})${RESET}"
    echo ""
  fi

  echo -e "${BOLD}FINDINGS:${RESET}"
  while IFS=$'\t' read -r sev cat item algo qs action; do
    local color="$DIM"
    case "$sev" in
      CRITICAL) color="$RED" ;;
      HIGH)     color="$RED" ;;
      MEDIUM)   color="$YELLOW" ;;
      LOW)      color="$CYAN" ;;
    esac
    printf "  ${color}[%-8s]${RESET} %s: %s\n" "$sev" "$item" "$algo"
  done < "$FINDINGS_FILE"
  echo ""

  echo -e "${BOLD}NEXT STEPS:${RESET}"
  local step=1
  [[ "$critical" -gt 0 || "$high" -gt 0 ]] && \
    echo -e "  ${step}. Run: ${CYAN}paramant-migrate --tls${RESET}   to replace vulnerable TLS certificates" && ((step++))
  grep -qP 'SSH\t.*\tRSA' "$FINDINGS_FILE" && \
    echo -e "  ${step}. Run: ${CYAN}paramant-migrate --ssh${RESET}   to replace RSA SSH host keys" && ((step++))
  grep -q 'HNDL\|unencrypted' "$FINDINGS_FILE" && \
    echo -e "  ${step}. Run: ${CYAN}paramant-migrate --backup${RESET} to re-encrypt unprotected backups" && ((step++))
  [[ "$old_count" -gt 0 ]] && \
    echo -e "  ${step}. Enroll sensitive files: ${CYAN}paramant-sender --watch /sensitive/${RESET}"
  echo ""
  echo -e "Full report: ${BOLD}${REPORT_FILE}${RESET}"
  echo -e "Summary: ${total} findings — ${RED}${critical} critical${RESET}, ${RED}${high} high${RESET}, ${YELLOW}${medium} medium${RESET}, ${CYAN}${low} low${RESET}"
}

# ── compare to previous scan ──────────────────────────────────────────────────
compare_scan() {
  local prev; prev=$(ls crypto-audit-*.json 2>/dev/null | grep -v "$SCAN_DATE" | sort | tail -1)
  [[ -z "$prev" ]] && { echo -e "${YELLOW}No previous scan found to compare.${RESET}"; return; }
  echo -e "\n${BOLD}=== COMPARISON: ${prev} vs today ===${RESET}"
  python3 - "$prev" "$REPORT_FILE" <<'PYEOF'
import json, sys
prev = json.load(open(sys.argv[1]))
curr = json.load(open(sys.argv[2]))
prev_items = {f["item"] for f in prev.get("findings", [])}
curr_items = {f["item"] for f in curr.get("findings", [])}
new_risks = [f for f in curr.get("findings", []) if f["item"] not in prev_items]
resolved  = [f for f in prev.get("findings", []) if f["item"] not in curr_items]
if new_risks:
    print("\nNEW RISKS:")
    for f in new_risks: print(f"  [{f['severity']}] {f['item']}: {f['algorithm']}")
if resolved:
    print("\nRESOLVED:")
    for f in resolved: print(f"  [{f['severity']}] {f['item']}")
if not new_risks and not resolved:
    print("  No changes since last scan.")
prev_qs = prev.get("summary", {}).get("quantum_safe_percentage", 0)
curr_qs = curr.get("summary", {}).get("quantum_safe_percentage", 0)
diff = curr_qs - prev_qs
print(f"\nQuantum-safe: {prev_qs}% → {curr_qs}% ({'↑' if diff >= 0 else '↓'}{abs(diff)}%)")
PYEOF
}

# ── main ───────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote)  REMOTE="$2"; shift ;;
    --report)  REPORT_FORMAT="$2"; shift ;;
    --compare) DO_COMPARE=1 ;;
    --_local)  LOCAL_MODE=1 ;;
    --help|-h) usage ;;
  esac; shift
done

# Remote mode: send this script to the target host and run it there
if [[ -n "$REMOTE" && $LOCAL_MODE -eq 0 ]]; then
  echo -e "[paramant-crypto-audit] → ${CYAN}${REMOTE}${RESET} (via SSH)"
  ssh "$REMOTE" 'bash -s -- --_local' < "$0"
  exit $?
fi

echo -e "[paramant-crypto-audit] ${DIM}scanning ${HOSTNAME_FQDN}...${RESET}"
scan_tls
scan_ssh
scan_services
scan_docker
scan_cron
OLD_COUNT=$(scan_old_files)
scan_email
scan_vpn
scan_database
scan_backup

SUMMARY=$(generate_report "$OLD_COUNT")
print_report "$SUMMARY" "$OLD_COUNT"
[[ $DO_COMPARE -eq 1 ]] && compare_scan

if [[ "$REPORT_FORMAT" == "pdf" ]]; then
  command -v wkhtmltopdf >/dev/null 2>&1 || { echo -e "${YELLOW}wkhtmltopdf not found — install it for PDF output${RESET}"; exit 0; }
  python3 -c "
import json, sys
d = json.load(open('${REPORT_FILE}'))
rows = ''.join(f'<tr><td>{f[\"severity\"]}</td><td>{f[\"category\"]}</td><td>{f[\"item\"]}</td><td>{f[\"algorithm\"]}</td><td>{f[\"action\"]}</td></tr>' for f in d['findings'])
html = f'<!DOCTYPE html><html><head><style>body{{font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #333;padding:8px}} .HIGH{{color:#e66}} .CRITICAL{{color:#f00}} .MEDIUM{{color:#fa0}} .LOW{{color:#6af}}</style></head><body><h1>PARAMANT Crypto Audit — {d[\"scan_date\"]}</h1><p>Host: {d[\"hostname\"]} | Risk: {d[\"risk_level\"]} | Quantum-safe: {d[\"summary\"][\"quantum_safe_percentage\"]}%</p><table><tr><th>Severity</th><th>Category</th><th>Item</th><th>Algorithm</th><th>Action</th></tr>{rows}</table></body></html>'
open('crypto-audit-${SCAN_DATE}.html', 'w').write(html)
"
  wkhtmltopdf "crypto-audit-${SCAN_DATE}.html" "crypto-audit-${SCAN_DATE}.pdf" 2>/dev/null && \
    echo -e "PDF report: ${BOLD}crypto-audit-${SCAN_DATE}.pdf${RESET}" || \
    echo -e "HTML report: ${BOLD}crypto-audit-${SCAN_DATE}.html${RESET}"
fi
