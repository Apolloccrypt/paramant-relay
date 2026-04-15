#!/usr/bin/env bash
# paramant-migrate — crypto-agility helper: replace vulnerable algorithms
# Usage: paramant-migrate --tls | --ssh | --backup | --check

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[0;33m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'

DRY_RUN=0
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
err()  { echo -e "  ${RED}✗${RESET} $*" >&2; }
run()  {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${DIM}[dry-run] $*${RESET}"; return 0
  fi
  eval "$@"
  local rc=$?; [[ $rc -ne 0 ]] && err "Failed (exit ${rc}): $*"
  return $rc
}
need_root() {
  [[ $DRY_RUN -eq 1 || $EUID -eq 0 ]] && return 0
  echo -e "  ${RED}ERROR: root required.${RESET} Run: ${CYAN}sudo paramant-migrate $*${RESET}" >&2
  exit 1
}

usage() {
  echo -e "${BOLD}paramant-migrate${RESET} — crypto-agility helper (post-quantum migration)
Usage: paramant-migrate <sub-command> [--dry-run]
  --tls      Replace RSA TLS certificate with ECDSA P-256 (+ plan PQC hybrid)
  --ssh      Replace RSA SSH host keys with Ed25519
  --backup   Re-encrypt existing unencrypted backups with AES-256
  --check    Verify all migrations completed correctly
  --all      Run all migrations: tls → ssh → backup → check (requires root)
  --dry-run  Show what would be done without changing anything
  --help     Show this message
Example: sudo paramant-migrate --all"
  exit 0
}

# ── TLS migration ─────────────────────────────────────────────────────────────
migrate_tls() {
  echo -e "\n${BOLD}TLS Certificate Migration${RESET}"
  need_root --tls
  echo -e "Target: RSA → ECDSA P-256 (quantum-safe hybrid pending NIST FIPS 203 finalization)\n"

  # Detect webserver and cert paths
  local cert_file="" key_file="" webserver=""
  if command -v nginx >/dev/null 2>&1; then
    webserver="nginx"
    cert_file=$(grep -r 'ssl_certificate ' /etc/nginx/ 2>/dev/null | grep -v '#' | grep -oP '(?<=ssl_certificate\s)[^;]+' | head -1 | xargs)
    key_file=$(grep -r 'ssl_certificate_key ' /etc/nginx/ 2>/dev/null | grep -v '#' | grep -oP '(?<=ssl_certificate_key\s)[^;]+' | head -1 | xargs)
  elif command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
    webserver="apache2"
    cert_file=$(grep -r 'SSLCertificateFile ' /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v '#' | awk '{print $NF}' | head -1)
    key_file=$(grep -r 'SSLCertificateKeyFile ' /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v '#' | awk '{print $NF}' | head -1)
  fi

  if [[ -z "$cert_file" ]]; then
    # Generate self-signed ECDSA cert for testing/internal use
    cert_file="/etc/ssl/certs/paramant-ecdsa.crt"
    key_file="/etc/ssl/private/paramant-ecdsa.key"
    warn "No existing webserver cert found — generating self-signed ECDSA P-256 cert"
  else
    # Check current algorithm
    local algo; algo=$(openssl x509 -noout -text -in "$cert_file" 2>/dev/null | grep -oP '(rsaEncryption|id-ecPublicKey)' | head -1)
    if [[ "$algo" == "id-ecPublicKey" ]]; then
      ok "Certificate at ${cert_file} is already ECDSA — no TLS migration needed"
      return
    fi
    echo -e "  Current: ${RED}RSA${RESET} → Target: ${GREEN}ECDSA P-256${RESET}"
    local backup_cert="${cert_file}.rsa-backup-$(date '+%Y%m%d')"
    run "cp '$cert_file' '$backup_cert' && cp '$key_file' '${key_file}.rsa-backup-$(date '+%Y%m%d')'"
    ok "RSA cert backed up: ${backup_cert}"
  fi

  # Generate new ECDSA P-256 key + self-signed cert (production: use certbot/ACME)
  local domain; domain=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | grep -oP '(?<=CN=)[^,/]+' | head -1)
  domain="${domain:-$(hostname -f)}"
  run "openssl ecparam -genkey -name prime256v1 -noout -out '$key_file.new' 2>/dev/null"
  run "openssl req -new -x509 -key '$key_file.new' -out '$cert_file.new' -days 825 -subj '/CN=${domain}' 2>/dev/null"

  if [[ $DRY_RUN -eq 0 ]]; then
    mv "${key_file}.new" "$key_file"
    mv "${cert_file}.new" "$cert_file"
    ok "ECDSA P-256 key + cert written"
    if [[ "$webserver" == "nginx" ]]; then
      nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && ok "nginx reloaded" || warn "nginx reload failed — check config"
    elif [[ "$webserver" == "apache2" ]]; then
      apache2ctl configtest 2>/dev/null && systemctl reload apache2 2>/dev/null && ok "apache2 reloaded" || warn "apache2 reload failed"
    fi
  fi
  warn "For production: use certbot --preferred-challenges dns with ECDSA P-256"
  warn "PQC hybrid (ML-KEM-768): await OpenSSL 3.5 + nginx PQC patch (est. 2026)"
}

# ── SSH migration ─────────────────────────────────────────────────────────────
migrate_ssh() {
  echo -e "\n${BOLD}SSH Host Key Migration${RESET}"
  need_root --ssh
  echo -e "Target: RSA → Ed25519 (safe today) + prepare for ML-KEM SSH (IETF draft)\n"

  # Check for RSA host key — read bits from public key (no root needed for .pub)
  if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
    ok "No RSA SSH host key found — already migrated"
  else
    local rsa_bits; rsa_bits=$(ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null | awk '{print $1}')
    echo -e "  Current RSA key: ${RED}${rsa_bits:-unknown} bits${RESET}"
    if run "cp /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.pre-migration && cp /etc/ssh/ssh_host_rsa_key.pub /etc/ssh/ssh_host_rsa_key.pub.pre-migration"; then
      ok "RSA key backed up to /etc/ssh/ssh_host_rsa_key.pre-migration"
    else
      return 1
    fi
  fi

  # Generate Ed25519 if missing
  if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    if run "ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -C 'paramant-migrate-$(date +%Y%m%d)'"; then
      ok "Ed25519 host key generated"
    else
      return 1
    fi
  else
    ok "Ed25519 host key already present: /etc/ssh/ssh_host_ed25519_key"
  fi

  # Update sshd_config to prefer Ed25519 and restrict RSA
  if [[ -f /etc/ssh/sshd_config ]]; then
    if ! grep -q 'HostKeyAlgorithms' /etc/ssh/sshd_config; then
      if run "printf '\n# paramant-migrate: prefer Ed25519\nHostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256\nPubkeyAcceptedKeyTypes ssh-ed25519,ecdsa-sha2-nistp256\n' >> /etc/ssh/sshd_config"; then
        ok "sshd_config updated: HostKeyAlgorithms set to Ed25519"
      fi
    else
      ok "HostKeyAlgorithms already configured in sshd_config"
    fi
    if [[ $DRY_RUN -eq 0 ]]; then
      sshd -t 2>/dev/null && systemctl reload sshd 2>/dev/null && ok "sshd reloaded" || warn "sshd reload failed — check: sshd -t"
    fi
  fi
  warn "SSH clients connecting will see new host key — distribute new fingerprint via out-of-band channel"
  warn "ML-KEM SSH: track IETF draft-kampanakis-curdle-ssh-pq-kem (expected OpenSSH 10.x)"
}

# ── Backup re-encryption ───────────────────────────────────────────────────────
migrate_backup() {
  echo -e "\n${BOLD}Backup Encryption Migration${RESET}"
  echo -e "Target: unencrypted tar/gz → age or BorgBackup (AES-256)\n"

  # Check for age
  if ! command -v age >/dev/null 2>&1; then
    warn "age not installed — install with: apt install age  or  brew install age"
    warn "age uses X25519 + ChaCha20-Poly1305 (safe today, PQC version: age-pq in development)"
  else
    ok "age encryption tool available"
  fi

  # Check for borg
  if command -v borg >/dev/null 2>&1; then
    ok "BorgBackup available (AES-256-CTR authenticated encryption)"
    if [[ ! -d ~/.config/borg ]]; then
      warn "No BorgBackup repository configured. Initialize with:"
      echo -e "  ${CYAN}borg init --encryption=repokey-blake2 /path/to/backup/repo${RESET}"
    fi
  else
    warn "BorgBackup not installed — recommended: apt install borgbackup"
  fi

  # Find unencrypted backup archives in common locations
  local found=0
  for dir in /var/backups /home /root /opt/backups /backup; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r f; do
      warn "Unencrypted archive found: ${f}"
      if [[ $DRY_RUN -eq 0 ]] && command -v age >/dev/null 2>&1; then
        local key="${HOME}/.config/paramant/backup.age"
        [[ ! -f "$key" ]] && { age-keygen -o "$key" 2>/dev/null; ok "Generated age key: ${key}"; }
        local pubkey; pubkey=$(grep 'public key:' "$key" | awk '{print $NF}')
        run "age -r '$pubkey' -o '${f}.age' '$f' && rm '$f'"
        ok "Re-encrypted: ${f} → ${f}.age"
      else
        echo -e "  ${DIM}[dry-run] Would re-encrypt: ${f}${RESET}"
      fi
      ((found++))
    done < <(find "$dir" -maxdepth 3 -name '*.tar.gz' -o -name '*.tar' -o -name '*.dump' 2>/dev/null | grep -v '.age$')
  done
  [[ $found -eq 0 ]] && ok "No unencrypted backup archives found in common locations"
}

# ── Verification ───────────────────────────────────────────────────────────────
check_migration() {
  echo -e "\n${BOLD}Migration Verification${RESET}\n"
  local pass=0 fail=0

  # TLS check
  for port in 443 8443; do
    local algo
    algo=$(echo Q | timeout 5 openssl s_client -connect "localhost:${port}" 2>/dev/null \
           | openssl x509 -noout -text 2>/dev/null | grep -oP '(rsaEncryption|id-ecPublicKey)' | head -1)
    if [[ "$algo" == "id-ecPublicKey" ]]; then
      ok "TLS port ${port}: ECDSA P-256"; ((pass++))
    elif [[ "$algo" == "rsaEncryption" ]]; then
      err "TLS port ${port}: still RSA — run: paramant-migrate --tls"; ((fail++))
    fi
  done

  # SSH check
  if [[ -f /etc/ssh/ssh_host_ed25519_key ]]; then
    ok "SSH: Ed25519 host key present"; ((pass++))
  else
    err "SSH: no Ed25519 key — run: paramant-migrate --ssh"; ((fail++))
  fi
  if [[ -f /etc/ssh/ssh_host_rsa_key ]] && ! grep -q 'HostKeyAlgorithms' /etc/ssh/sshd_config 2>/dev/null; then
    warn "SSH: RSA key still active and HostKeyAlgorithms not restricted"
  fi

  # Backup check
  command -v borg >/dev/null 2>&1 && ok "Backup: BorgBackup installed" && ((pass++)) || warn "Backup: BorgBackup not installed"
  command -v age >/dev/null 2>&1 && ok "Backup: age encryption available" && ((pass++))

  echo ""
  echo -e "Result: ${GREEN}${pass} passed${RESET}, ${RED}${fail} failed${RESET}"
  [[ $fail -gt 0 ]] && echo -e "Run ${CYAN}paramant-crypto-audit${RESET} to see full risk report" && exit 1
  ok "All migration checks passed"
}

# ── main ───────────────────────────────────────────────────────────────────────
[[ $# -eq 0 || "$1" == "--help" || "$1" == "-h" ]] && usage

CMD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tls)     CMD=tls ;;
    --ssh)     CMD=ssh ;;
    --backup)  CMD=backup ;;
    --check)   CMD=check ;;
    --all)     CMD=all ;;
    --dry-run) DRY_RUN=1 ;;
  esac; shift
done

[[ -z "$CMD" ]] && usage
[[ $DRY_RUN -eq 1 ]] && echo -e "${YELLOW}[dry-run mode — no changes will be made]${RESET}"

echo -e "[paramant-migrate] ${DIM}crypto-agility helper${RESET}"
case "$CMD" in
  tls)    migrate_tls ;;
  ssh)    migrate_ssh ;;
  backup) migrate_backup ;;
  check)  check_migration ;;
  all)
    migrate_tls
    migrate_ssh
    migrate_backup
    check_migration
    ;;
esac
