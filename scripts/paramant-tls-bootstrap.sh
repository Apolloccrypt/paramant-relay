#!/usr/bin/env bash
# paramant-tls-bootstrap -- obtain a Let's Encrypt certificate for a relay domain.
#
# Called by install.sh (as root) after /setup has been applied with a domain.
# NOT called by the relay process itself: TLS issuance needs root + certbot,
# which the containerised relay must not have.
#
# Usage: paramant-tls-bootstrap.sh DOMAIN ADMIN_EMAIL [EXTRA_DOMAIN ...]
# Exit codes: 0 ok | 2 DNS mismatch | 3 certbot missing | 4 certbot failed
set -euo pipefail

DOMAIN="${1:?usage: $0 DOMAIN ADMIN_EMAIL [EXTRA_DOMAIN ...]}"
ADMIN_EMAIL="${2:?need admin email}"
shift 2 || true
EXTRA_DOMAINS=("$@")

log() { echo "[tls-bootstrap] $*"; }

# -- DNS preflight: does DOMAIN resolve to this host's public IP? --
EXPECTED_IP="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 8 ifconfig.me 2>/dev/null || echo '')"
ACTUAL_IP="$(dig +short "$DOMAIN" A | grep -E '^[0-9.]+$' | head -1 || true)"

if [[ -z "$EXPECTED_IP" ]]; then
  log "WARN: could not determine public IP; skipping DNS preflight."
elif [[ -z "$ACTUAL_IP" ]]; then
  log "DNS_MISMATCH: $DOMAIN does not resolve to an A record yet."
  exit 2
elif [[ "$EXPECTED_IP" != "$ACTUAL_IP" ]]; then
  log "DNS_MISMATCH: $DOMAIN -> $ACTUAL_IP, this host is $EXPECTED_IP."
  log "Point an A record at $EXPECTED_IP and re-run."
  exit 2
else
  log "DNS OK: $DOMAIN -> $ACTUAL_IP"
fi

# -- certbot availability --
if ! command -v certbot >/dev/null 2>&1; then
  log "CERTBOT_MISSING: install certbot (e.g. apt install certbot python3-certbot-nginx)."
  exit 3
fi

# -- build -d args (primary + any sector subdomains) --
DOMAIN_ARGS=(-d "$DOMAIN")
for d in "${EXTRA_DOMAINS[@]:-}"; do
  [[ -n "$d" ]] && DOMAIN_ARGS+=(-d "$d")
done

log "Requesting certificate for: $DOMAIN ${EXTRA_DOMAINS[*]:-}"
if certbot certonly --nginx --non-interactive --agree-tos \
     --email "$ADMIN_EMAIL" "${DOMAIN_ARGS[@]}"; then
  log "TLS_OK: $DOMAIN"
  exit 0
else
  log "CERTBOT_FAILED: see /var/log/letsencrypt/letsencrypt.log"
  exit 4
fi
