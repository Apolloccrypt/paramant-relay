#!/usr/bin/env bash
# PARAMANT deploy script
# BELANGRIJK: Vul YOUR_ADMIN_IP en X-Admin-Token in deploy/nginx/nginx-paramant.conf
# vóór je dit script uitvoert. Commit die wijzigingen NOOIT terug.
# Usage: ./deploy/deploy.sh [server_ip]
# Example: ./deploy/deploy.sh YOUR_SERVER_IP

set -e
SERVER=${1:-YOUR_SERVER_IP}
APP_DIR=/home/paramant

# Laad secrets uit deploy/.env
ENV_FILE="$(dirname "$0")/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "FOUT: $ENV_FILE niet gevonden. Kopieer deploy/.env.example naar deploy/.env en vul secrets in."
  exit 1
fi
source "$ENV_FILE"

# Guard: check verplichte secrets
for var in ADMIN_TOKEN TOTP_SECRET RESEND_API_KEY FLY_API_TOKEN; do
  if [ -z "${!var}" ]; then
    echo "FOUT: $var niet gezet in .env"
    exit 1
  fi
done

echo "==> Deploying to $SERVER"

# 1. Relay JS
echo "--- relay.js naar alle sectors"
for sector in relay-health relay-legal relay-finance relay-iot; do
  scp relay/relay.js root@$SERVER:$APP_DIR/$sector/relay.js
  scp relay/relay.js root@$SERVER:$APP_DIR/$sector/ghost-pipe-relay.js
done

# 2. Frontend
echo "--- frontend"
for f in frontend/*.html; do
  scp "$f" root@$SERVER:$APP_DIR/app/$(basename "$f")
done

# 3. Nginx config
echo "--- nginx"
scp deploy/nginx/paramant root@$SERVER:/etc/nginx/sites-enabled/paramant
ssh root@$SERVER "nginx -t && systemctl reload nginx"

# 4. Systemd services (inject secrets)
echo "--- systemd services"
TMPDIR=$(mktemp -d)
for f in deploy/systemd/*.service; do
  sed \
    -e "s|REPLACE_ADMIN_TOKEN|$ADMIN_TOKEN|g" \
    -e "s|REPLACE_TOTP_SECRET|$TOTP_SECRET|g" \
    -e "s|REPLACE_RESEND_KEY|$RESEND_API_KEY|g" \
    -e "s|REPLACE_FLY_TOKEN|$FLY_API_TOKEN|g" \
    "$f" > "$TMPDIR/$(basename $f)"
done
scp "$TMPDIR"/*.service root@$SERVER:/etc/systemd/system/
rm -rf "$TMPDIR"
ssh root@$SERVER "systemctl daemon-reload"

# 5. Restart relays
echo "--- relays herstarten"
ssh root@$SERVER "for s in paramant-relay-health paramant-relay-legal paramant-relay-finance paramant-relay-iot; do systemctl restart \$s; done"

echo "==> Deploy klaar"
