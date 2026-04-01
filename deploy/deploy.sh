#!/usr/bin/env bash
# PARAMANT deploy script
# Usage: ./deploy/deploy.sh [server_ip]
# Example: ./deploy/deploy.sh 116.203.86.81

set -e
SERVER=${1:-116.203.86.81}
APP_DIR=/home/paramant

# Laad secrets uit deploy/.env
ENV_FILE="$(dirname "$0")/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "FOUT: $ENV_FILE niet gevonden. Kopieer deploy/.env.example naar deploy/.env en vul secrets in."
  exit 1
fi
source "$ENV_FILE"

echo "==> Deploying to $SERVER"

# 1. Relay JS
echo "--- relay.js naar alle sectors"
for sector in relay-health relay-legal relay-finance relay-iot; do
  scp relay/relay.js root@$SERVER:$APP_DIR/$sector/relay.js
  scp relay/relay.js root@$SERVER:$APP_DIR/$sector/ghost-pipe-relay.js
done

# 2. Frontend
echo "--- frontend"
scp frontend/r34ct0r.html root@$SERVER:$APP_DIR/app/r34ct0r.html
scp frontend/index.html   root@$SERVER:$APP_DIR/app/index.html

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
