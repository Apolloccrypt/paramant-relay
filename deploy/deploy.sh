#!/usr/bin/env bash
# PARAMANT deploy script
# Usage: ./deploy/deploy.sh [server_ip]
# Example: ./deploy/deploy.sh YOUR_SERVER_IP

set -e
SERVER=${1:-YOUR_SERVER_IP}
APP_DIR=/home/paramant

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

# 4. Systemd services
echo "--- systemd services"
scp deploy/systemd/*.service root@$SERVER:/etc/systemd/system/
ssh root@$SERVER "systemctl daemon-reload"

# 5. Restart relays
echo "--- relays herstarten"
ssh root@$SERVER "for s in paramant-relay-health paramant-relay-legal paramant-relay-finance paramant-relay-iot; do systemctl restart \$s; done"

echo "==> Deploy klaar"
