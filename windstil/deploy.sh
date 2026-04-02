#!/usr/bin/env bash
# Windstil deploy script
# Gebruik: ./deploy.sh
# Vereist: ~/.ssh/hetzner_windstil2 aanwezig op lokale machine

set -e

SERVER="root@195.201.16.120"
SSH_KEY="$HOME/.ssh/hetzner_windstil2"
REMOTE_DIR="/var/www/windstil"

if [ ! -f "$SSH_KEY" ]; then
  echo "FOUT: SSH key niet gevonden: $SSH_KEY"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Build
echo "==> Build..."
cd "$SCRIPT_DIR"
npm run build

# 2. Maak remote dir aan als die niet bestaat
echo "==> Remote dir aanmaken..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SERVER" "mkdir -p $REMOTE_DIR"

# 3. Kopieer dist naar server
echo "==> Bestanden uploaden naar $SERVER:$REMOTE_DIR ..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -r "$SCRIPT_DIR/dist/"* "$SERVER:$REMOTE_DIR/"

# 4. Nginx config uploaden en activeren (als nog niet gedaan)
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SERVER" bash << 'REMOTE'
  # Controleer of nginx geinstalleerd is
  if ! command -v nginx &>/dev/null; then
    apt-get update -qq && apt-get install -y nginx
  fi

  # Schrijf site config als die nog niet bestaat
  if [ ! -f /etc/nginx/sites-available/windstil ]; then
    cat > /etc/nginx/sites-available/windstil << 'NGINX'
server {
    listen 80;
    server_name _;

    root /var/www/windstil;
    index index.html;

    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache assets
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    gzip on;
    gzip_types text/plain text/css application/javascript application/json;
}
NGINX
    ln -sf /etc/nginx/sites-available/windstil /etc/nginx/sites-enabled/windstil
    # Verwijder default site als die er is
    rm -f /etc/nginx/sites-enabled/default
  fi

  nginx -t && systemctl reload nginx
  echo "Nginx geladen"
REMOTE

echo ""
echo "==> Deploy klaar!"
echo "    Open: http://195.201.16.120"
