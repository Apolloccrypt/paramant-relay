#!/bin/sh
# PARAMANT nginx entrypoint — auto-generates self-signed cert if none exists
CERT=/etc/nginx/certs/cert.pem
KEY=/etc/nginx/certs/key.pem
DOMAIN=${DOMAIN:-localhost}
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[paramant] No TLS cert found — generating self-signed for $DOMAIN"
    mkdir -p /etc/nginx/certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY" \
        -out "$CERT" \
        -subj "/CN=$DOMAIN/O=PARAMANT/C=NL" \
        -addext "subjectAltName=DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    echo "[paramant] Self-signed cert generated for $DOMAIN"
    echo "[paramant] For production: replace with Let's Encrypt via install.sh"
fi
