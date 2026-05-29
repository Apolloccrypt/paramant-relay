#!/usr/bin/env bash
# DEV-ONLY: boot the full passkey flow locally on ONE origin so you can register
# a passkey and sign in with it in your own browser (ADR R018, PR-A).
#
#   relay-health (:3001)  +  admin (:4200, /api)  +  single-origin proxy (:8080)
#
# Prereq: Redis on 127.0.0.1:6379. If you don't have one:
#   docker run -d --name paramant-dev-redis -p 6379:6379 redis:7-alpine
#
# NOT for production (prod is nginx in front of these services). Touches nothing
# in deploy/ or docker-compose.yml. Ctrl-C stops everything it started.
set -uo pipefail
cd "$(dirname "$0")/.."

ORIGIN="http://localhost:8080"
EMAIL="${DEV_EMAIL:-dev@localhost}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
export ADMIN_TOKEN="${ADMIN_TOKEN:-dev-admin-$(openssl rand -hex 8)}"
export INTERNAL_AUTH_TOKEN="${INTERNAL_AUTH_TOKEN:-dev-internal-$(openssl rand -hex 8)}"
# Required by the relay to encrypt user-TOTP secrets (AES-256-GCM, 32-byte key).
# Without it, TOTP setup/verify throws — and the add-passkey step-up needs a
# TOTP-enabled account to test against. Per-run dev key (fresh account each run).
export PARAMANT_TOTP_MASTER_KEY="${PARAMANT_TOTP_MASTER_KEY:-$(openssl rand -base64 32)}"

say() { printf '\n\033[1m[dev]\033[0m %s\n' "$1"; }

# 0. deps + redis reachability ------------------------------------------------
[ -d admin/node_modules/@simplewebauthn ] || { say "installing admin deps..."; (cd admin && npm install >/dev/null 2>&1); }
node -e "const{createClient}=require('./admin/node_modules/redis');(async()=>{try{const c=createClient({url:process.env.REDIS_URL});await c.connect();await c.ping();await c.quit()}catch(e){console.error(e.message);process.exit(1)}})()" \
  || { say "Redis not reachable at $REDIS_URL. Start one:  docker run -d --name paramant-dev-redis -p 6379:6379 redis:7-alpine"; exit 1; }

# 1. relay-health: serves /v2/user/webauthn/* + envelope store ----------------
say "starting relay-health on :3001 ..."
( cd relay && PORT=3001 SECTOR=health RELAY_MODE=ghost_pipe \
    ADMIN_TOKEN="$ADMIN_TOKEN" INTERNAL_AUTH_TOKEN="$INTERNAL_AUTH_TOKEN" REDIS_URL="$REDIS_URL" \
    PARAMANT_TOTP_MASTER_KEY="$PARAMANT_TOTP_MASTER_KEY" \
    node relay.js >/tmp/paramant-dev-relay.log 2>&1 ) & RELAY_PID=$!

# 2. admin: BASE_PATH='' so /api/* is direct; rpId/origin pinned to the proxy --
say "starting admin on :4200 ..."
( cd admin && PORT=4200 BASE_PATH= \
    ADMIN_TOKEN="$ADMIN_TOKEN" INTERNAL_AUTH_TOKEN="$INTERNAL_AUTH_TOKEN" REDIS_URL="$REDIS_URL" \
    RELAY_MAIN=http://127.0.0.1:3001 RELAY_HEALTH=http://127.0.0.1:3001 \
    RELAY_LEGAL=http://127.0.0.1:3001 RELAY_FINANCE=http://127.0.0.1:3001 RELAY_IOT=http://127.0.0.1:3001 \
    SITE_URL="$ORIGIN" WEBAUTHN_RP_ID=localhost WEBAUTHN_ORIGIN="$ORIGIN" \
    node server.js >/tmp/paramant-dev-admin.log 2>&1 ) & ADMIN_PID=$!

# 3. single-origin proxy ------------------------------------------------------
say "starting dev proxy on :8080 ..."
( DEV_PORT=8080 ADMIN_URL=http://127.0.0.1:4200 RELAY_URL=http://127.0.0.1:3001 \
    node scripts/dev-local-proxy.js ) & PROXY_PID=$!

trap 'echo; say "stopping..."; kill $RELAY_PID $ADMIN_PID $PROXY_PID 2>/dev/null || true' EXIT INT TERM

# 4. wait for relay + admin to answer (10s budget each) -----------------------
for i in $(seq 1 20); do curl -sf http://127.0.0.1:3001/health >/dev/null 2>&1 && break; sleep 0.5
  [ "$i" = 20 ] && { say "relay did not become ready — see /tmp/paramant-dev-relay.log"; }; done
for i in $(seq 1 20); do [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4200/api/user/session/verify 2>/dev/null)" != "000" ] && break; sleep 0.5
  [ "$i" = 20 ] && { say "admin did not become ready — see /tmp/paramant-dev-admin.log"; }; done

# 5. create a dev account (so login's findUserByEmail resolves) + mint a -------
#    setup_token (the TOFU mailbox-proof) directly in Redis — no email needed.
KEY="pgp_$(openssl rand -hex 32)"
curl -fsS -X POST http://127.0.0.1:3001/v2/admin/keys \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$KEY\",\"email\":\"$EMAIL\",\"label\":\"dev\",\"plan\":\"community\",\"active\":true}" >/dev/null \
  || say "WARN: account create returned non-2xx (see relay log); passkey register may still work, login needs the account"
TOK="$(openssl rand -hex 32)"
KEY="$KEY" TOK="$TOK" EMAIL="$EMAIL" node -e "const{createClient}=require('./admin/node_modules/redis');(async()=>{const c=createClient({url:process.env.REDIS_URL});await c.connect();await c.set('paramant:user:setup_token:'+process.env.TOK,JSON.stringify({user_id:process.env.KEY,email:process.env.EMAIL}),{EX:1209600});await c.quit()})()" \
  || { say "could not mint setup_token"; exit 1; }

cat <<EOF

================= paramant passkey — local test =================
  1) Register a passkey:  $ORIGIN/auth/setup/$TOK
  2) Then sign in:        $ORIGIN/auth/login   (email: $EMAIL)

  account email : $EMAIL
  logs          : /tmp/paramant-dev-relay.log  /tmp/paramant-dev-admin.log
  Ctrl-C stops relay + admin + proxy.
=================================================================
EOF

wait
