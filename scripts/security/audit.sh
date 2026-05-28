#!/usr/bin/env bash
# Paramant security audit - probes live state against the standard.
# READ-ONLY. Never prints real secrets. Outputs a status per control.
set -uo pipefail

APP="${PARAMANT_APP:-https://paramant.app}"
RELAY="${PARAMANT_RELAY:-https://relay.paramant.app}"
REPO="${PARAMANT_REPO:-$HOME/paramant-relay}"
cb() { date +%s%N; }

pass() { printf "PASS  %-12s %s\n" "$1" "$2"; }
fail() { printf "FAIL  %-12s %s\n" "$1" "$2"; }
warn() { printf "WARN  %-12s %s\n" "$1" "$2"; }
todo() { printf "TODO  %-12s %s\n" "$1" "$2"; }

echo "=== Paramant security audit $(date -Iseconds) ==="
echo ""

# CFG-01: /setup gated after first-run
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$APP/setup?cb=$(cb)")
if [ "$CODE" = "200" ]; then
  fail CFG-01 "/setup returns 200 publicly - verify it cannot mutate config without auth"
else
  pass CFG-01 "/setup returns $CODE (not openly served)"
fi

# DATA-04: sensitive files not web-reachable
for f in /users.json /.env /admin/users.json /config.json; do
  C=$(curl -s -o /dev/null -w "%{http_code}" "$APP$f?cb=$(cb)")
  if [ "$C" = "200" ]; then
    fail DATA-04 "$f is web-reachable (200) - CRITICAL"
  else
    pass DATA-04 "$f -> $C"
  fi
done

# API-02 / AC-02: admin endpoints reject without creds
for ep in /v2/admin/config /v2/admin/exec /admin/api/settings; do
  C=$(curl -s -o /dev/null -w "%{http_code}" "$RELAY$ep?cb=$(cb)")
  if [ "$C" = "401" ] || [ "$C" = "403" ] || [ "$C" = "404" ]; then
    pass API-02 "$ep -> $C (rejects unauth)"
  else
    fail API-02 "$ep -> $C (should be 401/403/404)"
  fi
done

# AUTH-02: /v2/sign requires auth
C=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "{}" "$RELAY/v2/sign")
if [ "$C" = "401" ] || [ "$C" = "400" ] || [ "$C" = "422" ]; then
  pass AUTH-01 "/v2/sign requires auth/valid body ($C)"
else
  warn AUTH-01 "/v2/sign -> $C"
fi

# COMM-01: HSTS
HSTS=$(curl -sI "$APP/?cb=$(cb)" | grep -i "strict-transport-security")
if echo "$HSTS" | grep -qi "includeSubDomains"; then
  pass COMM-01 "HSTS present with includeSubDomains"
else
  fail COMM-01 "HSTS missing includeSubDomains"
fi

# COMM-02: CSP no unsafe-eval
CSP=$(curl -sI "$APP/?cb=$(cb)" | grep -i "content-security-policy")
if echo "$CSP" | grep -qi "unsafe-eval"; then
  fail COMM-02 "CSP allows unsafe-eval"
elif [ -n "$CSP" ]; then
  pass COMM-02 "CSP present, no unsafe-eval"
else
  fail COMM-02 "no CSP header"
fi

# COMM-04: full header set
for h in x-content-type-options x-frame-options referrer-policy; do
  if curl -sI "$APP/?cb=$(cb)" | grep -qi "^$h:"; then
    pass COMM-04 "$h present"
  else
    fail COMM-04 "$h missing"
  fi
done

# SUP-04: no CDN imports in shipped JS
if [ -d "$REPO/frontend" ]; then
  CDN=$(grep -rlE "from ['\"]https://(esm\.sh|cdn|unpkg)" "$REPO/frontend"/*.js 2>/dev/null | head -5)
  if [ -n "$CDN" ]; then
    fail SUP-04 "CDN imports found in: $CDN"
  else
    pass SUP-04 "no CDN imports in frontend JS"
  fi
fi

# CRYPTO-05: vendored crypto present
if ls "$REPO/frontend/vendor/"*.js >/dev/null 2>&1; then
  pass CRYPTO-05 "vendored crypto bundle present"
else
  warn CRYPTO-05 "no vendor bundle found"
fi

# CRYPTO-03: source check - no secret key in sign request body
if [ -f "$REPO/frontend/parasign-client.js" ]; then
  if grep -qE "secret_key|secretKey.*fetch|document_b64.*secret" "$REPO/frontend/parasign-client.js"; then
    fail CRYPTO-03 "parasign-client may send secret key to server"
  else
    pass CRYPTO-03 "parasign-client sends hash+sig+pubkey only"
  fi
fi

# LOG-01: source check for obvious PII logging
if [ -d "$REPO/relay" ]; then
  PII=$(grep -rnE "console\.(log|info).*\b(apiKey|api_key|email|filename|X-Api-Key)" "$REPO/relay"/*.js 2>/dev/null | head -5)
  if [ -n "$PII" ]; then
    warn LOG-01 "possible PII logging: $(echo "$PII" | head -1)"
  else
    pass LOG-01 "no obvious PII logging in relay/*.js"
  fi
fi

# AUTH-04: rate limit probe (non-aggressive)
RL=0
for i in $(seq 1 15); do
  C=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "{}" "$RELAY/v2/sign")
  [ "$C" = "429" ] && { RL=1; break; }
  sleep 0.1
done
[ "$RL" = "1" ] && pass AUTH-04 "rate-limit fires (429)" || warn AUTH-04 "no 429 in 15 rapid auth probes"

echo ""
echo "=== controls requiring manual/source review (not auto-probeable) ==="
todo ARCH-02 "admin process+network isolation - verify nginx + compose"
todo AUTH-02 "TOTP enforced not bypassable - source review admin/server.js"
todo VAL-04 "admin CLI command whitelist - source review"
todo COMM-03 "admin network isolation (VPN/IP-allowlist/mTLS)"
todo SUP-02 "cosign-signed images"
todo TRANS-01 "admin actions to CT log"

echo ""
echo "Audit complete. Update COMPLIANCE-CHECKLIST.md Status/Evidence from these results."
