#!/usr/bin/env bash
# e2e-auth-flow.sh — auth stack regression test
#
# Exercises the full signup→TOTP→login sequence against live containers.
# All three bugs that reached production in afb80c7/c7dd74b would fail here:
#   Bug 1: GET /v2/admin/keys missing email field   → Test A
#   Bug 2: Admin container ReferenceError crashes   → Test B
#   Bug 3: Uninitialized redisClient / missing      → Tests C, D
#           verifyTotpGeneric
#
# Usage:
#   ./tests/e2e-auth-flow.sh
#   ADMIN_TOKEN=xxx INTERNAL_AUTH_TOKEN=yyy ./tests/e2e-auth-flow.sh
#
# Requires: curl, python3
# Token extraction requires: docker (user must be in docker group)
# Exits 0 on pass (or all-skipped), 1 on any failure.

set -uo pipefail

RELAY_HEALTH="http://127.0.0.1:3001"
ADMIN_URL="http://127.0.0.1:4200/admin"

PASS=0; FAIL=0; SKIP=0

pass() { echo "  PASS  $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $1 [no docker access — run as docker group member or export tokens]"; SKIP=$((SKIP+1)); }
section() { echo ""; echo "── $1"; }

# ── Token acquisition ─────────────────────────────────────────────────────────
section "Token acquisition"
HAVE_DOCKER=false
if docker info &>/dev/null 2>&1; then
  HAVE_DOCKER=true
fi

if [ -z "${ADMIN_TOKEN:-}" ] && $HAVE_DOCKER; then
  ADMIN_TOKEN=$(docker exec paramant-relay-admin printenv ADMIN_TOKEN 2>/dev/null) || ADMIN_TOKEN=""
fi
if [ -z "${INTERNAL_AUTH_TOKEN:-}" ] && $HAVE_DOCKER; then
  INTERNAL_AUTH_TOKEN=$(docker exec paramant-relay-admin printenv INTERNAL_AUTH_TOKEN 2>/dev/null) || INTERNAL_AUTH_TOKEN=""
fi

ADMIN_TOKEN="${ADMIN_TOKEN:-}"
INTERNAL_AUTH_TOKEN="${INTERNAL_AUTH_TOKEN:-}"

if [ -n "$ADMIN_TOKEN" ] && [ -n "$INTERNAL_AUTH_TOKEN" ]; then
  echo "  Tokens acquired (ADMIN=${#ADMIN_TOKEN} chars, INTERNAL=${#INTERNAL_AUTH_TOKEN} chars)"
elif [ -n "$ADMIN_TOKEN" ]; then
  echo "  ADMIN_TOKEN acquired; INTERNAL_AUTH_TOKEN missing — TOTP endpoint tests will skip"
else
  echo "  No tokens available — token-dependent tests (A, C, D) will skip"
  echo "  To run full suite: add user to docker group, or export ADMIN_TOKEN and INTERNAL_AUTH_TOKEN"
fi

# ── A: GET /v2/admin/keys must include email field in every key entry ─────────
section "A: GET /v2/admin/keys email field (Bug #1 regression)"
if [ -n "$ADMIN_TOKEN" ]; then
  _tmp=$(mktemp)
  _code=$(curl -s -o "$_tmp" -w "%{http_code}" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$RELAY_HEALTH/v2/admin/keys") || _code=0
  _body=$(cat "$_tmp"); rm -f "$_tmp"
  if [ "$_code" != "200" ]; then
    fail "A: GET /v2/admin/keys returned HTTP $_code"
  else
    _check=$(python3 -c "
import json, sys
d = json.loads(sys.argv[1])
keys = d.get('keys', [])
missing = [k.get('key','?')[:16] for k in keys if 'email' not in k]
if missing:
    print('FAIL: email field absent from %d key(s): %s' % (len(missing), ', '.join(missing)))
else:
    print('PASS: %d keys, email field present in all entries' % len(keys))
" "$_body" 2>/dev/null || echo "FAIL: parse error — $_body")
    if echo "$_check" | grep -q '^PASS'; then
      pass "A: $_check"
    else
      fail "A: $_check"
    fi
  fi
else
  skip "A: ADMIN_TOKEN unavailable"
fi

# ── B: Admin container must have zero ReferenceErrors in recent logs ──────────
section "B: Admin container no ReferenceErrors (Bug #2 regression)"
if $HAVE_DOCKER; then
  _ref=$(docker logs paramant-relay-admin --since 1h 2>&1 | grep -c 'ReferenceError' || true)
  if [ "${_ref:-0}" -eq 0 ]; then
    pass "B: no ReferenceErrors in admin container logs (last 1h)"
  else
    fail "B: found $_ref ReferenceError(s) — recent log lines:"
    docker logs paramant-relay-admin --since 1h 2>&1 | grep 'ReferenceError' | head -5
  fi
else
  skip "B: docker not accessible — cannot inspect container logs"
fi

# ── C: setup-totp endpoint functional (redisClient init + verifyTotpGeneric) ─
section "C: setup-totp endpoint — redisClient + verifyTotpGeneric (Bug #3 regression)"
if [ -n "$ADMIN_TOKEN" ] && [ -n "$INTERNAL_AUTH_TOKEN" ]; then
  _tmp=$(mktemp)
  _code=$(curl -s -o "$_tmp" -w "%{http_code}" \
    -X POST "$RELAY_HEALTH/v2/user/setup-totp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "X-Internal-Auth: $INTERNAL_AUTH_TOKEN" \
    -d '{"user_id":"pgp_test_e2e","provisional":true}') || _code=0
  _body=$(cat "$_tmp"); rm -f "$_tmp"
  _ok=$(python3 -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
    e = d.get('error', '')
    # 'secret' in response = fresh provisional setup
    # 'totp_already_configured' (409) = redis live, TOTP active, idempotent
    ok = 'secret' in d or e == 'totp_already_configured'
    print('ok' if ok else 'fail:' + str(d))
except Exception as ex:
    print('fail:parse:' + str(ex))
" "$_body" 2>/dev/null || echo "fail:python-error")
  if [ "$_ok" = "ok" ]; then
    pass "C: setup-totp OK — HTTP $_code (redisClient connected, verifyTotpGeneric live)"
  else
    fail "C: setup-totp unexpected response — $_body (HTTP $_code)"
  fi
else
  skip "C: INTERNAL_AUTH_TOKEN unavailable (docker required)"
fi

# ── D: verify-totp endpoint responds without 500 ─────────────────────────────
section "D: verify-totp endpoint responds (no 500 crash)"
if [ -n "$ADMIN_TOKEN" ] && [ -n "$INTERNAL_AUTH_TOKEN" ]; then
  _tmp=$(mktemp)
  _code=$(curl -s -o "$_tmp" -w "%{http_code}" \
    -X POST "$RELAY_HEALTH/v2/user/verify-totp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "X-Internal-Auth: $INTERNAL_AUTH_TOKEN" \
    -d '{"user_id":"pgp_test_e2e","totp":"000000"}') || _code=0
  _body=$(cat "$_tmp"); rm -f "$_tmp"
  if [ "$_code" = "500" ] || [ -z "$_body" ]; then
    fail "D: verify-totp returned 500 or empty response — $_body"
  else
    pass "D: verify-totp responded HTTP $_code (not 500) — $_body"
  fi
else
  skip "D: INTERNAL_AUTH_TOKEN unavailable"
fi

# ── E: session/verify returns authenticated:false for unauthenticated request ─
section "E: session/verify shape check (no auth cookie)"
_tmp=$(mktemp)
_code=$(curl -s -o "$_tmp" -w "%{http_code}" "$ADMIN_URL/api/user/session/verify") || _code=0
_body=$(cat "$_tmp"); rm -f "$_tmp"
_ok=$(python3 -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
    # Must have 'authenticated' key with boolean false for unauth request
    ok = ('authenticated' in d) and (d['authenticated'] is False)
    print('ok' if ok else 'fail:unexpected shape:' + str(d))
except Exception as ex:
    print('fail:parse:' + str(ex))
" "$_body" 2>/dev/null || echo "fail:python-error")
if [ "$_ok" = "ok" ]; then
  pass "E: session/verify returns {authenticated: false} for unauth — HTTP $_code"
else
  fail "E: session/verify — $_ok — body: $_body (HTTP $_code)"
fi

# ── F: login endpoint returns structured error, not 500 ──────────────────────
section "F: login structured error (not 500)"
_tmp=$(mktemp)
_code=$(curl -s -o "$_tmp" -w "%{http_code}" \
  -X POST "$ADMIN_URL/api/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"e2e-nonexistent@example.com","totp":"000000"}') || _code=0
_body=$(cat "$_tmp"); rm -f "$_tmp"
if [[ "$_code" =~ ^(401|403|429)$ ]]; then
  pass "F: login returned HTTP $_code with structured error (not 500)"
else
  fail "F: login returned HTTP $_code — $_body"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
printf "  Results: %d passed  %d failed  %d skipped\n" "$PASS" "$FAIL" "$SKIP"
echo "═══════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ]
