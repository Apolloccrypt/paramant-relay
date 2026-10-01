#!/usr/bin/env bash
# Auth regression smoke tests.
# Run after any change to admin/server.js, relay/relay.js, or auth-related code.
# Exit 0 = all pass. Exit 1 = at least one failure.
#
# Usage: ./tests/auth-smoke.sh [base_url]
# Default base URL: https://paramant.app

set -uo pipefail

BASE="${1:-${PARAMANT_BASE:-https://paramant.app}}"
PASS=0
FAIL=0
FAILURES=""

check() {
  local name="$1"
  local actual="$2"
  local expected="$3"
  if [ "$actual" = "$expected" ]; then
    printf "  PASS  %s\n" "$name"
    PASS=$((PASS + 1))
  else
    printf "  FAIL  %s  (got '%s', expected '%s')\n" "$name" "$actual" "$expected"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  - $name"
  fi
}

# "not this status code" needs one more case than it looks like. curl writes
# %{http_code} as 000 when it never got a response at all: DNS failure, refused
# connection, or the --max-time 8 running out. Compared against '500' that is
# "not 500", so every one of the ten checks below reported PASS for an endpoint
# that answered nothing, which is a worse outcome than the 500 they exist to
# catch. This script is a post-deploy and post-rollback gate, and a hung route
# next to a healthy homepage is exactly the partial outage it should catch.
check_not() {
  local name="$1"
  local actual="$2"
  local bad="$3"
  if [ -z "$actual" ] || [ "$actual" = "000" ]; then
    printf "  FAIL  %s  (no response at all: curl returned '%s')\n" "$name" "$actual"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  - $name (no response)"
  elif [ "$actual" != "$bad" ] && [ "${actual#5}" != "$actual" ]; then
    # Every caller of this helper sits under a section header that promises
    # "never 5xx", but the check only ever excluded the ONE code it was handed.
    # A 503 therefore passed a check named "not 500", which is how the store
    # outage of 2026-09-06 left nineteen of twenty-one checks green while the
    # admin could not write to redis at all: only the captcha check, the one
    # that demands an exact 200, went red. The name stays (it is what the
    # runbook and the deploy log quote); the verdict now matches the promise.
    printf "  FAIL  %s  (got '%s'; the endpoint must never answer 5xx)\n" "$name" "$actual"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  - $name (got $actual)"
  elif [ "$actual" != "$bad" ]; then
    printf "  PASS  %s\n" "$name"
    PASS=$((PASS + 1))
  else
    printf "  FAIL  %s  (got '%s', should not be '%s')\n" "$name" "$actual" "$bad"
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  - $name"
  fi
}

echo "════════ AUTH SMOKE TESTS ════════"
echo "  Target: $BASE"
echo ""

# ── 1. Deprecated /request-key returns 410, not 500 ──────────────────────────
# Regression: admin container orphan code caused this to crash
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
  -X POST "$BASE/api/request-key" \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke-test@example.com"}')
check 'deprecated /request-key returns 410' "$CODE" '410'

# Verify JSON body contains migration_path
BODY=$(curl -sS --max-time 8 \
  -X POST "$BASE/api/request-key" \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke-test@example.com"}')
HAS_PATH=$(echo "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("yes" if "migration_path" in d else "no")' 2>/dev/null || echo 'no')
check '410 body contains migration_path' "$HAS_PATH" 'yes'

# ── 2a. The admin can still reach its store ──────────────────────────────────
# admin/server.js already answers this honestly on GET /admin/health ("degraded"
# when redis cannot be reached) and nothing checked it, so a store fault could
# only be inferred from whichever route happened to write first. On 2026-09-06
# that was the captcha challenge, which reported a bare 500 internal_error and
# named nothing. Checked BEFORE the captcha, so the log reads cause then effect.
STORE=$(curl -sS --max-time 8 "$BASE/admin/health" 2>/dev/null || echo '{}')
STORE_OK=$(echo "$STORE" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("yes" if d.get("redis",{}).get("ok") is True else "no")' \
  2>/dev/null || echo 'no')
check 'admin can reach its redis store' "$STORE_OK" 'yes'

# ── 2. CAPTCHA challenge returns correct shape ────────────────────────────────
# Regression: if pow-captcha.js is broken, signup crashes with 500
CHALLENGE=$(curl -sS --max-time 8 "$BASE/api/captcha/challenge" 2>/dev/null || echo '{}')
CHALLENGE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "$BASE/api/captcha/challenge")
check 'captcha challenge returns 200' "$CHALLENGE_CODE" '200'
HAS_FIELDS=$(echo "$CHALLENGE" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("yes" if all(k in d for k in ["challenge_id","salt","difficulty"]) else "no")' \
  2>/dev/null || echo 'no')
check 'captcha response has challenge_id+salt+difficulty' "$HAS_FIELDS" 'yes'

# ── 3. Signup rejects request without captcha proof (never 5xx) ──────────────
# Regression: missing email validation crashes with TypeError
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
  -X POST "$BASE/api/user/signup" \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke-test@example.com"}')
check_not 'signup without captcha not 500' "$CODE" '500'
check_not 'signup without captcha not 502' "$CODE" '502'
# Expect 400 (bad request — missing proof) or 403 (captcha failed)
if [ "$CODE" = '400' ] || [ "$CODE" = '403' ]; then
  check 'signup without captcha returns 400 or 403' 'ok' 'ok'
else
  check 'signup without captcha returns 400 or 403' "$CODE" '400_or_403'
fi

# ── 4. Login rejects invalid credentials (never 5xx) ─────────────────────────
# Regression: if email field is missing, toLowerCase() crash → 500
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
  -X POST "$BASE/api/user/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"nobody@example.invalid","code":"000000"}')
check_not 'login with bad creds not 500' "$CODE" '500'
check_not 'login with bad creds not 502' "$CODE" '502'

# ── 5. Login with missing email field doesn't crash ──────────────────────────
# Regression: req.body.email.toLowerCase() with undefined email → TypeError 500
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
  -X POST "$BASE/api/user/login" \
  -H 'Content-Type: application/json' \
  -d '{}')
check_not 'login with empty body not 500' "$CODE" '500'
check_not 'login with empty body not 502' "$CODE" '502'

# ── 6. Setup endpoint with invalid token doesn't crash (never 5xx) ───────────
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
  -X POST "$BASE/api/user/setup/invalid-token-that-does-not-exist" \
  -H 'Content-Type: application/json' \
  -d '{}')
check_not 'setup with invalid token not 500' "$CODE" '500'
check_not 'setup with invalid token not 502' "$CODE" '502'

# ── 7. Unauthenticated /api/user/ endpoint returns 4xx, never 5xx ────────────
# /api/auth/check is not proxied by nginx; test /api/user/login instead
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
  -X POST "$BASE/api/user/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke-auth-check@example.invalid","code":"000000"}')
check_not 'user/login with bad creds not 500' "$CODE" '500'
check_not 'user/login with bad creds not 502' "$CODE" '502'

# ── 8. Homepage loads ─────────────────────────────────────────────────────────
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/")
check 'homepage returns 200' "$CODE" '200'

# Verify no /request-key links leaked back onto homepage
# grep -c exits 1 on zero matches; suppress exit code to avoid || echo '0' doubling
LEAK=$(curl -sS --max-time 10 "$BASE/" 2>/dev/null | (grep -c 'href="/request-key"' || true))
check 'homepage has zero /request-key links' "$LEAK" '0'

# ── 9. Auth pages load (never 5xx) ───────────────────────────────────────────
for path in /signup /auth/login; do
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "$BASE$path")
  check "$path returns 200" "$CODE" '200'
done

# ── 10. request-key page redirects (has meta refresh) ────────────────────────
RK_BODY=$(curl -sS --max-time 8 "$BASE/request-key" 2>/dev/null || echo '')
HAS_REFRESH=$(echo "$RK_BODY" | (grep -c 'http-equiv="refresh"' || true))
check '/request-key page has meta refresh' "$HAS_REFRESH" '1'
POINTS_TO_SIGNUP=$(echo "$RK_BODY" | (grep -c 'url=/signup' || true))
check '/request-key redirect points to /signup' "$POINTS_TO_SIGNUP" '1'

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════ RESULT ════════"
printf "PASS: %d\nFAIL: %d\n" "$PASS" "$FAIL"
if [ $FAIL -gt 0 ]; then
  printf "\nFailed tests:%b\n" "$FAILURES"
  exit 1
fi
exit 0
