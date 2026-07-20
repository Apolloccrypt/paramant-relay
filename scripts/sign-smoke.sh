#!/usr/bin/env bash
# Sign-path smoke tests (post-deploy, read-only).
#
# Guards the 2026-07-20 regression class: a too-broad auth gate made the keyless
# internal POST /v2/envelopes/:id/sign fall into the create-envelope gate and
# return 401 "API key required" — so a logged-in user saw "Please sign in to sign
# documents". These checks detect "sign-handler unreachable (401)" against a live
# base BEFORE a customer hits it. No real user data is mutated: only a dummy
# envelope id and a keyless/sessionless probe are used.
#
# Usage: ./scripts/sign-smoke.sh [base_url]
# Default base URL: https://paramant.app
#
# Exit 0 = all pass. Exit 1 = at least one failure.

set -uo pipefail

BASE="${1:-${PARAMANT_BASE:-https://paramant.app}}"
DUMMY_ID="smoke-dummy-envelope-000000"   # matches the relay id shape [A-Za-z0-9_-]{20,64}
PASS=0
FAIL=0
FAILURES=""

check() {
  local name="$1" actual="$2" expected="$3"
  if [ "$actual" = "$expected" ]; then
    printf "  PASS  %s\n" "$name"; PASS=$((PASS + 1))
  else
    printf "  FAIL  %s  (got '%s', expected '%s')\n" "$name" "$actual" "$expected"
    FAIL=$((FAIL + 1)); FAILURES="$FAILURES\n  - $name"
  fi
}

check_not() {
  local name="$1" actual="$2" bad="$3"
  if [ "$actual" != "$bad" ]; then
    printf "  PASS  %s\n" "$name"; PASS=$((PASS + 1))
  else
    printf "  FAIL  %s  (got '%s', should not be '%s')\n" "$name" "$actual" "$bad"
    FAIL=$((FAIL + 1)); FAILURES="$FAILURES\n  - $name"
  fi
}

# check_in NAME ACTUAL "space separated allowed codes"
check_in() {
  local name="$1" actual="$2" allowed="$3" hit=0 c
  for c in $allowed; do [ "$actual" = "$c" ] && hit=1; done
  if [ "$hit" = 1 ]; then
    printf "  PASS  %s  (got '%s')\n" "$name" "$actual"; PASS=$((PASS + 1))
  else
    printf "  FAIL  %s  (got '%s', expected one of '%s')\n" "$name" "$actual" "$allowed"
    FAIL=$((FAIL + 1)); FAILURES="$FAILURES\n  - $name"
  fi
}

code() { # METHOD PATH [JSON_BODY]
  local m="$1" p="$2" b="${3:-}"
  if [ -n "$b" ]; then
    curl -sS -o /dev/null -w '%{http_code}' --max-time 12 -X "$m" "$BASE$p" \
      -H 'Content-Type: application/json' -d "$b"
  else
    curl -sS -o /dev/null -w '%{http_code}' --max-time 12 -X "$m" "$BASE$p"
  fi
}

echo "======== SIGN SMOKE TESTS ========"
echo "  Target: $BASE"
echo ""

# 1. THE regression: keyless POST /v2/envelopes/:id/sign must REACH the handler,
#    never 401. 400 (its own validation) or 404 (not_found) = handler reached.
SIGN_CODE=$(code POST "/v2/envelopes/$DUMMY_ID/sign" '{}')
check_not 'sign handler reachable without key (NOT 401)' "$SIGN_CODE" '401'
check_in  'sign handler returns its own 400/404 (reached)' "$SIGN_CODE" '400 404'

# 2. Billing checkout stays gated (401) without a key.
BILL_CODE=$(code POST "/v2/billing/checkout" '{"product":"parasign","plan":"pro","interval":"month"}')
check 'billing/checkout requires a key (401)' "$BILL_CODE" '401'

# 3. The logged-in sign-flow endpoints EXIST (401 unauthenticated, never 404).
ACT_CODE=$(code POST "/api/user/sign/activation" '{}')
check_not '/api/user/sign/activation exists (not 404)' "$ACT_CODE" '404'
check_in  '/api/user/sign/activation is auth-gated (401/400)' "$ACT_CODE" '401 400'

SUB_CODE=$(code POST "/api/user/sign/submit" '{}')
check_not '/api/user/sign/submit exists (not 404)' "$SUB_CODE" '404'
check_in  '/api/user/sign/submit is auth-gated (401/400)' "$SUB_CODE" '401 400'

# 4. Optional: a REAL logged-in sign, only when a session cookie is provided.
#    export PARAMANT_SESSION_COOKIE='paramant_user_session=...'  (and PARAMANT_SIGN_BODY
#    as the activation JSON). Absent -> skipped, never a failure.
if [ -n "${PARAMANT_SESSION_COOKIE:-}" ]; then
  ACT_AUTH=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 12 \
    -X POST "$BASE/api/user/sign/activation" \
    -H 'Content-Type: application/json' -H "Cookie: $PARAMANT_SESSION_COOKIE" \
    -d "${PARAMANT_SIGN_BODY:-{}}")
  check_not 'logged-in sign/activation authenticated (not 401)' "$ACT_AUTH" '401'
else
  echo "  (skip logged-in sign: set PARAMANT_SESSION_COOKIE to enable)"
fi

echo ""
echo "======== RESULT ========"
printf "PASS: %d\nFAIL: %d\n" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf "\nFailed tests:%b\n" "$FAILURES"
  exit 1
fi
exit 0
