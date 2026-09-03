#!/bin/bash
# Post-deploy smoke test suite for the paramant relay.
# The version it expects is read from relay/package.json, not hardcoded: this
# file asserted 3.0.0 while relay.js already reported 3.1.0, so the one check
# that could have caught the version drift was itself part of it.
# Run AFTER the deploy completes. Exits 0 if all critical checks pass.
#
# Usage:
#   scripts/post-deploy-verify.sh [SITE_URL] [RELAY_LOCAL_URL]
#     SITE_URL         public base, default https://paramant.app
#     RELAY_LOCAL_URL  optional; e.g. http://127.0.0.1:3000 when run ON the
#                      server, used only for endpoints nginx does not expose
#                      publicly (/v2/health/deep). Omitted -> those checks SKIP.
#
# Requires: curl, jq. ASCII-only output.
#
# Routing reality (deploy/nginx-paramant-public.conf):
#   paramant.app/health     -> relay-main:3000   (exact match only)
#   paramant.app/v2/...      -> relay-main:3000   (/v2/admin is 404 publicly)
#   paramant.app/admin/...   -> admin:4200
#   paramant.app/.well-known -> static files
#   paramant.app/  /setup /dashboard /docs -> frontend upstream
#   /v2/health/deep is NOT publicly routed -> use RELAY_LOCAL_URL on the server.

set -uo pipefail

SITE="${1:-https://paramant.app}"
RELAY_LOCAL="${2:-}"
REPORT="/tmp/deploy-verify-$(date +%s).md"
PASS=0
FAIL=0
SKIP=0
CRITICAL=0

CURL="curl -sS --max-time 15"

note() { echo "$1" | tee -a "$REPORT"; }

# check NAME EXPECTED ACTUAL [critical=yes|no]
check() {
  local name="$1" expected="$2" actual="$3" critical="${4:-no}"
  if [ "$expected" = "$actual" ]; then
    note "PASS: $name ($actual)"
    PASS=$((PASS+1))
  else
    note "FAIL: $name (expected '$expected', got '$actual')"
    FAIL=$((FAIL+1))
    [ "$critical" = "yes" ] && CRITICAL=$((CRITICAL+1))
  fi
}

# contains NAME HAYSTACK NEEDLE [critical=yes|no]
contains() {
  local name="$1" hay="$2" needle="$3" critical="${4:-no}"
  if [[ "$hay" == *"$needle"* ]]; then
    note "PASS: $name (found '$needle')"
    PASS=$((PASS+1))
  else
    note "FAIL: $name (missing '$needle')"
    FAIL=$((FAIL+1))
    [ "$critical" = "yes" ] && CRITICAL=$((CRITICAL+1))
  fi
}

skip() { note "SKIP: $1"; SKIP=$((SKIP+1)); }

http_code() {
  local code
  code=$($CURL -o /dev/null -w "%{http_code}" "$1" 2>/dev/null)
  echo "${code:-000}"
}

{
  echo "# Post-deploy verify - $(date -Iseconds)"
  echo "Site: $SITE"
  echo "Relay-local: ${RELAY_LOCAL:-<not provided>}"
  echo ""
} > "$REPORT"

EXPECT_VER=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "$(dirname "$0")/../relay/package.json" | head -1)
if [ -z "$EXPECT_VER" ]; then
  echo "FATAL: could not read the version from relay/package.json" >&2
  exit 2
fi

note "== CRITICAL: relay /health =="
HEALTH_JSON=$($CURL "$SITE/health" 2>/dev/null)
HEALTH_VER=$(printf '%s' "$HEALTH_JSON" | jq -r '.version // empty' 2>/dev/null)
check "/health HTTP" "200" "$(http_code "$SITE/health")" yes
check "/health version" "$EXPECT_VER" "$HEALTH_VER" yes

note ""
note "== CRITICAL: /v2/capabilities (R006 core = 1 KEM) =="
CAPS=$($CURL "$SITE/v2/capabilities" 2>/dev/null)
KEMS=$(printf '%s' "$CAPS" | jq -r '.kem | length' 2>/dev/null)
KEM0=$(printf '%s' "$CAPS" | jq -r '.kem[0].name // empty' 2>/dev/null)
SIGS=$(printf '%s' "$CAPS" | jq -r '.sig | length' 2>/dev/null)
check "/v2/capabilities KEM count" "1" "$KEMS" yes
check "/v2/capabilities KEM[0] name" "ML-KEM-768" "$KEM0" no
check "/v2/capabilities sig count (none + ML-DSA-65)" "2" "$SIGS" no

note ""
note "== relay deep health (server-local only) =="
# The route is /v2/health/deep, and it always was: this file probed a bare
# /health/deep that relay.js has never served, so the check answered 404 on
# every run and the suite could never exit 0. Phase 6g of deploy/deploy-3.1.sh
# waved that away as "known red", which is a warning nobody reads.
#
# 401 is the PASS here, not 200. Outside RELAY_MODE=full the route sits behind
# X-Internal-Auth (#322), and this script has no token: it reads no .env and
# takes no secret on its command line, so the strongest thing it can prove
# without one is that the gate is shut. A 200 without a token would mean the
# relay is in full mode or the gate is open, and both are worth a FAIL here.
# The authenticated 200 is proved by phase 6c of the deploy script, which does
# have the token.
if [ -n "$RELAY_LOCAL" ]; then
  check "/v2/health/deep closed without a token" "401" "$(http_code "$RELAY_LOCAL/v2/health/deep")" no
else
  skip "/v2/health/deep (no RELAY_LOCAL_URL given; run on server with http://127.0.0.1:3000)"
fi

note ""
note "== frontend pages =="
check "/setup reachable" "200" "$(http_code "$SITE/setup")" no
check "/docs reachable"  "200" "$(http_code "$SITE/docs")" no
DASH=$($CURL -L "$SITE/dashboard" 2>/dev/null)
contains "/dashboard renders cards" "$DASH" "dh-acct-grid" no
HOMEPG=$($CURL -L "$SITE/" 2>/dev/null)
contains "homepage advertises PQC" "$HOMEPG" "ML-KEM" no

note ""
note "== admin pages =="
check "/admin/settings.html reachable" "200" "$(http_code "$SITE/admin/settings.html")" no
check "/admin/cli.html reachable"      "200" "$(http_code "$SITE/admin/cli.html")" no

note ""
note "== well-known / hygiene =="
PGP=$($CURL "$SITE/.well-known/openpgp-key.asc" 2>/dev/null)
if [[ "$PGP" == *"PLACEHOLDER"* ]]; then
  note "FAIL: PGP placeholder still live"
  FAIL=$((FAIL+1))
else
  note "PASS: PGP no placeholder"
  PASS=$((PASS+1))
fi

{
  echo ""
  echo "## Summary"
  echo "- PASS: $PASS"
  echo "- FAIL: $FAIL"
  echo "- SKIP: $SKIP"
  echo "- CRITICAL FAIL: $CRITICAL"
} >> "$REPORT"

echo ""
echo "Report written to: $REPORT"
echo "------------------------------------------------------------"
echo "PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP  CRITICAL=$CRITICAL"

if [ "$CRITICAL" -gt 0 ]; then
  echo ""
  echo "CRITICAL FAILURES DETECTED - CONSIDER ROLLBACK (scripts/rollback-3.0.0.sh)"
  exit 2
elif [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "Non-critical failures - investigate but no rollback needed"
  exit 1
else
  echo ""
  echo "ALL CHECKS PASSED"
  exit 0
fi
