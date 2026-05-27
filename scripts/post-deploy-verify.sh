#!/bin/bash
# Post-deploy smoke test suite for paramant 3.0.0.
# Run AFTER the deploy completes. Exits 0 if all critical checks pass.
#
# Usage:
#   scripts/post-deploy-verify.sh [SITE_URL] [RELAY_LOCAL_URL]
#     SITE_URL         public base, default https://paramant.app
#     RELAY_LOCAL_URL  optional; e.g. http://127.0.0.1:3000 when run ON the
#                      server, used only for endpoints nginx does not expose
#                      publicly (/health/deep). Omitted -> those checks SKIP.
#
# Requires: curl, jq. ASCII-only output.
#
# Routing reality (deploy/nginx-paramant-public.conf):
#   paramant.app/health     -> relay-main:3000   (exact match only)
#   paramant.app/v2/...      -> relay-main:3000   (/v2/admin is 404 publicly)
#   paramant.app/admin/...   -> admin:4200
#   paramant.app/.well-known -> static files
#   paramant.app/  /setup /dashboard /docs -> frontend upstream
#   /health/deep is NOT publicly routed -> use RELAY_LOCAL_URL on the server.

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
  if printf '%s' "$hay" | grep -q "$needle"; then
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

note "== CRITICAL: relay /health =="
HEALTH_JSON=$($CURL "$SITE/health" 2>/dev/null)
HEALTH_VER=$(printf '%s' "$HEALTH_JSON" | jq -r '.version // empty' 2>/dev/null)
check "/health HTTP" "200" "$(http_code "$SITE/health")" yes
check "/health version" "3.0.0" "$HEALTH_VER" yes

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
if [ -n "$RELAY_LOCAL" ]; then
  check "/health/deep HTTP" "200" "$(http_code "$RELAY_LOCAL/health/deep")" no
else
  skip "/health/deep (no RELAY_LOCAL_URL given; run on server with http://127.0.0.1:3000)"
fi

note ""
note "== frontend pages =="
check "/setup reachable" "200" "$(http_code "$SITE/setup")" no
check "/docs reachable"  "200" "$(http_code "$SITE/docs")" no
DASH=$($CURL -L "$SITE/dashboard" 2>/dev/null)
contains "/dashboard renders cards" "$DASH" "cards-grid" no
HOME=$($CURL -L "$SITE/" 2>/dev/null)
contains "homepage advertises PQC" "$HOME" "ML-KEM" no

note ""
note "== admin pages =="
check "/admin/settings.html reachable" "200" "$(http_code "$SITE/admin/settings.html")" no
check "/admin/cli.html reachable"      "200" "$(http_code "$SITE/admin/cli.html")" no

note ""
note "== well-known / hygiene =="
PGP=$($CURL "$SITE/.well-known/openpgp-key.asc" 2>/dev/null)
if printf '%s' "$PGP" | grep -q "PLACEHOLDER"; then
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
