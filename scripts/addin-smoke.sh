#!/usr/bin/env bash
# Add-in / ParaShare surface smoke tests.
# Covers what scripts/post-deploy-verify.sh does not: the Outlook add-in surfaces
# (addin.paramant.app) and the /v2 endpoints the add-in + Chromium extension use.
#
# Usage: scripts/addin-smoke.sh [SITE_URL] [ADDIN_URL]
#   SITE_URL   relay + webapp base, default https://paramant.app  (env PARAMANT_BASE)
#   ADDIN_URL  add-in static host, default https://addin.paramant.app (env ADDIN_BASE)
#
# Optional: PARAMANT_SMOKE_KEY (env) -> a real key for a 1KB upload+delete round.
#   The key comes from the environment ONLY. Never commit a key.
#   Note: an accepted upload consumes one monthly transfer on that key; a key that
#   is over its monthly cap yields a clean 402 (which this test accepts as a pass).
#
# Exit 0 = all pass. Exit 1 = at least one failure.

set -uo pipefail

SITE="${1:-${PARAMANT_BASE:-https://paramant.app}}"
ADDIN="${2:-${ADDIN_BASE:-https://addin.paramant.app}}"
PASS=0
FAIL=0
FAILURES=""

CURL="curl -sS --max-time 15"

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

http_code() { $CURL -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }

echo "════════ ADD-IN SMOKE TESTS ════════"
echo "  Site:   $SITE"
echo "  Add-in: $ADDIN"
echo ""

# ── 1. Add-in static surfaces load ────────────────────────────────────────────
# The Outlook manifest points DesktopSettings/SourceLocation at these exact URLs.
check 'addin taskpane.html returns 200' "$(http_code "$ADDIN/taskpane.html")" '200'
check 'addin commands.html returns 200' "$(http_code "$ADDIN/commands.html")" '200'

# ── 2. /v2/check-key rejects a nonsense key with {valid:false} ─────────────────
# Both extension clients gate on this before upload.
CK_BODY=$($CURL -X POST "$SITE/v2/check-key" \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: pgp_this_key_does_not_exist_0000000000' 2>/dev/null || echo '{}')
CK_VALID=$(printf '%s' "$CK_BODY" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print("false" if d.get("valid") is False else "other")
except Exception:
    print("parse_error")' 2>/dev/null || echo 'parse_error')
check '/v2/check-key on a nonsense key returns valid:false' "$CK_VALID" 'false'

# ── 3. POST /v2/inbound without a key returns 401, not 404 ─────────────────────
# Regression guard: the upload route must be authenticated, not missing.
IN_CODE=$($CURL -o /dev/null -w '%{http_code}' -X POST "$SITE/v2/inbound" \
  -H 'Content-Type: application/json' -d '{}' 2>/dev/null)
check 'POST /v2/inbound without key returns 401' "$IN_CODE" '401'
check_not 'POST /v2/inbound without key is not 404 (route exists)' "$IN_CODE" '404'

# ── 4. Optional real-key round: 1KB upload + delete, or a clean 402 over cap ───
if [ -n "${PARAMANT_SMOKE_KEY:-}" ]; then
  TMPB=$(mktemp)
  head -c 1024 /dev/urandom > "$TMPB"
  PAYLOAD=$(base64 -w0 < "$TMPB" 2>/dev/null || base64 < "$TMPB" | tr -d '\n')
  HASH=$(sha256sum < "$TMPB" | awk '{print $1}')
  rm -f "$TMPB"
  BODY=$(printf '{"hash":"%s","payload":"%s","ttl_ms":60000,"meta":{"device_id":"paramant-smoke"}}' "$HASH" "$PAYLOAD")

  RESP=$($CURL -w $'\n%{http_code}' -X POST "$SITE/v2/inbound" \
    -H 'Content-Type: application/json' -H "X-Api-Key: $PARAMANT_SMOKE_KEY" -d "$BODY" 2>/dev/null)
  UP_CODE=$(printf '%s' "$RESP" | tail -n1)
  UP_JSON=$(printf '%s' "$RESP" | sed '$d')

  if [ "$UP_CODE" = '200' ]; then
    HAS_TOKEN=$(printf '%s' "$UP_JSON" | python3 -c \
      'import json,sys; print("yes" if json.load(sys.stdin).get("download_token") else "no")' 2>/dev/null || echo 'no')
    check 'keyed 1KB upload returns a download_token' "$HAS_TOKEN" 'yes'
    DEL_CODE=$($CURL -o /dev/null -w '%{http_code}' -X DELETE "$SITE/v2/inbound/$HASH" \
      -H "X-Api-Key: $PARAMANT_SMOKE_KEY" 2>/dev/null)
    check 'keyed upload cleans up via DELETE (200)' "$DEL_CODE" '200'
  elif [ "$UP_CODE" = '402' ]; then
    IS_QUOTA=$(printf '%s' "$UP_JSON" | python3 -c \
      'import json,sys; print("yes" if json.load(sys.stdin).get("error")=="monthly_transfer_quota_reached" else "no")' 2>/dev/null || echo 'no')
    check 'keyed upload over cap returns a clean 402 monthly_transfer_quota_reached' "$IS_QUOTA" 'yes'
  else
    check 'keyed 1KB upload returns 200 or 402' "$UP_CODE" '200_or_402'
  fi
else
  echo "  SKIP  keyed upload round (set PARAMANT_SMOKE_KEY to enable)"
fi

# ── 5. Manifest validity ───────────────────────────────────────────────────────
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(dirname "$SCRIPT_DIR")
MANIFEST="$REPO_ROOT/extensions/outlook-addin/manifest.xml"
if [ -f "$MANIFEST" ]; then
  # Hard check: the XML must be well-formed.
  if command -v xmllint >/dev/null 2>&1; then
    if xmllint --noout "$MANIFEST" >/dev/null 2>&1; then
      check 'manifest.xml is well-formed (xmllint)' 'ok' 'ok'
    else
      check 'manifest.xml is well-formed (xmllint)' 'bad' 'ok'
    fi
  elif command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import xml.dom.minidom,sys; xml.dom.minidom.parse(sys.argv[1])' "$MANIFEST" >/dev/null 2>&1; then
      check 'manifest.xml is well-formed (python)' 'ok' 'ok'
    else
      check 'manifest.xml is well-formed (python)' 'bad' 'ok'
    fi
  else
    echo "  SKIP  manifest well-formedness (no xmllint or python3)"
  fi
  # Bonus check: office-addin-manifest schema validate, only if already installed
  # (no network install; keeps post-deploy fast and offline-safe).
  if npx --no-install office-addin-manifest --version >/dev/null 2>&1; then
    if npx --no-install office-addin-manifest validate "$MANIFEST" >/dev/null 2>&1; then
      check 'office-addin-manifest validate passes' 'ok' 'ok'
    else
      check 'office-addin-manifest validate passes' 'bad' 'ok'
    fi
  else
    echo "  SKIP  office-addin-manifest validate (not installed; did XML well-formedness)"
  fi
else
  echo "  SKIP  manifest.xml not found at $MANIFEST"
fi

# ── Summary ─────────────────────────────────────────────────────────────────────
echo ""
echo "════════ RESULT ════════"
printf "PASS: %d\nFAIL: %d\n" "$PASS" "$FAIL"
if [ $FAIL -gt 0 ]; then
  printf "\nFailed tests:%b\n" "$FAILURES"
  exit 1
fi
exit 0
