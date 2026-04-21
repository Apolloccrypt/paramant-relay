#!/usr/bin/env bash
# Static sanity checks — runs as git pre-commit hook.
# Catches the exact bug class that broke auth this week:
#   1. redisClient used but not initialized
#   2. Node.js syntax errors (container crashes on startup)
#   3. Undefined TOTP helpers called in relay code
#   4. req.body.field.method() without null guard (crashes on missing field)
#
# Exit 0 = all clear. Exit 1 = problems found (commit blocked).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0

echo "════════ STATIC SANITY ════════"

# ── 1. Node.js syntax check ──────────────────────────────────────────────────
# If any file has a syntax error, the Node process refuses to start.
# This was the root cause of the admin container crash loop.
echo ""
echo "1. Syntax check (node --check)..."
for f in \
  "$ROOT/admin/server.js" \
  "$ROOT/admin/lib/"*.js \
  "$ROOT/relay/relay.js"; do
  [ -f "$f" ] || continue
  if node --check "$f" 2>/dev/null; then
    printf "   OK  %s\n" "$(basename "$f")"
  else
    printf "   FAIL  %s  — has syntax errors, container will refuse to start:\n" "$(basename "$f")"
    node --check "$f" 2>&1 | head -5
    FAIL=$((FAIL + 1))
  fi
done

# ── 2. redisClient initialization ────────────────────────────────────────────
# A file that uses redisClient must either:
#   (a) initialize it: let redisClient = null + createClient(...)
#   (b) import a redis module
# Violation caused a relay crash when redisClient was undefined.
echo ""
echo "2. redisClient initialization check..."
for f in \
  "$ROOT/admin/server.js" \
  "$ROOT/admin/lib/"*.js \
  "$ROOT/relay/relay.js"; do
  [ -f "$f" ] || continue
  if grep -q 'redisClient' "$f" 2>/dev/null; then
    if grep -qE 'let redisClient|const redisClient|redisClient = |require.*redis|from.*redis' "$f"; then
      printf "   OK  %s  (redisClient initialized or imported)\n" "$(basename "$f")"
    else
      printf "   FAIL  %s  — uses redisClient but no initialization/import found\n" "$(basename "$f")"
      FAIL=$((FAIL + 1))
    fi
  fi
done

# ── 3. TOTP function availability ────────────────────────────────────────────
# verifyTotpGeneric and similar functions were undefined in relay.js after
# a bad merge. Check that any file calling them either defines or imports them.
echo ""
echo "3. TOTP helper availability check..."
for f in \
  "$ROOT/relay/relay.js" \
  "$ROOT/admin/server.js"; do
  [ -f "$f" ] || continue
  for func in verifyTotpGeneric verifyTotp storeUserTotpSecret getUserTotpSecret; do
    if grep -q "$func" "$f" 2>/dev/null; then
      if grep -qE "function $func|const $func|require.*totp|require.*user-totp|from.*totp|$func\s*=" "$f"; then
        printf "   OK  %s  (%s defined or imported)\n" "$(basename "$f")" "$func"
      else
        printf "   WARN  %s  — calls %s but no clear definition/import found\n" "$(basename "$f")" "$func"
        # WARN not FAIL — may be via module scope we can't grep simply
      fi
    fi
  done
done

# ── 4. Unsafe req.body field access ──────────────────────────────────────────
# Pattern req.body.someField.toLowerCase() crashes with TypeError when
# someField is undefined (missing from request body). Check admin server only.
echo ""
echo "4. Unsafe req.body field access check..."
if [ -f "$ROOT/admin/server.js" ]; then
  # Find req.body.X.Y() patterns — these crash when X is undefined
  UNSAFE=$(grep -nE 'req\.body\.[a-zA-Z_]+\.[a-zA-Z_]+\(' "$ROOT/admin/server.js" 2>/dev/null || true)
  if [ -n "$UNSAFE" ]; then
    COUNT=$(echo "$UNSAFE" | wc -l)
    printf "   WARN  %d unsafe req.body.field.method() pattern(s) found:\n" "$COUNT"
    echo "$UNSAFE" | head -5 | sed 's/^/     /'
    printf "         Add null check: const x = req.body.field; if (!x) return 400;\n"
    # WARN not FAIL — some are safe (inside already-validated blocks)
  else
    printf "   OK  admin/server.js  (no raw req.body.X.Y() patterns)\n"
  fi
fi

# ── 5. Orphan code detection ──────────────────────────────────────────────────
# Orphan code (code left over from a bad regex replacement) can introduce
# unexpected syntax errors. Check for the specific patterns that caused issues.
echo ""
echo "5. Orphan code detection..."
if [ -f "$ROOT/admin/server.js" ]; then
  # Check for }); immediately followed by const/let/if (orphan handler body)
  if grep -qP '^\}\);\s*\n\s+(const|let|var|if|try|return)\s' "$ROOT/admin/server.js" 2>/dev/null; then
    printf "   WARN  admin/server.js  — possible orphan code after });\n"
  else
    printf "   OK  admin/server.js  (no orphan code pattern detected)\n"
  fi
fi

# ── 6. request-key handler returns 410, not 200 or 500 ───────────────────────
# Verify the deprecation is in place in the source file.
echo ""
echo "6. Deprecated endpoint returns 410 in source..."
if [ -f "$ROOT/admin/server.js" ]; then
  if grep -A5 "post('/request-key'" "$ROOT/admin/server.js" | grep -q 'status(410)'; then
    printf "   OK  admin/server.js  (/request-key handler returns 410)\n"
  else
    printf "   FAIL  admin/server.js  — /request-key handler does not return 410\n"
    FAIL=$((FAIL + 1))
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════ RESULT ════════"
if [ $FAIL -eq 0 ]; then
  echo "PASS (all hard checks clear)"
else
  echo "FAIL: $FAIL hard problem(s) found — fix before committing"
fi
exit $FAIL
