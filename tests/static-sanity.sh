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
#   (c) receive it as a function parameter (pure helpers like admin/lib/webauthn.js
#       take (redisClient, ...) and never touch a free global — also safe)
# Violation caused a relay crash when a free/global redisClient was undefined;
# a parameter named redisClient is NOT that bug, so it must not trip this check.
echo ""
echo "2. redisClient initialization check..."
for f in \
  "$ROOT/admin/server.js" \
  "$ROOT/admin/lib/"*.js \
  "$ROOT/relay/relay.js"; do
  [ -f "$f" ] || continue
  if grep -q 'redisClient' "$f" 2>/dev/null; then
    if grep -qE 'let redisClient|const redisClient|redisClient = |require.*redis|from.*redis|\(redisClient|, *redisClient' "$f"; then
      printf "   OK  %s  (redisClient initialized, imported, or a parameter)\n" "$(basename "$f")"
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

# ── 7. DID-auth credential is replay-protected ───────────────────────────────
# The DID-auth signature MUST bind a freshness window + one-time nonce, not just
# req.url (which replayed forever). Guard against a regression to the bare form.
echo ""
echo "7. DID-auth replay protection present..."
RELAY="$ROOT/relay/relay.js"
if [ -f "$RELAY" ]; then
  did7_fail=0
  # 7a. The replay nonce cache + freshness window + bound message must exist.
  for needle in "_usedDidNonces" "DID_AUTH_SKEW_MS" "didAuthMessage(" "x-did-nonce" "x-did-ts"; do
    if ! grep -q "$needle" "$RELAY"; then
      printf "   FAIL  relay.js  — DID-auth replay guard missing: %s\n" "$needle"
      did7_fail=1
    fi
  done
  # 7b. authByDid must NOT verify the bare url/payload (the old, replayable form:
  #     crypto.verify('SHA256', Buffer.from(payload), ...) on a multi-line call).
  if grep -A2 -P "crypto\.verify\(\s*$" "$RELAY" 2>/dev/null | grep -q "Buffer.from(payload)"; then
    printf "   FAIL  relay.js  — DID-auth still verifies bare Buffer.from(payload) (replayable)\n"
    did7_fail=1
  fi
  if [ "$did7_fail" -eq 0 ]; then
    printf "   OK  relay.js  (DID-auth binds ts+nonce, no bare-url replay)\n"
  else
    FAIL=$((FAIL + did7_fail))
  fi
fi

# ── 8. Open-mode envelope signatures are signer-bound ────────────────────────
# Open party slots have no email/invite-token gate, so the signature MUST commit
# to the signer pubkey (recipe v4) — otherwise any caller who knows the envelope
# id can fill any slot with a substituted key.
echo ""
echo "8. Open-mode envelope signer binding present..."
ENV="$ROOT/relay/envelope.js"
if [ -f "$ENV" ]; then
  if grep -q "effectiveRecipe" "$ENV" && grep -q "v >= 4" "$ENV"; then
    printf "   OK  envelope.js  (open-mode sign() binds signer pubkey via recipe v4)\n"
  else
    printf "   FAIL  envelope.js  — open-mode signature is not signer-bound (recipe v4 missing)\n"
    FAIL=$((FAIL + 1))
  fi
fi

# ── 9. Public installers keep release pinning ─────────────────────────────────
# /etc/os-release exports VERSION on Debian-family hosts. Installer scripts must
# not use that variable for the release tag, and must not fall back to main HEAD.
echo ""
echo "9. Public installer release pinning..."
for f in \
  "$ROOT/install.sh" \
  "$ROOT/frontend/install.sh" \
  "$ROOT/frontend/install-pi.sh"; do
  [ -f "$f" ] || continue
  name="${f#$ROOT/}"
  installer_fail=0
  if grep -qE '^VERSION=' "$f" 2>/dev/null; then
    printf "   FAIL  %s  — uses VERSION, which /etc/os-release can clobber\n" "$name"
    installer_fail=1
  fi
  if ! grep -q 'RELAY_VERSION="${PARAMANT_VERSION:-' "$f" 2>/dev/null; then
    printf "   FAIL  %s  — missing PARAMANT_VERSION-backed RELAY_VERSION pin\n" "$name"
    installer_fail=1
  fi
  if grep -qE '\|\|[[:space:]]*git clone --depth 1 "\$REPO"' "$f" 2>/dev/null; then
    printf "   FAIL  %s  — falls back to an unpinned default-branch clone\n" "$name"
    installer_fail=1
  fi
  if [ "$installer_fail" -eq 0 ]; then
    printf "   OK  %s  (release tag is isolated from OS VERSION and fail-closed)\n" "$name"
  else
    FAIL=$((FAIL + installer_fail))
  fi
done

# ── 10. Commit/GitHub style guard ────────────────────────────────────────────
# Same gate as the secret checks: block em-dashes, emoji, and AI attribution
# markers in the commit message(s) and the added diff lines.
# scripts/check-commit-style.sh is the single source of truth; the committed
# pre-push hook (.githooks/pre-push) runs the same script on push.
#
# WHICH commits get scanned depends on where this runs, and it has to.
# Locally and on a push the default is right: the last commit, which is the one
# being made. On a pull request in GitHub Actions it is not. actions/checkout
# checks out refs/pull/N/merge, so HEAD is a merge commit whose message reads
# "Merge <sha> into <sha>" and for which git show prints no diff at all. The
# default range would therefore scan an empty commit and report OK over a branch
# full of em-dashes, which is a green tick bought with nothing. So when
# GITHUB_BASE_REF is set, scan the commits the pull request actually adds.
# The job that does this checks out with fetch-depth: 0; without the base branch
# in the clone the range cannot be built, and the check says so rather than
# quietly falling back to the vacuous default.
# PARAMANT_STYLE_RANGE overrides both, for a caller that knows better.
echo ""
echo "10. Commit/GitHub style guard (scripts/check-commit-style.sh)..."
STYLE="$ROOT/scripts/check-commit-style.sh"
STYLE_RANGE="${PARAMANT_STYLE_RANGE:-}"
STYLE_WHAT="last commit"
if [ -n "$STYLE_RANGE" ]; then
  STYLE_WHAT="range $STYLE_RANGE"
elif [ -n "${GITHUB_BASE_REF:-}" ]; then
  for base in "origin/$GITHUB_BASE_REF" "$GITHUB_BASE_REF"; do
    if git -C "$ROOT" rev-parse --verify --quiet "$base^{commit}" >/dev/null 2>&1; then
      STYLE_RANGE="$base..HEAD"
      STYLE_WHAT="range $STYLE_RANGE (the commits this pull request adds)"
      break
    fi
  done
  if [ -z "$STYLE_RANGE" ]; then
    printf "   WARN  GITHUB_BASE_REF=%s is not in this clone (needs fetch-depth: 0);\n" "$GITHUB_BASE_REF"
    printf "         falling back to the last commit, which on a merge ref scans nothing\n"
  fi
fi
if [ -x "$STYLE" ]; then
  if [ -n "$STYLE_RANGE" ]; then
    STYLE_OUT="$("$STYLE" "$STYLE_RANGE" 2>&1)" && STYLE_RC=0 || STYLE_RC=1
  else
    STYLE_OUT="$("$STYLE" 2>&1)" && STYLE_RC=0 || STYLE_RC=1
  fi
  if [ "$STYLE_RC" -eq 0 ]; then
    printf "   OK  %s: message(s) + added lines are style-clean\n" "$STYLE_WHAT"
  else
    printf "   FAIL  style guard flagged the %s:\n" "$STYLE_WHAT"
    printf '%s\n' "$STYLE_OUT" | sed 's/^/     /'
    FAIL=$((FAIL + 1))
  fi
else
  printf "   WARN  %s not found or not executable, style guard skipped\n" "$STYLE"
fi

# ── 11. Test files keep one declaration per top-level name ──────────────
# Every suite is a flat top-level script, so each open pull request appends to
# the SAME namespace. On 2026-09-02 five of them did within the hour and main
# went red on the last merge: const tiers twice in relay/test/pricing-page.test.js,
# const pricingVisible twice in tests/ui-truthfulness.test.mjs. Each branch was
# green alone; the collision existed only in the merge.
# scripts/check-test-declarations.sh parses every suite (a duplicate const is a
# SyntaxError, so the whole file stops running) and separately reports duplicate
# top-level var/function names, which are legal, silent, and change what the
# assertions above them measure.
echo ""
echo "11. Test-scope guard (scripts/check-test-declarations.sh)..."
SCOPE="$ROOT/scripts/check-test-declarations.sh"
if [ -x "$SCOPE" ]; then
  if SCOPE_OUT="$("$SCOPE" 2>&1)"; then
    printf '%s\n' "$SCOPE_OUT" | sed 's/^/   /'
  else
    printf '%s\n' "$SCOPE_OUT" | sed 's/^/   /'
    FAIL=$((FAIL + 1))
  fi
else
  printf "   WARN  %s not found or not executable, test-scope guard skipped\n" "$SCOPE"
fi

# ── 12. Test suites do not write into tracked docs/ by default ───────────────
# tests/app-shots.mjs renders 36 PNGs. It used to write them straight into
# docs/brand/assets/app-2026/, which is tracked, so every local run of the
# browser suites left 36 modified files behind and the next `git commit -a`
# carried them. Refreshing those references is a deliberate act:
# PARAMANT_WRITE_BRAND_SHOTS=1. This is the pre-commit half of that rule, so a
# suite that hardcodes the path is caught before the commit rather than in CI.
# The full guard, including a real dry run of the suite, is
# tests/brand-shots-optin.test.mjs.
echo ""
echo "12. Brand screenshots stay opt-in..."
SHOTS_FLAG='PARAMANT_WRITE_BRAND_SHOTS'
SHOTS_RESOLVER="$ROOT/scripts/brand-shots-dir.mjs"
if [ ! -f "$SHOTS_RESOLVER" ]; then
  printf "   FAIL  scripts/brand-shots-dir.mjs is gone; nothing decides where the shots land\n"
  FAIL=$((FAIL + 1))
elif ! grep -qE "^export const FLAG = '$SHOTS_FLAG';" "$SHOTS_RESOLVER" || ! grep -q 'env\[FLAG\]' "$SHOTS_RESOLVER"; then
  # The assignment and the read, not a mention: the file documents the variable
  # in its header, so a plain grep for the name stays green over a resolver that
  # has stopped reading it.
  printf "   FAIL  scripts/brand-shots-dir.mjs no longer reads %s, so the opt-in is gone\n" "$SHOTS_FLAG"
  FAIL=$((FAIL + 1))
else
  SHOTS_BAD=""
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in *brand-shots-dir.mjs|*brand-shots-optin.test.mjs) continue ;; esac
    grep -qE "docs/brand/assets|'docs', 'brand', 'assets'" "$f" || continue
    grep -qE "$SHOTS_FLAG|brand-shots-dir\.mjs" "$f" && continue
    SHOTS_BAD="$SHOTS_BAD $f"
  done <<< "$(find "$ROOT/tests" "$ROOT/scripts" -type f \( -name '*.mjs' -o -name '*.js' -o -name '*.sh' \) -not -path '*/node_modules/*')"
  if [ -n "$SHOTS_BAD" ]; then
    for f in $SHOTS_BAD; do
      printf "   FAIL  %s names the tracked screenshot directory without the opt-in\n" "${f#"$ROOT/"}"
    done
    printf "         Write to a temp dir by default and let %s=1 opt in.\n" "$SHOTS_FLAG"
    FAIL=$((FAIL + 1))
  else
    printf "   OK  no suite writes the tracked reference images without %s=1\n" "$SHOTS_FLAG"
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
