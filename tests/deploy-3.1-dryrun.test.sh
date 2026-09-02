#!/usr/bin/env bash
# Dry-run test for deploy/deploy-3.1.sh.
#
# The deploy script is the only thing in this repo that recreates production
# containers and rewrites the nginx config, and it cannot be exercised against
# the server from CI. So this test asserts the two properties that can be
# checked without a server:
#
#   1. every phase of deploy/DEPLOY-3.1.md is reached, in every mode
#   2. no line the script would print can carry a key value
#
# It runs the script with --dry-run, which executes nothing: every remote block
# and every gated local command is printed instead. Exit 0 = all pass.
#
# Usage: bash tests/deploy-3.1-dryrun.test.sh

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/deploy/deploy-3.1.sh"
PASS=0
FAIL=0
FAILURES=""

pass() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); FAILURES="$FAILURES
  - $1"; }

check_has() {   # haystack-file, pattern, name
  if grep -qE -- "$2" "$1"; then pass "$3"; else fail "$3 (no line matching /$2/)"; fi
}
check_lacks() { # haystack-file, pattern, name
  if grep -qE -- "$2" "$1"; then
    fail "$3"
    grep -nE -- "$2" "$1" | head -5 | sed 's/^/        /'
  else
    pass "$3"
  fi
}

echo "======== deploy-3.1.sh dry run ========"

# ---------------------------------------------------------------- 1. syntax --
echo ""
echo "1. The script parses"
if [ -f "$SCRIPT" ]; then pass "deploy/deploy-3.1.sh exists"; else
  fail "deploy/deploy-3.1.sh is missing"
  echo ""; echo "RESULT: $PASS passed, $FAIL failed"; exit 1
fi
if [ -x "$SCRIPT" ]; then pass "deploy/deploy-3.1.sh is executable"; else fail "deploy/deploy-3.1.sh is not executable"; fi
if bash -n "$SCRIPT" 2>/dev/null; then pass "bash -n clean"; else
  fail "bash -n reported a syntax error"
  bash -n "$SCRIPT" 2>&1 | sed 's/^/        /'
fi
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S error "$SCRIPT" >/dev/null 2>&1; then pass "shellcheck (severity error) clean"; else
    fail "shellcheck reported an error-level finding"
    shellcheck -S error "$SCRIPT" 2>&1 | head -20 | sed 's/^/        /'
  fi
else
  printf '  SKIP  shellcheck not installed\n'
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FULL="$WORK/full.txt"
PRE="$WORK/preflight.txt"
RB="$WORK/rollback.txt"

# The script writes its log under deploy/logs/, which is gitignored. Point it
# at the real place anyway: the test asserts the log is written and readable.
( cd "$ROOT" && bash "$SCRIPT" --dry-run                          >"$FULL" 2>&1 ); FULL_RC=$?
( cd "$ROOT" && bash "$SCRIPT" --dry-run --preflight-only         >"$PRE"  2>&1 ); PRE_RC=$?
( cd "$ROOT" && bash "$SCRIPT" --dry-run --rollback 20260101-0000 >"$RB"   2>&1 ); RB_RC=$?

# ------------------------------------------------------------------ 2. modes --
echo ""
echo "2. Every mode runs to the end and exits 0"
[ "$FULL_RC" -eq 0 ] && pass "--dry-run exits 0"                 || fail "--dry-run exits $FULL_RC"
[ "$PRE_RC"  -eq 0 ] && pass "--dry-run --preflight-only exits 0" || fail "--dry-run --preflight-only exits $PRE_RC"
[ "$RB_RC"   -eq 0 ] && pass "--dry-run --rollback exits 0"       || fail "--dry-run --rollback exits $RB_RC"

# Bad arguments are refused, not guessed at.
( cd "$ROOT" && bash "$SCRIPT" --rollback nonsense >/dev/null 2>&1 )
[ $? -eq 2 ] && pass "--rollback with a malformed TS exits 2" || fail "--rollback with a malformed TS was accepted"
( cd "$ROOT" && bash "$SCRIPT" --nope >/dev/null 2>&1 )
[ $? -eq 2 ] && pass "an unknown flag exits 2" || fail "an unknown flag was accepted"

# ----------------------------------------------------------------- 3. phases --
echo ""
echo "3. Every phase of the runbook is reached"
check_has "$FULL" '^PHASE 0: Before you start'                  "phase 0, before you start"
check_has "$FULL" '^PHASE 1: Layout and environment'            "phase 1, layout and environment"
check_has "$FULL" '^PHASE 2: Rollback tags and backups'         "phase 2, rollback tags and backups"
check_has "$FULL" '^PHASE 3: Pull main, run the sanity gate'    "phase 3, pull and build"
check_has "$FULL" '^PHASE 4: Recreate, the canary relay first'  "phase 4, recreate"
check_has "$FULL" '^PHASE 5: Frontend and nginx'                "phase 5, frontend and nginx"
check_has "$FULL" '^PHASE 6: Smoke tests'                       "phase 6, smoke tests"
check_has "$FULL" '^PHASE 7: Summary'                           "phase 7, summary"
check_has "$RB"   '^PHASE 8: Rollback to 20260101-0000'         "phase 8, rollback, under --rollback"

echo ""
echo "3b. Each mode stops where it should"
check_has   "$PRE" '^PHASE 1: '                 "preflight reaches phase 1"
check_lacks "$PRE" '^PHASE [2-8]: '             "preflight stops before phase 2, no deploy write"
check_has   "$PRE" 'PREFLIGHT ONLY'             "preflight says so on the last line"
check_lacks "$RB"  '^PHASE [0-7]: '             "rollback runs phase 8 only"
check_has   "$FULL" '^DEPLOY FINISHED'          "full run reaches the end marker"

# ---------------------------------------------------- 4. the runbook's checks --
echo ""
echo "4. The assertions the runbook demands are in the script"
check_has "$FULL" 'checkout_head=41501bb'                        "asserts the checkout is on 41501bb"
check_has "$FULL" '"recurring":false'                            "asserts billing_config recurring:false"
check_has "$FULL" '"mode_source":"inferred"'                     "asserts billing_config mode_source:inferred"
check_has "$FULL" '"version":"3\.1\.0"'                          "asserts relay_started version 3.1.0"
check_has "$FULL" 'manifest lines = 6|after manifest lines'      "asserts the rollback manifest has six lines"
check_has "$FULL" 'rsync -rc --no-times'                         "rsyncs the docroot"
check_lacks "$FULL" 'rsync -rc[^|]*--delete'                     "never rsyncs the docroot with --delete"
check_has "$FULL" 'paraid deny lines'                            "measures the ParaID deny before and after"
check_has "$FULL" 'nginx -t'                                     "runs nginx -t before reloading"
check_has "$FULL" 'auth-smoke\.sh'                               "runs tests/auth-smoke.sh"
check_has "$FULL" 'v1/paraid/issue-document'                     "probes the removed ParaID route"
check_has "$FULL" 'X-Internal-Auth'                              "probes /v2/health/deep behind the internal header"

echo ""
echo "4b. Every destructive phase carries evidence before and after"
for phase in 2 3 4 5; do
  body="$(awk -v p="^PHASE $phase:" '$0 ~ p {f=1} /^PHASE [0-9]+:/ && $0 !~ p && f {exit} f' "$FULL")"
  b=$(printf '%s\n' "$body" | grep -cE '(^|> )(echo ")?before ' || true)
  a=$(printf '%s\n' "$body" | grep -cE '(^|> )(echo ")?after ' || true)
  if [ "$b" -gt 0 ] && [ "$a" -gt 0 ]; then
    pass "phase $phase prints evidence before ($b) and after ($a)"
  else
    fail "phase $phase is missing evidence lines (before=$b after=$a)"
  fi
done

# ---------------------------------------------------------------- 5. secrets --
echo ""
echo "5. No line the script would print can carry a key value"
# A real Mollie, ParaSign or GitHub key, or a hex token, in any printed line.
check_lacks "$FULL" '(live|test|psk_test|psk_live|sk|gho|ghp|ghs)_[A-Za-z0-9_-]{12,}' \
  "no key-shaped literal in the output"
check_lacks "$FULL" '[0-9a-f]{32,}' \
  "no long hex run (an INTERNAL_AUTH_TOKEN or ADMIN_TOKEN value) in the output"
check_lacks "$FULL" 'BEGIN [A-Z ]*(PRIVATE KEY|OPENSSH)' \
  "no private key material in the output"
check_lacks "$FULL" 'paramant_prod_claude' \
  "the ssh key path is masked, never printed"

# The script must never turn tracing on remotely: set -x would expand $T and
# $tok into the log.
check_lacks "$FULL" '(^|> )[[:space:]]*set -x|set -euxo|set -uxo' \
  "no remote block enables tracing"

# Any line that reads a secret out of .env must consume it, never echo it. The
# three shapes the runbook does allow are a length, a five-character prefix, and
# handing the value straight to curl as a header whose only output is a status
# code. A write whose stdout is redirected into .env is a fourth: it reaches the
# file, never the log. Strip those four, then flag any bare expansion that is
# left.
STRIPPED="$WORK/stripped.txt"
sed -E 's/\$\{#[A-Za-z_]+\}//g
        s/\$\(printf %s "\$[A-Za-z_]+" \| cut -c1-5\)//g
        s/-H "X-(Internal-Auth|Admin-Token): \$[A-Za-z_]+"//g
        /(>|>>)[[:space:]]*"?\.env"?[[:space:]]*$/d' "$FULL" > "$STRIPPED"
check_lacks "$STRIPPED" '(echo|printf)[^|]*\$\{?(T|A|tok|TOKEN)\}?([^A-Za-z_0-9]|$)' \
  "no bare echo or printf of a secret variable"

# The only shapes allowed near a secret are presence, length and a 5-char
# prefix. Assert those are what the script actually does.
check_has "$FULL" 'cut -c1-5' "secrets are reported by prefix only"
check_has "$FULL" 'echo empty' "secrets are reported as present or empty"

# Same scan over the source, so a future edit that prints a value fails here
# even if the printing line sits in a branch the dry run does not walk.
echo ""
echo "5b. The same scan over the source of deploy/deploy-3.1.sh"
check_lacks "$SCRIPT" '(live|test|psk_test|psk_live|sk|gho|ghp|ghs)_[A-Za-z0-9_-]{12,}' \
  "no key-shaped literal in the source"
check_lacks "$SCRIPT" '[0-9a-f]{32,}' "no long hex run in the source"
check_lacks "$SCRIPT" '(^|; |&& )[[:space:]]*set -x' "the source never enables tracing"

# ------------------------------------------------------------------- 6. safe --
echo ""
echo "6. A dry run reaches nothing"
check_has "$FULL" '\[dry-run\] not executed' "gated local commands are printed, not run"
check_has "$FULL" '\[dry-run\] >'            "remote blocks are printed, not run"
check_lacks "$FULL" '^  \| '                 "no line of real remote output, so no ssh was made"
check_has "$FULL" 'DRY RUN \(nothing is executed on the server\)' "the run announces itself as a dry run"

# ---------------------------------------------------------------- 7. logging --
echo ""
echo "7. The run is written to deploy/logs/"
LOGLINE="$(grep -m1 '^  log ' "$FULL" | awk '{print $2}')"
if [ -n "$LOGLINE" ] && [ -f "$LOGLINE" ]; then
  pass "the log file named in the header exists ($(basename "$LOGLINE"))"
else
  fail "no readable log file at '${LOGLINE:-<unnamed>}'"
fi
if git -C "$ROOT" check-ignore -q deploy/logs/ 2>/dev/null; then
  pass "deploy/logs/ is gitignored"
else
  fail "deploy/logs/ is not gitignored; a deploy log would be committable"
fi

# ------------------------------------------------------------------- result --
echo ""
echo "======== RESULT ========"
echo "  passed: $PASS"
echo "  failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf 'Failures:%s\n' "$FAILURES"
  exit 1
fi
echo "All checks passed."
exit 0
