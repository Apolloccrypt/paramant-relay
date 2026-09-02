#!/usr/bin/env bash
# Dry-run test for deploy/deploy-3.1.sh.
#
# The deploy script is the only thing in this repo that recreates production
# containers and rewrites the nginx config, and it cannot be exercised against
# the server from CI. So this test asserts the properties that can be checked
# without a server:
#
#   1. every phase of deploy/DEPLOY-3.1.md is reached, in every mode
#   2. ssh argument passing survives the join-and-resplit that ssh performs
#   3. every remote block runs under set -euo pipefail
#   4. --preflight-only writes nothing
#   5. no line the script would print, and no line in its source, can carry a
#      key value
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

check_has() {   # file, pattern, name
  if grep -qE -- "$2" "$1"; then pass "$3"; else fail "$3 (no line matching /$2/)"; fi
}
check_lacks() { # file, pattern, name
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

# ------------------------------------------------ 2. the ssh argv join bug ---
echo ""
echo "2. ssh joins argv into one string; a multi-word argument must survive it"
# This is a regression test for a real bug. ssh does not preserve argv: it
# joins everything after the host into a single command string, which the
# remote shell splits again on whitespace. So passing the six service names as
# one argument used to arrive as six separate parameters, and every remote
# `for svc in $2` ran exactly once. Phase 1 then checked 1 of 6 containers and
# phase 2 wrote a 1-line rollback manifest.
#
# There is no sshd to talk to here, so the join is reproduced exactly: "$*"
# concatenates with spaces, and bash -c re-splits, which is what sshd does.
if eval "$(sed -n '/^q_args()/,/^}/p' "$SCRIPT")" 2>/dev/null && declare -F q_args >/dev/null; then
  pass "q_args() could be extracted from the script"

  SVCS="relay-main relay-health relay-finance relay-legal relay-iot admin"
  BODY='echo "argc=$#"; for s in $2; do echo "svc $s"; done'

  # ssh: the client joins, the server re-splits.
  fake_ssh() { local joined="$*"; bash -c "$joined"; }

  quoted="$(printf '%s\n' "$BODY" | fake_ssh "bash -s --$(q_args /opt/paramant-relay "$SVCS")")"
  n_svc="$(printf '%s\n' "$quoted" | grep -c '^svc ' || true)"
  argc="$(printf '%s\n' "$quoted" | sed -n 's/^argc=//p')"

  if [ "$argc" = "2" ]; then pass "the remote shell sees 2 arguments, not 7"; else
    fail "the remote shell sees argc=$argc, expected 2 (arguments are being re-split)"
  fi
  if [ "$n_svc" = "6" ]; then pass "all six service names survive the ssh join"; else
    fail "only $n_svc of 6 service names survived the ssh join"
    printf '%s\n' "$quoted" | sed 's/^/        /'
  fi

  # Negative control: without the quoting the bug comes back. If this ever
  # passes, the simulation stopped reproducing ssh and the test above is empty.
  unquoted="$(printf '%s\n' "$BODY" | fake_ssh "bash -s --" /opt/paramant-relay "$SVCS")"
  n_bad="$(printf '%s\n' "$unquoted" | grep -c '^svc ' || true)"
  if [ "$n_bad" = "1" ]; then
    pass "negative control: unquoted arguments really do collapse to 1 of 6"
  else
    fail "negative control saw $n_bad of 6; the simulation no longer reproduces ssh"
  fi
else
  fail "could not extract q_args() from the script to test it"
fi

# The script must never hand raw arguments to ssh again.
if grep -vE '^[[:space:]]*#' "$SCRIPT" | grep -qE "ssh .*'bash -s' --"; then
  fail "no unquoted 'bash -s' -- argument list is left in the script"
  grep -nvE '^[[:space:]]*#' "$SCRIPT" | grep -E "ssh .*'bash -s' --" | head -3 | sed 's/^/        /'
else
  pass "no unquoted 'bash -s' -- argument list is left in the script"
fi
check_has "$SCRIPT" 'bash -s --\$qargs' \
  "the remote command is built from the quoted argument string"

# --------------------------------------------- 3. every heredoc is strict ----
echo ""
echo "3. Every remote block runs under set -euo pipefail"
HD_TOTAL="$(grep -c "<<'EOF'" "$SCRIPT" || true)"
HD_STRICT="$(grep -c '^set -euo pipefail$' "$SCRIPT" || true)"
# One of the strict lines is the script's own; the rest are the heredocs.
if [ "$HD_STRICT" -eq $((HD_TOTAL + 1)) ]; then
  pass "all $HD_TOTAL remote blocks plus the script itself are strict"
else
  fail "found $HD_TOTAL heredocs but $HD_STRICT strict-mode lines (expected $((HD_TOTAL + 1)))"
fi
check_lacks "$SCRIPT" '^set -uo pipefail$' "no remote block runs without -e"
# `cp x && chmod y` hides a failing cp from -e, because the AND-list as a whole
# is what -e judges.
check_lacks "$SCRIPT" '^cp .* && chmod ' "no cp-and-chmod pair hides a failure from -e"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FULL="$WORK/full.txt"
PRE="$WORK/preflight.txt"
RB="$WORK/rollback.txt"

( cd "$ROOT" && bash "$SCRIPT" --dry-run                          >"$FULL" 2>&1 ); FULL_RC=$?
( cd "$ROOT" && bash "$SCRIPT" --dry-run --preflight-only         >"$PRE"  2>&1 ); PRE_RC=$?
( cd "$ROOT" && bash "$SCRIPT" --dry-run --rollback 20260101-0000 >"$RB"   2>&1 ); RB_RC=$?

# ------------------------------------------------------------------ 4. modes --
echo ""
echo "4. Every mode runs to the end and exits 0"
[ "$FULL_RC" -eq 0 ] && pass "--dry-run exits 0"                  || fail "--dry-run exits $FULL_RC"
[ "$PRE_RC"  -eq 0 ] && pass "--dry-run --preflight-only exits 0" || fail "--dry-run --preflight-only exits $PRE_RC"
[ "$RB_RC"   -eq 0 ] && pass "--dry-run --rollback exits 0"       || fail "--dry-run --rollback exits $RB_RC"

( cd "$ROOT" && bash "$SCRIPT" --rollback nonsense >/dev/null 2>&1 )
[ $? -eq 2 ] && pass "--rollback with a malformed TS exits 2" || fail "--rollback with a malformed TS was accepted"
( cd "$ROOT" && bash "$SCRIPT" --nope >/dev/null 2>&1 )
[ $? -eq 2 ] && pass "an unknown flag exits 2" || fail "an unknown flag was accepted"

# ----------------------------------------------------------------- 5. phases --
echo ""
echo "5. Every phase of the runbook is reached"
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
echo "5b. Each mode stops where it should"
check_has   "$PRE" '^PHASE 1: '                 "preflight reaches phase 1"
check_lacks "$PRE" '^PHASE [2-8]: '             "preflight stops before phase 2"
check_has   "$PRE" 'PREFLIGHT ONLY'             "preflight says so on the last line"
check_lacks "$RB"  '^PHASE [0-7]: '             "rollback runs phase 8 only"
check_has   "$FULL" '^DEPLOY FINISHED'          "full run reaches the end marker"

echo ""
echo "5c. --preflight-only writes nothing"
check_has   "$PRE" 'read-only'                          "preflight announces itself as read-only"
check_has   "$PRE" 'Nothing was written'                "preflight ends by saying nothing was written"
check_lacks "$PRE" 'WRITE'                              "no phase header in preflight is marked WRITE"
check_has   "$PRE"  'bash -s --.* report'               "the token step is invoked in report mode"
check_lacks "$PRE"  'bash -s --.* write'                "no step in preflight is invoked in write mode"
check_has   "$FULL" 'bash -s --.* write'                "a full run invokes the token step in write mode"
check_has   "$PRE" 'REPORT ONLY'                        "the token step reports instead of generating"

# ---------------------------------------------------- 6. the runbook's checks --
echo ""
echo "6. The assertions the runbook demands are in the script"
check_has "$FULL" 'checkout_head = 41501bb'                      "asserts the checkout is on 41501bb"
check_has "$FULL" 'services seen = 6'                            "asserts all six services were seen"
check_has "$FULL" '"recurring":false'                            "asserts billing_config recurring:false"
check_has "$FULL" '"mode_source":"inferred"'                     "asserts billing_config mode_source:inferred"
check_has "$FULL" '"version":"3\.1\.0"'                          "asserts relay_started version 3.1.0"
check_has "$FULL" 'after manifest lines = 6'                     "asserts the manifest has six lines"
check_has "$FULL" 'after tags for this TS = 6'                   "asserts six rollback IMAGES exist, not six lines of text"
check_has "$FULL" 'after \.env backup bytes >= 1'                "asserts the .env backup has real bytes"
check_has "$FULL" 'after docroot tar entries >= 1'               "asserts the docroot tar has real entries"
check_has "$FULL" 'rsync -rc --no-times'                         "rsyncs the docroot"
check_lacks "$FULL" 'rsync -rc[^|]*--delete'                     "never rsyncs the docroot with --delete"
check_has "$FULL" 'diff-filter=D'                                "derives the stale docroot files from git, not a wildcard"
check_has "$FULL" 'after paraid deny'                            "measures the ParaID deny before and after"
check_has "$FULL" 'after edited files = 2'                       "asserts both named nginx confs were rewritten"
check_has "$FULL" 'readlink -f'                                  "resolves sites-enabled symlinks before backing up or editing"
check_has "$FULL" 'nginx -t'                                     "runs nginx -t before reloading"
check_has "$FULL" 'auth-smoke\.sh'                               "runs tests/auth-smoke.sh"
check_has "$FULL" 'v1/paraid/issue-document'                     "probes the removed ParaID route"
check_has "$FULL" 'compliance/nis2'                              "probes a page main deleted"
check_has "$FULL" 'X-Internal-Auth'                              "probes /v2/health/deep behind the internal header"

echo ""
echo "6aa. The inline receipt opt-in (#342) is set, buffered and proven"
check_has "$FULL" 'PARAMANT_INLINE_RECEIPT_HEADER'      "phase 1 handles the inline receipt flag"
check_has "$FULL" 'proxy_buffer_size 32k'               "phase 5 raises the proxy buffers the fat header needs"
check_has "$FULL" 'before outbound locations'           "phase 5 refuses to add buffers to a location that is not there"
check_has "$FULL" 'effective outbound buffers'          "phase 6 reads the LOADED nginx config, not the file"
check_has "$SCRIPT" 'x-paramant-receipt:'               "phase 6 checks the inline receipt header on a real download"
check_has "$SCRIPT" 'x-paramant-receipt-\$f:'            "phase 6 checks the id/hash/url reference shape too"
check_has "$SCRIPT" '\-gt 16000'                         "phase 6 asserts the header block really exceeded 16 KB"
check_has "$SCRIPT" 'PARAMANT_SMOKE_API_KEY is not set'  "phase 6 says plainly what it could NOT prove without a key"
check_has "$FULL"   'needs PARAMANT_SMOKE_API_KEY'      "the dry run names the key the full proof needs"

echo ""
echo "6ab. The compose file really passes the receipt variables through"
# There is no env_file in docker-compose.yml: .env only substitutes ${VAR}
# inside the compose file, so a variable without a line in x-relay-env never
# reaches a container no matter what .env says.
COMPOSE="$ROOT/docker-compose.yml"
check_lacks "$COMPOSE" '^[[:space:]]*env_file' \
  "docker-compose.yml still has no env_file, so x-relay-env is the only route in"
for v in PARAMANT_INLINE_RECEIPT_HEADER PARAMANT_RECEIPT_PER_ACCOUNT_MAX \
         PARAMANT_RECEIPT_UNCAPPED_MAX PARAMANT_RECEIPT_TOTAL_MAX; do
  check_has "$COMPOSE" "^  $v: " "x-relay-env declares $v"
done
check_has "$FULL" 'compose inline flag on'  "phase 4 proves the flag renders BEFORE the recreate"
check_has "$FULL" 'docker compose config'   "that proof uses docker compose config, not a guess"

echo ""
echo "6ac. The round-2 guards"
check_has "$SCRIPT" 'BLOCK_AWK'                          "the buffer guard counts inside each /v2/outbound block"
check_has "$FULL"   'after outbound blocks with buffer'  "phase 5 reports blocks, not file-wide grep hits"
check_has "$SCRIPT" 'REFUSED'                            "phase 5b refuses a deletion that resolves outside the docroot"
check_has "$FULL"   'after refused outside docroot'      "phase 5b reports how many deletions it refused"
check_has "$SCRIPT" 'NOT PROVEN'                         "phase 6h says NOT PROVEN when the header block is under 16 KB"

echo ""
echo "6b. Rollback restores in an order that cannot half-fail"
check_has "$RB" 'missing backups = 0'    "rollback refuses to start when a backup it needs is absent"
check_has "$RB" 'restore \.env first'    "rollback restores .env before recreating the containers"
check_has "$RB" 'after recreated services = 6' "rollback asserts all six services came back"
check_has "$RB" 'removed added-by-deploy' "rollback removes the files the deploy added, which tar x cannot"
check_has "$RB" 'not reloading'          "rollback tests nginx before reloading it"

echo ""
echo "6c. Every destructive phase carries evidence before and after"
for phase in 2 3 4 5; do
  body="$(awk -v p="^PHASE $phase:" '$0 ~ p {f=1} /^PHASE [0-9]+:/ && $0 !~ p && f {exit} f' "$FULL")"
  b=$(printf '%s\n' "$body" | grep -cE '(^|> )[[:space:]]*(echo ")?before ' || true)
  a=$(printf '%s\n' "$body" | grep -cE '(^|> )[[:space:]]*(echo ")?after ' || true)
  if [ "$b" -gt 0 ] && [ "$a" -gt 0 ]; then
    pass "phase $phase prints evidence before ($b) and after ($a)"
  else
    fail "phase $phase is missing evidence lines (before=$b after=$a)"
  fi
done

# ---------------------------------------------------------------- 7. secrets --
echo ""
echo "7. No line the script would print can carry a key value"
check_lacks "$FULL" '(live|test|psk_test|psk_live|sk|gho|ghp|ghs)_[A-Za-z0-9_-]{12,}' \
  "no key-shaped literal in the output"
check_lacks "$FULL" '[0-9a-f]{32,}' \
  "no long hex run (an INTERNAL_AUTH_TOKEN or ADMIN_TOKEN value) in the output"
check_lacks "$FULL" 'BEGIN [A-Z ]*(PRIVATE KEY|OPENSSH)' \
  "no private key material in the output"
check_lacks "$FULL" 'paramant_prod_claude' \
  "the ssh key path is masked, never printed"
check_lacks "$FULL" '(^|> )[[:space:]]*set -x|set -euxo|set -uxo' \
  "no remote block enables tracing"

# Any line that reads a secret must consume it, never echo it. The three shapes
# the runbook does allow are a length, a five-character prefix, and handing the
# value straight to curl as a header whose only output is a status code. A write
# whose stdout is redirected into .env is a fourth: it reaches the file, never
# the log. Strip those four, then flag any bare expansion that is left.
STRIPPED="$WORK/stripped.txt"
sed -E 's/\$\{#[A-Za-z_]+\}//g
        s/\$\(printf %s "\$[A-Za-z_]+" \| cut -c1-5\)//g
        s/-H "X-(Internal-Auth|Admin-Token|Api-Key): \$[A-Za-z_]+"//g
        /(>|>>)[[:space:]]*"?\.env"?[[:space:]]*$/d' "$FULL" > "$STRIPPED"
check_lacks "$STRIPPED" '(echo|printf)[^|]*\$\{?(T|A|K|tok|TOKEN|KEY|SECRET)\}?([^A-Za-z_0-9]|$)' \
  "no bare echo or printf of a known secret variable"

# A name list only catches the names on it. Learn instead which variables hold
# a value read out of .env (or minted by openssl), then flag any echo or printf
# of one of those, whatever it ended up being called. This is what catches a
# rename that a fixed list would wave through.
SRCSTRIP="$WORK/srcstrip.txt"
sed -E 's/\$\{#[A-Za-z_]+\}//g
        s/\$\(printf %s "\$[A-Za-z_]+" \| cut -c1-5\)//g
        s/-H "X-(Internal-Auth|Admin-Token|Api-Key): \$[A-Za-z_]+"//g
        /(>|>>)[[:space:]]*"?\.env"?[[:space:]]*$/d' "$SCRIPT" > "$SRCSTRIP"
# A counting read (grep -c, wc -l) yields a number, not content, so the
# variable it fills is not tainted.
TAINT="$(grep -E '(\.env|openssl rand)' "$SCRIPT" \
         | grep -vE 'grep -c|grep -qc|wc -l' \
         | grep -oE '(^|[[:space:]])[A-Za-z_][A-Za-z_0-9]*=' \
         | tr -d ' =' | sort -u)"
# Let the taint inherit over one assignment, so `s3cr="$tok"` is tainted too.
# One hop only: a full dataflow analysis is not what a shell test should be,
# and two hops have never appeared in this script. If that changes, this is
# the line to extend, and the limit is written down here on purpose.
for _v in $TAINT; do
  _heirs="$(grep -oE "(^|[[:space:]])[A-Za-z_][A-Za-z_0-9]*=\"?\\\$\{?$_v\}?\"?[[:space:]]*\$" "$SCRIPT" \
            | grep -oE '[A-Za-z_][A-Za-z_0-9]*=' | tr -d ' =' || true)"
  [ -n "$_heirs" ] && TAINT="$TAINT $_heirs"
done
TAINT="$(printf '%s\n' $TAINT | sort -u)"
if [ -z "$TAINT" ]; then
  fail "the taint scan found no variable reading .env; the scan is not looking at anything"
else
  TLEAK="$WORK/taintleak.txt"
  : > "$TLEAK"
  for v in $TAINT; do
    grep -nE "(echo|printf)[^|]*\\\$\\{?$v\\}?([^A-Za-z_0-9]|\$)" "$SRCSTRIP" >> "$TLEAK" || true
  done
  if [ ! -s "$TLEAK" ]; then
    pass "no .env-derived variable is ever echoed (tainted: $(printf '%s' "$TAINT" | tr '\n' ' '))"
  else
    fail "a variable holding a value read from .env would be printed"
    sort -u "$TLEAK" | head -5 | sed 's/^/        /'
  fi
fi

check_has "$FULL" 'cut -c1-5' "secrets are reported by prefix only"
check_has "$FULL" 'echo empty' "secrets are reported as present or empty"

echo ""
echo "7b. The same scan over the source, including branches the dry run misses"
check_lacks "$SCRIPT" '(live|test|psk_test|psk_live|sk|gho|ghp|ghs)_[A-Za-z0-9_-]{12,}' \
  "no key-shaped literal in the source"
check_lacks "$SCRIPT" '[0-9a-f]{32,}' "no long hex run in the source"
check_lacks "$SCRIPT" '(^|; |&& )[[:space:]]*set -x' "the source never enables tracing"

# Every read of .env in the source has to go somewhere that is not stdout: into
# a variable, into a redirect, or into a counter. A read whose output falls
# through to the log is a leak whatever the variable ends up being called, so
# this scans the shape of the read and not the name of the variable.
ENVREADS="$WORK/envreads.txt"
# The tool name has to sit at a command position and be a whole word, or
# "header" matches "head" and every sentence mentioning .env is a finding.
grep -nE '(^|[;&|(]|[[:space:]])(cat|grep|awk|sed|head|tail|cut|printenv)[[:space:]][^|]*\.env' "$SCRIPT" > "$ENVREADS" || true
LEAKY="$WORK/leaky.txt"
: > "$LEAKY"
while IFS= read -r line; do
  [ -n "$line" ] || continue
  code="${line#*:}"
  # Comments describe, they do not execute.
  case "$(printf '%s' "$code" | sed 's/^[[:space:]]*//')" in '#'*) continue;; esac
  # Allowed: captured into a substitution, assigned, redirected, or counted.
  case "$code" in
    *'$('*|*'`'*|*'>'*|*'grep -c'*|*'grep -qc'*|*'sed -i'*|*'grep -q '*) continue;; esac
  printf '%s\n' "$line" >> "$LEAKY"
done < "$ENVREADS"
if [ ! -s "$LEAKY" ]; then
  pass "every read of .env is captured, redirected or counted, never printed ($(wc -l < "$ENVREADS") read(s) checked)"
else
  fail "a read of .env would reach stdout"
  sed 's/^/        /' "$LEAKY"
fi
check_lacks "$SCRIPT" '(^|[^-])cat[[:space:]]+[^|;]*\.env([^.a-zA-Z]|$)' \
  "the source never cats .env"

# ------------------------------------------------------------------- 8. safe --
echo ""
echo "8. A dry run reaches nothing"
check_has "$FULL" '\[dry-run\] not executed' "gated local commands are printed, not run"
check_has "$FULL" '\[dry-run\] >'            "remote blocks are printed, not run"
check_lacks "$FULL" '^  \| '                 "no line of real remote output, so no ssh was made"
check_has "$FULL" 'DRY RUN \(nothing is executed on the server\)' "the run announces itself as a dry run"

# ---------------------------------------------------------------- 9. logging --
echo ""
echo "9. The run is written to deploy/logs/"
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
