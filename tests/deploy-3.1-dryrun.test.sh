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

# extract_remote <label>: the body of one remote block, verbatim from the
# script. A block that touches an nginx conf is sent with remote_nginx, which
# prepends NGINX_RESOLVE_SNIPPET on the wire, so the snippet is prepended here
# too. What these tests run is then exactly what the server runs.
extract_snippet() {
  sed -n "/^NGINX_RESOLVE_SNIPPET=/,/^RESOLVER\$/p" "$SCRIPT" | sed '1d;$d'
}
extract_remote() {
  local label="$1" line kind
  line="$(grep -nE "^  remote(_nginx)? \"$label\"" "$SCRIPT" | head -1)"
  [ -n "$line" ] || return 1
  kind="$(printf '%s' "$line" | sed -E 's/^[0-9]+:[[:space:]]*([a-z_]+).*/\1/')"
  [ "$kind" = remote_nginx ] && extract_snippet
  sed -n "/^  remote\(_nginx\)\? \"$label\"/,/^EOF\$/p" "$SCRIPT" | sed '1d;$d'
}

# resolve_conf_slots() is the function the script sends to the server. It is
# used here too, to build the phase 2b backups that a 5c fixture needs, exactly
# the way 2b builds them. The function itself is tested in section 6i-1.
eval "$(extract_snippet)" 2>/dev/null || true

# seed_2b_backups <sites-dir> <ngbk-dir> <ts> <slots>: what phase 2b leaves in
# /etc/nginx/backups. 5c refuses to edit a conf that has no backup under the
# run TS, because restore() could not put that conf back, so every 5c fixture
# has to have been through 2b first.
seed_2b_backups() {
  local sites="$1" ngbk="$2" ts="$3" slots="$4" name
  mkdir -p "$ngbk"
  declare -F resolve_conf_slots >/dev/null || return 0
  resolve_conf_slots "$sites" "$slots" >/dev/null
  for name in $RESOLVED_CONFS; do
    cp -a "$(readlink -f "$sites/$name")" "$ngbk/$name.pre-3.1-$ts"
  done
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
check_has   "$PRE" 'no file was written, no container touched' \
  "preflight ends by saying what it did not write"
check_has   "$PRE" 'git fetch in phase 1a'   "preflight names the one thing it does run: git fetch"
check_has   "$PRE" 'does not move HEAD'      "preflight says what that fetch does not do"
check_lacks "$PRE" 'WRITE'                              "no phase header in preflight is marked WRITE"
check_has   "$PRE"  'bash -s --.* report'               "the token step is invoked in report mode"
check_lacks "$PRE"  'bash -s --.* write'                "no step in preflight is invoked in write mode"
check_has   "$FULL" 'bash -s --.* write'                "a full run invokes the token step in write mode"
check_has   "$PRE" 'REPORT ONLY'                        "the token step reports instead of generating"

# ---------------------------------------------------- 6. the runbook's checks --
echo ""
echo "6. The assertions the runbook demands are in the script"
check_has "$FULL" 'checkout_head = 41501bb'                      "falls back to 41501bb when the server has no deployed-head marker"
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
check_has "$FULL" 'after edited files'                           "measures how many nginx confs were rewritten"
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
echo "6f. The expected starting commit is a parameter, so a second deploy runs"
# The old phase 1a asserted `checkout_head = 41501bb` and nothing else. After
# the first successful deploy the checkout is on main, so every later run, and
# every resume of a run that died in phase 5, stopped on that one line. These
# checks are the four situations the parameter has to cover.
check_has "$SCRIPT" 'PARAMANT_EXPECTED_HEAD'   "the expected commit can be given explicitly"
check_has "$SCRIPT" 'DEPLOYED_HEAD_FILE'       "the script knows where the deployed-head marker lives"
check_has "$FULL"   'deployed_marker'          "phase 1a reads the marker off the server"
check_has "$FULL"   'merge-base --is-ancestor' "phase 1a asks whether the checkout is an ancestor of the deploy ref"
check_has "$FULL"   'git fetch origin'         "that ancestor question is asked after a fetch, not against stale refs"
check_has "$FULL"   'after deployed marker'    "phase 7 writes the marker the next run reads"
check_lacks "$SCRIPT" 'expect "checkout_head = \$EXPECT_PROD_COMMIT"' \
  "the hard-coded one-commit gate is gone from phase 1a"

# The decision itself is a pure function, so every case can be put through it
# here without a server. Same trick as q_args above.
if eval "$(sed -n '/^sha_eq()/,/^}/p' "$SCRIPT")" 2>/dev/null \
   && eval "$(sed -n '/^head_gate_verdict()/,/^}/p' "$SCRIPT")" 2>/dev/null \
   && declare -F head_gate_verdict >/dev/null; then
  pass "head_gate_verdict() and sha_eq() could be extracted from the script"

  # Synthetic commits. Never a real sha, so nothing here can be mistaken for
  # a value read off the server.
  A=aaaaaaa1111222233334444555566667777888899
  B=bbbbbbb1111222233334444555566667777888899
  OLD=41501bb

  gate() {   # override marker head fallback ancestor -> prints "<rc> <text>"
    local out rc=0
    out="$(head_gate_verdict "$1" "$2" "$3" "$4" "$5")" || rc=$?
    printf '%s %s\n' "$rc" "$out"
  }
  gate_is() {   # name, want-rc, want-word, args...
    local name="$1" wrc="$2" word="$3"; shift 3
    local got; got="$(gate "$@")"
    if [ "${got%% *}" = "$wrc" ] && printf '%s' "$got" | grep -q "$word"; then
      pass "$name"
    else
      fail "$name (got: $got)"
    fi
  }

  echo ""
  echo "6f-1. First deploy: no marker, so the runbook's own starting commit applies"
  gate_is "no marker and the checkout is on $OLD: OK" 0 'first deploy' \
          "" none "$OLD" "$OLD" unknown
  gate_is "no marker and the checkout is somewhere else: STOP" 1 'must be on' \
          "" none "$A" "$OLD" yes
  gate_is "an empty marker file reads as no marker at all" 0 'first deploy' \
          "" "" "$OLD" "$OLD" unknown

  echo ""
  echo "6f-2. Second deploy: the marker is the expectation, plus an ancestor test"
  gate_is "the checkout matches the marker and is an ancestor of the ref: OK" 0 'last deploy recorded' \
          "" "$A" "$A" "$OLD" yes
  gate_is "the checkout matches the marker but is NOT an ancestor: STOP" 1 'not an ancestor' \
          "" "$A" "$A" "$OLD" no
  gate_is "the ref could not be resolved on the server: STOP, not a pass" 1 'could not decide' \
          "" "$A" "$A" "$OLD" unknown
  gate_is "the checkout drifted away from the marker: STOP" 1 'outside a deploy' \
          "" "$A" "$B" "$OLD" yes
  gate_is "a marker never makes $OLD acceptable again by itself" 1 'outside a deploy' \
          "" "$A" "$OLD" "$OLD" yes
  gate_is "the marker may be written short and still match a full sha" 0 'last deploy recorded' \
          "" "${A:0:7}" "$A" "$OLD" yes

  echo ""
  echo "6f-3. PARAMANT_EXPECTED_HEAD overrides both, on equality alone"
  gate_is "the override matches: OK, no marker consulted" 0 'PARAMANT_EXPECTED_HEAD names' \
          "$A" none "$A" "$OLD" no
  gate_is "the override matches while the marker says otherwise: OK" 0 'PARAMANT_EXPECTED_HEAD names' \
          "$A" "$B" "$A" "$OLD" unknown
  gate_is "the override does not match: STOP, even on the runbook commit" 1 'PARAMANT_EXPECTED_HEAD names' \
          "$A" none "$OLD" "$OLD" yes
  gate_is "a short override matches a full checkout sha" 0 'PARAMANT_EXPECTED_HEAD names' \
          "${A:0:7}" none "$A" "$OLD" yes

  echo ""
  echo "6f-4. Nonsense answers are stops, never passes"
  gate_is "an empty checkout sha: STOP" 1 'never printed' \
          "" none "" "$OLD" yes
  if sha_eq abc abc; then
    fail "sha_eq accepts a 3-character prefix; that is not an identification"
  else
    pass "sha_eq refuses anything shorter than 7 characters"
  fi
  if sha_eq "$A" "$B"; then fail "sha_eq matched two different commits"
  else pass "sha_eq refuses two different commits"; fi
else
  fail "could not extract head_gate_verdict() from the script to test it"
fi

echo ""
echo "6f-5. The whole script, run with the override set"
OVR="$WORK/override.txt"
( cd "$ROOT" && PARAMANT_EXPECTED_HEAD=deadbee1234567 bash "$SCRIPT" --dry-run --preflight-only >"$OVR" 2>&1 )
OVR_RC=$?
[ "$OVR_RC" -eq 0 ] && pass "--dry-run with PARAMANT_EXPECTED_HEAD set exits 0" \
                    || fail "--dry-run with PARAMANT_EXPECTED_HEAD set exits $OVR_RC"
check_has   "$OVR" 'expected head deadbee1234567' "the header names the override it will gate on"
check_lacks "$OVR" 'no marker in'                 "with the override set, the marker fallback is not announced"
check_has   "$PRE" 'deployed-head'                "without the override, the header names the marker file"

echo ""
echo "6g. Phase 5c is idempotent: an edit that is already applied is not FATAL"
# The old 5c stopped with FATAL as soon as an edit had nothing to do, so the
# second deploy died on the nginx step even though the conf was exactly right.
# This runs the REAL 5c remote block, extracted from the script, against
# synthetic confs, with nginx and systemctl stubbed. Three passes:
#
#   1. the conf in its pre-3.1 shape        -> edits applied, files rewritten
#   2. the same conf, run again             -> already applied, nothing rewritten
#   3. a conf with neither shape            -> FATAL, which is still correct
NG="$WORK/ng"
mkdir -p "$NG/bin" "$NG/sites" "$NG/bk"
cat > "$NG/bin/nginx" <<'STUB'
#!/bin/sh
exit 0
STUB
cat > "$NG/bin/systemctl" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$NG/bin/nginx" "$NG/bin/systemctl"

# The 5c body, verbatim from the script, resolver and all.
extract_remote "nginx edits" > "$NG/5c.sh"
if [ -s "$NG/5c.sh" ]; then
  pass "the 5c remote block could be extracted from the script"
else
  fail "could not extract the 5c remote block from the script"
fi

make_conf() {   # file, sign-shape(old|new|absent), dicom-shape, compliance(yes|no), buffers(yes|no)
  local f="$1" sign="$2" dicom="$3" comp="$4" buf="$5"
  {
    echo 'server {'
    echo '    server_name paramant.app;'
    case "$sign" in
      old)    echo '    location = /sign { auth_request /api/user/check; error_page 401 = @login_redirect; try_files /sign.html =404; }' ;;
      new)    echo '    location = /sign { try_files /sign.html =404; }' ;;
      absent) : ;;
    esac
    if [ "$comp" = yes ]; then
      echo '    location = /compliance { try_files /compliance/index.html =404; }'
      echo '    location = /compliance/nis2 { try_files /compliance/nis2.html =404; }'
      echo '    location = /compliance/iec62443 { try_files /compliance/iec62443.html =404; }'
      echo '    location = /compliance/nen7510 { try_files /compliance/nen7510.html =404; }'
    fi
    case "$dicom" in
      old)    echo '    location = /dicom { try_files /dicom.html =404; }' ;;
      new)    echo '    location = /dicom { return 404; }' ;;
      absent) : ;;
    esac
    echo '    location = /v1/paraid/issue-document { deny all; }'
    echo '    location ~ ^/v2/outbound {'
    if [ "$buf" = yes ]; then
      echo '        proxy_buffer_size 32k;'
      echo '        proxy_buffers 8 32k;'
      echo '        proxy_busy_buffers_size 64k;'
    fi
    echo '        proxy_pass http://relay;'
    echo '    }'
    echo '}'
  } > "$f"
}

field_5c() { printf '%s\n' "$1" | sed -n "s/^$2 = //p" | head -1; }

# sites-enabled is symlinks into sites-available on the real server, so the
# fixture is too: that is also what exercises the readlink -f resolution.
mkdir -p "$NG/available"
make_conf "$NG/available/paramant-public.conf" old old yes no
make_conf "$NG/available/paramant-live.conf"   old old yes no
ln -sfn "$NG/available/paramant-public.conf" "$NG/sites/paramant-public.conf"
ln -sfn "$NG/available/paramant-live.conf"   "$NG/sites/paramant-live.conf"

echo ""
echo "6g-1. First run: the conf is in its pre-3.1 shape, so there is work to do"
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0000 "paramant-public.conf paramant-live.conf"
OUT1="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0000 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" 2>&1)"; RC1=$?
if [ "$RC1" -eq 0 ]; then pass "5c exits 0 on a conf that still needs the edits"; else
  fail "5c exits $RC1 on a conf that still needs the edits"
  printf '%s\n' "$OUT1" | sed 's/^/        /' | head -20
fi
# Everything after this run is the END state the deploy is actually for.
for want in "after sign gated:0" "after compliance:0" "after dicom try_files:0"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUT1" "$f")" = "$v" ]; then pass "5c leaves $f at $v"; else
    fail "5c left $f at '$(field_5c "$OUT1" "$f")', expected $v"; fi
done
if [ "$(field_5c "$OUT1" 'after edited files')" = "2" ]; then
  pass "5c rewrote both confs on the first run"
else
  fail "5c rewrote $(field_5c "$OUT1" 'after edited files') conf(s) on the first run, expected 2"
fi
if [ "$(field_5c "$OUT1" 'after outbound blocks with buffer')" \
   = "$(field_5c "$OUT1" 'after outbound locations')" ]; then
  pass "every /v2/outbound block came out with the buffer"
else
  fail "the buffer landed in $(field_5c "$OUT1" 'after outbound blocks with buffer') of $(field_5c "$OUT1" 'after outbound locations') blocks"
fi
# /pararules moved to /rules in the two-product-names round. The old path is
# indexed, so the 301 has to be in every block that answers for the site, not
# just the first one the edit happened to walk into.
if [ "$(field_5c "$OUT1" 'before pararules blocks with redirect')" = "0" ]; then
  pass "the fixture starts without the /pararules redirect, so the edit has work to do"
else
  fail "the fixture already carries the redirect; this run would prove nothing"
fi
if [ "$(field_5c "$OUT1" 'after pararules blocks with redirect')" \
   = "$(field_5c "$OUT1" 'after pararules blocks')" ] \
   && [ "$(field_5c "$OUT1" 'after pararules blocks')" = "2" ]; then
  pass "every site block came out with the 301 from /pararules to /rules"
else
  fail "the 301 landed in $(field_5c "$OUT1" 'after pararules blocks with redirect') of $(field_5c "$OUT1" 'after pararules blocks') site blocks"
fi
if [ "$(field_5c "$OUT1" 'after pararules redirect lines')" = "2" ]; then
  pass "the redirect was written once per conf, not twice"
else
  fail "5c wrote $(field_5c "$OUT1" 'after pararules redirect lines') redirect line(s), expected 2"
fi

echo ""
echo "6g-2. Second run on the same confs: already applied, not FATAL"
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0001 "paramant-public.conf paramant-live.conf"
OUT2="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0001 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" 2>&1)"; RC2=$?
if [ "$RC2" -eq 0 ]; then pass "a second 5c on an already-edited conf exits 0"; else
  fail "a second 5c on an already-edited conf exits $RC2 (this is the bug)"
  printf '%s\n' "$OUT2" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT2" | grep -q FATAL; then
  fail "a second 5c still prints FATAL"
  printf '%s\n' "$OUT2" | grep FATAL | sed 's/^/        /'
else
  pass "a second 5c prints no FATAL"
fi
for want in "before sign state:done" "before compliance state:done" "before dicom state:done" \
            "before edits pending:0" "before everything already applied:yes" \
            "before pararules blocks with redirect:2" \
            "after pararules redirect lines:2" \
            "after edited files:0"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUT2" "$f")" = "$v" ]; then pass "second run reports $f = $v"; else
    fail "second run reports $f = '$(field_5c "$OUT2" "$f")', expected $v"; fi
done
if printf '%s\n' "$OUT2" | grep -q 'reloaded nginx'; then
  pass "a second 5c still tests and reloads nginx, so a hand edit cannot hide"
else
  fail "a second 5c never reloaded nginx"
fi

echo ""
echo "6g-3. A conf with neither the old nor the wanted shape is still FATAL"
make_conf "$NG/available/paramant-public.conf" absent absent no yes
make_conf "$NG/available/paramant-live.conf"   absent absent no yes
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0002 "paramant-public.conf paramant-live.conf"
OUT3="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0002 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" 2>&1)"; RC3=$?
if [ "$RC3" -ne 0 ]; then pass "5c stops on a conf that is not the one the runbook describes"; else
  fail "5c accepted a conf carrying neither shape"; fi
if printf '%s\n' "$OUT3" | grep -q "FATAL 'sign'"; then
  pass "it names which edit it could not place"
else
  fail "the FATAL does not name the edit"
  printf '%s\n' "$OUT3" | sed 's/^/        /' | head -20
fi
if [ "$(field_5c "$OUT3" 'before sign state')" = unknown ]; then
  pass "the unrecognisable conf reads as state unknown, not as done"
else
  fail "state for an absent /sign location is '$(field_5c "$OUT3" 'before sign state')', expected unknown"
fi

# And the script must read the already-applied answer, not just print it.
check_has "$SCRIPT" 'before everything already applied' \
  "phase 5c reports whether every edit was already applied"
check_has "$SCRIPT" 'already applied' \
  "the script has an already-applied verdict instead of a FATAL"
check_has "$FULL"   'before edits pending'  "the dry run shows the pending-edit count"
check_has "$FULL"   'before sign state'     "the dry run shows the per-edit state read"
check_has "$SCRIPT" 'location = /pararules { return 301 https://\$host/rules; }' \
  "phase 5c writes the permanent 301 from /pararules to /rules"
check_has "$SCRIPT" 'the four nginx changes' \
  "the 5c step name counts the /pararules redirect as one of the edits"

echo ""
echo "6g-4. A multi-line auth_request on /sign is todo, never already applied"
# SIGN_RE only matches the one-line spelling the repo conf uses. A hand edit
# between two deploys that puts the gate back across several lines leaves that
# count at zero, and a line-based state read would call it done and report
# "already applied" while /sign sits behind the login again. The state is read
# per BLOCK for exactly this.
cat > "$NG/available/paramant-public.conf" <<'CONF'
server {
    server_name paramant.app;
    location = /sign {
        auth_request /api/user/check;
        error_page 401 = @login_redirect;
        try_files /sign.html =404;
    }
    location = /dicom { return 404; }
    location = /v1/paraid/issue-document { deny all; }
    location ~ ^/v2/outbound {
        proxy_buffer_size 32k;
        proxy_buffers 8 32k;
        proxy_busy_buffers_size 64k;
        proxy_pass http://relay;
    }
}
CONF
cp "$NG/available/paramant-public.conf" "$NG/available/paramant-live.conf"
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0003 "paramant-public.conf paramant-live.conf"
OUT4="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0003 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" 2>&1)"; RC4=$?

if [ "$(field_5c "$OUT4" 'before sign gated')" = "0" ]; then
  pass "the one-line pattern really does miss a multi-line auth_request (the trap)"
else
  fail "the fixture does not reproduce the trap: before sign gated = $(field_5c "$OUT4" 'before sign gated')"
fi
if [ "$(field_5c "$OUT4" 'before sign blocks with auth_request')" = "2" ]; then
  pass "the block read finds the auth_request the line read missed"
else
  fail "the block read found $(field_5c "$OUT4" 'before sign blocks with auth_request') of 2 gated /sign blocks"
fi
if [ "$(field_5c "$OUT4" 'before sign state')" = "todo" ]; then
  pass "a multi-line auth_request reads as todo, not as done"
else
  fail "a multi-line auth_request reads as '$(field_5c "$OUT4" 'before sign state')', expected todo"
fi
if [ "$(field_5c "$OUT4" 'before everything already applied')" = "no" ]; then
  pass "the run does NOT report already applied while /sign is gated"
else
  fail "the run reported already applied with /sign still behind auth_request"
fi
if [ "$RC4" -ne 0 ] && printf '%s\n' "$OUT4" | grep -q 'still carry an auth_request'; then
  pass "the edit could not remove it, so 5c stops and says so instead of shipping it"
else
  fail "5c exited $RC4 with /sign still gated"
  printf '%s\n' "$OUT4" | sed 's/^/        /' | head -20
fi

echo ""
echo "6h. A deploy AFTER a rollback still prunes the pages the rollback restored"
# Phase 8 restores the docroot from the pre-3.1 tar, which puts every pruned
# page back, and leaves the checkout, and so the marker, on main. Diffing
# marker..HEAD then names nothing deleted, 5b prunes nothing, and phase 6e dies
# on /compliance/nis2 answering 200 with everything else already live. 5b takes
# the OLDER of the deployed commit and the runbook floor for this reason.
RB5B="$WORK/rb5b"
mkdir -p "$RB5B/repo" "$RB5B/docroot"
extract_remote "prune deleted frontend files" > "$RB5B/5b.sh"
if [ -s "$RB5B/5b.sh" ]; then
  pass "the 5b remote block could be extracted from the script"
else
  fail "could not extract the 5b remote block from the script"
fi
(
  cd "$RB5B/repo"
  git init -q . && git config user.email t@example.com && git config user.name t
  mkdir -p frontend/compliance
  for f in nis2 iec62443 nen7510; do echo "page $f" > "frontend/compliance/$f.html"; done
  echo index > frontend/index.html
  git add -A && git commit -qm floor
  git rev-parse HEAD > "$RB5B/floor"
  git rm -q frontend/compliance/nis2.html frontend/compliance/iec62443.html frontend/compliance/nen7510.html
  git commit -qm "remove the compliance pages"
  git rev-parse HEAD > "$RB5B/head"
) >/dev/null 2>&1
FLOOR="$(cat "$RB5B/floor")"
HEADC="$(cat "$RB5B/head")"

# The docroot as phase 8 leaves it: the deleted pages are back.
mkdir -p "$RB5B/docroot/compliance"
for f in nis2 iec62443 nen7510; do echo "page $f" > "$RB5B/docroot/compliance/$f.html"; done
echo index > "$RB5B/docroot/index.html"

# The marker is on main, because the rollback did not move the checkout.
OUT5="$(bash "$RB5B/5b.sh" "$RB5B/repo" "$RB5B/docroot" "$HEADC" "dist" "$FLOOR" 2>&1)"; RC5=$?
if [ "$RC5" -eq 0 ]; then pass "5b exits 0 in the deploy-after-rollback situation"; else
  fail "5b exits $RC5 in the deploy-after-rollback situation"
  printf '%s\n' "$OUT5" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT5" | grep -q "took the floor"; then
  pass "5b takes the older floor as its base, not the commit the marker names"
else
  fail "5b kept the marker commit as its base, so it prunes nothing after a rollback"
  printf '%s\n' "$OUT5" | sed 's/^/        /' | head -20
fi
if [ "$(field_5c "$OUT5" 'before prune base')" = "$FLOOR" ]; then
  pass "the base it actually diffs against is the floor"
else
  fail "the prune base is '$(field_5c "$OUT5" 'before prune base')', expected the floor"
fi
if [ "$(field_5c "$OUT5" 'before deleted-in-git count')" = "3" ]; then
  pass "git names the three restored pages as deleted, where marker..HEAD named none"
else
  fail "the delete list has $(field_5c "$OUT5" 'before deleted-in-git count') entries, expected 3"
fi
if [ "$(field_5c "$OUT5" 'after removed')" = "3" ]; then
  pass "all three pages the rollback restored are pruned again"
else
  fail "5b removed $(field_5c "$OUT5" 'after removed') of 3 restored pages"
fi
if [ ! -f "$RB5B/docroot/compliance/nis2.html" ] && [ -f "$RB5B/docroot/index.html" ]; then
  pass "the docroot lost the pruned page and kept the one main still ships"
else
  fail "the docroot is wrong after the prune"
fi

# The healthy second deploy: nothing was restored, so everything is already
# gone. That is an OK answer and must not be a failure.
OUT6="$(bash "$RB5B/5b.sh" "$RB5B/repo" "$RB5B/docroot" "$HEADC" "dist" "$FLOOR" 2>&1)"; RC6=$?
if [ "$RC6" -eq 0 ] && [ "$(field_5c "$OUT6" 'after already absent')" = "3" ] \
   && [ "$(field_5c "$OUT6" 'after removed')" = "0" ]; then
  pass "running 5b again prunes nothing and reports all three as already absent"
else
  fail "the second 5b run exits $RC6, removed=$(field_5c "$OUT6" 'after removed') absent=$(field_5c "$OUT6" 'after already absent')"
fi

check_has "$SCRIPT" 'merge-base --is-ancestor "\$FLOOR" "\$BASE"' \
  "the older-of-the-two choice is git's answer, not a guess"
check_has "$FULL"   'before prune base'   "the dry run shows which base 5b will diff against"

echo ""
echo "6i. The conf names differ per server, so a slot is a list of candidates"
# Production on 03-09 carries /etc/nginx/sites-enabled/paramant-public.conf and
# no paramant-live.conf at all: deploy/signup-fix-deploy.sh edits paramant.conf
# on that same host. Phase 2b stopped on the name it could not find, which was
# correct but unrunnable. A slot is now a "|" separated candidate list, the
# server takes the first candidate that is really in sites-enabled, and it logs
# which one that was.
SLOTS_DEFAULT="$(sed -n 's/^NGINX_CONF_SLOTS="\${PARAMANT_NGINX_CONFS:-\(.*\)}"$/\1/p' "$SCRIPT")"
if [ "$SLOTS_DEFAULT" = "paramant-public.conf paramant-live.conf|paramant.conf" ]; then
  pass "the default names paramant.conf as the second candidate of slot 2"
else
  fail "the default slots are '$SLOTS_DEFAULT', expected paramant-live.conf|paramant.conf as slot 2"
fi
check_has "$SCRIPT" 'PARAMANT_NGINX_CONFS' "PARAMANT_NGINX_CONFS still overrides the whole list"
check_has "$FULL"   'nginx confs   paramant-public.conf paramant-live.conf\|paramant.conf' \
  "the run header prints the candidates it will resolve on the server"

echo ""
echo "6i-1. resolve_conf_slots picks the first candidate that is there"
NG2="$WORK/ng2"
mkdir -p "$NG2/bin" "$NG2/available" "$NG2/bk" "$NG2/unit-both" "$NG2/unit-fallback" "$NG2/unit-none"
cp "$NG/bin/nginx" "$NG/bin/systemctl" "$NG2/bin/"
: > "$NG2/available/u-public"; : > "$NG2/available/u-live"; : > "$NG2/available/u-paramant"
ln -sfn "$NG2/available/u-public"   "$NG2/unit-both/paramant-public.conf"
ln -sfn "$NG2/available/u-live"     "$NG2/unit-both/paramant-live.conf"
ln -sfn "$NG2/available/u-paramant" "$NG2/unit-both/paramant.conf"
ln -sfn "$NG2/available/u-public"   "$NG2/unit-fallback/paramant-public.conf"
ln -sfn "$NG2/available/u-paramant" "$NG2/unit-fallback/paramant.conf"
ln -sfn "$NG2/available/u-public"   "$NG2/unit-none/paramant-public.conf"
# A symlink into nothing is not a conf. -e follows the link on purpose.
ln -sfn "$NG2/available/does-not-exist" "$NG2/unit-none/paramant-live.conf"

if eval "$(extract_snippet)" 2>/dev/null && declare -F resolve_conf_slots >/dev/null; then
  pass "resolve_conf_slots() could be extracted from the script"

  SL="paramant-public.conf paramant-live.conf|paramant.conf"

  # Run it in THIS shell, not in a command substitution: the answer is in
  # RESOLVED_CONFS and RESOLVED_MISSING, and a subshell would keep them.
  resolve_conf_slots "$NG2/unit-both" "$SL" > "$NG2/unit-out.txt"
  OUTU="$(cat "$NG2/unit-out.txt")"
  if [ "$RESOLVED_CONFS" = "paramant-public.conf paramant-live.conf" ] && [ "$RESOLVED_MISSING" = 0 ]; then
    pass "with both names present, slot 2 resolves to paramant-live.conf"
  else
    fail "with both present it resolved to '$RESOLVED_CONFS' (missing $RESOLVED_MISSING)"
  fi
  if printf '%s\n' "$OUTU" | grep -q 'nginxconf paramant-live.conf resolved to paramant-live.conf'; then
    pass "the choice is logged under the slot name"
  else
    fail "no 'resolved to' line for slot 2"
    printf '%s\n' "$OUTU" | sed 's/^/        /'
  fi

  resolve_conf_slots "$NG2/unit-fallback" "$SL" > "$NG2/unit-out.txt"
  OUTU="$(cat "$NG2/unit-out.txt")"
  if [ "$RESOLVED_CONFS" = "paramant-public.conf paramant.conf" ] && [ "$RESOLVED_MISSING" = 0 ]; then
    pass "with paramant-live.conf absent, slot 2 resolves to paramant.conf (production, 03-09)"
  else
    fail "the fallback resolved to '$RESOLVED_CONFS' (missing $RESOLVED_MISSING)"
  fi
  if printf '%s\n' "$OUTU" | grep -q 'nginxconf paramant-live.conf resolved to paramant.conf'; then
    pass "the log says which name it landed on, not which name it was looking for"
  else
    fail "the resolved name is not in the log"
    printf '%s\n' "$OUTU" | sed 's/^/        /'
  fi

  resolve_conf_slots "$NG2/unit-none" "$SL" > "$NG2/unit-out.txt"
  OUTU="$(cat "$NG2/unit-out.txt")"
  if [ "$RESOLVED_MISSING" = 1 ] && [ "$RESOLVED_CONFS" = "paramant-public.conf" ]; then
    pass "no candidate of a slot present: the slot resolves to nothing, and says so"
  else
    fail "a slot with no candidate resolved to '$RESOLVED_CONFS' (missing $RESOLVED_MISSING)"
  fi
  # This is the exact pattern phase 2b asserts on, so the STOP still fires.
  if printf '%s\n' "$OUTU" | grep -qE 'nginxconf [a-z.-]+ ABSENT'; then
    pass "the ABSENT line matches the pattern phase 2b stops on"
  else
    fail "the ABSENT line does not match /nginxconf [a-z.-]+ ABSENT/"
    printf '%s\n' "$OUTU" | sed 's/^/        /'
  fi
  if printf '%s\n' "$OUTU" | grep -q 'paramant-live.conf paramant.conf'; then
    pass "it names every candidate it tried"
  else
    fail "the ABSENT line does not name the candidates it tried"
  fi
else
  fail "could not extract resolve_conf_slots() from the script to test it"
fi

echo ""
echo "6i-2. 5c on a replica that has paramant.conf instead of paramant-live.conf"
mkdir -p "$NG2/sites-fb"
make_conf "$NG2/available/paramant-public.conf" old old yes no
make_conf "$NG2/available/paramant.conf"        old old yes no
ln -sfn "$NG2/available/paramant-public.conf" "$NG2/sites-fb/paramant-public.conf"
ln -sfn "$NG2/available/paramant.conf"        "$NG2/sites-fb/paramant.conf"
seed_2b_backups "$NG2/sites-fb" "$NG2/bk" 20260101-0100 "paramant-public.conf paramant-live.conf|paramant.conf"
OUT7="$(cd "$NG2" && PATH="$NG2/bin:$PATH" bash "$NG/5c.sh" 20260101-0100 "$NG2/sites-fb" "$NG2/bk" \
        "paramant-public.conf paramant-live.conf|paramant.conf" 2>&1)"; RC7=$?
if [ "$RC7" -eq 0 ]; then pass "5c exits 0 on a server that calls the backend conf paramant.conf"; else
  fail "5c exits $RC7 on the production naming"
  printf '%s\n' "$OUT7" | sed 's/^/        /' | head -25
fi
if printf '%s\n' "$OUT7" | grep -q 'nginxconf paramant-live.conf resolved to paramant.conf'; then
  pass "5c logs the resolved name"
else
  fail "5c never logged which name it resolved slot 2 to"
fi
if printf '%s\n' "$OUT7" | grep -q 'target paramant.conf ->'; then
  pass "5c edits the resolved file, not the candidate string"
else
  fail "5c did not name paramant.conf as a target"
fi
for want in "after sign gated:0" "after compliance:0" "after dicom try_files:0" "after edited files:2"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUT7" "$f")" = "$v" ]; then pass "on the production naming, $f = $v"; else
    fail "on the production naming, $f = '$(field_5c "$OUT7" "$f")', expected $v"; fi
done
if [ "$(field_5c "$OUT7" 'after outbound blocks with buffer')" \
   = "$(field_5c "$OUT7" 'after outbound locations')" ]; then
  pass "the buffers landed in every /v2/outbound block of both resolved confs"
else
  fail "the buffer landed in $(field_5c "$OUT7" 'after outbound blocks with buffer') of $(field_5c "$OUT7" 'after outbound locations') blocks"
fi
if grep -q 'return 404' "$NG2/available/paramant.conf" \
   && ! grep -q 'auth_request' "$NG2/available/paramant.conf" \
   && ! grep -q 'location = /compliance' "$NG2/available/paramant.conf"; then
  pass "the three edits really landed in the file called paramant.conf"
else
  fail "paramant.conf on disk did not get the edits"
fi

echo ""
echo "6i-3. With both names present the first candidate wins and the other is left alone"
mkdir -p "$NG2/sites-both"
make_conf "$NG2/available/paramant-public.conf" old old yes no
make_conf "$NG2/available/paramant-live.conf"   old old yes no
make_conf "$NG2/available/paramant.conf"        old old yes no
BEFORE_MD5="$(md5sum < "$NG2/available/paramant.conf")"
ln -sfn "$NG2/available/paramant-public.conf" "$NG2/sites-both/paramant-public.conf"
ln -sfn "$NG2/available/paramant-live.conf"   "$NG2/sites-both/paramant-live.conf"
ln -sfn "$NG2/available/paramant.conf"        "$NG2/sites-both/paramant.conf"
seed_2b_backups "$NG2/sites-both" "$NG2/bk" 20260101-0101 "paramant-public.conf paramant-live.conf|paramant.conf"
OUT8="$(cd "$NG2" && PATH="$NG2/bin:$PATH" bash "$NG/5c.sh" 20260101-0101 "$NG2/sites-both" "$NG2/bk" \
        "paramant-public.conf paramant-live.conf|paramant.conf" 2>&1)"; RC8=$?
if [ "$RC8" -eq 0 ] && printf '%s\n' "$OUT8" | grep -q 'nginxconf paramant-live.conf resolved to paramant-live.conf'; then
  pass "with both present, slot 2 resolves to paramant-live.conf"
else
  fail "5c exited $RC8 and did not resolve slot 2 to paramant-live.conf"
  printf '%s\n' "$OUT8" | sed 's/^/        /' | head -25
fi
if [ "$(field_5c "$OUT8" 'after edited files')" = "2" ]; then
  pass "exactly two confs were rewritten, not three"
else
  fail "5c rewrote $(field_5c "$OUT8" 'after edited files') conf(s), expected 2"
fi
if [ "$(md5sum < "$NG2/available/paramant.conf")" = "$BEFORE_MD5" ]; then
  pass "the losing candidate paramant.conf was not touched"
else
  fail "5c also rewrote paramant.conf, which is not in any resolved slot"
fi

echo ""
echo "6i-4. A slot with no candidate at all is a stop, with the same hint"
mkdir -p "$NG2/sites-none"
make_conf "$NG2/available/paramant-public.conf" old old yes no
ln -sfn "$NG2/available/paramant-public.conf" "$NG2/sites-none/paramant-public.conf"
seed_2b_backups "$NG2/sites-none" "$NG2/bk" 20260101-0102 "paramant-public.conf paramant-live.conf|paramant.conf"
OUT9="$(cd "$NG2" && PATH="$NG2/bin:$PATH" bash "$NG/5c.sh" 20260101-0102 "$NG2/sites-none" "$NG2/bk" \
        "paramant-public.conf paramant-live.conf|paramant.conf" 2>&1)"; RC9=$?
if [ "$RC9" -ne 0 ] && printf '%s\n' "$OUT9" | grep -q 'FATAL 1 nginx conf slot'; then
  pass "5c stops when a slot has no candidate on the server"
else
  fail "5c exited $RC9 with a slot that resolved to nothing"
  printf '%s\n' "$OUT9" | sed 's/^/        /' | head -20
fi
check_has "$SCRIPT" 'set PARAMANT_NGINX_CONFS if they are named differently' \
  "the STOP in 2b still hands over the same hint"

echo ""
echo "6i-5. A missing ParaID deny is still FATAL, and it names the resolved conf"
mkdir -p "$NG2/sites-noparaid"
make_conf "$NG2/available/paramant-public.conf" old old yes no
make_conf "$NG2/available/paramant.conf"        old old yes no
sed -i '/paraid\/issue-document/d' "$NG2/available/paramant-public.conf"
sed -i '/paraid\/issue-document/d' "$NG2/available/paramant.conf"
ln -sfn "$NG2/available/paramant-public.conf" "$NG2/sites-noparaid/paramant-public.conf"
ln -sfn "$NG2/available/paramant.conf"        "$NG2/sites-noparaid/paramant.conf"
seed_2b_backups "$NG2/sites-noparaid" "$NG2/bk" 20260101-0103 "paramant-public.conf paramant-live.conf|paramant.conf"
OUT10="$(cd "$NG2" && PATH="$NG2/bin:$PATH" bash "$NG/5c.sh" 20260101-0103 "$NG2/sites-noparaid" "$NG2/bk" \
         "paramant-public.conf paramant-live.conf|paramant.conf" 2>&1)"; RC10=$?
if [ "$RC10" -ne 0 ] && printf '%s\n' "$OUT10" | grep -q 'FATAL the ParaID deny is not present'; then
  pass "5c still stops when the ParaID deny anchor is gone"
else
  fail "5c exited $RC10 on a conf without the ParaID deny"
  printf '%s\n' "$OUT10" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT10" | grep -q 'FATAL the ParaID deny is not present in the resolved conf(s) paramant-public.conf paramant.conf'; then
  pass "the FATAL names the confs it actually read, resolved names and all"
else
  fail "the ParaID FATAL does not name the resolved confs"
  printf '%s\n' "$OUT10" | grep FATAL | sed 's/^/        /'
fi

echo ""
echo "6i-6. The rollback resolves the same way, so it looks for the backup that exists"
RBN="$WORK/rbnginx"
RBTS=20260101-0200
mkdir -p "$RBN/bin" "$RBN/compose" "$RBN/bk" "$RBN/ngbk" "$RBN/sites" "$RBN/available" "$RBN/root/app"
cp "$NG/bin/nginx" "$NG/bin/systemctl" "$RBN/bin/"
for svc in relay-main relay-health relay-finance relay-legal relay-iot admin; do
  echo "$svc|img/$svc:3.1.0|paramant-rollback/$svc:$RBTS" >> "$RBN/bk/rollback-images-$RBTS.txt"
done
echo "PARAMANT=1" > "$RBN/bk/.env-pre-3.1-$RBTS"
echo pre-rollback-index > "$RBN/root/app/index.html"
tar czf "$RBN/bk/docroot-pre-3.1-$RBTS.tgz" -C "$RBN/root" app
# The server calls the backend conf paramant.conf, so phase 2b filed the backup
# under that name. A rollback that looked for paramant-live.conf would stop.
echo "server { server_name public; }"  > "$RBN/available/paramant-public.conf"
echo "server { server_name backend; }" > "$RBN/available/paramant.conf"
echo "server { server_name public-backup; }"  > "$RBN/ngbk/paramant-public.conf.pre-3.1-$RBTS"
echo "server { server_name backend-backup; }" > "$RBN/ngbk/paramant.conf.pre-3.1-$RBTS"
ln -sfn "$RBN/available/paramant-public.conf" "$RBN/sites/paramant-public.conf"
ln -sfn "$RBN/available/paramant.conf"        "$RBN/sites/paramant.conf"

extract_remote "rollback preconditions" > "$RBN/8a.sh"
extract_remote "rollback nginx and docroot" > "$RBN/8c.sh"
if [ -s "$RBN/8a.sh" ] && [ -s "$RBN/8c.sh" ]; then
  pass "the 8a and 8c remote blocks could be extracted from the script"
else
  fail "could not extract the rollback blocks from the script"
fi

OUT11="$(PATH="$RBN/bin:$PATH" bash "$RBN/8a.sh" "$RBN/compose" "$RBTS" "$RBN/bk" "$RBN/ngbk" \
         "$RBN/sites" "paramant-public.conf paramant-live.conf|paramant.conf" 2>&1)"; RC11=$?
if [ "$RC11" -eq 0 ]; then pass "8a exits 0 against the production naming"; else
  fail "8a exits $RC11"
  printf '%s\n' "$OUT11" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT11" | grep -q 'nginxconf paramant-live.conf resolved to paramant.conf'; then
  pass "8a resolves slot 2 to paramant.conf before it looks for a backup"
else
  fail "8a did not resolve the slot"
fi
if [ "$(field_5c "$OUT11" 'missing backups')" = "0" ]; then
  pass "8a finds every backup it needs under the resolved names"
else
  fail "8a reports $(field_5c "$OUT11" 'missing backups') missing backup(s)"
  printf '%s\n' "$OUT11" | grep -i backup | sed 's/^/        /'
fi
if printf '%s\n' "$OUT11" | grep -q 'paramant-live.conf.pre-3.1'; then
  fail "8a is still looking for a backup named after the candidate string"
else
  pass "8a never looks for paramant-live.conf.pre-3.1, the name that is not there"
fi

# And with that backup gone, 8a must refuse instead of half-rolling back.
mv "$RBN/ngbk/paramant.conf.pre-3.1-$RBTS" "$RBN/ngbk/paramant.conf.pre-3.1-$RBTS.moved"
OUT12="$(PATH="$RBN/bin:$PATH" bash "$RBN/8a.sh" "$RBN/compose" "$RBTS" "$RBN/bk" "$RBN/ngbk" \
         "$RBN/sites" "paramant-public.conf paramant-live.conf|paramant.conf" 2>&1)"
if [ "$(field_5c "$OUT12" 'missing backups')" = "1" ]; then
  pass "a missing backup under the resolved name is counted, so the rollback stops"
else
  fail "with the paramant.conf backup gone, 8a still reports $(field_5c "$OUT12" 'missing backups') missing"
fi
mv "$RBN/ngbk/paramant.conf.pre-3.1-$RBTS.moved" "$RBN/ngbk/paramant.conf.pre-3.1-$RBTS"

echo bogus-added-by-deploy > "$RBN/root/app/added.html"
OUT13="$(PATH="$RBN/bin:$PATH" bash "$RBN/8c.sh" "$RBTS" "$RBN/bk" "$RBN/root/app" "$RBN/ngbk" \
         "$RBN/sites" "paramant-public.conf paramant-live.conf|paramant.conf" "dist" 2>&1)"; RC13=$?
if [ "$RC13" -eq 0 ]; then pass "8c exits 0 against the production naming"; else
  fail "8c exits $RC13"
  printf '%s\n' "$OUT13" | sed 's/^/        /' | head -20
fi
if [ "$(field_5c "$OUT13" 'restored nginx confs')" = "2" ]; then
  pass "8c restored both resolved confs"
else
  fail "8c restored $(field_5c "$OUT13" 'restored nginx confs') conf(s), expected 2"
fi
if grep -q 'backend-backup' "$RBN/available/paramant.conf"; then
  pass "the backup really landed in the file the slot resolved to"
else
  fail "paramant.conf on disk is not the restored backup"
fi
if printf '%s\n' "$OUT13" | grep -q 'before nginx paramant.conf bytes'; then
  pass "8c reports the restore under the resolved name"
else
  fail "8c never named paramant.conf in its evidence"
fi

# A slot with no candidate must stop 8c too, before it writes anything.
OUT14="$(PATH="$RBN/bin:$PATH" bash "$RBN/8c.sh" "$RBTS" "$RBN/bk" "$RBN/root/app" "$RBN/ngbk" \
         "$RBN/sites" "paramant-public.conf paramant-live.conf|not-there.conf" "dist" 2>&1)"; RC14=$?
if [ "$RC14" -ne 0 ] && printf '%s\n' "$OUT14" | grep -q 'FATAL 1 nginx conf slot'; then
  pass "8c stops when a slot resolves to nothing"
else
  fail "8c exited $RC14 with an unresolvable slot"
fi

# No remote block may still loop over the raw candidate string.
if grep -nE '^for name in \$(CONFS|SLOTS)' "$SCRIPT" >/dev/null; then
  fail "a remote block still loops over the candidate string instead of the resolved names"
  grep -nE '^for name in \$(CONFS|SLOTS)' "$SCRIPT" | sed 's/^/        /'
else
  pass "every remote block loops over \$RESOLVED_CONFS, never over the candidate string"
fi

echo ""
echo "6i-7. sites-enabled changed between phase 2b and 5c: stop, do not edit"
# 2b and 5c each ask the server what is there when they run, which is what
# makes the slots work at all. It also means they can disagree: phases 3 and 4
# pull, build and recreate in between, and if sites-enabled is rearranged in
# that window 5c resolves to a conf 2b never backed up. Every FATAL in 5c calls
# restore(), restore() can only put back what was filed, so the run used to end
# on "restoring the backed up confs" with that conf left edited and nothing to
# roll it back to. 5c now refuses before the first sed.
NG3="$WORK/ng3"
mkdir -p "$NG3/bin" "$NG3/available" "$NG3/bk" "$NG3/sites"
cp "$NG/bin/nginx" "$NG/bin/systemctl" "$NG3/bin/"
SL3="paramant-public.conf paramant-live.conf|paramant.conf"

# Phase 2b ran while the server still had paramant-live.conf.
make_conf "$NG3/available/paramant-public.conf" old old yes no
make_conf "$NG3/available/paramant-live.conf"   old old yes no
ln -sfn "$NG3/available/paramant-public.conf" "$NG3/sites/paramant-public.conf"
ln -sfn "$NG3/available/paramant-live.conf"   "$NG3/sites/paramant-live.conf"
seed_2b_backups "$NG3/sites" "$NG3/bk" 20260101-0300 "$SL3"
if [ -f "$NG3/bk/paramant-live.conf.pre-3.1-20260101-0300" ] \
   && [ ! -f "$NG3/bk/paramant.conf.pre-3.1-20260101-0300" ]; then
  pass "2b filed the backup under paramant-live.conf, the name that was there then"
else
  fail "the 2b fixture did not file the backup the scenario needs"
fi

# Between 2b and 5c the backend conf is renamed on the server.
make_conf "$NG3/available/paramant.conf" old old yes no
rm -f "$NG3/sites/paramant-live.conf"
ln -sfn "$NG3/available/paramant.conf" "$NG3/sites/paramant.conf"
MD5_PUB="$(md5sum < "$NG3/available/paramant-public.conf")"
MD5_BE="$(md5sum < "$NG3/available/paramant.conf")"

OUT15="$(cd "$NG3" && PATH="$NG3/bin:$PATH" bash "$NG/5c.sh" 20260101-0300 "$NG3/sites" "$NG3/bk" \
         "$SL3" 2>&1)"; RC15=$?
if [ "$RC15" -ne 0 ]; then pass "5c stops when the conf it resolved has no 2b backup"; else
  fail "5c edited a conf that has no backup (exit $RC15)"
  printf '%s\n' "$OUT15" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT15" | grep -q 'FATAL no phase 2b backup .*paramant.conf.pre-3.1-20260101-0300 for paramant.conf'; then
  pass "the FATAL names the conf and the backup it went looking for"
else
  fail "the FATAL does not name the missing backup"
  printf '%s\n' "$OUT15" | grep FATAL | sed 's/^/        /'
fi
if [ "$(field_5c "$OUT15" 'before confs without a backup')" = "1" ]; then
  pass "the count of confs without a backup is reported, so the deploy can assert on it"
else
  fail "before confs without a backup = '$(field_5c "$OUT15" 'before confs without a backup')', expected 1"
fi
# The whole point: nothing was written, so there is nothing left modified.
if [ "$(md5sum < "$NG3/available/paramant.conf")" = "$MD5_BE" ] \
   && [ "$(md5sum < "$NG3/available/paramant-public.conf")" = "$MD5_PUB" ]; then
  pass "neither conf was touched, so no conf is left modified without a backup"
else
  fail "5c changed a conf before it stopped"
fi
if printf '%s\n' "$OUT15" | grep -qi 'estoring the backed up confs'; then
  fail "5c still claims to restore confs on a run where one of them has no backup"
else
  pass "5c does not promise a restore it could not deliver"
fi
check_lacks "$SCRIPT" 'for b in "\$NGBK"/\*\.pre-3\.1' \
  "restore() no longer globs the backup dir; it restores exactly the resolved confs"

echo ""
echo "6i-7b. With the backup filed under the resolved name, the same run is clean"
# Control: the stop above is about the missing backup, not about the rename.
cp -a "$NG3/available/paramant.conf" "$NG3/bk/paramant.conf.pre-3.1-20260101-0300"
OUT16="$(cd "$NG3" && PATH="$NG3/bin:$PATH" bash "$NG/5c.sh" 20260101-0300 "$NG3/sites" "$NG3/bk" \
         "$SL3" 2>&1)"; RC16=$?
if [ "$RC16" -eq 0 ] && [ "$(field_5c "$OUT16" 'before confs without a backup')" = "0" ]; then
  pass "with the backup in place the same fixture runs through"
else
  fail "the control run exits $RC16 with $(field_5c "$OUT16" 'before confs without a backup') conf(s) unbacked"
  printf '%s\n' "$OUT16" | sed 's/^/        /' | head -20
fi
if [ "$(field_5c "$OUT16" 'after edited files')" = "2" ]; then
  pass "and it edits both resolved confs"
else
  fail "the control run edited $(field_5c "$OUT16" 'after edited files') conf(s), expected 2"
fi

echo ""
echo "6i-7c. A FATAL after the edits really does put every resolved conf back"
# restore() used to walk the backup dir. Now it walks the resolved names, so
# what it restores is exactly what was edited. The multi-line auth_request is
# the cheapest way to reach a FATAL that happens after the sed calls.
NG4="$WORK/ng4"
mkdir -p "$NG4/bin" "$NG4/available" "$NG4/bk" "$NG4/sites"
cp "$NG/bin/nginx" "$NG/bin/systemctl" "$NG4/bin/"
cat > "$NG4/available/paramant-public.conf" <<'CONF'
server {
    server_name paramant.app;
    location = /sign {
        auth_request /api/user/check;
        error_page 401 = @login_redirect;
        try_files /sign.html =404;
    }
    location = /dicom { return 404; }
    location = /v1/paraid/issue-document { deny all; }
    location ~ ^/v2/outbound {
        proxy_pass http://relay;
    }
}
CONF
cp "$NG4/available/paramant-public.conf" "$NG4/available/paramant.conf"
ln -sfn "$NG4/available/paramant-public.conf" "$NG4/sites/paramant-public.conf"
ln -sfn "$NG4/available/paramant.conf"        "$NG4/sites/paramant.conf"
seed_2b_backups "$NG4/sites" "$NG4/bk" 20260101-0400 "$SL3"
MD4_PUB="$(md5sum < "$NG4/available/paramant-public.conf")"
MD4_BE="$(md5sum < "$NG4/available/paramant.conf")"

OUT17="$(cd "$NG4" && PATH="$NG4/bin:$PATH" bash "$NG/5c.sh" 20260101-0400 "$NG4/sites" "$NG4/bk" \
         "$SL3" 2>&1)"; RC17=$?
if [ "$RC17" -ne 0 ] && printf '%s\n' "$OUT17" | grep -q 'still carry an auth_request'; then
  pass "the run reaches the post-edit FATAL, so restore() is exercised"
else
  fail "the fixture did not reach the post-edit FATAL (exit $RC17)"
  printf '%s\n' "$OUT17" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT17" | grep -q 'restored paramant.conf from' \
   && printf '%s\n' "$OUT17" | grep -q 'restored paramant-public.conf from'; then
  pass "restore() says which conf it put back, under the resolved name"
else
  fail "restore() did not report both confs"
  printf '%s\n' "$OUT17" | grep -i restor | sed 's/^/        /'
fi
if [ "$(md5sum < "$NG4/available/paramant.conf")" = "$MD4_BE" ] \
   && [ "$(md5sum < "$NG4/available/paramant-public.conf")" = "$MD4_PUB" ]; then
  pass "both confs are byte for byte what they were before the run"
else
  fail "a conf was left modified after the FATAL restore"
fi

echo ""
echo "6d. The CI gate on main is one verdict per required workflow"
# The old gate was `gh run list --branch main -L 5`: five runs of whichever
# workflows happened to run last, with a stop on any `failure` among them. On
# 2026-09-02 that stopped --preflight-only on a red `heartbeat` run, which is
# the hourly alarm reporting that its own two canary secrets are missing, and it
# waved through two runs that were still in_progress because "in progress" is
# not the string "failure".
check_lacks "$SCRIPT" 'gh run list --branch main -L 5' \
  "the mixed-workflow 'last 5 runs on main' gate is gone from the script"

# The gated list must be exactly the workflows that run on a push to main
# without a paths: filter. It is derived here from .github/workflows rather than
# copied, so a new push-gated workflow that nobody adds to the gate fails this
# test instead of quietly deploying ungated.
DERIVED=""
for _f in "$ROOT"/.github/workflows/*.yml; do
  [ -f "$_f" ] || continue
  _blk="$(awk '/^on:/                              {inon=1; next}
               inon && /^[^[:space:]#]/            {inon=0}
               inon && /^  push:/                  {inpush=1; next}
               inon && inpush && /^  [^[:space:]]/ {inpush=0}
               inpush' "$_f")"
  [ -n "$_blk" ] || continue                                    # no push trigger
  printf '%s\n' "$_blk" | grep -qE 'branches:.*[][ ,]main([][ ,]|$)|^[[:space:]]*-[[:space:]]*main[[:space:]]*$' || continue
  printf '%s\n' "$_blk" | grep -qE '^[[:space:]]*paths:' && continue   # path-gated: may not run at all
  DERIVED="$DERIVED $(basename "$_f")"
done
DERIVED="$(printf '%s\n' $DERIVED | sort | tr '\n' ' ' | sed 's/^ *//; s/ *$//')"
GATED="$(sed -n 's/^REQUIRED_WORKFLOWS="\${PARAMANT_REQUIRED_WORKFLOWS:-\(.*\)}"$/\1/p' "$SCRIPT" \
         | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/^ *//; s/ *$//')"
if [ -z "$DERIVED" ]; then
  fail "no push-to-main workflow was derived from .github/workflows; the derivation is not looking at anything"
elif [ "$DERIVED" = "$GATED" ]; then
  pass "the gated list is exactly the push-to-main workflows without a paths: filter ($GATED)"
else
  fail "the gated list does not match .github/workflows"
  printf '        gated:   %s\n' "$GATED"
  printf '        derived: %s\n' "$DERIVED"
fi

# Every required workflow really is asked about, by name, in the dry run.
for _wf in test.yml csp-inline-check.yml sign-e2e.yml product-heartbeat.yml; do
  check_has "$FULL" "gh run list --workflow $_wf --branch main --status completed -L 1" \
    "the dry run reads the last completed run of $_wf on main"
done

# And the three excluded ones are not. The space after --workflow anchors these:
# "--workflow product-heartbeat.yml" does not match "--workflow heartbeat.yml".
check_lacks "$FULL" 'gh run list --workflow heartbeat\.yml' \
  "heartbeat.yml is not gated on (schedule only, red by design without its canary secrets)"
check_lacks "$FULL" 'gh run list --workflow docker-publish\.yml' \
  "docker-publish.yml is not gated on (path-gated on relay/**)"
check_lacks "$FULL" 'gh run list --workflow build-image\.yml' \
  "build-image.yml is not gated on (path-gated on relay/**)"
check_has "$SCRIPT" 'Deliberately NOT in the list' \
  "the script writes down why each excluded workflow is excluded"

echo ""
echo "6e. A required run still in flight is waited on, not read as not-failing"
check_has "$FULL"   'status in_progress'       "the gate asks GitHub which runs have not finished"
check_has "$SCRIPT" 'in_progress queued'       "queued counts as unfinished too"
check_has "$FULL"   'gh run watch'             "an unfinished run of a required workflow is waited on"
check_has "$SCRIPT" 'CI_WAIT_SECONDS:-900'     "that wait is capped at 15 minutes"
check_has "$SCRIPT" 'STILL RUNNING after'      "a run still going after the wait blocks instead of passing"
check_has "$SCRIPT" 'conclusion // "NONE"'     "a workflow with no completed run on main is NONE, not a pass"
check_has "$SCRIPT" 'headSha'                  "in-flight runs are matched against the sha that would be deployed"

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
