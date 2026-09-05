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
        "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC1=$?
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
# The second admin screen. frontend/admin.html is routed from nowhere, but 5a
# rsyncs all of frontend/ into the docroot and the generic try_files served it:
# /admin.html answered 200 with the full admin markup and no session asked for.
# The 404 has to travel with a deploy, or the next one puts the page back on the
# open web. Same block anchor as the /pararules 301, so it is read the same way:
# every site block, both lines, once each.
if [ "$(field_5c "$OUT1" 'before admin guard blocks with 404')" = "0" ]; then
  pass "the fixture starts serving the second admin screen, so the edit has work to do"
else
  fail "the fixture already carries the admin 404s; this run would prove nothing"
fi
if [ "$(field_5c "$OUT1" 'after admin guard blocks with 404')" \
   = "$(field_5c "$OUT1" 'after admin guard blocks')" ] \
   && [ "$(field_5c "$OUT1" 'after admin guard blocks')" = "2" ]; then
  pass "every site block came out with /admin.html and /js/admin.page.js on 404"
else
  fail "the admin 404s landed in $(field_5c "$OUT1" 'after admin guard blocks with 404') of $(field_5c "$OUT1" 'after admin guard blocks') site blocks"
fi
if [ "$(field_5c "$OUT1" 'after admin guard lines')" = "4" ]; then
  pass "both 404 lines were written once per conf, not twice"
else
  fail "5c wrote $(field_5c "$OUT1" 'after admin guard lines') admin 404 line(s), expected 4"
fi
if grep -q 'location = /admin\.html { return 404; }' "$NG/available/paramant-live.conf" \
   && grep -q 'location = /js/admin\.page\.js { return 404; }' "$NG/available/paramant-live.conf"; then
  pass "the guard is in the conf on disk, not only in the counters"
else
  fail "neither 404 reached paramant-live.conf on disk"
fi

echo ""
echo "6g-2. Second run on the same confs: already applied, not FATAL"
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0001 "paramant-public.conf paramant-live.conf"
OUT2="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0001 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC2=$?
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
            "before admin guard blocks with 404:2" \
            "after admin guard lines:4" \
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
        "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC3=$?
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
check_has "$SCRIPT" 'the seven nginx changes' \
  "the 5c step name counts the /pararules redirect, the :8090 access_log and the admin 404 as edits"
check_has "$SCRIPT" 'location = /admin\.html \{ return 404; \}' \
  "phase 5c writes the 404 on the second admin screen"
check_has "$SCRIPT" 'location = /js/admin\.page\.js \{ return 404; \}' \
  "phase 5c writes the 404 on the loader that screen is the only consumer of"
# The repo confs and the phase have to agree. 5c edits the live confs by anchor
# and never copies a repo file over them, so a guard that lives in only one of
# the two is a guard that a rebuilt server, or a hand-applied 5c, would miss.
for conf in nginx-paramant-live.conf nginx-paramant-public.conf; do
  check_has "$ROOT/deploy/$conf" 'location = /admin\.html \{ return 404; \}' \
    "$conf 404s /admin.html, so the repo conf says what the phase does"
  check_has "$ROOT/deploy/$conf" 'location = /js/admin\.page\.js \{ return 404; \}' \
    "$conf 404s /js/admin.page.js"
done

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
        "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC4=$?

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
echo "6g-5. access_log off lands in the :8090 block that backs /dicom/"
# The sixth 5c edit. #374 put `access_log off;` in the :8090 server block of
# deploy/nginx-paramant-live.conf and wrote "repo only, so far" above it,
# because 5c edits the live confs by anchor and never copies a repo file over
# them: the line did not travel with a deploy. /security claims logging is off
# on every block that serves the site, and this is the block that made that a
# half-truth on the server.
#
# The anchor is the listen line, not the hostname: the :8090 block carries no
# server_name and no ParaID deny, so neither of the anchors the other five
# edits use marks it.
make_dicom_conf() {   # file, alog(missing|present|none)
  local f="$1" alog="$2"
  {
    echo 'server {'
    echo '    server_name paramant.app;'
    echo '    access_log off;'
    echo '    location = /sign { try_files /sign.html =404; }'
    echo '    location = /dicom { return 404; }'
    echo '    location = /v1/paraid/issue-document { deny all; }'
    echo '    location = /pararules { return 301 https://$host/rules; }'
    echo '    location = /admin.html { return 404; }'
    echo '    location = /js/admin.page.js { return 404; }'
    echo '    location /dicom/ { proxy_pass http://127.0.0.1:8090; }'
    echo '    location ~ ^/v2/outbound {'
    echo '        proxy_buffer_size 32k;'
    echo '        proxy_buffers 8 32k;'
    echo '        proxy_busy_buffers_size 64k;'
    echo '        proxy_pass http://relay;'
    echo '    }'
    echo '}'
    if [ "$alog" != none ]; then
      echo 'server {'
      echo '    listen 127.0.0.1:8090;'
      [ "$alog" = present ] && echo '    access_log off;'
      echo '    location = /outlook/taskpane { alias /home/paramant/app/outlook/taskpane.html; }'
      echo '    location / { proxy_pass https://fly-upstream; }'
      echo '}'
    fi
  } > "$f"
}

# The public conf has no :8090 block, exactly as on the server. Every other
# edit is already applied in both, so the access_log line is the ONLY thing
# left to do and the counters below cannot be read as some other edit's work.
make_dicom_conf "$NG/available/paramant-public.conf" none
make_dicom_conf "$NG/available/paramant-live.conf"   missing
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0004 "paramant-public.conf paramant-live.conf"
PUB_BEFORE="$(cat "$NG/available/paramant-public.conf")"
OUT5="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0004 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC5=$?
if [ "$RC5" -eq 0 ]; then pass "5c exits 0 on a conf whose :8090 block still logs"; else
  fail "5c exits $RC5 on a conf whose :8090 block still logs"
  printf '%s\n' "$OUT5" | sed 's/^/        /' | head -20
fi
if [ "$(field_5c "$OUT5" 'before 8090 blocks')" = "1" ] \
   && [ "$(field_5c "$OUT5" 'before 8090 blocks with access_log off')" = "0" ]; then
  pass "the fixture starts with one :8090 block and no access_log off, so the edit has work to do"
else
  fail "the fixture reads $(field_5c "$OUT5" 'before 8090 blocks with access_log off') of $(field_5c "$OUT5" 'before 8090 blocks') :8090 block(s) already off; this run would prove nothing"
fi
if [ "$(field_5c "$OUT5" 'before edits pending')" = "1" ]; then
  pass "the access_log line is counted as a pending edit in its own right"
else
  fail "5c counted $(field_5c "$OUT5" 'before edits pending') pending edit(s), expected exactly 1"
fi
if [ "$(field_5c "$OUT5" 'after 8090 blocks with access_log off')" \
   = "$(field_5c "$OUT5" 'after 8090 blocks')" ] \
   && [ "$(field_5c "$OUT5" 'after 8090 blocks')" = "1" ]; then
  pass "the :8090 block came out with access_log off"
else
  fail "access_log off landed in $(field_5c "$OUT5" 'after 8090 blocks with access_log off') of $(field_5c "$OUT5" 'after 8090 blocks') :8090 block(s)"
fi
if [ "$(field_5c "$OUT5" 'after edited files')" = "1" ]; then
  pass "only the conf that carries the :8090 block was rewritten"
else
  fail "5c rewrote $(field_5c "$OUT5" 'after edited files') conf(s), expected 1"
fi
if [ "$PUB_BEFORE" = "$(cat "$NG/available/paramant-public.conf")" ]; then
  pass "the conf without a :8090 block is byte-identical afterwards"
else
  fail "5c changed the conf that has no :8090 block"
  diff <(printf '%s\n' "$PUB_BEFORE") "$NG/available/paramant-public.conf" | sed 's/^/        /' | head -10
fi
# One line, after the listen line, inside the :8090 block. Not two, and not in
# the site block at the top, which already had one.
if [ "$(grep -c '^    access_log off;$' "$NG/available/paramant-live.conf")" = "2" ]; then
  pass "the live conf carries exactly two access_log off lines: the site block's and the new one"
else
  fail "the live conf carries $(grep -c '^    access_log off;$' "$NG/available/paramant-live.conf") access_log off line(s), expected 2"
fi
if grep -A1 '^    listen 127\.0\.0\.1:8090;$' "$NG/available/paramant-live.conf" \
   | grep -q '^    access_log off;$'; then
  pass "the line sits directly under the listen line it is anchored on"
else
  fail "the inserted line is not directly under listen 127.0.0.1:8090"
  sed 's/^/        /' "$NG/available/paramant-live.conf" | head -30
fi

echo ""
echo "6g-6. A second run over the same confs writes nothing: the diff is empty"
cp -a "$NG/available/paramant-live.conf"   "$WORK/live-after-first.conf"
cp -a "$NG/available/paramant-public.conf" "$WORK/pub-after-first.conf"
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0005 "paramant-public.conf paramant-live.conf"
OUT6="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0005 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC6=$?
if [ "$RC6" -eq 0 ]; then pass "a second 5c over the edited confs exits 0"; else
  fail "a second 5c over the edited confs exits $RC6"
  printf '%s\n' "$OUT6" | sed 's/^/        /' | head -20
fi
for want in "before 8090 blocks:1" "before 8090 blocks with access_log off:1" \
            "before edits pending:0" "before everything already applied:yes" \
            "after edited files:0"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUT6" "$f")" = "$v" ]; then pass "second run reports $f = $v"; else
    fail "second run reports $f = '$(field_5c "$OUT6" "$f")', expected $v"; fi
done
if diff -u "$WORK/live-after-first.conf" "$NG/available/paramant-live.conf" > "$WORK/live-diff.txt" \
   && diff -u "$WORK/pub-after-first.conf" "$NG/available/paramant-public.conf" >> "$WORK/live-diff.txt"; then
  pass "the second run leaves both confs byte-identical, so the edit is idempotent"
else
  fail "the second run changed a conf that was already correct"
  sed 's/^/        /' "$WORK/live-diff.txt" | head -20
fi

echo ""
echo "6g-7. A :8090 block that already has the line is left alone from the start"
# The no-op case on a conf that was never edited by this script, which is what
# a server that had the line put there by hand looks like.
make_dicom_conf "$NG/available/paramant-public.conf" none
make_dicom_conf "$NG/available/paramant-live.conf"   present
cp -a "$NG/available/paramant-live.conf" "$WORK/live-present.conf"
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0006 "paramant-public.conf paramant-live.conf"
OUT7A="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0006 "$NG/sites" "$NG/bk" \
         "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC7A=$?
if [ "$RC7A" -eq 0 ]; then pass "5c exits 0 on a conf whose :8090 block is already off"; else
  fail "5c exits $RC7A on a conf whose :8090 block is already off"
  printf '%s\n' "$OUT7A" | sed 's/^/        /' | head -20
fi
for want in "before 8090 blocks:1" "before 8090 blocks with access_log off:1" \
            "before edits pending:0" "after edited files:0"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUT7A" "$f")" = "$v" ]; then pass "the no-op run reports $f = $v"; else
    fail "the no-op run reports $f = '$(field_5c "$OUT7A" "$f")', expected $v"; fi
done
if cmp -s "$WORK/live-present.conf" "$NG/available/paramant-live.conf"; then
  pass "a conf that already had the line is byte-identical afterwards"
else
  fail "5c rewrote a conf whose :8090 block was already correct"
  diff -u "$WORK/live-present.conf" "$NG/available/paramant-live.conf" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT7A" | grep -q 'reloaded nginx'; then
  pass "the no-op run still tests and reloads nginx"
else
  fail "the no-op run never reloaded nginx"
fi

check_has "$SCRIPT" 'print "    access_log off;"' \
  "phase 5c writes access_log off into the :8090 block"
check_has "$SCRIPT" 'ALOG_AWK' \
  "the access_log edit is a two-pass awk, like the buffer and the /pararules edits"
check_has "$FULL"   'before 8090 blocks with access_log off' \
  "the dry run shows the :8090 access_log counters"

echo ""
echo "6g-8. A :8090 block that logs to a FILE is refused, not quietly stacked"
# `access_log off;` written above an `access_log /var/log/nginx/dicom.log;`
# leaves two access_log directives on the same level, and it undoes a log
# somebody put there on purpose. Neither is a deploy's call to make, so the
# phase counts those blocks, says how many it found and stops before it writes
# anything.
make_dicom_conf "$NG/available/paramant-public.conf" none
make_dicom_conf "$NG/available/paramant-live.conf"   missing
# One line, straight into the :8090 block: the shape a server gets when someone
# wants that gateway logged.
sed -i 's|^    listen 127\.0\.0\.1:8090;$|    listen 127.0.0.1:8090;\n    access_log /var/log/nginx/dicom.log;|' \
  "$NG/available/paramant-live.conf"
cp -a "$NG/available/paramant-live.conf" "$WORK/live-filelog.conf"
seed_2b_backups "$NG/sites" "$NG/bk" 20260101-0007 "paramant-public.conf paramant-live.conf"
OUT8="$(cd "$NG" && PATH="$NG/bin:$PATH" bash "$NG/5c.sh" 20260101-0007 "$NG/sites" "$NG/bk" \
        "paramant-public.conf paramant-live.conf" </dev/null 2>&1)"; RC8B=$?
if [ "$(field_5c "$OUT8" 'before 8090 blocks logging to a file')" = "1" ]; then
  pass "the phase counts the :8090 block that logs to a file"
else
  fail "the file-logging block is counted as $(field_5c "$OUT8" 'before 8090 blocks logging to a file'), expected 1"
fi
if [ "$RC8B" -ne 0 ] && printf '%s\n' "$OUT8" | grep -q 'write their access log to a FILE'; then
  pass "5c stops and names it instead of writing access_log off above it"
else
  fail "5c exited $RC8B on a :8090 block that logs to a file"
  printf '%s\n' "$OUT8" | sed 's/^/        /' | head -20
fi
if cmp -s "$WORK/live-filelog.conf" "$NG/available/paramant-live.conf"; then
  pass "nothing was written: the conf is byte-identical after the refusal"
else
  fail "5c wrote to the conf before refusing it"
  diff -u "$WORK/live-filelog.conf" "$NG/available/paramant-live.conf" | sed 's/^/        /' | head -20
fi
# And the awk itself, with the FATAL out of the way, still refuses that block.
# If the precondition is ever loosened, this is the lock that is left.
eval "$(sed -n "/^ALOG_AWK='/,/^}'\$/p" "$SCRIPT")"
awk "$ALOG_AWK" "$WORK/live-filelog.conf" "$WORK/live-filelog.conf" > "$WORK/live-filelog-out.conf"
if cmp -s "$WORK/live-filelog.conf" "$WORK/live-filelog-out.conf"; then
  pass "the edit awk on its own leaves a file-logging :8090 block untouched"
else
  fail "the edit awk would stack access_log off on top of a file log"
  diff -u "$WORK/live-filelog.conf" "$WORK/live-filelog-out.conf" | sed 's/^/        /' | head -10
fi
# The plain fixtures must read zero, or the counter would be meaningless.
if [ "$(field_5c "$OUT5" 'before 8090 blocks logging to a file')" = "0" ] \
   && [ "$(field_5c "$OUT5" 'after 8090 blocks logging to a file')" = "0" ]; then
  pass "a :8090 block with no access_log at all does not read as logging to a file"
else
  fail "the plain fixture reads $(field_5c "$OUT5" 'before 8090 blocks logging to a file') file-logging block(s), expected 0"
fi
if [ "$(field_5c "$OUT7A" 'before 8090 blocks logging to a file')" = "0" ]; then
  pass "access_log off itself does not read as logging to a file"
else
  fail "a block with access_log off reads as logging to a file"
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
OUT5="$(bash "$RB5B/5b.sh" "$RB5B/repo" "$RB5B/docroot" "$HEADC" "dist" "$FLOOR" </dev/null 2>&1)"; RC5=$?
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
OUT6="$(bash "$RB5B/5b.sh" "$RB5B/repo" "$RB5B/docroot" "$HEADC" "dist" "$FLOOR" </dev/null 2>&1)"; RC6=$?
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
        "paramant-public.conf paramant-live.conf|paramant.conf" </dev/null 2>&1)"; RC7=$?
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
        "paramant-public.conf paramant-live.conf|paramant.conf" </dev/null 2>&1)"; RC8=$?
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
        "paramant-public.conf paramant-live.conf|paramant.conf" </dev/null 2>&1)"; RC9=$?
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
         "paramant-public.conf paramant-live.conf|paramant.conf" </dev/null 2>&1)"; RC10=$?
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
         "$RBN/sites" "paramant-public.conf paramant-live.conf|paramant.conf" </dev/null 2>&1)"; RC11=$?
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
         "$RBN/sites" "paramant-public.conf paramant-live.conf|paramant.conf" </dev/null 2>&1)"
if [ "$(field_5c "$OUT12" 'missing backups')" = "1" ]; then
  pass "a missing backup under the resolved name is counted, so the rollback stops"
else
  fail "with the paramant.conf backup gone, 8a still reports $(field_5c "$OUT12" 'missing backups') missing"
fi
mv "$RBN/ngbk/paramant.conf.pre-3.1-$RBTS.moved" "$RBN/ngbk/paramant.conf.pre-3.1-$RBTS"

echo bogus-added-by-deploy > "$RBN/root/app/added.html"
OUT13="$(PATH="$RBN/bin:$PATH" bash "$RBN/8c.sh" "$RBTS" "$RBN/bk" "$RBN/root/app" "$RBN/ngbk" \
         "$RBN/sites" "paramant-public.conf paramant-live.conf|paramant.conf" "dist" </dev/null 2>&1)"; RC13=$?
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
         "$RBN/sites" "paramant-public.conf paramant-live.conf|not-there.conf" "dist" </dev/null 2>&1)"; RC14=$?
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
         "$SL3" </dev/null 2>&1)"; RC15=$?
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
         "$SL3" </dev/null 2>&1)"; RC16=$?
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
         "$SL3" </dev/null 2>&1)"; RC17=$?
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
echo "6i-8. remote_nginx must not run remote() in a subshell"
# Deploy run 4 (TS 20260903-0216) stopped in phase 2b on "the server never
# printed 'after .env backup bytes'" while the server had printed exactly that,
# 1420 bytes, and had resolved both confs. The wrapper was a pipeline,
#
#   { printf '%s\n' "$NGINX_RESOLVE_SNIPPET"; cat; } | remote "$@"
#
# and every stage of a pipeline is a subshell, so remote() and _remote_run()
# set REMOTE_OUT and REMOTE_RC in a child that then exited. Every expect after
# a remote_nginx call read whatever the PREVIOUS block had left behind.
#
# The block-level tests above extract heredoc bodies and never touch the
# wrapper, which is why 252 green checks missed this. This one drives the real
# remote_nginx(), with _remote_run() stubbed, and asks the calling shell what
# it can see afterwards.
WRAP="$WORK/wrap"
mkdir -p "$WRAP"

# The stub stands in for the ssh call: it records the body it was handed and
# sets the two variables the way _remote_run() does on a real run.
cat > "$WRAP/stub.sh" <<'STUB'
die() { echo "die: $*" >&2; return 1; }
_remote_run() {
  cat > "$WRAPDIR/stdin.txt"
  REMOTE_OUT="after .env backup bytes = 1420"
  REMOTE_RC=0
  return 0
}
STUB

# harness <wrapper-source-file>: source the stub, the snippet, remote() and one
# spelling of remote_nginx(), call it, and report what the CALLER can see.
cat > "$WRAP/harness.sh" <<'HARNESS'
set -uo pipefail
WRAPDIR="$1"; WRAPPER="$2"; SCRIPT="$3"
# shellcheck source=/dev/null
. "$WRAPDIR/stub.sh"
eval "$(sed -n '/^NGINX_RESOLVE_SNIPPET=/,/^)"$/p' "$SCRIPT")"
eval "$(sed -n '/^remote() {$/,/^}$/p' "$SCRIPT")"
# shellcheck source=/dev/null
. "$WRAPPER"
REMOTE_OUT="stale output from the previous block"
REMOTE_RC=7
remote_nginx "unit" one two <<'BODY'
set -euo pipefail
echo body-marker
BODY
echo "PARENT REMOTE_OUT=[$REMOTE_OUT]"
echo "PARENT REMOTE_RC=[$REMOTE_RC]"
HARNESS

# The wrapper as the script spells it today.
sed -n '/^remote_nginx() {$/,/^}$/p' "$SCRIPT" > "$WRAP/wrapper-now.sh"
if [ -s "$WRAP/wrapper-now.sh" ]; then
  pass "remote_nginx() could be extracted from the script"
else
  fail "could not extract remote_nginx() from the script"
fi

WOUT="$(WRAPDIR="$WRAP" bash "$WRAP/harness.sh" "$WRAP" "$WRAP/wrapper-now.sh" "$SCRIPT" 2>&1)"
if printf '%s\n' "$WOUT" | grep -q 'PARENT REMOTE_OUT=\[after \.env backup bytes = 1420\]'; then
  pass "REMOTE_OUT set by the remote call is visible in the shell that called remote_nginx"
else
  fail "REMOTE_OUT did not reach the caller; every expect after a remote_nginx would judge the previous block"
  printf '%s\n' "$WOUT" | sed 's/^/        /' | head -10
fi
if printf '%s\n' "$WOUT" | grep -q 'PARENT REMOTE_RC=\[0\]'; then
  pass "REMOTE_RC reaches the caller too, so a failing block still stops the deploy"
else
  fail "REMOTE_RC did not reach the caller (got: $(printf '%s\n' "$WOUT" | sed -n 's/^PARENT REMOTE_RC=//p'))"
fi
# The body still has to arrive whole, and the resolver still has to come first.
if [ -f "$WRAP/stdin.txt" ]; then
  R_LINE="$(grep -n '^resolve_conf_slots() {' "$WRAP/stdin.txt" | head -1 | cut -d: -f1)"
  B_LINE="$(grep -n '^echo body-marker$' "$WRAP/stdin.txt" | head -1 | cut -d: -f1)"
  if [ -n "$R_LINE" ] && [ -n "$B_LINE" ] && [ "$R_LINE" -lt "$B_LINE" ]; then
    pass "the resolver is defined before the block body in what the server receives"
  else
    fail "the stdin the server would get is wrong (resolver at '${R_LINE:-none}', body at '${B_LINE:-none}')"
    sed 's/^/        /' "$WRAP/stdin.txt" | head -8
  fi
  if grep -q '^set -euo pipefail$' "$WRAP/stdin.txt"; then
    pass "the body arrives intact, strict mode and all"
  else
    fail "the block body did not survive the wrapper"
  fi
else
  fail "the stub was never handed a body"
fi

# Negative control: the pipeline spelling, so this test cannot pass by accident
# on a harness that would wave the bug through.
cat > "$WRAP/wrapper-pipe.sh" <<'OLD'
remote_nginx() {
  { printf '%s\n' "$NGINX_RESOLVE_SNIPPET"; cat; } | remote "$@"
}
OLD
POUT="$(WRAPDIR="$WRAP" bash "$WRAP/harness.sh" "$WRAP" "$WRAP/wrapper-pipe.sh" "$SCRIPT" 2>&1)"
if printf '%s\n' "$POUT" | grep -q 'PARENT REMOTE_OUT=\[stale output from the previous block\]'; then
  pass "negative control: the pipeline spelling really does lose REMOTE_OUT in a subshell"
else
  fail "the negative control no longer reproduces the run-4 bug, so the check above proves nothing"
  printf '%s\n' "$POUT" | sed 's/^/        /' | head -10
fi

# And no remote call anywhere may be piped into again. Comment lines are left
# out: the wrapper writes down the spelling that caused this, on purpose.
PIPED="$(grep -nE '\|[[:space:]]*remote(_soft|_nginx)?[[:space:]]+"' "$SCRIPT" \
         | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
if [ -n "$PIPED" ]; then
  fail "a remote call is piped into, which puts it in a subshell and loses REMOTE_OUT"
  printf '%s\n' "$PIPED" | sed 's/^/        /'
else
  pass "no remote call is on the right-hand side of a pipe"
fi

echo ""
echo "6j. Phase 3a: an untracked path is not a dirty working tree"
# Deploy run 5 (TS 20260903-0242) reached phase 3a for the first time and
# stopped on
#
#   dirty ?? backups/
#   FATAL working tree not clean
#
# An untracked directory in the server checkout, and nothing else wrong. A
# fast-forward pull cannot lose an untracked file, so that was a stop for
# nothing. A modified TRACKED file is a different matter and still stops the
# run. This runs the real 3a remote block against two throwaway repositories,
# one per case.
G3A="$WORK/g3a"
mkdir -p "$G3A"
extract_remote "git pull" > "$G3A/3a.sh"
if [ -s "$G3A/3a.sh" ]; then
  pass "the 3a remote block could be extracted from the script"
else
  fail "could not extract the 3a remote block from the script"
fi

# make_3a_repo <dir>: a checkout one commit behind its origin, so 3a has a real
# fast-forward to perform and "did it pull" is a question with an answer.
make_3a_repo() {
  local d="$1"
  rm -rf "$d"
  mkdir -p "$d"
  (
    set -e
    cd "$d"
    git init -q --bare origin.git
    # git init --bare picks its own default branch name, and if that is not the
    # one we push the clone comes out empty with only a warning. Say it.
    git --git-dir=origin.git symbolic-ref HEAD refs/heads/main
    git init -q seed && cd seed
    git config user.email t@example.com && git config user.name t
    git config commit.gpgsign false
    echo one > tracked.txt
    git add -A && git commit -qm one
    git branch -M main
    git remote add origin ../origin.git
    git push -q origin main
    cd ..
    git clone -q origin.git checkout
    cd checkout
    git config user.email t@example.com && git config user.name t
    git config commit.gpgsign false
    cd ../seed
    echo two > tracked.txt
    git commit -qam two
    git push -q origin main
  ) >/dev/null 2>&1
}

# A silently broken fixture would make both cases below pass for the wrong
# reason, so the fixture is checked before it is used.
fixture_3a_ok() {   # dir
  git -C "$1/checkout" rev-parse HEAD >/dev/null 2>&1 \
    && [ -f "$1/checkout/tracked.txt" ] \
    && [ -z "$(git -C "$1/checkout" status --porcelain)" ]
}

echo ""
echo "6j-1. Only an untracked path: the deploy pulls and says what it left alone"
make_3a_repo "$G3A/ok"
if fixture_3a_ok "$G3A/ok"; then
  pass "the fixture is a clean checkout one commit behind its origin"
else
  fail "the 3a fixture is broken, so the two cases below prove nothing"
fi
mkdir -p "$G3A/ok/checkout/backups"
echo state > "$G3A/ok/checkout/backups/full-state.tar.gz.age"
HEAD_BEFORE="$(git -C "$G3A/ok/checkout" rev-parse HEAD)"
OUT18="$(bash "$G3A/3a.sh" "$G3A/ok/checkout" </dev/null 2>&1)"; RC18=$?
if [ "$RC18" -eq 0 ]; then pass "3a runs through with an untracked backups/ in the checkout"; else
  fail "3a exits $RC18 on an untracked path (this is the run-5 stop)"
  printf '%s\n' "$OUT18" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT18" | grep -q '^  untracked backups/'; then
  pass "it prints the untracked path instead of hiding it"
else
  fail "the untracked path was not reported"
  printf '%s\n' "$OUT18" | sed 's/^/        /' | head -12
fi
for want in "before untracked paths:1" "before tracked changes:0"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUT18" "$f")" = "$v" ]; then pass "3a reports $f = $v"; else
    fail "3a reports $f = '$(field_5c "$OUT18" "$f")', expected $v"; fi
done
if printf '%s\n' "$OUT18" | grep -q 'FATAL'; then
  fail "3a still prints a FATAL for an untracked path"
  printf '%s\n' "$OUT18" | grep FATAL | sed 's/^/        /'
else
  pass "no FATAL: an untracked path is not dirt"
fi
if [ "$(git -C "$G3A/ok/checkout" rev-parse HEAD)" != "$HEAD_BEFORE" ]; then
  pass "the fast-forward pull really happened"
else
  fail "3a exited 0 but the checkout never moved"
fi
if [ -f "$G3A/ok/checkout/backups/full-state.tar.gz.age" ]; then
  pass "the untracked file is still there, untouched by the pull"
else
  fail "the pull removed an untracked file"
fi

echo ""
echo "6j-2. A modified tracked file still stops the deploy, before the pull"
make_3a_repo "$G3A/dirty"
if fixture_3a_ok "$G3A/dirty"; then
  pass "the second fixture is clean before the hand edit goes in"
else
  fail "the 3a fixture is broken, so the stop below proves nothing"
fi
echo "hand edit between deploys" > "$G3A/dirty/checkout/tracked.txt"
HEAD_BEFORE="$(git -C "$G3A/dirty/checkout" rev-parse HEAD)"
OUT19="$(bash "$G3A/3a.sh" "$G3A/dirty/checkout" </dev/null 2>&1)"; RC19=$?
if [ "$RC19" -ne 0 ]; then pass "3a stops when a tracked file is modified"; else
  fail "3a pulled over a modified tracked file (exit $RC19)"
  printf '%s\n' "$OUT19" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUT19" | grep -q 'FATAL working tree not clean: 1 tracked file'; then
  pass "the FATAL says how many tracked files, so the reason is not guesswork"
else
  fail "the FATAL does not name the tracked change"
  printf '%s\n' "$OUT19" | grep FATAL | sed 's/^/        /'
fi
if printf '%s\n' "$OUT19" | grep -q '^  dirty  M tracked.txt'; then
  pass "it lists the tracked file it stopped on"
else
  fail "the dirty listing is missing"
  printf '%s\n' "$OUT19" | sed 's/^/        /' | head -12
fi
if [ "$(field_5c "$OUT19" 'before tracked changes')" = "1" ]; then
  pass "the tracked-change count is reported, so the deploy can assert on it"
else
  fail "before tracked changes = '$(field_5c "$OUT19" 'before tracked changes')', expected 1"
fi
if [ "$(git -C "$G3A/dirty/checkout" rev-parse HEAD)" = "$HEAD_BEFORE" ]; then
  pass "it stopped BEFORE the pull, so the hand edit is still there to look at"
else
  fail "3a pulled anyway; the local change is now tangled with the pull"
fi
# git would refuse this pull by itself, which is a net and not a gate: it would
# report a merge conflict instead of "you have a hand edit here". Assert that
# the fetch was never even attempted, so the gate is provably in FRONT of it.
if printf '%s\n' "$OUT19" | grep -qE '^  (fetch|pull) '; then
  fail "3a reached the fetch or pull with a modified tracked file; the gate is not in front of them"
  printf '%s\n' "$OUT19" | grep -E '^  (fetch|pull) ' | sed 's/^/        /' | head -4
else
  pass "no fetch and no pull were attempted; the gate is the first thing 3a does"
fi
if grep -q 'hand edit between deploys' "$G3A/dirty/checkout/tracked.txt"; then
  pass "the modified file is untouched, which is what makes the stop useful"
else
  fail "the tracked change was lost"
fi

echo ""
echo "6j-3. The gate reads tracked and untracked separately, and says so"
check_has "$SCRIPT" 'git status --porcelain --untracked-files=no' \
  "the dirty gate asks git for tracked changes only"
check_has "$SCRIPT" 'git ls-files --others --directory --exclude-standard' \
  "untracked paths are read separately, to be reported rather than judged"
check_lacks "$SCRIPT" '\$\(git status --porcelain\)' \
  "the old all-or-nothing porcelain read is gone"
check_has "$FULL" 'before untracked paths'  "the dry run shows the untracked count"
check_has "$FULL" 'before tracked changes'  "the dry run shows the tracked count"
check_has "$SCRIPT" 'expect_count "before tracked changes" 0' \
  "the deploy asserts that no tracked file was modified"
# backups/ is ignored in the repo, so a checkout that pulls this commit stops
# reporting it at all.
check_has "$ROOT/.gitignore" '^backups/$' "backups/ is gitignored, so the next pull makes it invisible"
if git -C "$ROOT" check-ignore -q backups/ 2>/dev/null; then
  pass "git agrees that backups/ is ignored"
else
  fail "backups/ is in .gitignore but git does not ignore it"
fi

echo ""
echo "6k. No remote block may let a command eat the script off stdin"
# Deploy run 6 (TS 20260903-0259) landed phases 3, 4 and 5, six containers on
# 3.1.0, the nginx edits applied, the site live, and then stopped in 6h on
#
#   STOP the server never printed 'effective outbound buffers'
#
# The body of a remote block is piped into `ssh ... bash -s`, so the script
# text IS file descriptor 0, and bash reads it lazily. `docker compose exec -T`
# reads stdin, so it swallowed everything bash had not parsed yet: the echo
# below the for-loop was simply gone. The two lines the loop itself printed
# came out fine, because the whole loop was parsed before it ran, which is
# exactly what made the log look like a measurement failure rather than a
# truncated script. 6i and the phase 7a marker never ran either, and the
# missing marker is what would have stopped the next run in 1a.
#
# The rule: every stdin-reading command inside a remote heredoc gets
# </dev/null. This scans the real blocks for the ones that do not.
#
# Heuristic, with its limit written down: backslash continuations are joined
# first, comments are skipped, and a `read` is accepted when the line carries a
# here-string or the loop it belongs to is redirected by a later `done <`.
# That covers every shape this script uses. A `read` in some other shape would
# be flagged, which is the safe direction to be wrong in.
STDIN_SCAN="$WORK/stdin-scan.txt"
# The commands that read stdin when nothing feeds them. Two families:
#   always     docker compose exec/run, docker exec/run, a nested ssh, xargs
#   when bare  cat, sort, wc, python -, node -, and any read
# "Bare" means no file operand and no redirect. `cat "$f"`, `wc -l < "$f"` and
# `sort file` are fine; `cat`, `wc -l` and `sort` on their own are not. xargs is
# in the first family on purpose: it reads stdin however many arguments it has,
# so `xargs rm -f` is not "xargs with an operand", it is xargs reading stdin.
#
# A command on the RIGHT of a pipe reads the pipe, not the script, so only the
# first segment of a pipeline is exposed. That is the whole reason the scan
# splits on "|" rather than grepping lines: `... | wc -l` is safe and common
# here, `wc -l` alone is the bug. Logical || is masked first so it is not read
# as a pipe.
#
# Heuristic, with its limit written down: backslash continuations are joined
# first, comments are skipped, and a `read` is accepted when the line carries a
# here-string or the loop it belongs to is redirected by a later `done <`.
# That covers every shape this script uses. Something in another shape gets
# flagged, which is the safe direction to be wrong in.
STDIN_AWK="$(cat <<'AWKPROG'
  # Blank every quoted span to a single token Q, so a "|" inside a string is
  # not read as a pipe and an argument is still visibly an argument. Q keeps
  # `cat "$f"` looking like cat-with-an-operand, which "" would not.
  function dequote(line) {
    gsub(/\047[^\047]*\047/, "Q", line)
    gsub(/"[^"]*"/, "Q", line)
    return line
  }
  # Everything before the first real pipe. A command to the RIGHT of a pipe
  # reads the pipe, not the script, so only this part is exposed to stdin.
  function exposed_segment(line,   n, seg) {
    gsub(/\|\|/, "\001", line)
    n = index(line, "|")
    seg = (n > 0) ? substr(line, 1, n - 1) : line
    gsub(/\001/, "||", seg)
    return seg
  }
  function has_stdin_redirect(line) {
    return (line ~ /<[[:space:]]*\/dev\/null/ || line ~ /<[[:space:]]*"?\$/ \
            || line ~ /<[[:space:]]*\// || line ~ /<</ || line ~ /<[[:space:]]*Q/)
  }
  # The command with no operand: end of segment, or only flags after it.
  #
  # ">" is in the closing class next to ";", "&", ")" and the backtick. An
  # output redirect is not an operand: `cat > /tmp/x` and `sort > /tmp/y` read
  # stdin exactly as a bare `cat` does, and both shapes slipped through while
  # the class ended at ")". `cat file > out` still does not match, because the
  # file operand sits between the command and the ">", which is the whole
  # distinction this function is for.
  function bare(seg, cmd,   re) {
    re = "(^|[;&(`]|[[:space:]]|[$][(])" cmd "([[:space:]]+-[^[:space:]]+)*[[:space:]]*($|[;&)`>])"
    return (seg ~ re)
  }
  /^  remote(_soft|_nginx)? ".*<<\047EOF\047$/ {
    inb = 1; lbl = $0
    sub(/^  remote(_soft|_nginx)? "/, "", lbl); sub(/".*$/, "", lbl)
    ln = 0; n = 0; delete body; delete bln
    next
  }
  inb && /^EOF$/ {
    inb = 0
    for (i = 1; i <= n; i++) {
      line = body[i]
      if (line ~ /^[[:space:]]*#/) continue

      # Family 1: reads stdin whatever its arguments. Judged on the WHOLE line,
      # including inside $( ) and inside quotes, because that is where two of
      # the three real ones live. Safety is </dev/null, nothing else.
      if (line ~ /docker compose exec|docker compose run|docker exec|docker run|(^|[^a-zA-Z_])ssh[[:space:]]/) {
        if (line !~ /<[[:space:]]*\/dev\/null/) printf "%s\tL%d\tALWAYS-READS\t%s\n", lbl, bln[i], line
        continue
      }
      # xargs reads stdin whatever arguments it is given, so a command name
      # after it is not an operand that feeds it. It is only safe behind a pipe.
      if (exposed_segment(dequote(line)) ~ /(^|[;&(`]|[[:space:]]|[$][(])xargs([[:space:]]|$)/) {
        if (line !~ /<[[:space:]]*\/dev\/null/) printf "%s\tL%d\tALWAYS-READS\t%s\n", lbl, bln[i], line
        continue
      }
      if (line ~ /(python|python3|node)[[:space:]]+-([[:space:]]|$)/) {
        if (line !~ /<[[:space:]]*\/dev\/null/) printf "%s\tL%d\tSTDIN-DASH\t%s\n", lbl, bln[i], line
        continue
      }
      # Family 2: a read, unless it has a here-string or its loop is redirected.
      if (line ~ /(^|[;&|(][[:space:]]*|[[:space:]])read[[:space:]]/) {
        if (line ~ /<<</ || line ~ /<[[:space:]]*\/dev\/null/) continue
        redirected = 0
        for (j = i + 1; j <= n; j++) if (body[j] ~ /^[[:space:]]*done[[:space:]]*</) { redirected = 1; break }
        if (!redirected) printf "%s\tL%d\tBARE-READ\t%s\n", lbl, bln[i], line
        continue
      }
      # Family 3: reads stdin only when given no file. Pipe position decides,
      # so this one works on the dequoted, pre-pipe part of the line.
      # Limit: a bare one nested inside $( ) inside a quoted string is not
      # seen. Every such case in this script is pipe-fed, and family 1 covers
      # the nested commands that are not.
      seg = exposed_segment(dequote(line))
      if (has_stdin_redirect(seg)) continue
      split("cat sort wc", risky, " ")
      for (k in risky) {
        if (bare(seg, risky[k])) {
          printf "%s\tL%d\tBARE-%s\t%s\n", lbl, bln[i], risky[k], line
          break
        }
      }
    }
    next
  }
  inb {
    ln++
    if (pend != "") { pend = pend " " $0 }
    else { pend = $0; pl = ln }
    if (pend ~ /\\$/) { sub(/\\$/, "", pend); next }
    n++; body[n] = pend; bln[n] = pl; pend = ""
  }
AWKPROG
)"
awk "$STDIN_AWK" "$SCRIPT" > "$STDIN_SCAN"

if [ ! -s "$STDIN_SCAN" ]; then
  pass "every stdin-reading command in every remote block reads from somewhere that is not the script"
else
  fail "a command in a remote block would read the rest of the script off stdin"
  sed 's/^/        /' "$STDIN_SCAN" | head -8
fi

# The scan has to be looking at something. Pinned to the REAL number of remote
# blocks, not a floor: a floor of "at least ten" would still pass if the
# extraction silently lost half of them, and losing the block that holds the
# bug is exactly how this check would go quiet. Adding or removing a remote
# block is a deliberate act, so updating this number is part of it.
SCAN_BLOCKS="$(grep -cE "^  remote(_soft|_nginx)? \".*<<'EOF'\$" "$SCRIPT" || true)"
if [ "$SCAN_BLOCKS" = "26" ]; then
  pass "the scan walked all 26 remote blocks"
else
  fail "the script has $SCAN_BLOCKS remote blocks, the scan expects 26; update the number here on purpose"
fi

# And the three commands that actually read stdin are still there, guarded.
check_has "$SCRIPT" 'docker compose exec -T "\$svc" sh -c .*</dev/null' \
  "the 6h inline-receipt probe reads from /dev/null"
check_has "$SCRIPT" '</dev/null 2>/dev/null \|\| echo "unreadable"' \
  "the phase 1b env probe reads from /dev/null"
check_has "$SCRIPT" 'docker exec "\$cid" grep -c _paraidAuth /app/relay\.js </dev/null' \
  "the rollback paraidAuth probe reads from /dev/null"
check_has "$FULL" 'effective outbound buffers' \
  "the line run 6 lost is still in the 6h block"

echo ""
echo "6k-1. The guard itself, against a block written to break it"
# The scan above is only worth its green if it goes red on the shape it is for.
# It did not. `bare()` accepted a command as bare when what followed it was the
# end of the segment or one of ; & ) `, and an output redirect is none of
# those, so `cat > /tmp/x` and `sort > /tmp/y` read as "cat with an operand"
# and walked straight through. Both of them eat the rest of the script exactly
# as a lone `cat` does; the redirect only decides where the swallowed text
# lands.
#
# The other direction matters just as much, and it is why ">" cannot simply be
# treated as the end of the command: `cat file > out` reads the FILE, not
# stdin, and flagging it would push a </dev/null onto a line that does not need
# one. The distinction is whether an operand sits between the command and the
# redirect, which is what bare() already measures.
STDIN_FIX="$WORK/stdin-fixture.sh"
cat > "$STDIN_FIX" <<'FIX'
  remote "guard fixture" "$COMPOSE_DIR" <<'EOF'
cat > /tmp/x
sort > /tmp/y
cat file > out
sort file > out
grep -c foo "$f" > /tmp/z
cat "$f" > "$g"
cat </dev/null > /tmp/ok
wc -l < "$f" > /tmp/n
printf '%s\n' "$x" | cat > /tmp/piped
EOF
FIX
FIXSCAN="$WORK/stdin-fixture-scan.txt"
awk "$STDIN_AWK" "$STDIN_FIX" > "$FIXSCAN"

if grep -q 'BARE-cat.*cat > /tmp/x' "$FIXSCAN"; then
  pass "the scan catches a bare cat that redirects its output"
else
  fail "'cat > /tmp/x' walks through the scan; it eats the rest of the script"
fi
if grep -q 'BARE-sort.*sort > /tmp/y' "$FIXSCAN"; then
  pass "the scan catches a bare sort that redirects its output"
else
  fail "'sort > /tmp/y' walks through the scan; it eats the rest of the script"
fi
for safe in 'cat file > out' 'sort file > out' 'grep -c foo' 'cat "$f" > "$g"' \
            'cat </dev/null' 'wc -l < "$f"' '| cat > /tmp/piped'; do
  if grep -qF -- "$safe" "$FIXSCAN"; then
    fail "the scan flags '$safe', which reads a file or a pipe and not the script"
    grep -F -- "$safe" "$FIXSCAN" | sed 's/^/        /' | head -3
  else
    pass "the scan leaves '$safe' alone"
  fi
done
if [ "$(wc -l < "$FIXSCAN")" = "2" ]; then
  pass "the fixture yields exactly the two findings it was written for"
else
  fail "the fixture yields $(wc -l < "$FIXSCAN") finding(s), expected 2"
  sed 's/^/        /' "$FIXSCAN" | head -10
fi

echo ""
echo "6l. --verify-only finishes a deploy that died in the checks"
# Run 6 did all the work and then lost 6h, 6i and the phase 7a marker. Redoing
# the whole script to get those back would re-tag, re-back-up, re-pull, rebuild
# and recreate six healthy containers. This mode runs phases 6 and 7 and gates
# on the server already being deployed.
VO="$WORK/verifyonly.txt"
( cd "$ROOT" && bash "$SCRIPT" --dry-run --verify-only >"$VO" 2>&1 ); VO_RC=$?
[ "$VO_RC" -eq 0 ] && pass "--dry-run --verify-only exits 0" \
                   || fail "--dry-run --verify-only exits $VO_RC"
check_has   "$VO" '^PHASE V: Preconditions for --verify-only' "verify-only gates before it verifies"
check_has   "$VO" '^PHASE 6: Smoke tests'                     "verify-only runs phase 6"
check_has   "$VO" '^PHASE 7: Summary'                         "verify-only runs phase 7"
check_lacks "$VO" '^PHASE [0-5]: '                            "verify-only runs none of phases 0 to 5"
check_has   "$VO" 'VERIFY ONLY FINISHED'                      "verify-only says where it stopped"
check_has   "$VO" 'after deployed marker'                     "verify-only writes the deployed-head marker, which is the point"

# The four things this mode must not do. Each is checked by the command that
# would do it, not by a phase header, so moving a step between phases cannot
# hide it.
check_lacks "$VO" 'docker tag '                 "verify-only tags no rollback image"
check_lacks "$VO" 'tar czf '                    "verify-only writes no backup"
check_lacks "$VO" 'git pull --ff-only'          "verify-only pulls nothing"
check_lacks "$VO" 'docker compose build'        "verify-only builds nothing"
check_lacks "$VO" 'force-recreate'              "verify-only recreates no container"
check_lacks "$VO" 'rsync -rc'                   "verify-only writes no docroot"
check_lacks "$VO" 'sed -i -E .location = /sign' "verify-only edits no nginx conf"
check_lacks "$VO" 'INTERNAL_AUTH_TOKEN=%s'      "verify-only writes nothing to .env"

# The gate itself is a pure comparison, so both answers can be checked here.
check_has "$VO" 'verify ref sha'          "the gate reads the deploy ref off the server"
check_has "$VO" 'verify ancestor'         "the gate asks whether the deployed commit is on the mainline"
check_has "$VO" 'verify health version'   "the gate reads the version the relay reports"
check_has "$VO" 'verify package version'  "the gate reads the version the checkout describes"
check_has "$SCRIPT" 'Run the full deploy instead' \
  "a server that is not already deployed is sent to the full deploy, not verified"
check_lacks "$SCRIPT" 'git rev-parse origin/main' \
  "Va uses \$DEPLOY_REF, not a hard-coded origin/main"
check_has "$VO" 'bash -s -- /opt/paramant-relay origin/main"   # verify preconditions' \
  "the deploy ref is handed to the gate as an argument, so the log says which ref it judged"

echo ""
echo "6l-1. The gate says no when the checkout is not origin/main"
# sha_eq is the same comparison phase 1a uses, and it is already extracted
# above. These are the two ways the gate can refuse.
if declare -F sha_eq >/dev/null; then
  A2=aaaaaaa1111222233334444555566667777888899
  B2=bbbbbbb1111222233334444555566667777888899
  if sha_eq "$A2" "$A2"; then pass "the gate passes a checkout that equals origin/main"; else
    fail "the gate would refuse a checkout that equals origin/main"; fi
  if sha_eq "$A2" "$B2"; then fail "the gate would accept a checkout that is not origin/main"; else
    pass "the gate refuses a checkout that is not origin/main"; fi
  if sha_eq "$A2" ""; then fail "the gate would accept an empty origin/main"; else
    pass "the gate refuses an unresolved origin/main"; fi
else
  fail "sha_eq was not available to test the verify-only gate with"
fi

echo ""
echo "6l-2. The three run modes do not combine"
( cd "$ROOT" && bash "$SCRIPT" --verify-only --preflight-only >/dev/null 2>&1 )
[ $? -eq 2 ] && pass "--verify-only with --preflight-only exits 2" \
             || fail "--verify-only and --preflight-only were accepted together"
( cd "$ROOT" && bash "$SCRIPT" --verify-only --rollback 20260101-0000 >/dev/null 2>&1 )
[ $? -eq 2 ] && pass "--verify-only with --rollback exits 2" \
             || fail "--verify-only and --rollback were accepted together"
check_has "$SCRIPT" 'verify-only' "the usage header documents the mode"

echo ""
echo "6m. The verify-only gate: on the mainline, not necessarily at its tip"
# The first spelling of this gate demanded HEAD == origin/main, which refuses
# exactly the state it was written for. Run 6 deployed 4e6de0b and main had
# already moved to 05bbd1b by the time the mode existed: main moves while a
# deploy runs, and a deploy that is BEHIND the tip is the normal case, not a
# fault. What is a fault is a checkout BESIDE the mainline, because then
# nobody knows what is running. So the gate is merge-base --is-ancestor.
#
# The remote half of Va is a real git question, so it is asked of real
# repositories here, one per answer.
GV="$WORK/gverify"
mkdir -p "$GV"
extract_remote "verify preconditions" > "$GV/va.sh"
if [ -s "$GV/va.sh" ]; then
  pass "the Va remote block could be extracted from the script"
else
  fail "could not extract the Va remote block from the script"
fi

# make_va_repo <dir> <where>: a checkout that is either behind origin/main
# (the run-6 shape) or on a branch beside it.
make_va_repo() {
  local d="$1" where="$2"
  rm -rf "$d"; mkdir -p "$d"
  (
    set -e
    cd "$d"
    git init -q --bare origin.git
    git --git-dir=origin.git symbolic-ref HEAD refs/heads/main
    git init -q seed && cd seed
    git config user.email t@example.com && git config user.name t
    git config commit.gpgsign false
    printf '{\n  "name": "p",\n  "version": "3.1.0"\n}\n' > package.json
    git add -A && git commit -qm one
    git branch -M main
    git remote add origin ../origin.git
    git push -q origin main
    DEPLOYED="$(git rev-parse HEAD)"
    echo two >> package.json.note && git add -A && git commit -qm two
    git push -q origin main
    cd ..
    git clone -q origin.git checkout
    cd checkout
    git config user.email t@example.com && git config user.name t
    git config commit.gpgsign false
    if [ "$where" = behind ]; then
      git checkout -q "$DEPLOYED"
    else
      # Beside the mainline: a commit that is not an ancestor of origin/main.
      git checkout -q "$DEPLOYED"
      git checkout -q -b sidetrack
      echo sidetrack > sidetrack.txt
      git add -A && git commit -qm "not on main"
    fi
  ) >/dev/null 2>&1
}

# The relay is not running here, so /health answers nothing. Stub curl to
# report the version, which is the half of Va that is about the containers.
mkdir -p "$GV/bin"
cat > "$GV/bin/curl" <<'STUB'
#!/bin/sh
echo '{"status":"ok","version":"3.1.0"}'
STUB
chmod +x "$GV/bin/curl"

echo ""
echo "6m-1. A checkout one commit behind origin/main is accepted"
make_va_repo "$GV/behind" behind
BEHIND_HEAD="$(git -C "$GV/behind/checkout" rev-parse HEAD)"
TIP="$(git -C "$GV/behind/checkout" rev-parse origin/main 2>/dev/null || echo none)"
if [ "$BEHIND_HEAD" != "$TIP" ] && [ "$TIP" != none ]; then
  pass "the fixture really is behind the tip ($(printf %s "$BEHIND_HEAD" | cut -c1-7) vs $(printf %s "$TIP" | cut -c1-7))"
else
  fail "the behind fixture is not behind anything, so it proves nothing"
fi
OUT20="$(PATH="$GV/bin:$PATH" bash "$GV/va.sh" "$GV/behind/checkout" origin/main </dev/null 2>&1)"; RC20=$?
if [ "$RC20" -eq 0 ]; then pass "Va runs on a checkout behind the tip"; else
  fail "Va exits $RC20 on a checkout behind the tip"
  printf '%s\n' "$OUT20" | sed 's/^/        /' | head -12
fi
if [ "$(field_5c "$OUT20" 'verify ancestor')" = "yes" ]; then
  pass "a commit behind the tip reads as on the mainline"
else
  fail "verify ancestor = '$(field_5c "$OUT20" 'verify ancestor')', expected yes"
fi
if [ "$(field_5c "$OUT20" 'verify head')" = "$BEHIND_HEAD" ]; then
  pass "Va reports the DEPLOYED commit, which is what phase 7a writes as the marker"
else
  fail "Va reports head '$(field_5c "$OUT20" 'verify head')', expected $BEHIND_HEAD"
fi
if [ "$(field_5c "$OUT20" 'verify package version')" = "3.1.0" ] \
   && [ "$(field_5c "$OUT20" 'verify health version')" = "3.1.0" ]; then
  pass "the two versions are read and agree"
else
  fail "versions read as package='$(field_5c "$OUT20" 'verify package version')' health='$(field_5c "$OUT20" 'verify health version')'"
fi

echo ""
echo "6m-2. A checkout beside the mainline is refused"
make_va_repo "$GV/beside" beside
OUT21="$(PATH="$GV/bin:$PATH" bash "$GV/va.sh" "$GV/beside/checkout" origin/main </dev/null 2>&1)"; RC21=$?
if [ "$(field_5c "$OUT21" 'verify ancestor')" = "no" ]; then
  pass "a commit beside the mainline reads as not an ancestor"
else
  fail "verify ancestor = '$(field_5c "$OUT21" 'verify ancestor')', expected no"
  printf '%s\n' "$OUT21" | sed 's/^/        /' | head -12
fi
# An unresolvable ref is a third answer, and it must not read as yes.
OUT22="$(PATH="$GV/bin:$PATH" bash "$GV/va.sh" "$GV/beside/checkout" origin/nope </dev/null 2>&1)"
if [ "$(field_5c "$OUT22" 'verify ancestor')" = "unknown" ]; then
  pass "a ref the server cannot resolve reads as unknown, not as yes"
else
  fail "an unresolvable ref reads as '$(field_5c "$OUT22" 'verify ancestor')'"
fi

echo ""
echo "6m-3. The local half turns those three answers into a verdict"
# Va's judgement is three lines of case, and the whole point of the review was
# that the wrong comparison passed the tests. So assert the verdict text is
# keyed on the ancestor answer and that equality with the tip is NOT a gate.
check_has "$SCRIPT" 'case "\$ancestor" in' \
  "Va decides on the ancestor answer"
check_has "$SCRIPT" 'is not an ancestor of \$DEPLOY_REF' \
  "the refusal names the mainline test, not an equality test"
check_lacks "$SCRIPT" 'sha_eq "\$head" "\$omain"' \
  "the old HEAD-equals-origin/main gate is gone"
check_has "$SCRIPT" 'this mode signs off on the DEPLOYED commit' \
  "being behind the ref is a note, not a stop"
check_has "$SCRIPT" 'PARAMANT_VERIFY_HEAD' \
  "the deployed commit can be named explicitly"
# The note has to be a note. If "behind the tip" ever becomes a die again, the
# word die will appear in the same branch as the note text.
BEHIND_BRANCH="$(awk '/this mode signs off on the DEPLOYED commit/,/^  note "no tag/' "$SCRIPT")"
if printf '%s\n' "$BEHIND_BRANCH" | grep -q '\bdie\b'; then
  fail "the behind-the-tip branch can still stop the run"
  printf '%s\n' "$BEHIND_BRANCH" | grep -n 'die' | sed 's/^/        /'
else
  pass "nothing in the behind-the-tip branch stops the run"
fi

echo ""
echo "6n. post-deploy-verify.sh probes a route the relay actually serves"
# Phase 6g runs scripts/post-deploy-verify.sh on the server. That script probed
# a bare /health/deep, which relay.js has never had: the route is
# /v2/health/deep. So the check answered 404 on every run, the suite could
# never exit 0, and 6g swallowed it with a warn that said the probe is "known
# red". A permanently red non-critical check is a check nobody reads, and it
# was the only thing standing between 6g and a hard verdict.
PDV="$ROOT/scripts/post-deploy-verify.sh"
check_has "$PDV" '/v2/health/deep' "the verify suite asks for /v2/health/deep"
# Comments may still name the old path, that is where the history is written.
# The runnable lines may not.
if grep -vE '^[[:space:]]*#' "$PDV" | grep -qE '(^|[^2])/health/deep'; then
  fail "a runnable line still names the bare /health/deep"
  grep -nvE '^[[:space:]]*#' "$PDV" | grep -E '(^|[^2])/health/deep' | sed 's/^/        /' | head -5
else
  pass "every /health/deep outside a comment is the v2 route"
fi
# 401 is the pass. Outside RELAY_MODE=full the route is behind X-Internal-Auth
# (#322) and this script holds no token, so a shut gate is the strongest thing
# it can prove without one. A 200 would mean the gate is open.
check_has "$PDV" 'check "/v2/health/deep closed without a token" "401"' \
  "an unauthenticated caller is expected to be refused, not served"
# The suite has to be able to reach exit 0, or 6g cannot be hard.
if grep -qE '^\s*check .*"/health/deep' "$PDV"; then
  fail "a check still expects the old path, so the suite can never exit 0"
else
  pass "no check in the suite expects a path the relay does not serve"
fi
# And 6g now treats anything other than 0 as a finding.
check_lacks "$SCRIPT" 'probe is known red' "6g no longer excuses a red probe"
check_lacks "$SCRIPT" 'exit 2 blocks'    "the 6g step name no longer says only exit 2 blocks"
check_has   "$SCRIPT" 'any non-zero exit blocks' "the 6g step name says every non-zero exit blocks"
PDV_BRANCH="$(awk '/vrc="\$\(remote_field .verify exit.\)"/,/^    fi$/' "$SCRIPT")"
if printf '%s\n' "$PDV_BRANCH" | grep -q 'warn '; then
  fail "6g can still pass a non-zero verify exit off as a warning"
  printf '%s\n' "$PDV_BRANCH" | grep -n 'warn ' | sed 's/^/        /'
else
  pass "no branch of the 6g verdict warns instead of stopping"
fi
if [ "$(printf '%s\n' "$PDV_BRANCH" | grep -c 'die ')" = "2" ]; then
  pass "both non-zero exits of the verify suite stop the deploy"
else
  fail "the 6g verdict has $(printf '%s\n' "$PDV_BRANCH" | grep -c 'die ') die branch(es), expected 2"
  printf '%s\n' "$PDV_BRANCH" | sed 's/^/        /' | head -20
fi

echo ""
echo "6n-1. One bad answer may not kill a healthy deploy"
# 6g is hard now, so every probe in post-deploy-verify.sh is a stop. curl writes
# 000 when the transfer never produced a status line at all: DNS did not
# resolve, the connection was refused or reset, TLS did not come up, the
# deadline passed. Without a retry, one CDN hiccup or one DNS blip ends a deploy
# that is completely healthy, AFTER the work landed and BEFORE 6h, 6i and the
# phase 7a marker. That is deploy run 6 all over again, and the missing marker
# is what stops the NEXT run in 1a.
#
# So: --retry-all-errors inside the curl, and one more whole curl around it when
# the answer is still 000. This runs the real http_code() out of the script,
# with curl stubbed, because the retry has to be provable and not just written
# down.
check_has "$PDV" 'curl -sS --max-time 15 --retry 2 --retry-delay 2 --retry-all-errors' \
  "the shared curl retries, transport errors included"
check_has "$PDV" 'HTTP_RETRIES' "http_code has a retry budget of its own"

RTY="$WORK/retry"
mkdir -p "$RTY/bin"
# The stub answers from a script it is given: one line per call, "<code> <exit>".
cat > "$RTY/bin/curl" <<'STUB'
#!/bin/sh
n=$(cat "$RETRY_STATE" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$RETRY_STATE"
line=$(sed -n "${n}p" "$RETRY_PLAN")
[ -n "$line" ] || line=$(tail -1 "$RETRY_PLAN")
printf '%s' "${line% *}"
exit "${line#* }"
STUB
chmod +x "$RTY/bin/curl"

# http_code(), verbatim from the script, with the two variables it reads.
{
  echo 'CURL="curl"'
  sed -n '/^HTTP_RETRIES=/,/^}$/p' "$PDV"
} > "$RTY/http_code.sh"
if grep -q '^http_code() {' "$RTY/http_code.sh"; then
  pass "http_code could be extracted from the verify suite"
else
  fail "could not extract http_code from the verify suite"
fi

# Green: the first attempt never got a status, the second did.
printf '000 7\n200 0\n' > "$RTY/plan"
export RETRY_PLAN="$RTY/plan" RETRY_STATE="$RTY/state"
: > "$RETRY_STATE"
GREEN="$(PATH="$RTY/bin:$PATH" PARAMANT_VERIFY_HTTP_RETRY_DELAY=0 \
         bash -c ". '$RTY/http_code.sh'; http_code https://example.invalid/health")"
if [ "$GREEN" = "200" ]; then
  pass "a 000 followed by a 200 answers 200, so one blip does not stop the deploy"
else
  fail "a 000 followed by a 200 answered '$GREEN', expected 200"
fi
if [ "$(cat "$RETRY_STATE")" = "2" ]; then
  pass "it took exactly two attempts to get there, so the retry really happened"
else
  fail "the probe made $(cat "$RETRY_STATE") attempt(s), expected 2"
fi

# Red: nothing answers, twice. That is not a blip and it must not be swallowed.
: > "$RETRY_STATE"
printf '000 7\n000 7\n' > "$RTY/plan"
RED="$(PATH="$RTY/bin:$PATH" PARAMANT_VERIFY_HTTP_RETRY_DELAY=0 \
       bash -c ". '$RTY/http_code.sh'; http_code https://example.invalid/health")"
if [ "$RED" = "000" ]; then
  pass "two 000s in a row are still reported as 000, so a real outage still fails"
else
  fail "two 000s answered '$RED', expected 000"
fi
if [ "$(cat "$RETRY_STATE")" = "2" ]; then
  pass "it gave up after the second attempt instead of retrying forever"
else
  fail "the probe made $(cat "$RETRY_STATE") attempt(s) on a dead host, expected 2"
fi

# A real status is an answer, whatever it is. Retrying a 503 would turn a
# genuine failure into a slow one and hide it behind a second reading.
: > "$RETRY_STATE"
printf '503 0\n200 0\n' > "$RTY/plan"
KEEP="$(PATH="$RTY/bin:$PATH" PARAMANT_VERIFY_HTTP_RETRY_DELAY=0 \
        bash -c ". '$RTY/http_code.sh'; http_code https://example.invalid/health")"
if [ "$KEEP" = "503" ] && [ "$(cat "$RETRY_STATE")" = "1" ]; then
  pass "a 503 is reported as a 503 on the first attempt, never retried into a 200"
else
  fail "a 503 became '$KEEP' after $(cat "$RETRY_STATE") attempt(s)"
fi
unset RETRY_PLAN RETRY_STATE

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

echo ""
echo "6o. The limit_req zones come from a tracked snippet, never bound twice"
# Until this round the five zones the two site confs rate limit on were typed
# into /etc/nginx/nginx.conf on the server by hand. Nothing in the repo said
# what they were, so a conf review could not see them and a rebuilt server
# would have had site confs referencing zones that did not exist.
#
# The snippet is now tracked, and phase 5d places it. The hard part is that a
# limit_req_zone may be bound only ONCE: writing a second definition of a name
# the server already binds is not a warning, it is a config that does not load.
# So 5d reads what nginx really loads, comments out the lines it would double,
# and proves with nginx -T that the file it wrote is loaded at all.
SNIPPET="$ROOT/deploy/nginx/snippets/paramant-limit-req.conf"
if [ -f "$SNIPPET" ]; then pass "deploy/nginx/snippets/paramant-limit-req.conf exists"; else
  fail "deploy/nginx/snippets/paramant-limit-req.conf is missing"; fi
if git -C "$ROOT" ls-files --error-unmatch deploy/nginx/snippets/paramant-limit-req.conf >/dev/null 2>&1; then
  pass "the snippet is tracked by git, which was the whole point"
else
  fail "the snippet is not tracked by git"
fi

# The zones the two repo confs REFERENCE, and the zones the snippet DEFINES.
# A referenced zone the snippet does not define is a zone that only exists
# because someone typed it on the server, which is the situation this closes.
zones_defined() {
  sed -nE 's/^[[:space:]]*limit_req_zone[[:space:]]+[^[:space:]]+[[:space:]]+zone=([A-Za-z0-9_]+).*/\1/p' "$@" | sort -u
}
zones_referenced() {
  sed -nE 's/^[[:space:]]*limit_req[[:space:]]+zone=([A-Za-z0-9_]+).*/\1/p' "$@" | sort -u
}
SNIP_DEF="$(zones_defined "$SNIPPET" 2>/dev/null || true)"
CONF_REF="$(zones_referenced "$ROOT/deploy/nginx-paramant-public.conf" "$ROOT/deploy/nginx-paramant-live.conf" 2>/dev/null || true)"
MISSING=""
for z in $CONF_REF; do
  printf '%s\n' "$SNIP_DEF" | grep -qx "$z" || MISSING="${MISSING:+$MISSING }$z"
done
if [ -n "$CONF_REF" ]; then
  pass "the repo confs reference $(printf '%s' "$CONF_REF" | wc -w | tr -d ' ') limit_req zone(s)"
else
  fail "no limit_req zone reference found in the repo confs; this check is looking at nothing"
fi
if [ -z "$MISSING" ]; then
  pass "the snippet defines every zone the two repo confs rate limit on"
else
  fail "the snippet defines no zone called: $MISSING"
fi
# Every zone is per client IP. /help/iot-integration says so in those words and
# tests/site-claims.test.mjs holds it there, so a key change here would make
# the site lie.
if [ -n "$SNIP_DEF" ] \
   && [ "$(grep -cE '^[[:space:]]*limit_req_zone[[:space:]]+\$binary_remote_addr' "$SNIPPET")" \
      = "$(grep -cE '^[[:space:]]*limit_req_zone' "$SNIPPET")" ]; then
  pass "every zone in the snippet is keyed on \$binary_remote_addr, so the limits stay per IP"
else
  fail "a zone in the snippet is keyed on something other than \$binary_remote_addr"
fi
if grep -qE '^[[:space:]]*limit_req_zone[^#]*rate=[0-9]+r/m;' "$SNIPPET" 2>/dev/null; then
  pass "the zones carry an explicit rate"
else
  fail "a zone in the snippet has no rate= of its own"
fi
check_has "$FULL" '5d\. the limit_req zones'          "phase 5 reaches step 5d"
check_has "$FULL" 'paramant-limit-req\.conf'          "the deploy names the tracked snippet"
check_has "$FULL" 'nginx -T'                          "5d reads the LOADED config, not the file tree"
check_has "$FULL" 'limit_req     /etc/nginx/conf\.d/' "the run header says where the snippet lands"

# ------ the real 5d block, against a fixture nginx ------
LR="$WORK/lr"
mkdir -p "$LR/bin" "$LR/sites/../available" "$LR/bk" "$LR/etc" "$LR/co/deploy/nginx/snippets"
mkdir -p "$LR/sites" "$LR/available"
cp "$SNIPPET" "$LR/co/deploy/nginx/snippets/paramant-limit-req.conf"
LR_DEST="$LR/etc/paramant-limit-req.conf"

# nginx stub. -t is the config test, -T the dump of every file nginx loaded.
# LRT_FILES is what the server's own config holds; the destination file is
# added on top, the way conf.d/*.conf is included by nginx.conf, unless
# LRT_NO_INCLUDE says this server does not include that directory.
cat > "$LR/bin/nginx" <<'STUB'
#!/bin/sh
case "${1:-}" in
  -t)
    if [ "${LRT_T_FAIL:-0}" = 1 ]; then
      echo 'nginx: [emerg] limit_req_zone "api" is already bound to key "$binary_remote_addr"' >&2
      exit 1
    fi
    echo "nginx: configuration file test is successful"
    ;;
  -T)
    if [ "${LRT_BIG_FAIL:-0}" = 1 ]; then exit 1; fi
    for f in $LRT_FILES; do
      [ -f "$f" ] || continue
      echo "# configuration file $f:"
      cat "$f"
    done
    if [ "${LRT_NO_INCLUDE:-0}" != 1 ] && [ -f "$LRT_DEST" ]; then
      echo "# configuration file $LRT_DEST:"
      cat "$LRT_DEST"
    fi
    ;;
esac
exit 0
STUB
cat > "$LR/bin/systemctl" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$LR/bin/nginx" "$LR/bin/systemctl"

# A site conf that rate limits, and a server nginx.conf that binds zones.
cat > "$LR/available/paramant-public.conf" <<'CONF'
server {
    server_name paramant.app;
    location = /v1/paraid/issue-document { deny all; }
    location ~ ^/v2/inbound {
        limit_req zone=relay_inbound burst=20 nodelay;
    }
    location ~ ^/v2/outbound {
        limit_req zone=relay_outbound burst=10 nodelay;
    }
}
CONF
cat > "$LR/available/paramant-live.conf" <<'CONF'
server {
    location /api/user/ {
        limit_req        zone=relay_auth burst=5 nodelay;
    }
    location /v2/ {
        limit_req        zone=api burst=10 nodelay;
    }
}
CONF
ln -sfn "$LR/available/paramant-public.conf" "$LR/sites/paramant-public.conf"
ln -sfn "$LR/available/paramant-live.conf"   "$LR/sites/paramant-live.conf"
LR_SLOTS="paramant-public.conf paramant-live.conf"

# The server config in three shapes: binds nothing, binds everything (which is
# production today), binds one of the five.
printf 'http {\n    server_tokens off;\n}\n' > "$LR/etc/nginx-none.conf"
{
  echo 'http {'
  sed -nE 's/^[[:space:]]*(limit_req_zone.*)$/    \1/p' "$SNIPPET"
  echo '}'
} > "$LR/etc/nginx-all.conf"
{
  echo 'http {'
  echo '    limit_req_zone $binary_remote_addr zone=relay_auth:10m rate=10r/m;'
  echo '}'
} > "$LR/etc/nginx-one.conf"

extract_remote "limit_req zones" > "$LR/5d.sh"
if [ -s "$LR/5d.sh" ]; then
  pass "the 5d remote block could be extracted from the script"
else
  fail "could not extract the 5d remote block from the script"
fi
# The extraction has to be the block and nothing else: the call is one line on
# purpose, because sed '1d' would otherwise leave half a continuation line of
# shell in front of the body.
# remote_nginx prepends the resolver, so the extract is resolver + body. What
# may NOT be in there is a stray line of the CALL: extract_remote drops one
# line, so a call spread over two lines would leave its continuation, an
# argument list, sitting in front of the body as shell to execute.
if [ "$(grep -cE '^set -euo pipefail$' "$LR/5d.sh")" = "1" ]; then
  pass "the extracted 5d block carries exactly one strict-mode line"
else
  fail "the extracted 5d block has $(grep -cE '^set -euo pipefail$' "$LR/5d.sh") strict-mode lines"
fi
if grep -qE '^[[:space:]]+"\$[A-Z_]+"' "$LR/5d.sh"; then
  fail "the 5d extract carries a leftover argument line, so the call spans more than one line"
  grep -nE '^[[:space:]]+"\$[A-Z_]+"' "$LR/5d.sh" | head -3 | sed 's/^/        /'
else
  pass "no leftover argument line in the 5d extract, so the whole call fits one line"
fi

run_5d() {   # server-conf, ts, [extra env assignments...]
  local conf="$1" ts="$2"; shift 2
  ( cd "$LR" && PATH="$LR/bin:$PATH" LRT_FILES="$conf $LR/available/paramant-public.conf $LR/available/paramant-live.conf" \
      LRT_DEST="$LR_DEST" env "$@" bash "$LR/5d.sh" "$LR/co" "$ts" "$LR/bk" "$LR_DEST" "$LR/sites" "$LR_SLOTS" </dev/null 2>&1 )
}
# zones bound exactly once across everything nginx would load
bound_once() {   # server-conf
  local dup
  dup="$(zones_defined "$1" "$LR_DEST" 2>/dev/null | sort | uniq -d)"
  [ -z "$dup" ]
}
# a name counted across the server conf and the placed file together
bound_total() { zones_defined "$1" "$LR_DEST" 2>/dev/null | wc -l | tr -d ' '; }

echo ""
echo "6o-1. A server that binds none of the zones: the snippet supplies all five"
rm -f "$LR_DEST"
OUTA="$(run_5d "$LR/etc/nginx-none.conf" 20260101-0000 LRT_X=1)"; RCA=$?
if [ "$RCA" -eq 0 ]; then pass "5d exits 0 on a server that binds no zone"; else
  fail "5d exits $RCA on a server that binds no zone"
  printf '%s\n' "$OUTA" | sed 's/^/        /' | head -20
fi
for want in "before duplicate zones:0" "after zone lines left elsewhere:0" \
            "after snippet loaded:yes" "after zones referenced and undefined:0" \
            "before dest existed:no" "after snippet changed:yes"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUTA" "$f")" = "$v" ]; then pass "5d reports $f = $v"; else
    fail "5d reports $f = '$(field_5c "$OUTA" "$f")', expected $v"; fi
done
SNIP_N="$(printf '%s\n' "$SNIP_DEF" | grep -c . || true)"
if [ "$(field_5c "$OUTA" 'after zone lines written')" = "$SNIP_N" ]; then
  pass "all $SNIP_N zone(s) of the snippet were written"
else
  fail "5d wrote $(field_5c "$OUTA" 'after zone lines written') zone line(s), expected $SNIP_N"
fi
if [ -f "$LR_DEST" ]; then pass "the snippet really landed on the server"; else
  fail "5d reported success but wrote no file"; fi
if [ "$(zones_defined "$LR_DEST" | wc -l | tr -d ' ')" = "$SNIP_N" ]; then
  pass "the placed file defines the same $SNIP_N zone(s) as the tracked snippet"
else
  fail "the placed file defines $(zones_defined "$LR_DEST" | wc -l | tr -d ' ') zone(s), the snippet has $SNIP_N"
fi
if printf '%s\n' "$OUTA" | grep -q 'reloaded nginx for the limit_req snippet'; then
  pass "5d reloads nginx after placing the snippet"
else
  fail "5d never reloaded nginx"
fi
if bound_once "$LR/etc/nginx-none.conf"; then
  pass "no zone is bound twice across the server config and the placed file"
else
  fail "a zone is bound twice: $(zones_defined "$LR/etc/nginx-none.conf" "$LR_DEST" | sort | uniq -d | tr '\n' ' ')"
fi

echo ""
echo "6o-2. Run it again with the file already there: the snippet is not its own duplicate"
# The dump nginx -T returns now INCLUDES the file 5d placed a moment ago. Read
# that naively and every zone reads as "already bound elsewhere", so the second
# deploy would comment out all five lines and delete the zones it just created.
OUTB="$(run_5d "$LR/etc/nginx-none.conf" 20260101-0001 LRT_X=1)"; RCB=$?
if [ "$RCB" -eq 0 ]; then pass "a second 5d over the same state exits 0"; else
  fail "a second 5d exits $RCB"
  printf '%s\n' "$OUTB" | sed 's/^/        /' | head -20
fi
if printf '%s\n' "$OUTB" | grep -q FATAL; then
  fail "a second 5d prints FATAL"
  printf '%s\n' "$OUTB" | grep FATAL | sed 's/^/        /'
else
  pass "a second 5d prints no FATAL"
fi
for want in "before duplicate zones:0" "after zone lines left elsewhere:0" \
            "before dest existed:yes" "after snippet changed:no"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUTB" "$f")" = "$v" ]; then pass "second run reports $f = $v"; else
    fail "second run reports $f = '$(field_5c "$OUTB" "$f")', expected $v"; fi
done
if [ "$(field_5c "$OUTB" 'after zone lines written')" = "$SNIP_N" ]; then
  pass "the second run keeps all $SNIP_N zone(s), it does not comment out its own file"
else
  fail "the second run left $(field_5c "$OUTB" 'after zone lines written') zone line(s) of $SNIP_N"
fi
if [ "$(field_5c "$OUTB" 'after snippet backup bytes')" -gt 0 ] 2>/dev/null; then
  pass "the second run backed the existing file up before writing"
else
  fail "the second run wrote over the existing file with no backup"
fi
if [ -f "$LR/bk/paramant-limit-req.conf.pre-3.1-20260101-0001" ]; then
  pass "the backup is filed under the run TS, the way 2b files the site confs"
else
  fail "no backup at bk/paramant-limit-req.conf.pre-3.1-20260101-0001"
fi

echo ""
echo "6o-3. The server already binds every zone: the deploy binds none of them again"
# This is production as it stands: all five names are in the server's own
# nginx.conf. Writing them a second time is an nginx that does not start.
rm -f "$LR_DEST"
OUTC="$(run_5d "$LR/etc/nginx-all.conf" 20260101-0002 LRT_X=1)"; RCC=$?
if [ "$RCC" -eq 0 ]; then pass "5d exits 0 when every zone is already bound"; else
  fail "5d exits $RCC when every zone is already bound"
  printf '%s\n' "$OUTC" | sed 's/^/        /' | head -20
fi
for want in "after zone lines written:0" "after snippet loaded:yes" \
            "after zones referenced and undefined:0"; do
  f="${want%%:*}"; v="${want##*:}"
  if [ "$(field_5c "$OUTC" "$f")" = "$v" ]; then pass "5d reports $f = $v"; else
    fail "5d reports $f = '$(field_5c "$OUTC" "$f")', expected $v"; fi
done
if [ "$(field_5c "$OUTC" 'before duplicate zones')" = "$SNIP_N" ] \
   && [ "$(field_5c "$OUTC" 'after zone lines left elsewhere')" = "$SNIP_N" ]; then
  pass "all $SNIP_N zone(s) were recognised as already bound and left where they are"
else
  fail "5d saw $(field_5c "$OUTC" 'before duplicate zones') duplicate(s) and commented out $(field_5c "$OUTC" 'after zone lines left elsewhere')"
fi
if [ "$(zones_defined "$LR_DEST" | wc -l | tr -d ' ')" = "0" ]; then
  pass "the placed file defines no zone at all, so nothing is bound twice"
else
  fail "the placed file still defines $(zones_defined "$LR_DEST" | wc -l | tr -d ' ') zone(s) the server already binds"
fi
if [ "$(bound_total "$LR/etc/nginx-all.conf")" = "$SNIP_N" ] && bound_once "$LR/etc/nginx-all.conf"; then
  pass "every zone is bound exactly once across the server config and the placed file"
else
  fail "the zones are bound $(bound_total "$LR/etc/nginx-all.conf") time(s) in total, expected $SNIP_N"
fi
if grep -qE '^# zone [A-Za-z0-9_]+ is already bound' "$LR_DEST"; then
  pass "the placed file says in writing which zone it left to the other config"
else
  fail "the placed file drops the duplicate lines without saying so"
fi

echo ""
echo "6o-4. The server binds one of the five: the other four come from the snippet"
rm -f "$LR_DEST"
OUTD="$(run_5d "$LR/etc/nginx-one.conf" 20260101-0003 LRT_X=1)"; RCD=$?
if [ "$RCD" -eq 0 ]; then pass "5d exits 0 on a partly bound server"; else
  fail "5d exits $RCD on a partly bound server"
  printf '%s\n' "$OUTD" | sed 's/^/        /' | head -20
fi
if [ "$(field_5c "$OUTD" 'before duplicate zones')" = "1" ] \
   && [ "$(field_5c "$OUTD" 'after zone lines written')" = "$((SNIP_N - 1))" ] \
   && [ "$(field_5c "$OUTD" 'after zone lines left elsewhere')" = "1" ]; then
  pass "one zone left where it was, $((SNIP_N - 1)) written from the snippet"
else
  fail "5d wrote $(field_5c "$OUTD" 'after zone lines written') and left $(field_5c "$OUTD" 'after zone lines left elsewhere'), expected $((SNIP_N - 1)) and 1"
fi
if [ "$(field_5c "$OUTD" 'before duplicate zone names')" = "relay_auth" ]; then
  pass "5d names the zone it left alone (relay_auth)"
else
  fail "5d named '$(field_5c "$OUTD" 'before duplicate zone names')' as the already bound zone"
fi
if [ "$(bound_total "$LR/etc/nginx-one.conf")" = "$SNIP_N" ] && bound_once "$LR/etc/nginx-one.conf"; then
  pass "still exactly one binding per zone, and all $SNIP_N of them exist"
else
  fail "$(bound_total "$LR/etc/nginx-one.conf") binding(s) across the two files, expected $SNIP_N with no duplicate"
fi
FIX_REF="$(zones_referenced "$LR/available/paramant-public.conf" "$LR/available/paramant-live.conf" | wc -l | tr -d ' ')"
if [ "$(field_5c "$OUTD" 'after zones referenced')" = "$FIX_REF" ]; then
  pass "5d counted every zone the site confs reference ($FIX_REF)"
else
  fail "5d counted $(field_5c "$OUTD" 'after zones referenced') referenced zone(s), expected $FIX_REF"
fi

echo ""
echo "6o-5. A destination nginx never reads is a FATAL, not a silent no-op"
# The file can be written, chmodded and still define nothing, because the
# directory it sits in is not included anywhere. nginx -t passes either way,
# so only the dump can tell the difference.
rm -f "$LR_DEST"
OUTE="$(run_5d "$LR/etc/nginx-none.conf" 20260101-0004 LRT_NO_INCLUDE=1)"; RCE=$?
if [ "$RCE" -ne 0 ]; then pass "5d exits non-zero when nginx does not load the file it wrote"; else
  fail "5d exited 0 while nginx never loaded the snippet"; fi
if printf '%s\n' "$OUTE" | grep -q 'after snippet loaded = no'; then
  pass "5d says the snippet was not loaded"
else
  fail "5d never reported that the snippet was not loaded"
fi
if printf '%s\n' "$OUTE" | grep -q 'PARAMANT_LIMIT_REQ_DEST'; then
  pass "the FATAL names the override that fixes it"
else
  fail "the FATAL does not say how to point the snippet somewhere nginx reads"
fi
if [ ! -f "$LR_DEST" ]; then
  pass "the file it wrote is gone again, so a failed 5d leaves no orphan in conf.d"
else
  fail "5d left $LR_DEST behind after failing"
fi

echo ""
echo "6o-6. nginx -t failing puts the previous file back, byte for byte"
rm -f "$LR_DEST"
printf '# an older snippet\nlimit_req_zone $binary_remote_addr zone=leftover:1m rate=1r/m;\n' > "$LR_DEST"
cp "$LR_DEST" "$LR/etc/expected-restore.conf"
OUTF="$(run_5d "$LR/etc/nginx-none.conf" 20260101-0005 LRT_T_FAIL=1)"; RCF=$?
if [ "$RCF" -ne 0 ]; then pass "5d exits non-zero when nginx -t rejects the config"; else
  fail "5d exited 0 after nginx -t failed"; fi
if printf '%s\n' "$OUTF" | grep -q 'FATAL nginx -t failed'; then
  pass "5d says nginx -t was what failed"
else
  fail "5d did not report the nginx -t failure"
fi
if cmp -s "$LR_DEST" "$LR/etc/expected-restore.conf"; then
  pass "the file that was there before the phase is back, unchanged"
else
  fail "5d left a rewritten file behind after nginx -t failed"
fi

echo ""
echo "6o-7. A zone the site confs use that nothing binds is a stop"
# The bug this catches: relay_auth deleted from the server's nginx.conf while
# /api/user/ still rate limits on it. nginx would refuse the config, but the
# deploy should say which zone and why, not leave that to a config test.
rm -f "$LR_DEST"
cat > "$LR/available/paramant-live.conf" <<'CONF'
server {
    location /api/user/ {
        limit_req        zone=nowhere_at_all burst=5 nodelay;
    }
}
CONF
OUTG="$(run_5d "$LR/etc/nginx-none.conf" 20260101-0006 LRT_X=1)"; RCG=$?
if [ "$RCG" -ne 0 ]; then pass "5d exits non-zero on a zone nothing binds"; else
  fail "5d exited 0 while a location rate limits on a zone that does not exist"; fi
if printf '%s\n' "$OUTG" | grep -q 'nowhere_at_all'; then
  pass "the FATAL names the zone that is missing"
else
  fail "the FATAL does not name the missing zone"
fi
if [ ! -f "$LR_DEST" ]; then
  pass "that failure rolls the snippet back too"
else
  fail "5d left the snippet in place after the referenced-zone check failed"
fi

echo ""
echo "6o-8. A checkout without the snippet stops before anything is written"
rm -f "$LR_DEST" "$LR/co/deploy/nginx/snippets/paramant-limit-req.conf"
OUTH="$(run_5d "$LR/etc/nginx-none.conf" 20260101-0007 LRT_X=1)"; RCH=$?
if [ "$RCH" -ne 0 ]; then pass "5d exits non-zero when the tracked snippet is not in the checkout"; else
  fail "5d exited 0 with no snippet to place"; fi
if [ ! -f "$LR_DEST" ]; then pass "and it wrote nothing"; else
  fail "5d wrote a file anyway"; fi
cp "$SNIPPET" "$LR/co/deploy/nginx/snippets/paramant-limit-req.conf"

# ------------------------------------ 6p. the deep-health verdict is judged --
#
# Step 6c printed "deep overall = red" and reported OK twice, on every run from
# 2026-09-03 02:59 to 2026-09-05 17:48, because it asserted the two HTTP status
# codes and never looked at the body. The codes are about the auth gate in
# front of the route; the route answers 200 whatever it thinks of the relay.
#
# Two things are tested here, and both need to be, because they fail in
# different places: the remote block has to EXPRESS the verdict and name what
# is not green, and expect_verdict has to JUDGE it.
echo ""
echo "6p. The deep-health verdict is expressed and judged"

DH="$WORK/deephealth"
mkdir -p "$DH"

# --- 6p-1. the remote block turns a body into lines a human can act on -------
# The python that parses the response, lifted out of the 6c heredoc exactly as
# the server runs it. Everything between the -c quote and the closing quote.
sed -n "/^  remote \"deep health\"/,/^EOF\$/p" "$SCRIPT" \
  | sed -n "/| python3 -c '/,/^' 2>\/dev\/null/p" | sed '1d;$d' > "$DH/parse.py"
if [ -s "$DH/parse.py" ]; then
  pass "the deep-health parser could be extracted from the 6c block"
else
  fail "could not extract the deep-health parser from the 6c block"
fi

cat > "$DH/red.json" <<'JSON'
{"overall":"red","version":"3.1.0","sector":"main","checks":[
 {"name":"relay","status":"green","detail":"relay 3.1.0 (main) up"},
 {"name":"storage","status":"red","detail":"not writable (/app): EROFS"},
 {"name":"tls","status":"yellow","detail":"TLS terminated at the edge (not on this relay)"}]}
JSON
cat > "$DH/green.json" <<'JSON'
{"overall":"green","version":"3.1.0","sector":"main","checks":[
 {"name":"relay","status":"green","detail":"relay 3.1.0 (main) up"},
 {"name":"storage","status":"green","detail":"data dir writable (/data)"}]}
JSON

PARSED_RED="$(python3 "$DH/parse.py" < "$DH/red.json" 2>&1 || true)"
if printf '%s\n' "$PARSED_RED" | grep -q '^deep overall = red$'; then
  pass "the parser prints the verdict"
else
  fail "the parser did not print 'deep overall = red'"
  printf '%s\n' "$PARSED_RED" | sed 's/^/        /'
fi
if printf '%s\n' "$PARSED_RED" | grep -q '^deep component storage = red -- not writable (/app): EROFS$'; then
  pass "the parser names the red component, its state and its detail"
else
  fail "the parser did not name the red component; the verdict would be a colour with no reason"
  printf '%s\n' "$PARSED_RED" | sed 's/^/        /'
fi
if printf '%s\n' "$PARSED_RED" | grep -q '^deep component tls = yellow -- '; then
  pass "and the yellow one too, not only the red"
else
  fail "the parser skipped the yellow component"
fi
if printf '%s\n' "$PARSED_RED" | grep -q '^deep not-green = 2$'; then
  pass "the parser counts the components that are not green"
else
  fail "the parser did not print 'deep not-green = 2'"
fi
PARSED_GREEN="$(python3 "$DH/parse.py" < "$DH/green.json" 2>&1 || true)"
if printf '%s\n' "$PARSED_GREEN" | grep -q '^deep not-green = 0$' \
   && ! printf '%s\n' "$PARSED_GREEN" | grep -q '^deep component '; then
  pass "an all-green body produces no component lines"
else
  fail "the parser invented a component line for an all-green body"
  printf '%s\n' "$PARSED_GREEN" | sed 's/^/        /'
fi

# --- 6p-2. expect_verdict judges what the block printed ---------------------
# Driven the way section 6n drives remote_nginx: the real function out of the
# script, a synthetic REMOTE_OUT, and a look at what the caller can see. die()
# is the script's own, so a stop is a non-zero exit and a STOP line.
cat > "$DH/harness.sh" <<'HARNESS'
set -uo pipefail
SCRIPT="$1"; VERDICT_OUT="$2"
DRY_RUN=0
WARNINGS=0
SUMMARY=""
LOG="/dev/null"
eval "$(sed -n '/^ok()    {/,/^  OK    \$\*"; }$/p' "$SCRIPT")"
eval "$(sed -n '/^warn()  {/,/^  WARN  \$\*"; }$/p' "$SCRIPT")"
eval "$(sed -n '/^die()   {/,/^          exit 1; }$/p' "$SCRIPT")"
eval "$(grep '^remote_field() {' "$SCRIPT")"
eval "$(sed -n '/^expect_verdict() {/,/^}$/p' "$SCRIPT")"
REMOTE_OUT="$VERDICT_OUT"
expect_verdict "deep overall" "deep component" "the deep-health verdict"
echo "SURVIVED warnings=$WARNINGS"
HARNESS

# Not a command substitution. A $( ) puts the call in a subshell, and then
# RV_RC is set in a child that exits, which is the run-4 bug section 6n exists
# for. The output goes to a file and the exit code stays in this shell.
RV_RC=0
run_verdict() {   # remote-output text -> $DH/out.txt, RV_RC
  RV_RC=0
  bash "$DH/harness.sh" "$SCRIPT" "$1" > "$DH/out.txt" 2>&1 || RV_RC=$?
}

RED_OUT="deep noauth code = 401
deep auth code = 200
deep overall = red
deep not-green = 1
deep component storage = red -- not writable (/app): EROFS"

YELLOW_OUT="deep overall = yellow
deep not-green = 1
deep component tls = yellow -- TLS terminated at the edge (not on this relay)"

GREEN_OUT="deep overall = green
deep not-green = 0"

run_verdict "$RED_OUT"; V="$(cat "$DH/out.txt")"
if [ "$RV_RC" -ne 0 ] && printf '%s\n' "$V" | grep -q 'STOP'; then
  pass "a red verdict stops the run"
else
  fail "a red verdict did not stop the run (exit $RV_RC)"
  printf '%s\n' "$V" | sed 's/^/        /'
fi
if printf '%s\n' "$V" | grep -q 'not green: deep component storage = red -- not writable (/app): EROFS'; then
  pass "and the stop names the component that is red"
else
  fail "the stop did not name the red component"
  printf '%s\n' "$V" | sed 's/^/        /'
fi
if printf '%s\n' "$V" | grep -q 'SURVIVED'; then
  fail "the run continued past a red verdict"
else
  pass "nothing after the red verdict ran"
fi

run_verdict "$GREEN_OUT"; V="$(cat "$DH/out.txt")"
if [ "$RV_RC" -eq 0 ] && printf '%s\n' "$V" | grep -q '^  OK    .*green' \
   && printf '%s\n' "$V" | grep -q 'SURVIVED warnings=0'; then
  pass "a green verdict passes, without a warning"
else
  fail "a green verdict did not pass cleanly (exit $RV_RC)"
  printf '%s\n' "$V" | sed 's/^/        /'
fi

run_verdict "$YELLOW_OUT"; V="$(cat "$DH/out.txt")"
if [ "$RV_RC" -eq 0 ] && printf '%s\n' "$V" | grep -q 'SURVIVED warnings=1' \
   && printf '%s\n' "$V" | grep -q '^  WARN  '; then
  pass "a yellow verdict warns and lets the run continue"
else
  fail "a yellow verdict was not a warning (exit $RV_RC)"
  printf '%s\n' "$V" | sed 's/^/        /'
fi
if printf '%s\n' "$V" | grep -q 'not green: deep component tls = yellow'; then
  pass "and the warning names the yellow component"
else
  fail "the warning did not name the yellow component"
fi

run_verdict "deep noauth code = 401
deep auth code = 200"; V="$(cat "$DH/out.txt")"
if [ "$RV_RC" -ne 0 ] && printf '%s\n' "$V" | grep -q 'never printed'; then
  pass "a missing verdict stops the run"
else
  fail "a missing verdict was waved through (exit $RV_RC)"
  printf '%s\n' "$V" | sed 's/^/        /'
fi

run_verdict "deep overall = unparseable"; V="$(cat "$DH/out.txt")"
if [ "$RV_RC" -ne 0 ]; then
  pass "an unparseable body stops the run, because an unreadable verdict is not a pass"
else
  fail "'unparseable' was read as a pass (exit $RV_RC)"
  printf '%s\n' "$V" | sed 's/^/        /'
fi

# --- 6p-3. negative control -------------------------------------------------
# The old 6c, spelled out: the two status-code assertions and nothing else,
# against the same red output. It has to pass, otherwise the checks above are
# not proving that anything changed.
cat > "$DH/old.sh" <<'OLD'
set -uo pipefail
SCRIPT="$1"; VERDICT_OUT="$2"
DRY_RUN=0
SUMMARY=""
LOG="/dev/null"
eval "$(sed -n '/^ok()    {/,/^  OK    \$\*"; }$/p' "$SCRIPT")"
eval "$(sed -n '/^die()   {/,/^          exit 1; }$/p' "$SCRIPT")"
eval "$(grep '^remote_field() {' "$SCRIPT")"
eval "$(sed -n '/^expect_count() {/,/^}$/p' "$SCRIPT")"
REMOTE_OUT="$VERDICT_OUT"
expect_count "deep noauth code" 401 "/v2/health/deep is 401 without X-Internal-Auth"
expect_count "deep auth code" 200 "/v2/health/deep is 200 with X-Internal-Auth"
echo "SURVIVED"
OLD
OLDRC=0
bash "$DH/old.sh" "$SCRIPT" "$RED_OUT" > "$DH/old-out.txt" 2>&1 || OLDRC=$?
OLDV="$(cat "$DH/old-out.txt")"
if [ "$OLDRC" -eq 0 ] && printf '%s\n' "$OLDV" | grep -q 'SURVIVED' \
   && [ "$(printf '%s\n' "$OLDV" | grep -c '^  OK    ')" -eq 2 ]; then
  pass "negative control: the status-code assertions alone really do report OK twice on a red relay"
else
  fail "the negative control no longer reproduces the bug, so the checks above prove nothing"
  printf '%s\n' "$OLDV" | sed 's/^/        /'
fi

# --- 6p-4. and 6c must keep calling it --------------------------------------
DEEP_BLOCK="$(sed -n '/step "6c\./,/step "6d\./p' "$SCRIPT")"
if printf '%s\n' "$DEEP_BLOCK" | grep -q 'expect_verdict "deep overall"'; then
  pass "step 6c judges the verdict, not only the two status codes"
else
  fail "step 6c no longer judges the deep-health verdict"
fi
if printf '%s\n' "$DEEP_BLOCK" | grep -q 'deep component %s = %s'; then
  pass "step 6c still prints the components that are not green"
else
  fail "step 6c stopped printing the components behind the verdict"
fi

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
