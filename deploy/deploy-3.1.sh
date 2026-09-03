#!/usr/bin/env bash
#
# deploy-3.1.sh - execute deploy/DEPLOY-3.1.md end to end, from the NUC.
#
# The runbook stays the readable source: every phase below names the runbook
# step it performs, and every assertion is a sentence the runbook already
# writes down. This script adds nothing to the plan, it only refuses to
# continue when a measurement disagrees with it.
#
# Usage:
#   bash deploy/deploy-3.1.sh                  full deploy, phases 0 to 7
#   bash deploy/deploy-3.1.sh --preflight-only phases 0 and 1, read-only
#   bash deploy/deploy-3.1.sh --rollback <TS>  phase 8, back to the <TS> backup
#   bash deploy/deploy-3.1.sh --verify-only    phases 6 and 7 only, on a server
#                                              that is already deployed
#   bash deploy/deploy-3.1.sh --dry-run        print every remote and gated
#                                              command instead of running it
#
# Flags combine with --dry-run: --dry-run --preflight-only, --dry-run
# --rollback <TS>, --dry-run --verify-only. The three run modes are mutually
# exclusive.
#
# --verify-only exists for a deploy that did its work and then died in the
# checks. It gates on the server already being deployed (checkout on
# origin/main, /health reporting the version that checkout describes) and then
# runs phases 6 and 7 and nothing else: no tags, no backups, no pull, no build,
# no recreate, no nginx edit, no .env write.
#
# The commit the production checkout must be on before phase 3 moves it is a
# parameter, not a constant. PARAMANT_EXPECTED_HEAD=<commit> wins; without it
# the script reads the deployed-head marker phase 7 wrote on the server; with
# no marker either it falls back to the runbook's starting commit. So a second
# deploy, and a resume of a failed one, no longer stop on the first gate.
#
# Secrets: this script never prints a key value. Environment variables are
# reported as "empty" or "set, prefix <first 5 chars>", which is the shape the
# runbook's own step 1 uses. No remote block runs under set -x, and no read of
# .env is ever written to stdout.
#
# Everything the script prints also lands in deploy/logs/deploy-3.1-<TS>.log.

set -euo pipefail

# ---------------------------------------------------------------- constants --

PROD_HOST="${PARAMANT_PROD_HOST:-root@116.203.86.81}"
PROD_KEY="${PARAMANT_PROD_KEY:-$HOME/.ssh/paramant_prod_claude}"
COMPOSE_DIR="${PARAMANT_COMPOSE_DIR:-/opt/paramant-relay}"
DOCROOT="${PARAMANT_DOCROOT:-/home/paramant/app}"
BACKUP_DIR="${PARAMANT_BACKUP_DIR:-/home/paramant/backups}"
NGINX_BACKUP_DIR=/etc/nginx/backups
NGINX_SITES=/etc/nginx/sites-enabled

# The two server confs the runbook names. Phase 5 edits these and nothing else:
# a wildcard loop over sites-enabled would silently rewrite a conf nobody
# reviewed.
#
# The names are not the same on every machine. The run of 03-09 stopped in
# phase 2b because production carries paramant-public.conf but no
# paramant-live.conf: the backend conf there is called paramant.conf. So a slot
# is a LIST of candidates separated by "|", and the server takes the first
# candidate that is really in sites-enabled. Slots are separated by whitespace,
# exactly as before, and PARAMANT_NGINX_CONFS still overrides the whole thing.
#
#   paramant-public.conf              slot 1, one candidate
#   paramant-live.conf|paramant.conf  slot 2, live first, paramant.conf next
#
# paramant.conf is an assumption, drawn from deploy/signup-fix-deploy.sh, which
# edits /etc/nginx/sites-enabled/paramant.conf on this same server. The script
# does not trust it: it looks on the server, logs the name it resolved to, and
# stops when a slot has no candidate at all.
NGINX_CONF_SLOTS="${PARAMANT_NGINX_CONFS:-paramant-public.conf paramant-live.conf|paramant.conf}"
NGINX_SLOT_COUNT="$(printf '%s' "$NGINX_CONF_SLOTS" | wc -w | tr -d ' ')"

# Present on the server by design, absent from the repo. Same list as
# scripts/check-prod-drift.sh: these are never pruned from the docroot.
DOCROOT_IGNORE="dist paramant-mark.svg developer.js docs/paramant-investor-brief.html"

DEPLOY_REF="${DEPLOY_REF:-origin/main}"

# Where the production checkout has to stand before phase 3 moves it.
#
# 41501bb is where the RUNBOOK starts: the stand of 08-08, before any 3.1
# deploy ran. Hard-coding it as the only acceptable answer made the script
# single-use: after the first successful deploy the checkout is on main, phase
# 1a stops on "expected 41501bb", and the same script can never be run again,
# not even to resume a deploy that failed halfway through phase 5.
#
# So the expected commit is a parameter with three sources, most specific first:
#
#   1. PARAMANT_EXPECTED_HEAD, if set. An explicit answer from whoever is
#      running the deploy, for the case where they know what the checkout is
#      on and why. Hard equality, no ancestor test.
#   2. the deployed-head marker, if the server has one. Phase 7 writes the
#      commit it left the checkout on into $BACKUP_DIR/deployed-head. Phase 1a
#      of the NEXT run reads it back and demands two things: the checkout is
#      still on that commit (nothing moved it outside a deploy), AND that
#      commit is an ancestor of the deploy ref (so phase 3a's --ff-only pull
#      can actually reach the ref from here).
#   3. EXPECT_PROD_COMMIT. No marker means no deploy has ever recorded one, so
#      this is the first run and the runbook's own starting point applies.
#
# A rollback (phase 8) deliberately does NOT rewrite the marker: it restores
# images, .env, nginx and the docroot, and leaves the checkout where it is. The
# marker names the checkout, so it stays true.
EXPECT_PROD_COMMIT="${EXPECT_PROD_COMMIT:-41501bb}"   # runbook: where we start
EXPECTED_HEAD="${PARAMANT_EXPECTED_HEAD:-}"           # explicit override, wins
DEPLOYED_HEAD_FILE="${PARAMANT_DEPLOYED_HEAD_FILE:-$BACKUP_DIR/deployed-head}"
EXPECT_VERSION="3.1.0"
SERVICES="relay-main relay-health relay-finance relay-legal relay-iot admin"
HOSTS="paramant.app health.paramant.app legal.paramant.app finance.paramant.app iot.paramant.app relay.paramant.app"

# The CI gate on main (runbook: "Before you start", point 1).
#
# One verdict per required workflow, not "the last 5 runs on main". That older
# gate mixed workflows in one window and read a red run of ANY of them as a
# stop: on 2026-09-02 --preflight-only stopped on a red `heartbeat` run, which
# is the hourly alarm saying its two canary secrets are absent. That is a
# statement about the alarm, not about whether main deploys.
#
# The list below is every workflow in .github/workflows that runs on a push to
# main WITHOUT a paths: filter. tests/deploy-3.1-dryrun.test.sh derives the same
# list from the workflow files and fails when the two disagree, so a new
# push-gated workflow cannot quietly stay outside the gate.
#
# Deliberately NOT in the list:
#   heartbeat.yml       does not run on push at all (schedule + workflow_dispatch)
#                       and is gated on vars.HEARTBEAT_ENABLED. It is red on
#                       purpose while the two canary secrets are missing, by its
#                       own design: "there is no skip, a missing secret fails and
#                       names the secret". Gating a deploy on it would mean no
#                       deploy can happen until the alarm has its secrets.
#   docker-publish.yml  path-gated on relay/**, so a main commit that touches
#                       only the frontend produces no run at all, and a hard
#                       "must be success" would block every such deploy. This
#                       runbook also does not deploy that published image:
#                       phase 4 recreates from the server's own checkout.
#   build-image.yml     path-gated on relay/** for the same reason. It is a
#                       toolchain-drift gate for pull requests, not a
#                       main-is-deployable gate.
#   security-posture.yml  runs on pull requests, schedule and workflow_dispatch,
#                       never on a push to main, and its live job is gated on
#                       vars.SECURITY_POSTURE_ENABLED. Its last completed run on
#                       main is the nightly external scan, which is red on
#                       purpose: today that is a missing CAA record, an unsigned
#                       zone, a duplicated HSTS header from a layer above the
#                       repo, and one Rust advisory carrying no severity in any
#                       database, which a human has to rule on. Every one of
#                       those is a statement about the DNS zone or the server,
#                       not about whether main deploys. Same reasoning as
#                       heartbeat.yml, one row up.
REQUIRED_WORKFLOWS="${PARAMANT_REQUIRED_WORKFLOWS:-test.yml csp-inline-check.yml sign-e2e.yml product-heartbeat.yml}"

# A required workflow still in_progress or queued on the sha we would deploy is
# neither a pass nor a failure: it is an answer that has not arrived. The old
# gate only looked for the literal string "failure", so two in_progress runs on
# 2026-09-02 counted as "not failing" and the gate waved them through. Wait for
# them instead, then judge what they became.
CI_WAIT_SECONDS="${PARAMANT_CI_WAIT_SECONDS:-900}"   # 15 minutes

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SSH_OPTS=(-i "$PROD_KEY" -o BatchMode=yes -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
SSH_SHOWN="ssh -i <prod-key> -o BatchMode=yes -o IdentitiesOnly=yes $PROD_HOST"

DRY_RUN=0
PREFLIGHT_ONLY=0
VERIFY_ONLY=0
ROLLBACK_TS=""
REMOTE_OUT=""
REMOTE_RC=0
PREV_HEAD=""
DEPLOYED_HEAD=""
WARNINGS=0
SUMMARY=""

# ------------------------------------------------------------------- output --

hr() { printf '%s\n' "------------------------------------------------------------------------"; }

phase() {
  echo
  hr
  printf 'PHASE %s: %s\n' "$1" "$2"
  printf '  runbook: %s\n' "$3"
  hr
}

step()  { printf '\n[step] %s\n' "$*"; }
ok()    { printf '  OK    %s\n' "$*"; SUMMARY="$SUMMARY
  OK    $*"; }
note()  { printf '  note  %s\n' "$*"; }
warn()  { printf '  WARN  %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); SUMMARY="$SUMMARY
  WARN  $*"; }
die()   { printf '\n  STOP  %s\n' "$*" >&2
          printf '\nThe deploy stopped. Nothing further ran. Log: %s\n' "${LOG:-<none>}" >&2
          exit 1; }

# --------------------------------------------------------------- executables --

# run_gated: a local command that reaches the network or the server, or that is
# slow. Printed, not run, under --dry-run.
GATED_OUT=""
run_gated() {
  printf '\n  $ %s\n' "$*"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] not executed\n'
    GATED_OUT=""
    return 0
  fi
  local rc=0
  GATED_OUT="$("$@" 2>&1)" || rc=$?
  printf '%s\n' "$GATED_OUT" | sed 's/^/  | /'
  return $rc
}

# ci_running_ids: the run ids of <workflow> on main that have not finished on
# <sha>. queued counts as running: it has not even started, so it certainly has
# no conclusion.
ci_running_ids() {   # workflow file, sha
  local st
  for st in in_progress queued; do
    gh run list --workflow "$1" --branch main --status "$st" -L 20 \
      --json databaseId,headSha \
      --jq ".[] | select(.headSha == \"$2\") | .databaseId" 2>/dev/null || true
  done
}

# ci_gate_workflow: the verdict for one required workflow. Returns 0 only when
# nothing of it is still in flight on the sha we would deploy AND its last
# completed run on main concluded success. Everything else, including a
# workflow that has never completed a run on main, returns non-zero.
ci_gate_workflow() {   # workflow file, sha
  local wf="$1" sha="$2" id ids concl

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ gh run list --workflow %s --branch main --status in_progress -L 20 --json databaseId,headSha\n' "$wf"
    printf '  [dry-run] not executed; a run of %s still in flight on the main sha is waited on with gh run watch, up to %ss, and judged afterwards\n' \
      "$wf" "$CI_WAIT_SECONDS"
  else
    ids="$(ci_running_ids "$wf" "$sha" | tr '\n' ' ')"
    for id in $ids; do
      printf '  %-22s run %s is still in flight on %s; waiting up to %ss\n' \
        "$wf" "$id" "$(printf '%s' "$sha" | cut -c1-7)" "$CI_WAIT_SECONDS"
      timeout "$CI_WAIT_SECONDS" gh run watch "$id" >/dev/null 2>&1 || true
    done
    if [ -n "${ids// /}" ]; then
      ids="$(ci_running_ids "$wf" "$sha" | tr '\n' ' ')"
      if [ -n "${ids// /}" ]; then
        printf '  %-22s STILL RUNNING after %ss (run %s)\n' "$wf" "$CI_WAIT_SECONDS" "$ids"
        return 1
      fi
    fi
  fi

  run_gated gh run list --workflow "$wf" --branch main --status completed -L 1 \
    --json conclusion,headSha,displayTitle,url || true
  [ "$DRY_RUN" -eq 1 ] && return 0

  concl="$(gh run list --workflow "$wf" --branch main --status completed -L 1 \
           --json conclusion --jq '.[0].conclusion // "NONE"' 2>/dev/null || echo UNKNOWN)"
  [ -n "$concl" ] || concl=UNKNOWN
  printf '  %-22s last completed run on main: %s\n' "$wf" "$concl"
  [ "$concl" = "success" ]
}

# q_args: shell-quote each argument into one string.
#
# This is load bearing. ssh does NOT preserve argv: it joins everything after
# the host into a single command string and the remote shell splits it again on
# whitespace. So `ssh host 'bash -s' -- "$COMPOSE_DIR" "$SERVICES"` arrives as
# `bash -s -- /opt/paramant-relay relay-main relay-health ...` and the remote
# $2 is "relay-main", not the six names. Every loop over "$2" then ran once.
# printf %q makes each argument survive that second split intact.
q_args() {
  local a out=""
  for a in "$@"; do out="$out $(printf '%q' "$a")"; done
  printf '%s' "$out"
}

# remote: run a heredoc on the server over one ssh call. Arguments after the
# label reach the remote bash as $1, $2, ... with their spaces intact.
# A non-zero exit stops the deploy and prints the output as the diagnosis.
_remote_run() {
  local label="$1"; shift
  local body qargs
  body="$(cat)"
  qargs="$(q_args "$@")"
  printf '\n  $ %s "bash -s --%s"   # %s\n' "$SSH_SHOWN" "$qargs" "$label"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s\n' "$body" | sed 's/^/  [dry-run] > /'
    REMOTE_OUT=""
    REMOTE_RC=0
    return 0
  fi
  REMOTE_RC=0
  REMOTE_OUT="$(printf '%s\n' "$body" | ssh "${SSH_OPTS[@]}" "$PROD_HOST" "bash -s --$qargs" 2>&1)" \
    || REMOTE_RC=$?
  printf '%s\n' "$REMOTE_OUT" | sed 's/^/  | /'
  return 0
}

remote() {
  local label="$1"
  _remote_run "$@"
  if [ "$REMOTE_RC" -ne 0 ]; then
    die "remote step '$label' exited $REMOTE_RC; the server output above is the diagnosis"
  fi
}

# remote_soft: same, but the caller judges the exit code itself.
remote_soft() { _remote_run "$@"; }

# -------------------------------------------- resolving the nginx conf names --
#
# Every remote block that touches an nginx conf needs the same answer: given a
# slot like "paramant-live.conf|paramant.conf", which of those names is really
# in sites-enabled on THIS server? Only the server can answer that, so the
# answer travels with the block. remote_nginx prepends the function below to
# the body, which means the server runs exactly this text, and so does
# tests/deploy-3.1-dryrun.test.sh when it extracts a block.
NGINX_RESOLVE_SNIPPET="$(cat <<'RESOLVER'
# resolve_conf_slots <sites-dir> <slots>: per slot, take the first candidate
# that exists in sites-enabled. Prints one line per slot, either
#   nginxconf <slot> resolved to <name>
# or, when no candidate of that slot is there,
#   nginxconf <slot> ABSENT, none of these is in <dir>: <candidates>
# A slot is named by its first candidate, so the log reads the same whichever
# name the server happens to use. Sets RESOLVED_CONFS to the chosen names in
# slot order and RESOLVED_MISSING to the number of slots that resolved to
# nothing. It never exits: the caller decides what an absent slot means.
resolve_conf_slots() {
  rc_sites="$1"; rc_slots="$2"
  RESOLVED_CONFS=""
  RESOLVED_MISSING=0
  for rc_slot in $rc_slots; do
    rc_chosen=""
    rc_oldifs="$IFS"
    IFS='|'
    for rc_cand in $rc_slot; do
      if [ -e "$rc_sites/$rc_cand" ]; then rc_chosen="$rc_cand"; break; fi
    done
    IFS="$rc_oldifs"
    if [ -z "$rc_chosen" ]; then
      echo "nginxconf ${rc_slot%%|*} ABSENT, none of these is in $rc_sites: $(printf '%s' "$rc_slot" | tr '|' ' ')"
      RESOLVED_MISSING=$((RESOLVED_MISSING + 1))
      continue
    fi
    echo "nginxconf ${rc_slot%%|*} resolved to $rc_chosen"
    RESOLVED_CONFS="${RESOLVED_CONFS:+$RESOLVED_CONFS }$rc_chosen"
  done
}
RESOLVER
)"

# remote_nginx: remote(), with resolve_conf_slots() already defined in the body.
#
# NOT a pipeline. The first version was
#
#   { printf '%s\n' "$NGINX_RESOLVE_SNIPPET"; cat; } | remote "$@"
#
# and every stage of a pipeline is a subshell, so remote() and _remote_run()
# ran in a child: REMOTE_OUT and REMOTE_RC were set there and thrown away when
# it exited. Every expect after a remote_nginx call then judged whatever the
# PREVIOUS remote block had left in REMOTE_OUT. Deploy run 4 (TS 20260903-0216)
# stopped in 2b on "the server never printed 'after .env backup bytes'" while
# the server had printed exactly that, 1420 bytes.
#
# So read the body here and hand remote() its stdin through a redirect. The
# printf runs in a subshell, remote() does not, and the two variables land in
# the caller.
remote_nginx() {
  local body
  body="$(cat)"
  remote "$@" < <(printf '%s\n%s\n' "$NGINX_RESOLVE_SNIPPET" "$body")
}

# expect: assert against the output of the last remote call. Skipped, loudly,
# under --dry-run, because there was no measurement to judge.
expect() {
  local pattern="$1" what="$2"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run): %s   [would match /%s/]\n' "$what" "$pattern"
    return 0
  fi
  if printf '%s\n' "$REMOTE_OUT" | grep -qE -- "$pattern"; then
    ok "$what"
  else
    die "$what -- expected to match /$pattern/ in the server output above"
  fi
}

expect_not() {
  local pattern="$1" what="$2"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run, must NOT match): %s   [/%s/]\n' "$what" "$pattern"
    return 0
  fi
  if printf '%s\n' "$REMOTE_OUT" | grep -qE -- "$pattern"; then
    die "$what -- server output matched /$pattern/, which the runbook forbids"
  fi
  ok "$what"
}

# remote_field: read one "name = value" line out of the last remote output.
remote_field() { printf '%s\n' "$REMOTE_OUT" | sed -n "s/^$1 = //p" | head -1; }

# expect_count: assert a printed measurement equals an exact number.
expect_count() {
  local field="$1" want="$2" what="$3" got
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run): %s   [%s = %s]\n' "$what" "$field" "$want"
    return 0
  fi
  got="$(remote_field "$field")"
  [ -n "$got" ] || die "$what -- the server never printed '$field'"
  [ "$got" = "$want" ] || die "$what -- $field is $got, expected $want"
  ok "$what ($field = $got)"
}

# expect_min: assert a printed measurement is at least N.
expect_min() {
  local field="$1" min="$2" what="$3" got
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run): %s   [%s >= %s]\n' "$what" "$field" "$min"
    return 0
  fi
  got="$(remote_field "$field")"
  [ -n "$got" ] || die "$what -- the server never printed '$field'"
  printf '%s' "$got" | grep -qE '^[0-9]+$' || die "$what -- $field is '$got', not a number"
  [ "$got" -ge "$min" ] || die "$what -- $field is $got, expected at least $min"
  ok "$what ($field = $got)"
}

# ------------------------------------------------ the starting commit gate --

# sha_eq: two git object names are the same commit when one is a prefix of the
# other. The server prints both a short and a full sha, the marker holds a full
# one, and PARAMANT_EXPECTED_HEAD may be either, so a plain [ a = b ] would
# reject a correct answer for being spelled shorter. Fewer than 7 characters is
# not an answer at all and never matches.
sha_eq() {
  local a="$1" b="$2" n
  [ -n "$a" ] && [ -n "$b" ] || return 1
  n=${#a}
  [ ${#b} -lt "$n" ] && n=${#b}
  [ "$n" -ge 7 ] || return 1
  [ "${a:0:$n}" = "${b:0:$n}" ]
}

# head_gate_verdict: is the commit the production checkout stands on an
# acceptable starting point? Pure: it reads no file, opens no connection and
# touches no global, so tests/deploy-3.1-dryrun.test.sh can extract it and put
# every case through it without a server.
#
#   $1 override   PARAMANT_EXPECTED_HEAD, empty when unset
#   $2 marker     what $DEPLOYED_HEAD_FILE holds, "none" when the file is absent
#   $3 head       the sha the production checkout is on (full)
#   $4 fallback   EXPECT_PROD_COMMIT, the runbook's first-deploy commit
#   $5 ancestor   yes | no | unknown: is head an ancestor of the deploy ref
#
# Prints "OK <sentence>" and returns 0, or "STOP <sentence>" and returns 1.
head_gate_verdict() {
  local override="$1" marker="$2" head="$3" fallback="$4" ancestor="$5"
  local short="${head:0:7}"

  if [ -z "$head" ]; then
    printf 'STOP the server never printed the commit its checkout is on\n'
    return 1
  fi

  # 1. An explicit answer wins, and is judged on equality alone. Someone who
  #    sets this has looked at the server; the script does not second-guess it.
  if [ -n "$override" ]; then
    if sha_eq "$head" "$override"; then
      printf 'OK checkout is on %s, which PARAMANT_EXPECTED_HEAD names\n' "$short"
      return 0
    fi
    printf 'STOP checkout is on %s, but PARAMANT_EXPECTED_HEAD names %s\n' "$short" "$override"
    return 1
  fi

  # 2. A marker means a previous run finished phase 7 and wrote down what it
  #    left the checkout on. Both halves have to hold.
  if [ -n "$marker" ] && [ "$marker" != none ]; then
    if ! sha_eq "$head" "$marker"; then
      printf 'STOP checkout is on %s, but the last deploy recorded %s; something moved the checkout outside a deploy, so the rollback images no longer match the source\n' \
        "$short" "${marker:0:7}"
      return 1
    fi
    case "$ancestor" in
      yes) printf 'OK checkout is on %s, the commit the last deploy recorded, and that commit is an ancestor of the deploy ref\n' "$short"
           return 0 ;;
      no)  printf 'STOP checkout %s is not an ancestor of the deploy ref; the ref does not contain what is deployed, so the fast-forward pull in phase 3a cannot succeed\n' "$short"
           return 1 ;;
      *)   printf 'STOP could not decide whether %s is an ancestor of the deploy ref; the server could not resolve the ref\n' "$short"
           return 1 ;;
    esac
  fi

  # 3. No marker: nothing has ever deployed from here, so the runbook's own
  #    starting point is the only acceptable answer.
  if sha_eq "$head" "$fallback"; then
    printf 'OK no deployed-head marker yet, so this is the first deploy, and the checkout is on %s as the runbook says\n' "$fallback"
    return 0
  fi
  printf 'STOP no deployed-head marker, so this is a first deploy and the checkout must be on %s; it is on %s. Set PARAMANT_EXPECTED_HEAD if you know why it moved\n' \
    "$fallback" "$short"
  return 1
}

# ------------------------------------------------- the static sanity reading --

# One implementation, used on the local checkout in phase 0 and on the server
# checkout in phase 3. The runbook's rule, verbatim: checks 1 to 9 are the
# gate, check 10 (the commit style guard on the last commit) is known red on
# main and does not block, anything else red blocks.
STYLE_GUARD_FAIL='FAIL  style guard flagged the last commit'

sanity_verdict() {
  local out="$1" where="$2"
  local fails other reached

  reached="$(printf '%s\n' "$out" | grep -c '10\. Commit/GitHub style guard' || true)"
  [ "$reached" -ge 1 ] || die "static sanity ($where) never reached check 10; the run did not complete"

  fails="$(printf '%s\n' "$out" | grep -E '^[[:space:]]*FAIL' || true)"
  other="$(printf '%s\n' "$fails" | grep -v "$STYLE_GUARD_FAIL" | grep -c . || true)"

  if [ "$other" -ne 0 ]; then
    printf '\n  blocking FAIL lines:\n'
    printf '%s\n' "$fails" | grep -v "$STYLE_GUARD_FAIL" | sed 's/^/    /'
    die "static sanity ($where): $other FAIL line(s) outside check 10; the runbook blocks on any of these"
  fi

  if printf '%s\n' "$fails" | grep -q "$STYLE_GUARD_FAIL"; then
    ok "static sanity ($where): checks 1 to 9 clear, only check 10 red, as the runbook expects"
  else
    ok "static sanity ($where): checks 1 to 10 clear"
  fi
}

# --------------------------------------------------------- argument handling --

usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --preflight-only) PREFLIGHT_ONLY=1; shift ;;
    --verify-only)    VERIFY_ONLY=1; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --rollback)       [ $# -ge 2 ] || { echo "--rollback needs a <TS>" >&2; exit 2; }
                      ROLLBACK_TS="$2"; shift 2 ;;
    -h|--help)        usage 0 ;;
    *)                echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

if [ -n "$ROLLBACK_TS" ] && [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  echo "--rollback and --preflight-only are different runs; pick one" >&2
  exit 2
fi
if [ "$VERIFY_ONLY" -eq 1 ] && { [ -n "$ROLLBACK_TS" ] || [ "$PREFLIGHT_ONLY" -eq 1 ]; }; then
  echo "--verify-only is its own run; do not combine it with --rollback or --preflight-only" >&2
  exit 2
fi
if [ -n "$ROLLBACK_TS" ] && ! printf '%s' "$ROLLBACK_TS" | grep -qE '^[0-9]{8}-[0-9]{4}$'; then
  echo "--rollback <TS> must look like 20260902-1830" >&2
  exit 2
fi

# ------------------------------------------------------------------ logging --

TS="$(date +%Y%m%d-%H%M)"
mkdir -p "$ROOT/deploy/logs"
if [ -n "$ROLLBACK_TS" ]; then
  LOG="$ROOT/deploy/logs/deploy-3.1-rollback-$ROLLBACK_TS.log"
else
  LOG="$ROOT/deploy/logs/deploy-3.1-$TS.log"
fi
exec > >(tee -a "$LOG") 2>&1

MODE="full deploy"
[ "$PREFLIGHT_ONLY" -eq 1 ] && MODE="preflight only (phases 0 and 1, read-only)"
[ "$VERIFY_ONLY" -eq 1 ] && MODE="verify only (phases 6 and 7 on an already deployed server)"
[ -n "$ROLLBACK_TS" ] && MODE="rollback to $ROLLBACK_TS (phase 8)"
[ "$DRY_RUN" -eq 1 ] && MODE="$MODE, DRY RUN (nothing is executed on the server)"

hr
echo "PARAMANT deploy 3.1.0 - deploy/DEPLOY-3.1.md as one command"
hr
printf '  run started   %s\n' "$(date -Is)"
printf '  mode          %s\n' "$MODE"
printf '  run TS        %s\n' "$TS"
printf '  target        %s\n' "$PROD_HOST"
printf '  compose dir   %s\n' "$COMPOSE_DIR"
printf '  docroot       %s\n' "$DOCROOT"
printf '  nginx confs   %s\n' "$NGINX_CONF_SLOTS"
printf '                %s slot(s); the first candidate present on the server wins\n' "$NGINX_SLOT_COUNT"
printf '  deploy ref    %s\n' "$DEPLOY_REF"
if [ -n "$EXPECTED_HEAD" ]; then
  printf '  expected head %s (PARAMANT_EXPECTED_HEAD)\n' "$EXPECTED_HEAD"
else
  printf '  expected head %s if the server has one, else %s (first deploy)\n' \
    "$DEPLOYED_HEAD_FILE" "$EXPECT_PROD_COMMIT"
fi
printf '  log           %s\n' "$LOG"

if [ "$DRY_RUN" -eq 0 ]; then
  [ -r "$PROD_KEY" ] || die "production key not readable: $PROD_KEY (run this from the NUC)"
  printf '  prod key      present, %s bytes, mode %s\n' \
    "$(stat -c%s "$PROD_KEY")" "$(stat -c%a "$PROD_KEY")"
else
  if [ -r "$PROD_KEY" ]; then
    printf '  prod key      present (not used in a dry run)\n'
  else
    printf '  prod key      absent (fine for a dry run)\n'
  fi
fi

# =============================================================== PHASE 0 =====

phase_0() {
  phase 0 "Before you start (read-only)" "Before you start, points 1 to 4"

  step "0a. CI on main, one verdict per required workflow"
  printf '  required: %s\n' "$REQUIRED_WORKFLOWS"
  printf '  excluded: heartbeat.yml (schedule only, red by design while its canary secrets are absent),\n'
  printf '            security-posture.yml (no push trigger, red by design while the posture gate is shut),\n'
  printf '            docker-publish.yml and build-image.yml (path-gated on relay/**, so they need not have run)\n'

  local main_sha wf ci_bad=0 ci_n=0
  if [ "$DRY_RUN" -eq 1 ]; then
    main_sha="<main sha>"
  else
    main_sha="$(gh api "repos/{owner}/{repo}/commits/main" --jq .sha 2>/dev/null || echo unknown)"
    printf '  main sha: %s\n' "$(printf '%s' "$main_sha" | cut -c1-7)"
    [ "$main_sha" = "unknown" ] && warn "could not read the main sha from gh; in-flight runs cannot be matched to it"
  fi

  for wf in $REQUIRED_WORKFLOWS; do
    ci_n=$((ci_n + 1))
    ci_gate_workflow "$wf" "$main_sha" || ci_bad=$((ci_bad + 1))
  done

  if [ "$DRY_RUN" -eq 0 ]; then
    if [ "$ci_bad" -gt 0 ]; then
      die "$ci_bad of $ci_n required workflows on main did not conclude success (or is still running); the runbook wants main green"
    fi
    ok "CI on main: all $ci_n required workflows concluded success ($REQUIRED_WORKFLOWS)"
  fi

  step "0b. static sanity on the commit that will be deployed ($DEPLOY_REF)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ git worktree add --detach <tmp> %s && tests/static-sanity.sh\n' "$DEPLOY_REF"
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): static sanity, checks 1 to 9 clear\n'
  else
    git fetch -q origin || warn "git fetch origin failed; $DEPLOY_REF may be stale"
    DEPLOY_SHA="$(git rev-parse --short "$DEPLOY_REF")"
    printf '\n  deploying commit %s (%s)\n' "$DEPLOY_SHA" "$DEPLOY_REF"
    local wt; wt="$(mktemp -d /tmp/paramant-deploy31.XXXXXX)"
    rmdir "$wt"
    git worktree add -q --detach "$wt" "$DEPLOY_REF" \
      || die "cannot create a worktree at $DEPLOY_REF to test the deploy commit"
    local out rc=0
    out="$(cd "$wt" && bash tests/static-sanity.sh 2>&1)" || rc=$?
    printf '%s\n' "$out" | sed 's/^/  | /'
    printf '  exit %s\n' "$rc"
    git worktree remove --force "$wt" >/dev/null 2>&1 || rm -rf "$wt"
    sanity_verdict "$out" "local, $DEPLOY_SHA"
  fi

  step "0c. frontend drift against $DEPLOY_REF"
  if run_gated bash scripts/check-prod-drift.sh "$DEPLOY_REF"; then
    [ "$DRY_RUN" -eq 0 ] && ok "prod drift guard: docroot matches $DEPLOY_REF"
  else
    if [ "$DRY_RUN" -eq 0 ]; then
      warn "prod drift guard reported drift or could not check; read the list above before phase 5 touches the docroot"
    fi
  fi

  step "0d. the timestamp this run is named by"
  printf '  TS = %s (rollback tags, backups and the manifest all carry it)\n' "$TS"
  ok "run timestamp fixed at $TS"
}

# =============================================================== PHASE 1 =====

phase_1() {
  if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
    phase 1 "Layout and environment (server, read-only)" "Step 1, without the writes"
    note "--preflight-only: steps 1c and 1d only report. Nothing is written."
  else
    phase 1 "Layout and environment (server, read-only plus two env writes)" "Step 1"
  fi

  step "1a. checkout, compose project and container health"
  note "the expected starting commit is a parameter: PARAMANT_EXPECTED_HEAD wins,"
  note "else the deployed-head marker a previous run wrote, else $EXPECT_PROD_COMMIT"
  remote "layout and health" "$COMPOSE_DIR" "$SERVICES" "$DEPLOYED_HEAD_FILE" "$DEPLOY_REF" <<'EOF'
set -euo pipefail
cd "$1"
MARKER="$3"; REF="$4"
echo "checkout_head = $(git rev-parse --short HEAD)"
echo "checkout_head_long = $(git rev-parse HEAD)"
echo "checkout_dir = $PWD"

# What the last finished deploy recorded, if any. An empty or whitespace-only
# file is not an answer, so it reads as absent.
m=none
if [ -f "$MARKER" ]; then
  m="$(tr -d '[:space:]' < "$MARKER")"
  [ -n "$m" ] || m=none
fi
echo "deployed_marker = $m"

# Refs only. fetch updates remote-tracking refs; it does not move HEAD, does
# not touch the working tree and does not check anything out. Phase 3a is still
# the only place that moves the checkout. Without this the ancestor test below
# would judge against a stale origin/main.
git fetch origin >/dev/null 2>&1 || echo "fetch = failed"
if ref_sha="$(git rev-parse --verify --quiet "$REF^{commit}")"; then
  echo "deploy_ref_sha = $ref_sha"
  if git merge-base --is-ancestor HEAD "$ref_sha" 2>/dev/null; then
    echo "head_is_ancestor_of_ref = yes"
  else
    echo "head_is_ancestor_of_ref = no"
  fi
else
  echo "deploy_ref_sha = unknown"
  echo "head_is_ancestor_of_ref = unknown"
fi

docker compose ls 2>&1 | sed 's/^/compose_ls /' || true
found=0
for svc in $2; do
  cid="$(docker compose ps -q "$svc" 2>/dev/null || true)"
  if [ -z "$cid" ]; then
    echo "container $svc MISSING"
    continue
  fi
  st="$(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealthcheck{{end}}' "$cid")"
  echo "container $svc $st"
  found=$((found + 1))
done
echo "services seen = $found"
EOF

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run): the starting commit gate\n'
    if [ -n "$EXPECTED_HEAD" ]; then
      printf '        PARAMANT_EXPECTED_HEAD is set, so the checkout must equal it and nothing else is consulted\n'
    else
      printf '        no marker in %s (first deploy): [would match /checkout_head = %s/]\n' \
        "$DEPLOYED_HEAD_FILE" "$EXPECT_PROD_COMMIT"
      printf '        with a marker (second deploy and after): the checkout must equal the marker AND be an ancestor of %s\n' \
        "$DEPLOY_REF"
    fi
  else
    local gate_head gate_marker gate_anc gate_out gate_rc=0
    gate_head="$(remote_field 'checkout_head_long')"
    gate_marker="$(remote_field 'deployed_marker')"
    gate_anc="$(remote_field 'head_is_ancestor_of_ref')"
    gate_out="$(head_gate_verdict "$EXPECTED_HEAD" "$gate_marker" "$gate_head" \
                "$EXPECT_PROD_COMMIT" "$gate_anc")" || gate_rc=$?
    if [ "$gate_rc" -eq 0 ]; then
      ok "${gate_out#OK }"
      # Phase 5b diffs the docroot against the commit that was deployed. That
      # is this one, read from the server, not a constant from August.
      PREV_HEAD="$gate_head"
    else
      die "${gate_out#STOP }"
    fi
  fi
  expect_count "services seen" 6 "all six services have a container"
  expect_not 'container [a-z-]+ MISSING' "no service is missing a container"
  expect_not 'unhealthy' "no container reports unhealthy"

  step "1b. environment presence (never values)"
  remote "env presence" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
for v in BILLING_MODE MOLLIE_API_KEY MOLLIE_TEST_API_KEY INTERNAL_AUTH_TOKEN ADMIN_TOKEN PARAMANT_TOTP_MASTER_KEY RELAY_REDIS_URL PARAMANT_INLINE_RECEIPT_HEADER; do
  printf 'env %-26s ' "$v"
  # </dev/null is load bearing on EVERY stdin-reading command in a remote
  # heredoc. The body of this block IS the ssh stdin (bash -s), so a command
  # that reads stdin eats the rest of the script. See the note above phase 6h.
  docker compose exec -T relay-main sh -c \
    "v=\$(printenv $v); if [ -z \"\$v\" ]; then echo empty; else echo \"set, prefix \$(printf %s \"\$v\" | cut -c1-5)\"; fi" \
    </dev/null 2>/dev/null || echo "unreadable"
done
EOF

  expect 'env BILLING_MODE +empty' \
    "BILLING_MODE is empty in the running relay, so the recurring layer stays off"
  expect 'env MOLLIE_API_KEY +set, prefix live_' \
    "MOLLIE_API_KEY is set with a live_ prefix, unchanged since 08-08"

  local envmode="write"
  [ "$PREFLIGHT_ONLY" -eq 1 ] && envmode="report"

  step "1c. INTERNAL_AUTH_TOKEN (${envmode}: step 6 cannot read /v2/health/deep without it)"
  remote "internal auth token" "$COMPOSE_DIR" "$envmode" <<'EOF'
set -euo pipefail
cd "$1"
MODE="$2"
# Counts only. The value is never read into a variable that reaches stdout.
before="$(grep -c '^INTERNAL_AUTH_TOKEN=.\+' .env || true)"
echo "before INTERNAL_AUTH_TOKEN lines = $before"
if [ "$before" -eq 0 ]; then
  if [ "$MODE" = report ]; then
    echo "action REPORT ONLY: INTERNAL_AUTH_TOKEN is missing and a full run would generate one"
  else
    cp -a .env ".env.bak-before-iat-$(date +%Y%m%d-%H%M%S)"
    sed -i '/^INTERNAL_AUTH_TOKEN=$/d' .env
    tok="$(openssl rand -hex 32)"
    printf 'INTERNAL_AUTH_TOKEN=%s\n' "$tok" >> .env
    chmod 600 .env
    echo "action GENERATED a new INTERNAL_AUTH_TOKEN and appended it to .env"
    echo "action new token prefix $(printf %s "$tok" | cut -c1-5), length ${#tok}"
    unset tok
  fi
else
  echo "action none, INTERNAL_AUTH_TOKEN was already set"
fi
echo "after INTERNAL_AUTH_TOKEN lines = $(grep -c '^INTERNAL_AUTH_TOKEN=.\+' .env || true)"
EOF

  if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
    if [ "$DRY_RUN" -eq 0 ] && printf '%s\n' "$REMOTE_OUT" | grep -q 'action REPORT ONLY'; then
      warn "INTERNAL_AUTH_TOKEN is missing; a full run will generate one. Preflight wrote nothing."
    else
      ok "INTERNAL_AUTH_TOKEN state reported, nothing written"
    fi
  else
    expect_count "after INTERNAL_AUTH_TOKEN lines" 1 "INTERNAL_AUTH_TOKEN present exactly once in .env"
    if [ "$DRY_RUN" -eq 0 ] && printf '%s\n' "$REMOTE_OUT" | grep -q 'action GENERATED'; then
      warn "a new INTERNAL_AUTH_TOKEN was generated on the server; note it in the deploy record"
    fi
  fi

  step "1d. PARAMANT_INLINE_RECEIPT_HEADER (${envmode}: keeps old SDK clients receipted)"
  note "the SDK release that reads the new receipt-by-reference shape (3.3.0) cannot"
  note "reach PyPI: the project has no trusted publisher. Reported 2026-09-02, not"
  note "measured here. So this deploy takes the runbook's first way out and turns the"
  note "deprecated inline header back on. Phase 5 raises the nginx proxy buffers that"
  note "the fat header needs, or every download would answer 502 instead."
  remote "inline receipt opt-in" "$COMPOSE_DIR" "$envmode" <<'EOF'
set -euo pipefail
cd "$1"
MODE="$2"
before="$(grep -c '^PARAMANT_INLINE_RECEIPT_HEADER=1$' .env || true)"
echo "before PARAMANT_INLINE_RECEIPT_HEADER lines = $before"
if [ "$before" -eq 0 ]; then
  if [ "$MODE" = report ]; then
    echo "action REPORT ONLY: PARAMANT_INLINE_RECEIPT_HEADER is not set and a full run would set it to 1"
  else
    cp -a .env ".env.bak-before-inline-receipt-$(date +%Y%m%d-%H%M%S)"
    sed -i '/^PARAMANT_INLINE_RECEIPT_HEADER=/d' .env
    echo 'PARAMANT_INLINE_RECEIPT_HEADER=1' >> .env
    chmod 600 .env
    echo "action SET PARAMANT_INLINE_RECEIPT_HEADER=1"
    echo "action deprecated, removed after 2026-12-01; take it out once 3.3.0 is on PyPI"
  fi
else
  echo "action none, PARAMANT_INLINE_RECEIPT_HEADER=1 was already set"
fi
echo "after PARAMANT_INLINE_RECEIPT_HEADER lines = $(grep -c '^PARAMANT_INLINE_RECEIPT_HEADER=1$' .env || true)"
EOF

  if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
    ok "inline receipt flag state reported, nothing written"
  else
    expect_count "after PARAMANT_INLINE_RECEIPT_HEADER lines" 1 \
      "PARAMANT_INLINE_RECEIPT_HEADER=1 present exactly once in .env"
    if [ "$DRY_RUN" -eq 0 ] && printf '%s\n' "$REMOTE_OUT" | grep -q 'action SET PARAMANT_INLINE'; then
      warn "the deprecated inline receipt header was switched on; remove it once paramant-sdk 3.3.0 reaches PyPI (one line in .env plus a recreate)"
    fi
  fi
}

# =============================================================== PHASE 2 =====

phase_2() {
  phase 2 "Rollback tags and backups (server, WRITE)" "Step 2"

  step "2a. tag the running images and write the manifest"
  remote "rollback tags" "$COMPOSE_DIR" "$TS" "$BACKUP_DIR" "$SERVICES" <<'EOF'
set -euo pipefail
cd "$1"
TS="$2"; BK="$3"; SVCS="$4"
mkdir -p "$BK"
MANIFEST="$BK/rollback-images-$TS.txt"
echo "before tags for this TS = $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -c ":$TS\$" || true)"
: > "$MANIFEST"
for svc in $SVCS; do
  cid="$(docker compose ps -q "$svc" 2>/dev/null || true)"
  if [ -z "$cid" ]; then
    echo "skip $svc (not running)"
    continue
  fi
  # Tag by image ID, not by the name compose recorded: on production the
  # recorded name (paramant-relay-<svc>:latest) no longer resolves to an
  # image, but the running container's image ID always does.
  img="$(docker inspect --format '{{.Config.Image}}' "$cid")"
  iid="$(docker inspect --format '{{.Image}}' "$cid")"
  docker tag "$iid" "paramant-rollback/$svc:$TS"
  echo "$svc|$img|paramant-rollback/$svc:$TS" >> "$MANIFEST"
done
ln -sfn "$MANIFEST" "$BK/rollback-images-latest.txt"
echo "--- manifest $MANIFEST ---"
cat "$MANIFEST"
echo "--- end manifest ---"
echo "after manifest lines = $(wc -l < "$MANIFEST")"
# The tags are what phase 8 actually restores, so count the tags, not the text.
echo "after tags for this TS = $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -c "^paramant-rollback/.*:$TS\$" || true)"
EOF

  expect_count "after manifest lines" 6 "the rollback manifest has six lines, one per service"
  expect_count "after tags for this TS" 6 "six rollback images really exist on the host, not just six lines of text"

  step "2b. back up .env, compose state, docroot and the nginx confs"
  remote_nginx "backups" "$COMPOSE_DIR" "$TS" "$BACKUP_DIR" "$DOCROOT" "$NGINX_BACKUP_DIR" "$NGINX_SITES" "$NGINX_CONF_SLOTS" <<'EOF'
set -euo pipefail
cd "$1"
TS="$2"; BK="$3"; DOCROOT="$4"; NGBK="$5"; NGSITES="$6"; SLOTS="$7"
mkdir -p "$BK" "$NGBK"

echo "before .env bytes = $(stat -c%s .env)"
cp .env "$BK/.env-pre-3.1-$TS"
chmod 600 "$BK/.env-pre-3.1-$TS"
echo "after .env backup bytes = $(stat -c%s "$BK/.env-pre-3.1-$TS")"

docker compose ps > "$BK/state-pre-3.1-$TS.txt"
echo "after compose state lines = $(wc -l < "$BK/state-pre-3.1-$TS.txt")"

echo "before docroot files = $(find "$DOCROOT" -type f | wc -l)"
tar czf "$BK/docroot-pre-3.1-$TS.tgz" -C "$(dirname "$DOCROOT")" "$(basename "$DOCROOT")"
echo "after docroot tar bytes = $(stat -c%s "$BK/docroot-pre-3.1-$TS.tgz")"
echo "after docroot tar entries = $(tar tzf "$BK/docroot-pre-3.1-$TS.tgz" | wc -l)"

# Which name does each slot have on THIS server? The backup is filed under the
# resolved name and phase 8 resolves the same way, so a rollback looks for the
# file that is really there.
resolve_conf_slots "$NGSITES" "$SLOTS"

# sites-enabled entries are usually symlinks into sites-available. cp -a of a
# symlink copies the link, not the file, which is not a backup: resolve first.
n=0
for name in $RESOLVED_CONFS; do
  link="$NGSITES/$name"
  target="$(readlink -f "$link")"
  echo "nginxconf $name -> $target ($(stat -c%s "$target") bytes)"
  cp -a "$target" "$NGBK/$name.pre-3.1-$TS"
  echo "nginxbackup $name.pre-3.1-$TS $(stat -c%s "$NGBK/$name.pre-3.1-$TS") bytes"
  n=$((n + 1))
done
echo "after nginx conf backups = $n"
echo "after nginx slots unresolved = $RESOLVED_MISSING"

if [ -x deploy/ops/backup-full-state.sh ]; then
  echo "--- deploy/ops/backup-full-state.sh ---"
  rc=0
  bash deploy/ops/backup-full-state.sh > /tmp/paramant-fullstate.$$ 2>&1 || rc=$?
  tail -25 /tmp/paramant-fullstate.$$
  rm -f /tmp/paramant-fullstate.$$
  echo "fullstate exit = $rc"
else
  echo "fullstate deploy/ops/backup-full-state.sh not present or not executable, skipped"
fi
EOF

  expect_min "after .env backup bytes" 1 ".env backup is a real file with content"
  expect_min "after docroot tar bytes" 1 "docroot tar is a real file with content"
  expect_min "after docroot tar entries" 1 "docroot tar holds entries"
  expect_count "after nginx conf backups" "$NGINX_SLOT_COUNT" \
    "every nginx conf slot resolved to a name on the server and was backed up"
  expect_not 'nginxconf [a-z.-]+ ABSENT' \
    "every nginx conf slot has a candidate on the server (set PARAMANT_NGINX_CONFS if they are named differently)"
}

# =============================================================== PHASE 3 =====

phase_3() {
  phase 3 "Pull main, run the sanity gate, build (server, WRITE)" "Step 3"

  step "3a. pull $DEPLOY_REF fast-forward only"
  remote "git pull" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
echo "before HEAD = $(git rev-parse --short HEAD)"
echo "before HEAD long = $(git rev-parse HEAD)"
# Only TRACKED changes are dirt. An untracked path is not.
#
# Deploy run 5 (TS 20260903-0242) got through phases 0, 1 and 2 and stopped
# here on "dirty ?? backups/" with nothing else wrong: an untracked directory
# in the server checkout, which no script in this repo writes, so what put it
# there is not established. It does not matter. `git pull --ff-only` cannot
# lose an untracked file, and it CAN lose a modified tracked one, so the
# tracked half is what the gate is for. The untracked half is reported and
# left alone, because a server checkout is a working directory too, and a
# deploy that refuses to run over a stray file it will not touch is a deploy
# that needs a person for no reason.
tracked="$(git status --porcelain --untracked-files=no)"
untracked="$(git ls-files --others --directory --exclude-standard)"

n_unt=0
[ -n "$untracked" ] && n_unt="$(printf '%s\n' "$untracked" | grep -c . || true)"
echo "before untracked paths = $n_unt"
if [ -n "$untracked" ]; then
  printf '%s\n' "$untracked" | sed 's/^/  untracked /'
fi

n_trk=0
[ -n "$tracked" ] && n_trk="$(printf '%s\n' "$tracked" | grep -c . || true)"
echo "before tracked changes = $n_trk"
if [ -n "$tracked" ]; then
  printf '%s\n' "$tracked" | sed 's/^/  dirty /'
  echo "FATAL working tree not clean: $n_trk tracked file(s) changed; stash and note what it was before deploying"
  exit 1
fi
git fetch origin 2>&1 | sed 's/^/  fetch /' || true
git pull --ff-only origin main 2>&1 | sed 's/^/  pull /'
echo "after HEAD = $(git rev-parse --short HEAD)"
echo "after HEAD long = $(git rev-parse HEAD)"
EOF

  expect_not 'FATAL working tree not clean' "server working tree was clean before the pull"
  expect_count "before tracked changes" 0 "no tracked file in the server checkout was modified before the pull"
  if [ "$DRY_RUN" -eq 0 ]; then
    local n_unt
    n_unt="$(remote_field 'before untracked paths')"
    if [ -n "$n_unt" ] && [ "$n_unt" != 0 ]; then
      note "$n_unt untracked path(s) in the server checkout, listed above and left alone: a fast-forward pull cannot lose them"
    fi
  fi
  if [ "$DRY_RUN" -eq 0 ]; then
    local after_head before_head want
    before_head="$(remote_field 'before HEAD long')"
    after_head="$(remote_field 'after HEAD long')"
    want="$(git rev-parse "$DEPLOY_REF")"
    [ -n "$after_head" ] || die "could not read the server HEAD after the pull"
    [ "$after_head" = "$want" ] \
      || die "server is on $after_head after the pull, expected $want ($DEPLOY_REF, the commit phase 0 tested)"
    ok "server checkout is on ${after_head:0:7}, the commit phase 0 tested"
    # Phase 7 writes this into the deployed-head marker, which is what the NEXT
    # run's phase 1a gate reads back.
    DEPLOYED_HEAD="$after_head"
    # Phase 1a already judged the starting commit against the marker, the
    # override or the runbook constant. All that is left is that nothing moved
    # the checkout between phase 1 and here.
    if [ -n "$PREV_HEAD" ] && [ -n "$before_head" ] && [ "$before_head" != "$PREV_HEAD" ]; then
      die "the checkout was on ${PREV_HEAD:0:7} in phase 1a and on ${before_head:0:7} at the pull; something moved it mid-deploy"
    fi
    PREV_HEAD="$before_head"
  fi

  step "3b. static sanity on the server, same reading rule as phase 0"
  remote_soft "static sanity" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
rc=0
bash tests/static-sanity.sh > /tmp/paramant-sanity.$$ 2>&1 || rc=$?
cat /tmp/paramant-sanity.$$
rm -f /tmp/paramant-sanity.$$
echo "sanity exit = $rc"
EOF
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run): static sanity on the server\n'
  else
    sanity_verdict "$REMOTE_OUT" "server"
  fi

  step "3c. build the relays and admin from source (containers untouched)"
  remote "docker compose build" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
echo "before images:"
docker compose images 2>/dev/null | sed 's/^/  img /' || true
rc=0
docker compose build > /tmp/paramant-build.$$ 2>&1 || rc=$?
tail -40 /tmp/paramant-build.$$
rm -f /tmp/paramant-build.$$
echo "build exit = $rc"
[ "$rc" -eq 0 ] || exit 1
echo "after images:"
docker compose images 2>/dev/null | sed 's/^/  img /' || true
EOF
  expect_count "build exit" 0 "docker compose build succeeded"
}

# =============================================================== PHASE 4 =====

phase_4() {
  phase 4 "Recreate, the canary relay first (server, WRITE)" "Step 4"

  step "4pre. the rendered compose really carries the receipt flag"
  note 'there is no env_file in docker-compose.yml: .env only substitutes'
  note '${VAR} into it, so a variable without a line in x-relay-env never'
  note 'reaches a container. This proves the flag lands BEFORE the recreate,'
  note 'instead of learning it from a failed smoke test at the very end.'
  remote "compose config" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
rendered="$(docker compose config 2>/dev/null)"
echo "compose inline flag on = $(printf '%s\n' "$rendered" | grep -c 'PARAMANT_INLINE_RECEIPT_HEADER: "1"' || true)"
echo "compose inline flag declared = $(printf '%s\n' "$rendered" | grep -c 'PARAMANT_INLINE_RECEIPT_HEADER:' || true)"
printf '%s\n' "$rendered" | grep -nE 'PARAMANT_(RECEIPT_|INLINE_RECEIPT)' | head -8 | sed 's/^/  cfg /' || true
EOF
  # Five relays share x-relay-env; the anchor itself renders once more.
  expect_min "compose inline flag on" 5 \
    "the rendered compose sets PARAMANT_INLINE_RECEIPT_HEADER=1 on all five relays"

  step "4a. relay-iot alone, then read its two boot lines"
  remote "recreate relay-iot" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"

wait_healthy() {  # container id, max seconds
  local w=0 s
  while [ "$w" -lt "${2:-60}" ]; do
    s="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealthcheck{{end}}' "$1" 2>/dev/null || echo unknown)"
    if [ "$s" = healthy ]; then
      echo "healthy $1 after ${w}s"; return 0
    elif [ "$s" = nohealthcheck ]; then
      echo "healthy $1 (no healthcheck defined, running)"; return 0
    elif [ "$s" = unhealthy ]; then
      echo "UNHEALTHY $1"; docker logs "$1" 2>&1 | tail -20 || true; return 1
    fi
    sleep 5; w=$((w + 5))
  done
  echo "NOTHEALTHY $1 after ${2:-60}s"
  return 1
}

old="$(docker compose ps -q relay-iot 2>/dev/null || true)"
if [ -n "$old" ]; then
  echo "before relay-iot image = $(docker inspect -f '{{.Image}}' "$old")"
else
  echo "before relay-iot image = none"
fi

docker compose up -d --no-deps relay-iot 2>&1 | sed 's/^/  up /'
cid="$(docker compose ps -q relay-iot)"
[ -n "$cid" ] || { echo "FATAL relay-iot has no container after up"; exit 1; }
echo "after relay-iot image = $(docker inspect -f '{{.Image}}' "$cid")"

wait_healthy "$cid" 120

echo "--- relay-iot boot lines ---"
docker logs "$cid" 2>&1 | grep -E '"relay_started"|"billing_config"' | tail -4 | sed 's/^/bootline /' || true
echo "--- end boot lines ---"
EOF

  expect 'healthy [0-9a-f]+ after' "relay-iot reached healthy"
  expect 'bootline .*"billing_config"' "relay-iot logged a billing_config line"
  expect 'bootline .*"billing_config".*"recurring":false' \
    "billing_config says recurring:false, the brake is on"
  expect 'bootline .*"billing_config".*"mode_source":"inferred"' \
    "billing_config says mode_source:inferred, so BILLING_MODE is not set anywhere"
  expect_not '"billing_config".*"recurring":true' "no relay reports recurring:true"
  expect "bootline .*\"relay_started\".*\"version\":\"$EXPECT_VERSION\"" \
    "relay_started reports version $EXPECT_VERSION"

  step "4b. relay-main, then the rest"
  remote "recreate the fleet" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"

wait_healthy() {
  local w=0 s
  while [ "$w" -lt "${2:-60}" ]; do
    s="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealthcheck{{end}}' "$1" 2>/dev/null || echo unknown)"
    if [ "$s" = healthy ]; then
      echo "healthy $1 after ${w}s"; return 0
    elif [ "$s" = nohealthcheck ]; then
      echo "healthy $1 (no healthcheck defined, running)"; return 0
    elif [ "$s" = unhealthy ]; then
      echo "UNHEALTHY $1"; docker logs "$1" 2>&1 | tail -20 || true; return 1
    fi
    sleep 5; w=$((w + 5))
  done
  echo "NOTHEALTHY $1 after ${2:-60}s"
  return 1
}

recreate() {
  local svc="$1" old cid
  old="$(docker compose ps -q "$svc" 2>/dev/null || true)"
  if [ -n "$old" ]; then
    echo "before $svc image = $(docker inspect -f '{{.Image}}' "$old")"
  else
    echo "before $svc image = none"
  fi
  docker compose up -d --no-deps "$svc" 2>&1 | sed 's/^/  up /'
  cid="$(docker compose ps -q "$svc")"
  [ -n "$cid" ] || { echo "FATAL $svc has no container after up"; return 1; }
  echo "after $svc image = $(docker inspect -f '{{.Image}}' "$cid")"
  wait_healthy "$cid" 120
  echo "recreated $svc"
}

recreate relay-main
for svc in relay-health relay-finance relay-legal admin; do
  recreate "$svc"
done

echo "--- billing stance on every relay ---"
for svc in relay-main relay-health relay-finance relay-legal relay-iot; do
  cid="$(docker compose ps -q "$svc")"
  printf 'stance %-14s ' "$svc"
  docker logs "$cid" 2>&1 | grep '"billing_config"' | tail -1 | grep -o '"recurring":[a-z]*' || echo "no billing_config line"
done
echo "--- versions ---"
for svc in relay-main relay-health relay-finance relay-legal relay-iot; do
  cid="$(docker compose ps -q "$svc")"
  printf 'version %-14s ' "$svc"
  docker logs "$cid" 2>&1 | grep '"relay_started"' | tail -1 | grep -o '"version":"[^"]*"' || echo "no relay_started line"
done
EOF

  expect 'recreated relay-main' "relay-main recreated and healthy"
  expect 'recreated admin' "admin recreated and healthy"
  expect_not 'NOTHEALTHY|UNHEALTHY|FATAL' "every recreated container reached healthy"
  expect_not 'stance .*"recurring":true' "no relay reports recurring:true after the recreate"
  expect_not 'version .*no relay_started line' "every relay logged relay_started"
}

# =============================================================== PHASE 5 =====

phase_5() {
  phase 5 "Frontend and nginx (server, WRITE)" "Step 5"

  # The base 5b diffs against, to learn which frontend files main deleted.
  #
  # The obvious base is the commit that was deployed. It is wrong after a
  # rollback. Phase 8 restores the docroot from the pre-3.1 tar, which puts all
  # 26 pruned pages BACK, and it leaves the checkout, and therefore the marker,
  # on main. The next deploy then diffs marker..HEAD, finds nothing deleted,
  # prunes nothing, and phase 6e dies on /compliance/nis2 answering 200 with
  # everything else already live. That is the worst place to find out.
  #
  # So the base is the OLDER of the deployed commit and the runbook's own
  # starting commit, which in practice means 41501bb on every run. The server
  # decides which is older, because only the server has both commits. Pruning
  # something that is already gone costs nothing: "pruned 0 of 26, 26 were
  # already gone" is the normal answer on a healthy second deploy.
  local base="${PREV_HEAD:-$EXPECT_PROD_COMMIT}"
  local base_floor="$EXPECT_PROD_COMMIT"

  step "5a. rsync the docroot, never with --delete"
  remote "rsync docroot" "$COMPOSE_DIR" "$DOCROOT" <<'EOF'
set -euo pipefail
SRC="$1/frontend/"; DST="$2/"
echo "before docroot files = $(find "$2" -type f | wc -l)"
echo "before would change = $(rsync -rinc --no-times "$SRC" "$DST" | grep -c . || true)"
rsync -rinc --no-times "$SRC" "$DST" | sed 's/^/  wouldchange /' | head -60 || true
rc=0
rsync -rc --no-times "$SRC" "$DST" > /tmp/paramant-rsync.$$ 2>&1 || rc=$?
tail -5 /tmp/paramant-rsync.$$ | sed 's/^/  rsync /'
rm -f /tmp/paramant-rsync.$$
echo "rsync exit = $rc"
[ "$rc" -eq 0 ] || exit 1
echo "after docroot files = $(find "$2" -type f | wc -l)"
echo "after would change = $(rsync -rinc --no-times "$SRC" "$DST" | grep -c . || true)"
EOF
  expect_count "rsync exit" 0 "docroot rsync succeeded"
  expect_count "after would change" 0 "docroot now matches the checkout frontend"

  step "5b. prune the frontend files main deleted (rsync without --delete leaves them)"
  note "a page removed from git keeps being served by try_files until the file"
  note "goes; the list comes from git, never from a wildcard on the server"
  note "the base is the older of the deployed commit and $base_floor, so a deploy"
  note "after a rollback still prunes the pages the restored docroot brought back"
  remote "prune deleted frontend files" "$COMPOSE_DIR" "$DOCROOT" "$base" "$DOCROOT_IGNORE" "$base_floor" <<'EOF'
set -euo pipefail
cd "$1"
DOCROOT="$2"; BASE="$3"; IGNORE="$4"; FLOOR="$5"

echo "before base candidate = $BASE"
echo "before base floor = $FLOOR"
# Older wins. "Older" here is git's own answer: FLOOR is older than BASE exactly
# when FLOOR is an ancestor of it. A rollback leaves BASE on main and the
# docroot back at the pre-3.1 tar, and only the floor still names every page
# that has to go.
if ! git rev-parse --verify --quiet "$FLOOR^{commit}" >/dev/null; then
  echo "before base choice = kept $BASE, the floor $FLOOR does not resolve in this checkout"
elif [ -z "$BASE" ]; then
  echo "before base choice = took the floor $FLOOR, no deployed commit was measured"
  BASE="$FLOOR"
elif git merge-base --is-ancestor "$FLOOR" "$BASE" 2>/dev/null; then
  echo "before base choice = took the floor $FLOOR, it is older than $BASE"
  BASE="$FLOOR"
else
  echo "before base choice = kept $BASE, the floor $FLOOR is not an ancestor of it"
fi
echo "before prune base = $BASE"

DEL="$(git diff --diff-filter=D --name-only "$BASE"..HEAD -- frontend/ || true)"
echo "before deleted-in-git count = $(printf '%s\n' "$DEL" | grep -c . || true)"

removed=0
kept=0
absent=0
outside=0
for f in $DEL; do
  rel="${f#frontend/}"
  # Never step outside the docroot, and never touch what the drift guard
  # legitimately expects to exist only on the server.
  case "$rel" in
    ''|*..*) echo "  skip suspicious path $f"; continue ;;
  esac
  skip=no
  for ig in $IGNORE; do
    case "$rel" in
      "$ig"|"$ig"/*) skip=yes ;;
    esac
  done
  if [ "$skip" = yes ]; then
    echo "  keep $rel (on the drift guard IGNORE list)"
    kept=$((kept + 1))
    continue
  fi
  if [ ! -f "$DOCROOT/$rel" ]; then
    absent=$((absent + 1))
    continue
  fi
  # A symlinked subdirectory inside the docroot would let this rm land outside
  # it. Resolve the path and refuse anything that is not really under DOCROOT.
  real="$(readlink -f "$DOCROOT/$rel")"
  realroot="$(readlink -f "$DOCROOT")"
  case "$real" in
    "$realroot"/*) : ;;
    *) echo "  REFUSED $rel resolves to $real, outside $realroot"
       outside=$((outside + 1))
       continue ;;
  esac
  rm -f "$real"
  echo "  removed $rel"
  removed=$((removed + 1))
done
echo "after removed = $removed"
echo "after kept on ignore list = $kept"
echo "after already absent = $absent"
echo "after refused outside docroot = $outside"
echo "after docroot files = $(find "$DOCROOT" -type f | wc -l)"
EOF
  expect_count "after refused outside docroot" 0 \
    "no deletion resolved to a path outside the docroot"
  if [ "$DRY_RUN" -eq 0 ]; then
    local rm_n ab_n del_n
    del_n="$(remote_field 'before deleted-in-git count')"
    rm_n="$(remote_field 'after removed')"
    ab_n="$(remote_field 'after already absent')"
    [ -n "$del_n" ] || die "the server never printed 'before deleted-in-git count'"
    # An empty list is an answer: between the deployed commit and the ref, main
    # deleted no frontend file. Demanding at least one only held for the first
    # deploy, where the runbook had already counted them. On a resume, or on a
    # deploy of a ref that deleted nothing, a hard minimum stops a run that has
    # nothing wrong with it. Already absent is likewise OK and always was.
    if [ "$del_n" -eq 0 ]; then
      ok "git names no frontend file deleted since the deployed commit, so there is nothing to prune"
    else
      ok "pruned $rm_n of $del_n stale docroot file(s) against base $(remote_field 'before prune base'), $ab_n were already gone"
    fi
  fi

  step "5c. the four nginx changes, by hand, keeping the ParaID deny"
  remote_nginx "nginx edits" "$TS" "$NGINX_SITES" "$NGINX_BACKUP_DIR" "$NGINX_CONF_SLOTS" <<'EOF'
set -euo pipefail
TS="$1"; SITES="$2"; NGBK="$3"; SLOTS="$4"

# Which name does each slot have here? Same question as phase 2b, answered the
# same way, so the confs that are edited are the confs that were backed up.
resolve_conf_slots "$SITES" "$SLOTS"
if [ "$RESOLVED_MISSING" -ne 0 ]; then
  echo "FATAL $RESOLVED_MISSING nginx conf slot(s) have no candidate in $SITES"
  exit 1
fi

# Resolve the named confs to real files. A symlink is not the file.
#
# And refuse to touch a conf that has no phase 2b backup under this run's TS.
# 2b and 5c resolve independently, on purpose: each asks the server what is
# there at the moment it runs. If sites-enabled changes in between, say
# paramant-live.conf is swapped for paramant.conf while phases 3 and 4 build
# and recreate, then 5c resolves to a conf 2b never backed up. Every FATAL
# below then calls restore(), which can only put back what was filed, so the
# run would end saying "restoring the backed up confs" with that conf left
# edited and nothing to roll it back to. The check is before the first sed, so
# nothing has been written yet when it stops.
TARGETS=""
nobackup=0
for name in $RESOLVED_CONFS; do
  t="$(readlink -f "$SITES/$name")"
  b="$NGBK/$name.pre-3.1-$TS"
  if [ ! -f "$b" ]; then
    echo "FATAL no phase 2b backup $b for $name, which this phase would edit"
    nobackup=$((nobackup + 1))
    continue
  fi
  echo "target $name -> $t (backup $b, $(stat -c%s "$b") bytes)"
  TARGETS="$TARGETS $t"
done
echo "before confs without a backup = $nobackup"
if [ "$nobackup" -ne 0 ]; then
  echo "FATAL $nobackup resolved conf(s) have no backup under this run TS $TS, so an edit here"
  echo "FATAL could not be undone. sites-enabled changed since phase 2b, or 2b never ran for"
  echo "FATAL this TS. Nothing was written. Run phase 2 again for this TS, or start the deploy"
  echo "FATAL over so 2b backs up the confs that are there now."
  exit 1
fi

# grep exits 1 when it matches nothing, and pipefail turns that into a failed
# pipeline. The count IS the answer here, and zero is a perfectly good answer,
# so grep's verdict is swallowed: without this, reading a count into a variable
# ends the block under set -e the moment a pattern is already gone.
count() { grep -hcE -- "$1" $TARGETS 2>/dev/null | awk '{s+=$1} END{print s+0}' || true; }

SIGN_RE='location = /sign[[:space:]]*\{[^}]*auth_request'
COMP_RE='^[[:space:]]*location = /compliance(/(nis2|iec62443|nen7510))?[[:space:]]*\{'
DICOM_RE='location = /dicom[[:space:]]*\{[[:space:]]*try_files /dicom\.html'
# The wanted END state of each edit, so an edit with nothing left to do can be
# told apart from a conf that was never the shape the runbook describes.
SIGN_LOC_RE='location = /sign[[:space:]]*\{'
DICOM404_RE='location = /dicom[[:space:]]*\{[[:space:]]*return 404'
PARAID_RE='paraid/issue'
RULES_RE='location = /pararules'
OUT_RE='^[[:space:]]*location[[:space:]]*~[[:space:]]*\^/v2/outbound[[:space:]]*\{'
BUF_RE='proxy_buffer_size 32k'

# /pararules became /rules in the two-product-names round. The page is indexed,
# so the old path keeps a permanent 301 rather than a migration step that gets
# tidied away in a later round.
#
# The anchor is the ParaID deny. It is in every server block by the 01-09
# server edit the runbook already relies on and FATALs on below, which makes it
# the one line that marks a block as "a block that answers for this site" in
# both confs: paramant-live.conf carries no server_name at all (it is the
# backend paramant-public.conf proxies to), so keying on the hostname would
# have put the redirect in one conf and not the other.
#
# Two passes, like the buffer edit below: pass one learns which blocks already
# carry the redirect, pass two inserts only into the ones that do not. A
# file-wide grep would stop at the first block and leave the rest bare.
RULES_AWK='
FNR==NR {
  if ($0 ~ /^server[[:space:]]*\{/) b++
  if ($0 ~ /location = \/pararules/) has[b]=1
  if ($0 ~ /paraid\/issue/) deny[b]=1
  next
}
{
  print
  if ($0 ~ /^server[[:space:]]*\{/) j++
  if ($0 ~ /paraid\/issue/ && deny[j] && !has[j] && !ins[j]) {
    print "    location = /pararules { return 301 https://$host/rules; }"
    ins[j]=1
  }
}'

# Count the server blocks that answer for the site (the ParaID deny marks them)
# and how many of those already carry the redirect.
RULES_COUNT_AWK='
/^server[[:space:]]*\{/ { b++ }
/paraid\/issue/ { deny[b]=1 }
/location = \/pararules/ { has[b]=1 }
END { for (i in deny) { t++; if (has[i]) w++ } printf "%d %d\n", t+0, w+0 }'

count_rules() { awk "$RULES_COUNT_AWK" $TARGETS | awk '{t+=$1; w+=$2} END{printf "%d %d\n", t, w}'; }

# Two-pass insert: learn which /v2/outbound blocks already carry the buffer,
# then insert only into the ones that do not.
BUF_AWK='
FNR==NR {
  if ($0 ~ /^[[:space:]]*location[[:space:]]*~[[:space:]]*\^\/v2\/outbound[[:space:]]*\{/) { b++; inb=1; depth=1; next }
  if (inb) {
    if ($0 ~ /proxy_buffer_size 32k/) has[b]=1
    depth += gsub(/\{/,"{") - gsub(/\}/,"}")
    if (depth <= 0) inb=0
  }
  next
}
{
  print
  if ($0 ~ /^[[:space:]]*location[[:space:]]*~[[:space:]]*\^\/v2\/outbound[[:space:]]*\{/) {
    j++
    if (!has[j]) {
      print "        proxy_buffer_size 32k;"
      print "        proxy_buffers 8 32k;"
      print "        proxy_busy_buffers_size 64k;"
    }
  }
}'

# Count /sign blocks, and how many of them carry an auth_request ANYWHERE
# inside the block, whatever the line layout is.
#
# SIGN_RE only sees the one-line spelling the repo conf uses. A hand edit
# between two deploys that put the gate back across several lines,
#
#     location = /sign {
#         auth_request /api/user/check;
#         ...
#     }
#
# leaves SIGN_RE at zero, which the state read below would call "done" and
# report as already applied while /sign is in fact behind the login again.
# Reading the block instead of the line closes that. The header line is NOT
# skipped, because the one-line spelling opens and closes on it.
SIGN_AWK='
/^[[:space:]]*location[[:space:]]*=[[:space:]]*\/sign[[:space:]]*\{/ { total++; inb=1; has=0; depth=0 }
inb {
  if ($0 ~ /auth_request/) has=1
  depth += gsub(/\{/,"{") - gsub(/\}/,"}")
  if (depth <= 0) { if (has) withauth++; inb=0 }
}
END { printf "%d %d\n", total+0, withauth+0 }'

count_sign() { awk "$SIGN_AWK" $TARGETS | awk '{t+=$1; w+=$2} END{printf "%d %d\n", t, w}'; }

# Count /v2/outbound blocks, and how many of them carry the buffer INSIDE the
# block. Counting matches per file cannot tell those apart.
BLOCK_AWK='
/^[[:space:]]*location[[:space:]]*~[[:space:]]*\^\/v2\/outbound[[:space:]]*\{/ { total++; inb=1; has=0; depth=1; next }
inb {
  if ($0 ~ /proxy_buffer_size 32k/) has=1
  depth += gsub(/\{/,"{") - gsub(/\}/,"}")
  if (depth <= 0) { if (has) withbuf++; inb=0 }
}
END { printf "%d %d\n", total+0, withbuf+0 }'

count_blocks() { awk "$BLOCK_AWK" $TARGETS | awk '{t+=$1; w+=$2} END{printf "%d %d\n", t, w}'; }

echo "before sign gated = $(count "$SIGN_RE")"
read -r _sbt _sbw <<< "$(count_sign)"
echo "before sign blocks = $_sbt"
echo "before sign blocks with auth_request = $_sbw"
echo "before compliance = $(count "$COMP_RE")"
echo "before dicom try_files = $(count "$DICOM_RE")"
echo "before paraid deny = $(count "$PARAID_RE")"
read -r _obt _obw <<< "$(count_blocks)"
echo "before outbound locations = $_obt"
echo "before outbound blocks with buffer = $_obw"
read -r _rbt _rbw <<< "$(count_rules)"
echo "before pararules blocks = $_rbt"
echo "before pararules blocks with redirect = $_rbw"

# Each edit is in one of three states, and only one of them is a stop:
#
#   todo     the old shape is present, so there is work to do
#   done     the old shape is gone AND the wanted end shape is there, so a
#            previous run already applied this edit. Not an error: it is what
#            every deploy after the first one looks like.
#   unknown  neither shape is present. The conf is not what the runbook
#            describes, and editing further would be editing blind.
#
# The old gate read "todo" as the only acceptable state, which made a second
# deploy FATAL on an edit that had simply already succeeded.
#
# Removal-only edits (compliance) have no wanted end shape other than absence,
# so for those "gone" is "done", the same rule 5b already uses for a file that
# is already absent.
state() {   # old-count, wanted-count, has-wanted-shape(yes|no)
  if [ "$1" -gt 0 ]; then echo todo
  elif [ "$3" = no ]; then echo done
  elif [ "$2" -gt 0 ]; then echo done
  else echo unknown
  fi
}

# /sign is judged on the BLOCK counts, so a multi-line auth_request reads as
# todo and never as done. The other two edits are single lines by construction:
# a /compliance location and the /dicom try_files both live on one line.
_b_comp="$(count "$COMP_RE")"
_b_dicom="$(count "$DICOM_RE")";   _b_dicom404="$(count "$DICOM404_RE")"

SIGN_STATE="$(state "$_sbw" "$_sbt" yes)"
COMP_STATE="$(state "$_b_comp" 0 no)"
DICOM_STATE="$(state "$_b_dicom" "$_b_dicom404" yes)"
echo "before sign location = $_sbt"
echo "before dicom 404 = $_b_dicom404"
echo "before sign state = $SIGN_STATE"
echo "before compliance state = $COMP_STATE"
echo "before dicom state = $DICOM_STATE"

unknown=0
for pair in "sign:$SIGN_STATE" "compliance:$COMP_STATE" "dicom:$DICOM_STATE"; do
  if [ "${pair#*:}" = unknown ]; then
    echo "FATAL '${pair%%:*}': the conf carries neither the shape the runbook edits nor the shape the edit leaves behind, so this conf is not the one the runbook describes"
    unknown=$((unknown + 1))
  fi
done
[ "$unknown" -eq 0 ] || exit 1

pending=0
for st in "$SIGN_STATE" "$COMP_STATE" "$DICOM_STATE"; do
  [ "$st" = todo ] && pending=$((pending + 1))
done
# A /v2/outbound block without the buffer is a fourth thing still to do, and a
# site block without the /pararules redirect a fifth.
pending=$((pending + _obt - _obw))
pending=$((pending + _rbt - _rbw))
echo "before edits pending = $pending"
if [ "$pending" -eq 0 ]; then
  echo "before everything already applied = yes"
else
  echo "before everything already applied = no"
fi

if [ "$(count "$PARAID_RE")" -eq 0 ]; then
  echo "FATAL the ParaID deny is not present in the resolved conf(s) $RESOLVED_CONFS; the 01-09 server edit this runbook relies on is gone"
  exit 1
fi
if [ "$(count "$OUT_RE")" -eq 0 ]; then
  echo "FATAL no location ~ ^/v2/outbound block found; the inline receipt header would 502"
  exit 1
fi

edited=0
for f in $TARGETS; do
  cp -a "$f" "/tmp/nginx-pre-3.1-$(basename "$f").$TS"
  # 1. /sign leaves the auth_request gate (#317).
  sed -i -E 's|(location = /sign[[:space:]]*\{)[[:space:]]*auth_request /api/user/check; error_page 401 = @login_redirect;|\1|' "$f"
  # 2. the /compliance locations go (#323), the redirect included.
  sed -i -E '/^[[:space:]]*location = \/compliance(\/(nis2|iec62443|nen7510))?[[:space:]]*\{/d' "$f"
  # 3. /dicom answers 404 instead of serving the page. The exact match stays so
  #    nginx cannot auto-redirect it into the /dicom/ proxy below.
  sed -i -E 's|(location = /dicom[[:space:]]*\{)[[:space:]]*try_files /dicom\.html[[:space:]]*=404;[[:space:]]*\}|\1 return 404; }|' "$f"
  # 4. #342: raise the proxy buffers on /v2/outbound. Nginx has to hold the
  #    whole upstream header block in ONE buffer, and the default 4k/8k is far
  #    under the ~19 KB the deprecated inline X-Paramant-Receipt costs, which
  #    is a 502 on every download.
  #
  #    The guard is per BLOCK, not per file. A file-wide grep passes as soon as
  #    proxy_buffer_size appears anywhere, so a conf that already sets it on
  #    /v2/inbound would leave the outbound block bare and every download would
  #    502. Pass one reads which outbound blocks already have it, pass two
  #    inserts only into the ones that do not, which also makes it idempotent.
  awk "$BUF_AWK" "$f" "$f" > "/tmp/nginx-buf.$$"
  cat "/tmp/nginx-buf.$$" > "$f"
  rm -f "/tmp/nginx-buf.$$"
  # 5. the permanent 301 from /pararules to /rules, one per site block.
  awk "$RULES_AWK" "$f" "$f" > "/tmp/nginx-rules.$$"
  cat "/tmp/nginx-rules.$$" > "$f"
  rm -f "/tmp/nginx-rules.$$"
  if ! cmp -s "$f" "/tmp/nginx-pre-3.1-$(basename "$f").$TS"; then
    echo "edited $(basename "$f")"
    edited=$((edited + 1))
  fi
done
echo "after edited files = $edited"
echo "after sign gated = $(count "$SIGN_RE")"
read -r _sat _saw <<< "$(count_sign)"
echo "after sign blocks = $_sat"
echo "after sign blocks with auth_request = $_saw"
echo "after compliance = $(count "$COMP_RE")"
echo "after dicom try_files = $(count "$DICOM_RE")"
echo "after dicom 404 = $(count 'location = /dicom[[:space:]]*\{[[:space:]]*return 404')"
echo "after paraid deny = $(count "$PARAID_RE")"
read -r _oat _oaw <<< "$(count_blocks)"
echo "after outbound locations = $_oat"
echo "after outbound blocks with buffer = $_oaw"
read -r _rat _raw <<< "$(count_rules)"
echo "after pararules blocks = $_rat"
echo "after pararules blocks with redirect = $_raw"
echo "after pararules redirect lines = $(count "$RULES_RE")"

# Restore exactly the confs this phase edited, not whatever the backup dir
# happens to hold for this TS. The precondition above proved every one of them
# has a backup, so "restoring the backed up confs" is a promise that holds for
# all of them and for nothing else.
restore() {
  for name in $RESOLVED_CONFS; do
    cp -a "$NGBK/$name.pre-3.1-$TS" "$(readlink -f "$SITES/$name")"
    echo "restored $name from $NGBK/$name.pre-3.1-$TS"
  done
}

if [ "$(count "$PARAID_RE")" -eq 0 ]; then
  echo "FATAL the ParaID deny disappeared; restoring"
  restore
  exit 1
fi

# The sed above only removes the one-line spelling of the gate. If a block
# still carries an auth_request, the edit did not take, and saying "OK" here
# would ship /sign behind the login. Restore and say what to do by hand.
if [ "$_saw" -gt 0 ]; then
  echo "FATAL $_saw of $_sat 'location = /sign' block(s) still carry an auth_request after the edit."
  echo "FATAL the runbook removes the ONE-LINE spelling; this conf spreads the gate over several lines,"
  echo "FATAL so someone edited it by hand between deploys. Take the auth_request and the error_page 401"
  echo "FATAL line out of the /sign block yourself, then run this phase again. Restoring the backed up confs."
  restore
  exit 1
fi

rc=0
nginx -t > /tmp/paramant-nginxt.$$ 2>&1 || rc=$?
sed 's/^/  nginxt /' /tmp/paramant-nginxt.$$
rm -f /tmp/paramant-nginxt.$$
if [ "$rc" -ne 0 ]; then
  echo "FATAL nginx -t failed, restoring the backed up confs"
  restore
  nginx -t 2>&1 | sed 's/^/  restoredtest /' || true
  systemctl reload nginx && echo "restored and reloaded the previous nginx conf"
  exit 1
fi
systemctl reload nginx
echo "reloaded nginx"
EOF

  expect_not 'FATAL' "nginx edits applied and the config tests clean"
  expect_count "before confs without a backup" 0 \
    "every conf 5c edited had a phase 2b backup under this run TS, so a FATAL could restore all of them"
  # How many files were rewritten depends on what was left to do, so the exact
  # count of 2 only holds on a run that found work in both confs. What always
  # holds is the END state, and that is asserted hard just below: no
  # auth_request on /sign, no /compliance locations, /dicom answering 404, a
  # buffer inside every /v2/outbound block, and the /pararules 301 inside every
  # block that answers for the site. Those five are the deploy.
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run): both named confs were rewritten, unless every edit was already applied\n'
  else
    local pend edited
    pend="$(remote_field 'before everything already applied')"
    edited="$(remote_field 'after edited files')"
    [ -n "$pend" ] && [ -n "$edited" ] \
      || die "could not read the nginx edit state from the server"
    if [ "$pend" = yes ]; then
      ok "nginx: already applied. All three edits, the outbound buffers and the /pararules 301 were in place before this run, so nothing was rewritten (edited files = $edited)"
    else
      [ "$edited" -ge 1 ] \
        || die "$(remote_field 'before edits pending') nginx edit(s) were still pending but no conf was rewritten"
      ok "nginx: $(remote_field 'before edits pending') pending edit(s), $edited conf(s) rewritten"
    fi
  fi
  expect_count "after sign gated" 0 "/sign is no longer behind auth_request"
  expect_count "after compliance" 0 "the /compliance locations are gone"
  expect_count "after dicom try_files" 0 "/dicom no longer serves the page"
  expect_min "after dicom 404" 1 "/dicom now returns 404"
  expect_min "before outbound locations" 1 "the /v2/outbound location the buffers go on exists"
  expect_min "after pararules redirect lines" 1 "/pararules answers a 301 to /rules"
  expect 'reloaded nginx' "nginx reloaded"
  if [ "$DRY_RUN" -eq 0 ]; then
    local ol bf
    ol="$(remote_field 'after outbound locations')"
    bf="$(remote_field 'after outbound blocks with buffer')"
    [ -n "$ol" ] && [ -n "$bf" ] || die "could not read the /v2/outbound block counts from the server"
    [ "$bf" = "$ol" ] \
      || die "proxy_buffer_size sits inside $bf of $ol /v2/outbound blocks; the inline receipt header would 502 on the rest"
    ok "every /v2/outbound block carries proxy_buffer_size 32k ($bf of $ol blocks)"
  fi
  if [ "$DRY_RUN" -eq 0 ]; then
    local rt rw
    rt="$(remote_field 'after pararules blocks')"
    rw="$(remote_field 'after pararules blocks with redirect')"
    [ -n "$rt" ] && [ -n "$rw" ] || die "could not read the /pararules redirect counts from the server"
    [ "$rw" = "$rt" ] \
      || die "the /pararules 301 sits in $rw of $rt site block(s); an indexed link to the old rules page would 404 on the rest"
    ok "every site block redirects /pararules to /rules ($rw of $rt blocks)"
  fi
  if [ "$DRY_RUN" -eq 0 ]; then
    local pb pa
    pb="$(remote_field 'before paraid deny')"
    pa="$(remote_field 'after paraid deny')"
    if [ -n "$pb" ] && [ -n "$pa" ] && [ "$pa" -ge "$pb" ] && [ "$pa" -gt 0 ]; then
      ok "the ParaID deny survived the edit ($pa line(s), was $pb)"
    else
      die "the ParaID deny changed from ${pb:-?} to ${pa:-?} lines; the runbook keeps it in this round"
    fi
  fi
}

# =============================================================== PHASE 6 =====

# http_code <url> [extra curl args...]
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@" || echo 000; }

phase_6() {
  phase 6 "Smoke tests" "Step 6"

  step "6a. public auth surface (tests/auth-smoke.sh)"
  if run_gated bash tests/auth-smoke.sh https://paramant.app; then
    [ "$DRY_RUN" -eq 0 ] && ok "auth-smoke.sh passed against https://paramant.app"
  else
    [ "$DRY_RUN" -eq 0 ] && die "auth-smoke.sh failed; the runbook rolls back on this (phase 8)"
  fi

  step "6b. /health on each of the six hosts, and the version it reports"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ curl -s -o /dev/null -w %%{http_code} https://<host>/health   # six hosts\n'
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): /health is 200 on six hosts, version %s\n' "$EXPECT_VERSION"
  else
    local h code ver
    for h in $HOSTS; do
      code="$(http_code "https://$h/health")"
      printf '  health %-26s %s\n' "$h" "$code"
      [ "$code" = "200" ] || die "/health on $h answered $code, expected 200"
    done
    ok "/health is 200 on all six hosts"
    ver="$(curl -s --max-time 15 https://paramant.app/health \
           | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version",""))' 2>/dev/null || echo "")"
    printf '  version reported by paramant.app/health = %s\n' "$ver"
    [ "$ver" = "$EXPECT_VERSION" ] || die "/health reports version '$ver', expected $EXPECT_VERSION"
    ok "/health reports version $EXPECT_VERSION"
  fi

  step "6c. /v2/health/deep, 401 without the token and 200 with it (server-local)"
  remote "deep health" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
# The token goes straight into a curl header. It is never echoed, and the only
# things printed are status codes and the parsed overall field.
T="$(grep '^INTERNAL_AUTH_TOKEN=' .env | head -1 | cut -d= -f2-)"
if [ -z "$T" ]; then echo "FATAL INTERNAL_AUTH_TOKEN empty in .env"; exit 1; fi
echo "deep token length = ${#T}"
echo "deep noauth code = $(curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://127.0.0.1:3000/v2/health/deep)"
echo "deep auth code = $(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "X-Internal-Auth: $T" http://127.0.0.1:3000/v2/health/deep)"
curl -s --max-time 15 -H "X-Internal-Auth: $T" http://127.0.0.1:3000/v2/health/deep \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("deep overall =", d.get("overall") or d.get("status") or "unknown")' 2>/dev/null \
  || echo "deep overall = unparseable"
unset T
EOF
  expect_count "deep noauth code" 401 "/v2/health/deep is 401 without X-Internal-Auth"
  expect_count "deep auth code" 200 "/v2/health/deep is 200 with X-Internal-Auth"

  step "6d. /v1/paraid/issue-document is 404 on all six hosts (#319)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ curl -s -o /dev/null -w %%{http_code} -X POST https://<host>/v1/paraid/issue-document   # six hosts\n'
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): issue-document is 404 on six hosts\n'
  else
    local h code
    for h in $HOSTS; do
      code="$(http_code -X POST "https://$h/v1/paraid/issue-document")"
      printf '  paraid %-26s %s\n' "$h" "$code"
      [ "$code" = "404" ] || die "/v1/paraid/issue-document on $h answered $code, expected 404"
    done
    ok "/v1/paraid/issue-document is 404 on all six hosts"
  fi

  step "6e. the pages main deleted are really gone, not just unlinked (#319, #323)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ curl -s -o /dev/null -w %%{http_code} https://paramant.app/compliance/nis2   # and /paraid\n'
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): /compliance/nis2 and /paraid are 404\n'
  else
    local p code
    for p in /compliance/nis2 /compliance/iec62443 /compliance/nen7510 /paraid /paraid-app /dicom; do
      code="$(http_code "https://paramant.app$p")"
      printf '  gone %-24s %s\n' "$p" "$code"
      [ "$code" = "404" ] || die "https://paramant.app$p answered $code, expected 404 after phase 5b removed the file"
    done
    ok "every page main deleted answers 404 on the public host"
  fi

  step "6f. /sign answers itself, 200 and no redirect to /auth/login (#317)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ curl -s -o /dev/null -w %%{http_code} https://paramant.app/sign\n'
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): /sign is 200 without a session\n'
  else
    local code
    code="$(http_code https://paramant.app/sign)"
    printf '  sign code = %s\n' "$code"
    [ "$code" = "200" ] || die "/sign answered $code, expected 200 without a login"
    ok "/sign is 200 without a login"
  fi

  step "6g. the 3.0.0 verify suite, on the server (informational, exit 2 blocks)"
  remote_soft "post-deploy-verify" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1" || exit 1
rc=0
bash scripts/post-deploy-verify.sh https://paramant.app http://127.0.0.1:3000 > /tmp/paramant-pdv.$$ 2>&1 || rc=$?
tail -40 /tmp/paramant-pdv.$$
rm -f /tmp/paramant-pdv.$$
echo "verify exit = $rc"
EOF
  if [ "$DRY_RUN" -eq 0 ]; then
    local vrc; vrc="$(remote_field 'verify exit')"
    if [ "$vrc" = "2" ]; then
      die "post-deploy-verify.sh exited 2 (critical); the runbook rolls back on this (phase 8)"
    elif [ "$vrc" = "0" ]; then
      ok "post-deploy-verify.sh passed"
    else
      warn "post-deploy-verify.sh exited ${vrc:-unknown} but not 2; its /health/deep probe is known red (the route is /v2/health/deep), read the list above"
    fi
  fi

  # Every stdin-reading command in a remote heredoc needs </dev/null.
  #
  # The body of a remote block is piped into `ssh ... bash -s`, so the script
  # text IS file descriptor 0. `docker compose exec -T` reads stdin, and bash
  # reads the script lazily, one compound command at a time: the exec swallowed
  # everything bash had not parsed yet. Deploy run 6 (TS 20260903-0259) is what
  # that looks like from the outside. The two `inline` lines came out fine,
  # because the whole for-loop was already parsed before it ran, and then the
  # echo below it was simply gone. Phase 6h stopped on "the server never
  # printed 'effective outbound buffers'", and 6i and the phase 7a marker never
  # ran at all, which left the next run with no marker to gate on.
  step "6h. the inline receipt opt-in really works end to end (#342)"
  remote "inline receipt config" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
for svc in relay-main relay-iot; do
  printf 'inline %-12s ' "$svc"
  docker compose exec -T "$svc" sh -c 'v=$(printenv PARAMANT_INLINE_RECEIPT_HEADER); [ -n "$v" ] && echo "$v" || echo empty' </dev/null 2>/dev/null || echo unreadable
done
# The effective config, not the file: nginx -T is what is actually loaded.
echo "effective outbound buffers = $(nginx -T 2>/dev/null | grep -c 'proxy_buffer_size 32k' || true)"
EOF
  expect 'inline relay-main +1' "relay-main runs with PARAMANT_INLINE_RECEIPT_HEADER=1"
  expect 'inline relay-iot +1'  "relay-iot runs with PARAMANT_INLINE_RECEIPT_HEADER=1"
  expect_min "effective outbound buffers" 1 "the loaded nginx config carries the raised proxy buffers"

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ curl -sI https://relay.paramant.app/v2/outbound/<64 hex that never existed>\n'
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): /v2/outbound proxies without a 502\n'
    printf '  SKIP  assert (dry-run): a real download carries the inline receipt (needs PARAMANT_SMOKE_API_KEY)\n'
  else
    # Keyless: the location proxies at all, and does not answer 502.
    local miss code
    miss="$(openssl rand -hex 32)"
    code="$(http_code "https://relay.paramant.app/v2/outbound/$miss")"
    printf '  outbound miss code = %s\n' "$code"
    case "$code" in
      5*) die "/v2/outbound answered $code for a hash that never existed; the location is not proxying cleanly" ;;
    esac
    ok "/v2/outbound proxies without a 5xx (answered $code for an unknown hash)"

    # The real proof needs an account, so it is opt-in. Without a key the
    # script says exactly what it could not check rather than implying it did.
    if [ -n "${PARAMANT_SMOKE_API_KEY:-}" ]; then
      local tmp payload hash body hdr up dn size
      tmp="$(mktemp)"; hdr="$(mktemp)"; body="$(mktemp)"
      head -c 4096 /dev/urandom > "$tmp"
      hash="$(sha256sum "$tmp" | cut -d" " -f1)"
      payload="$(base64 -w0 "$tmp")"
      printf '{"hash":"%s","payload":"%s"}' "$hash" "$payload" > "$body"
      up="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
            -X POST https://relay.paramant.app/v2/inbound \
            -H "X-Api-Key: $PARAMANT_SMOKE_API_KEY" \
            -H 'Content-Type: application/json' --data-binary "@$body")"
      printf '  smoke upload code = %s\n' "$up"
      case "$up" in
        20*) : ;;
        *) rm -f "$tmp" "$hdr" "$body"; die "smoke upload answered $up; cannot test the receipt header" ;;
      esac
      dn="$(curl -s -o /dev/null -D "$hdr" -w '%{http_code}' --max-time 30 \
            -H "X-Api-Key: $PARAMANT_SMOKE_API_KEY" \
            "https://relay.paramant.app/v2/outbound/$hash")"
      size="$(stat -c%s "$hdr")"
      printf '  smoke download code = %s, response header block = %s bytes\n' "$dn" "$size"
      # Header names only. The receipt itself is never printed.
      grep -io '^x-paramant-receipt[a-z-]*:' "$hdr" | sort -u | sed 's/^/  header /' || true
      [ "$dn" = "200" ] || { rm -f "$tmp" "$hdr" "$body"; die "smoke download answered $dn, expected 200 (502 means the proxy buffers are still too small)"; }
      grep -qi '^x-paramant-receipt:' "$hdr" \
        || { rm -f "$tmp" "$hdr" "$body"; die "no inline X-Paramant-Receipt header; the opt-in did not take"; }
      local f
      for f in id hash url; do
        grep -qi "^x-paramant-receipt-$f:" "$hdr" \
          || { rm -f "$tmp" "$hdr" "$body"; die "the download is missing X-Paramant-Receipt-$f, the reference shape #342 added"; }
      done
      grep -qi '^x-paramant-receipt-deprecated:' "$hdr" \
        && warn "the deprecation header is present alongside the inline one; the relay thinks the opt-in is off"
      ok "the download carries both the inline receipt and the id/hash/url reference"
      if [ "$size" -gt 16000 ]; then
        ok "a real download returned 200 with a ${size}-byte header block, so nginx carried the fat inline receipt through the raised buffers"
      else
        # No ok line here on purpose: the summary must not read as if the
        # oversized-header path was proven when it was not.
        warn "NOT PROVEN: the header block was only ${size} bytes, under the 16 KB that makes this test meaningful. The download worked, but the oversized-header path through nginx is untested."
      fi
      rm -f "$tmp" "$hdr" "$body"
    else
      warn "PARAMANT_SMOKE_API_KEY is not set: NOT proven that a real download returns the inline receipt through nginx without a 502. Only the config was checked. Set the variable to a ParaSend key to run the full test."
    fi
  fi

  step "6i. billing stance once more, from every relay log"
  remote "billing stance" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
for svc in relay-main relay-health relay-finance relay-legal relay-iot; do
  cid="$(docker compose ps -q "$svc")"
  printf 'stance %-14s ' "$svc"
  docker logs "$cid" 2>&1 | grep '"billing_config"' | tail -1 | grep -o '"recurring":[a-z]*' || echo "no billing_config line"
done
EOF
  expect_not '"recurring":true' "every relay still reports recurring:false"
}

# =============================================================== PHASE V =====

# --verify-only: finish a deploy that got its work done and then died in the
# checks. Run 6 (TS 20260903-0259) is the case it exists for: phases 3, 4 and 5
# all landed, six containers on 3.1.0, the nginx edits applied, the site live,
# and then 6h stopped on a swallowed line. Re-running the whole script would
# re-tag, re-back-up, re-pull, rebuild and recreate six healthy containers to
# get at two checks and one marker file. This mode runs phases 6 and 7 and
# nothing else: no tags, no backups, no pull, no build, no recreate, no nginx
# edit, no .env write.
#
# That is only safe when the server really is already deployed, so this phase
# is the gate, in the same spirit as phase 1a: the checkout has to BE the
# commit that would have been deployed, and the containers have to be running
# the version that checkout describes. Anything else and the mode refuses,
# because "verify" on a half-deployed server would sign off on nothing.
phase_v() {
  phase V "Preconditions for --verify-only (server, read-only)" "no runbook step; this mode replaces one"

  step "Va. the checkout is origin/main and the running relay matches it"
  remote "verify preconditions" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
# Fetch so origin/main is the real one, not a stale ref. It moves no file.
git fetch origin >/dev/null 2>&1 || true
echo "verify head = $(git rev-parse HEAD)"
echo "verify head short = $(git rev-parse --short HEAD)"
echo "verify origin main = $(git rev-parse origin/main 2>/dev/null || echo unknown)"
# The version the checkout describes, and the version the containers report.
# These have to agree, or the containers were not built from this checkout.
echo "verify package version = $(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' package.json | head -1)"
echo "verify health version = $(curl -s --max-time 5 http://127.0.0.1:3000/health </dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -1)"
EOF

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  SKIP  assert (dry-run): the checkout is origin/main and the relay reports the package version
'
    return 0
  fi

  local head omain pkg health
  head="$(remote_field 'verify head')"
  omain="$(remote_field 'verify origin main')"
  pkg="$(remote_field 'verify package version')"
  health="$(remote_field 'verify health version')"

  [ -n "$head" ] || die "the server never printed the commit its checkout is on"
  [ -n "$omain" ] && [ "$omain" != unknown ]     || die "the server could not resolve origin/main, so there is nothing to compare the checkout against"
  sha_eq "$head" "$omain"     || die "--verify-only needs a server that is already deployed: the checkout is on ${head:0:7} and origin/main is ${omain:0:7}. Run the full deploy instead"
  ok "the server checkout is on origin/main (${head:0:7})"

  [ -n "$pkg" ] || die "could not read the version out of package.json in the server checkout"
  [ -n "$health" ] || die "/health did not report a version, so the relay is not up; --verify-only has nothing to verify"
  [ "$pkg" = "$health" ]     || die "/health reports $health but the checkout describes $pkg, so the containers were not built from this checkout. Run the full deploy instead"
  ok "the running relay reports $health, the version the checkout describes"

  note "no tag, backup, pull, build, recreate or nginx edit will run in this mode"
}

# =============================================================== PHASE 7 =====

phase_7() {
  phase 7 "Summary" "Step 7, what to do after the deploy"

  step "7a. record the deployed commit, so the next run's phase 1a has a gate"
  note "without this marker the next run falls back to $EXPECT_PROD_COMMIT and stops:"
  note "that is exactly the gate that made this script single-use"
  remote "record deployed head" "$COMPOSE_DIR" "$BACKUP_DIR" "$DEPLOYED_HEAD_FILE" <<'EOF'
set -euo pipefail
cd "$1"
BK="$2"; MARKER="$3"
mkdir -p "$BK"
if [ -f "$MARKER" ]; then
  echo "before deployed marker = $(tr -d '[:space:]' < "$MARKER")"
else
  echo "before deployed marker = none"
fi
# The checkout is the source the containers were built from, so the checkout is
# what the marker names. Read it here rather than being told, so the file can
# never claim something the server is not on.
head="$(git rev-parse HEAD)"
tmp="$MARKER.tmp.$$"
printf '%s\n' "$head" > "$tmp"
chmod 644 "$tmp"
mv -f "$tmp" "$MARKER"
echo "after deployed marker = $(tr -d '[:space:]' < "$MARKER")"
echo "after deployed marker short = $(git rev-parse --short HEAD)"
EOF

  if [ "$DRY_RUN" -eq 0 ]; then
    local wrote
    wrote="$(remote_field 'after deployed marker')"
    [ -n "$wrote" ] \
      || die "could not write $DEPLOYED_HEAD_FILE; the next deploy would fall back to $EXPECT_PROD_COMMIT and stop on phase 1a"
    if [ -n "$DEPLOYED_HEAD" ] && [ "$wrote" != "$DEPLOYED_HEAD" ]; then
      die "the marker says $wrote but phase 3 left the checkout on $DEPLOYED_HEAD"
    fi
    ok "deployed-head marker written: ${wrote:0:7} in $DEPLOYED_HEAD_FILE (the next run gates on this, not on $EXPECT_PROD_COMMIT)"
  fi

  echo
  echo "Result lines, in order:"
  printf '%s\n' "$SUMMARY"
  echo
  printf '  warnings      %s\n' "$WARNINGS"
  printf '  run TS        %s\n' "$TS"
  printf '  rollback with bash deploy/deploy-3.1.sh --rollback %s\n' "$TS"
  printf '  log           %s\n' "$LOG"
  echo
  echo "Still by hand, on purpose (runbook step 7):"
  echo "  1. watch thirty minutes: docker compose logs -f --tail=200 relay-main"
  echo "  2. mint the ParaSign canary key and set PARASIGN_CANARY_KEY as an"
  echo "     Actions secret, then dispatch product-heartbeat.yml once"
  echo "  3. scripts/check-prod-drift.sh origin/main must print OK"
  echo "  4. git tag v$EXPECT_VERSION <commit> and push it, put the live date in CHANGELOG.md"
  echo "  5. write the deploy down in the vault, with the billing_config line as logged"
  echo
  echo "BILLING_MODE stays empty. Turning the recurring layer on is a separate"
  echo "change that needs a Mollie test key first (runbook, 'Deciding on the"
  echo "recurring layer, later, not today')."
}

# =============================================================== PHASE 8 =====

phase_8() {
  phase 8 "Rollback to $ROLLBACK_TS (server, WRITE)" "Step 8"

  step "8a. the manifest, the saved images and the backups this rollback needs"
  remote_nginx "rollback preconditions" "$COMPOSE_DIR" "$ROLLBACK_TS" "$BACKUP_DIR" "$NGINX_BACKUP_DIR" "$NGINX_SITES" "$NGINX_CONF_SLOTS" <<'EOF'
set -euo pipefail
cd "$1"
TS="$2"; BK="$3"; NGBK="$4"; SITES="$5"; SLOTS="$6"
M="$BK/rollback-images-$TS.txt"
[ -f "$M" ] || { echo "FATAL no manifest $M"; exit 1; }
echo "manifest lines = $(wc -l < "$M")"
sed 's/^/  manifest /' "$M"

missing=0
while IFS='|' read -r svc image rbtag; do
  [ -n "${svc:-}" ] || continue
  if docker image inspect "$rbtag" >/dev/null 2>&1; then
    echo "  present $rbtag"
  else
    echo "  MISSING $rbtag"
    missing=$((missing + 1))
  fi
done < "$M"
echo "missing rollback images = $missing"

# Everything 8c will restore has to be here BEFORE 8b starts recreating, so a
# half rollback is impossible.
absent=0
for f in "$BK/.env-pre-3.1-$TS" "$BK/docroot-pre-3.1-$TS.tgz"; do
  if [ -f "$f" ]; then
    echo "  backup present $f ($(stat -c%s "$f") bytes)"
  else
    echo "  backup MISSING $f"
    absent=$((absent + 1))
  fi
done
# The backups were filed under the name phase 2b resolved, so resolve again
# instead of guessing: on this server the slot may well be paramant.conf.
resolve_conf_slots "$SITES" "$SLOTS"
absent=$((absent + RESOLVED_MISSING))
for name in $RESOLVED_CONFS; do
  f="$NGBK/$name.pre-3.1-$TS"
  if [ -f "$f" ]; then
    echo "  backup present $f ($(stat -c%s "$f") bytes)"
  else
    echo "  backup MISSING $f"
    absent=$((absent + 1))
  fi
done
echo "missing backups = $absent"
EOF
  expect_not 'FATAL no manifest' "the manifest for $ROLLBACK_TS exists"
  expect_count "manifest lines" 6 "the manifest still has its six lines"
  expect_count "missing rollback images" 0 "every rollback image from $ROLLBACK_TS is still on the host"
  expect_count "missing backups" 0 "every .env, docroot and nginx backup this rollback needs is present"

  step "8b. restore .env first, then retag the saved images and recreate all six"
  note ".env goes back before the containers, so the recreate reads the old file"
  remote "rollback images and env" "$COMPOSE_DIR" "$ROLLBACK_TS" "$BACKUP_DIR" <<'EOF'
set -euo pipefail
cd "$1"
TS="$2"; BK="$3"
M="$BK/rollback-images-$TS.txt"

echo "before .env bytes = $(stat -c%s .env)"
cp -a .env ".env.bak-rollback-$TS"
cp "$BK/.env-pre-3.1-$TS" .env
chmod 600 .env
echo "after .env bytes = $(stat -c%s .env)"

SVCS=""
while IFS='|' read -r svc image rbtag; do
  [ -n "${svc:-}" ] || continue
  cid="$(docker compose ps -q "$svc" 2>/dev/null || true)"
  if [ -n "$cid" ]; then
    echo "before $svc image = $(docker inspect -f '{{.Image}}' "$cid")"
  else
    echo "before $svc image = none"
  fi
  docker tag "$rbtag" "$image"
  SVCS="$SVCS $svc"
done < "$M"

# shellcheck disable=SC2086
docker compose up -d --no-deps --force-recreate $SVCS 2>&1 | sed 's/^/  up /'

n=0
for svc in $SVCS; do
  cid="$(docker compose ps -q "$svc" 2>/dev/null || true)"
  if [ -n "$cid" ]; then
    echo "after $svc image = $(docker inspect -f '{{.Image}}' "$cid")"
    n=$((n + 1))
  else
    echo "after $svc image = none"
  fi
done
echo "after recreated services = $n"
EOF
  expect_count "after recreated services" 6 "all six services came back on their saved images"

  step "8c. restore the nginx confs and the docroot"
  remote_nginx "rollback nginx and docroot" "$ROLLBACK_TS" "$BACKUP_DIR" "$DOCROOT" "$NGINX_BACKUP_DIR" "$NGINX_SITES" "$NGINX_CONF_SLOTS" "$DOCROOT_IGNORE" <<'EOF'
set -euo pipefail
TS="$1"; BK="$2"; DOCROOT="$3"; NGBK="$4"; SITES="$5"; SLOTS="$6"; IGNORE="$7"

resolve_conf_slots "$SITES" "$SLOTS"
if [ "$RESOLVED_MISSING" -ne 0 ]; then
  echo "FATAL $RESOLVED_MISSING nginx conf slot(s) have no candidate in $SITES"
  exit 1
fi

n=0
for name in $RESOLVED_CONFS; do
  b="$NGBK/$name.pre-3.1-$TS"
  [ -f "$b" ] || { echo "FATAL missing nginx backup $b"; exit 1; }
  target="$(readlink -f "$SITES/$name")"
  echo "before nginx $name bytes = $(stat -c%s "$target")"
  cp -a "$b" "$target"
  echo "after nginx $name bytes = $(stat -c%s "$target")"
  n=$((n + 1))
done
echo "restored nginx confs = $n"

# Test before reload. A reload on a broken conf keeps the old workers alive and
# hides the breakage until the next restart.
rc=0
nginx -t > /tmp/paramant-nginxt.$$ 2>&1 || rc=$?
sed 's/^/  nginxt /' /tmp/paramant-nginxt.$$
rm -f /tmp/paramant-nginxt.$$
[ "$rc" -eq 0 ] || { echo "FATAL nginx -t failed on the restored conf; not reloading"; exit 1; }
systemctl reload nginx
echo "reloaded nginx"

TAR="$BK/docroot-pre-3.1-$TS.tgz"
[ -f "$TAR" ] || { echo "FATAL missing docroot tar $TAR"; exit 1; }
echo "before docroot files = $(find "$DOCROOT" -type f | wc -l)"

# tar x overlays: it puts back what phase 5 changed or removed, but it does NOT
# remove what phase 5 ADDED. Delete those first, so the docroot really is the
# pre-deploy one. Anything on the drift guard IGNORE list is left alone.
base="$(basename "$DOCROOT")"
tar tzf "$TAR" | sed -e "s|^\./||" -e "s|^$base/||" -e '/\/$/d' | sort -u > /tmp/paramant-intar.$$
( cd "$DOCROOT" && find . -type f | sed 's|^\./||' | sort -u ) > /tmp/paramant-onserver.$$
added=0
kept=0
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  skip=no
  for ig in $IGNORE; do
    case "$rel" in
      "$ig"|"$ig"/*) skip=yes ;;
    esac
  done
  if [ "$skip" = yes ]; then
    kept=$((kept + 1))
    continue
  fi
  rm -f "$DOCROOT/$rel"
  echo "  removed added-by-deploy $rel"
  added=$((added + 1))
done < <(comm -13 /tmp/paramant-intar.$$ /tmp/paramant-onserver.$$)
rm -f /tmp/paramant-intar.$$ /tmp/paramant-onserver.$$
echo "removed files the deploy added = $added"
echo "kept on ignore list = $kept"

tar xzf "$TAR" -C "$(dirname "$DOCROOT")"
echo "after docroot files = $(find "$DOCROOT" -type f | wc -l)"
EOF
  expect_not 'FATAL' "nginx confs and docroot restored, nginx tested clean before the reload"
  expect_count "restored nginx confs" "$NGINX_SLOT_COUNT" "every resolved nginx conf came back"
  expect 'reloaded nginx' "nginx reloaded on the restored conf"

  step "8d. health after the rollback"
  remote "rollback health" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
ok=no
for _ in $(seq 1 30); do
  if curl -fs --max-time 3 http://127.0.0.1:3000/health >/dev/null 2>&1; then ok=yes; break; fi
  sleep 2
done
echo "rollback relay health = $ok"
echo "rollback version = $(curl -s --max-time 5 http://127.0.0.1:3000/health | grep -o '"version":"[^"]*"' || echo unknown)"
cid="$(docker compose ps -q relay-main)"
echo "rollback paraidAuth occurrences = $(docker exec "$cid" grep -c _paraidAuth /app/relay.js </dev/null 2>/dev/null || echo 0)"
EOF
  expect 'rollback relay health = yes' "the relay answers /health after the rollback"

  step "8e. smoke tests after the rollback"
  if run_gated bash tests/auth-smoke.sh https://paramant.app; then
    [ "$DRY_RUN" -eq 0 ] && ok "auth-smoke.sh passed after the rollback"
  else
    [ "$DRY_RUN" -eq 0 ] && warn "auth-smoke.sh failed after the rollback; the site needs hands, not another script"
  fi
  if [ "$DRY_RUN" -eq 0 ]; then
    local h code
    for h in $HOSTS; do
      code="$(http_code "https://$h/health")"
      printf '  health %-26s %s\n' "$h" "$code"
      [ "$code" = "200" ] || warn "/health on $h answered $code after the rollback"
    done
  else
    printf '\n  $ curl -s -o /dev/null -w %%{http_code} https://<host>/health   # six hosts\n'
    printf '  [dry-run] not executed\n'
  fi

  echo
  echo "Rollback summary:"
  printf '%s\n' "$SUMMARY"
  printf '\n  warnings      %s\n' "$WARNINGS"
  printf '  log           %s\n' "$LOG"
  echo
  echo "The checkout stays on main; the images are what run. Decide separately"
  echo "whether to move the checkout back."
  echo
  echo "The deployed-head marker is left as it is on purpose: it names the"
  echo "COMMIT THE CHECKOUT IS ON, and this rollback did not move the checkout."
  echo "If you do move it back by hand, either update"
  printf '%s\n' "  $DEPLOYED_HEAD_FILE to match, or run the next deploy with"
  echo "  PARAMANT_EXPECTED_HEAD=<the commit you moved to>."
}

# ------------------------------------------------------------------- driver --

if [ -n "$ROLLBACK_TS" ]; then
  phase_8
  echo
  hr
  echo "ROLLBACK FINISHED, warnings: $WARNINGS"
  hr
  exit 0
fi

if [ "$VERIFY_ONLY" -eq 1 ]; then
  phase_v
  phase_6
  phase_7
  echo
  hr
  echo "VERIFY ONLY FINISHED, warnings: $WARNINGS"
  hr
  exit 0
fi

phase_0
phase_1

if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  echo
  hr
  echo "PREFLIGHT ONLY: phases 0 and 1 done. Read-only for the working tree and"
  echo "the containers: no file was written, no container touched, no nginx conf"
  echo "changed. The one thing that did run is git fetch in phase 1a, which"
  echo "updates remote-tracking refs so the ancestor test judges against the real"
  echo "origin/main. It does not move HEAD and does not check anything out."
  printf 'Warnings: %s. Log: %s\n' "$WARNINGS" "$LOG"
  hr
  exit 0
fi

phase_2
phase_3
phase_4
phase_5
phase_6
phase_7

echo
hr
echo "DEPLOY FINISHED, warnings: $WARNINGS"
hr
