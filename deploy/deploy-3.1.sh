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
#   bash deploy/deploy-3.1.sh --dry-run        print every remote and gated
#                                              command instead of running it
#
# Flags combine: --dry-run --preflight-only, --dry-run --rollback <TS>.
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
# reviewed. Override only if the server names them differently.
NGINX_CONFS="${PARAMANT_NGINX_CONFS:-paramant-public.conf paramant-live.conf}"

# Present on the server by design, absent from the repo. Same list as
# scripts/check-prod-drift.sh: these are never pruned from the docroot.
DOCROOT_IGNORE="dist paramant-mark.svg developer.js docs/paramant-investor-brief.html"

DEPLOY_REF="${DEPLOY_REF:-origin/main}"
EXPECT_PROD_COMMIT="${EXPECT_PROD_COMMIT:-41501bb}"   # runbook: where we start
EXPECT_VERSION="3.1.0"
SERVICES="relay-main relay-health relay-finance relay-legal relay-iot admin"
HOSTS="paramant.app health.paramant.app legal.paramant.app finance.paramant.app iot.paramant.app relay.paramant.app"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SSH_OPTS=(-i "$PROD_KEY" -o BatchMode=yes -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
SSH_SHOWN="ssh -i <prod-key> -o BatchMode=yes -o IdentitiesOnly=yes $PROD_HOST"

DRY_RUN=0
PREFLIGHT_ONLY=0
ROLLBACK_TS=""
REMOTE_OUT=""
REMOTE_RC=0
PREV_HEAD=""
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
printf '  nginx confs   %s\n' "$NGINX_CONFS"
printf '  deploy ref    %s\n' "$DEPLOY_REF"
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

  step "0a. CI on main"
  run_gated gh run list --branch main -L 5 || warn "gh run list did not succeed; check CI on main by hand"
  if [ "$DRY_RUN" -eq 0 ]; then
    local concl
    concl="$(gh run list --branch main -L 5 --json conclusion --jq '.[].conclusion' 2>/dev/null || echo UNKNOWN)"
    printf '  conclusions: %s\n' "$(printf '%s' "$concl" | tr '\n' ' ')"
    if printf '%s\n' "$concl" | grep -qx 'failure'; then
      die "CI on main has a failing run in the last 5; the runbook wants main green"
    fi
    if printf '%s\n' "$concl" | grep -qx 'UNKNOWN'; then
      warn "could not read CI conclusions from gh; check main by hand before continuing"
    else
      ok "CI on main: no failing run in the last 5"
    fi
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
  remote "layout and health" "$COMPOSE_DIR" "$SERVICES" <<'EOF'
set -euo pipefail
cd "$1"
echo "checkout_head = $(git rev-parse --short HEAD)"
echo "checkout_dir = $PWD"
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

  expect "checkout_head = $EXPECT_PROD_COMMIT" \
    "production checkout is on $EXPECT_PROD_COMMIT, the commit the runbook measured"
  expect_count "services seen" 6 "all six services have a container"
  expect_not 'container [a-z-]+ MISSING' "no service is missing a container"
  expect_not 'unhealthy' "no container reports unhealthy"

  step "1b. environment presence (never values)"
  remote "env presence" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
for v in BILLING_MODE MOLLIE_API_KEY MOLLIE_TEST_API_KEY INTERNAL_AUTH_TOKEN ADMIN_TOKEN PARAMANT_TOTP_MASTER_KEY RELAY_REDIS_URL PARAMANT_INLINE_RECEIPT_HEADER; do
  printf 'env %-26s ' "$v"
  docker compose exec -T relay-main sh -c \
    "v=\$(printenv $v); if [ -z \"\$v\" ]; then echo empty; else echo \"set, prefix \$(printf %s \"\$v\" | cut -c1-5)\"; fi" \
    2>/dev/null || echo "unreadable"
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
  img="$(docker inspect --format '{{.Config.Image}}' "$cid")"
  docker tag "$img" "paramant-rollback/$svc:$TS"
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
  remote "backups" "$COMPOSE_DIR" "$TS" "$BACKUP_DIR" "$DOCROOT" "$NGINX_BACKUP_DIR" "$NGINX_SITES" "$NGINX_CONFS" <<'EOF'
set -euo pipefail
cd "$1"
TS="$2"; BK="$3"; DOCROOT="$4"; NGBK="$5"; NGSITES="$6"; CONFS="$7"
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

# sites-enabled entries are usually symlinks into sites-available. cp -a of a
# symlink copies the link, not the file, which is not a backup: resolve first.
n=0
for name in $CONFS; do
  link="$NGSITES/$name"
  if [ ! -e "$link" ]; then
    echo "nginxconf $name ABSENT"
    continue
  fi
  target="$(readlink -f "$link")"
  echo "nginxconf $name -> $target ($(stat -c%s "$target") bytes)"
  cp -a "$target" "$NGBK/$name.pre-3.1-$TS"
  echo "nginxbackup $name.pre-3.1-$TS $(stat -c%s "$NGBK/$name.pre-3.1-$TS") bytes"
  n=$((n + 1))
done
echo "after nginx conf backups = $n"

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
  expect_count "after nginx conf backups" 2 "both named nginx confs were resolved and backed up"
  expect_not 'nginxconf [a-z.-]+ ABSENT' \
    "both named nginx confs exist on the server (set PARAMANT_NGINX_CONFS if they are named differently)"
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
if [ -n "$(git status --porcelain)" ]; then
  git status --porcelain | sed 's/^/  dirty /'
  echo "FATAL working tree not clean; stash and note what it was before deploying"
  exit 1
fi
git fetch origin 2>&1 | sed 's/^/  fetch /' || true
git pull --ff-only origin main 2>&1 | sed 's/^/  pull /'
echo "after HEAD = $(git rev-parse --short HEAD)"
echo "after HEAD long = $(git rev-parse HEAD)"
EOF

  expect_not 'FATAL working tree not clean' "server working tree was clean before the pull"
  if [ "$DRY_RUN" -eq 0 ]; then
    local after_head want
    PREV_HEAD="$(remote_field 'before HEAD long')"
    after_head="$(remote_field 'after HEAD long')"
    want="$(git rev-parse "$DEPLOY_REF")"
    [ -n "$after_head" ] || die "could not read the server HEAD after the pull"
    [ "$after_head" = "$want" ] \
      || die "server is on $after_head after the pull, expected $want ($DEPLOY_REF, the commit phase 0 tested)"
    ok "server checkout is on ${after_head:0:7}, the commit phase 0 tested"
    if ! printf '%s\n' "$REMOTE_OUT" | grep -q "before HEAD = $EXPECT_PROD_COMMIT"; then
      warn "server was not on $EXPECT_PROD_COMMIT before the pull; the rollback images are still correct, but the runbook's starting point was different"
    fi
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

  local base="${PREV_HEAD:-$EXPECT_PROD_COMMIT}"

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
  remote "prune deleted frontend files" "$COMPOSE_DIR" "$DOCROOT" "$base" "$DOCROOT_IGNORE" <<'EOF'
set -euo pipefail
cd "$1"
DOCROOT="$2"; BASE="$3"; IGNORE="$4"

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
  expect_min "before deleted-in-git count" 1 \
    "git names at least one frontend file deleted since the deployed commit"
  expect_count "after refused outside docroot" 0 \
    "no deletion resolved to a path outside the docroot"
  if [ "$DRY_RUN" -eq 0 ]; then
    local rm_n ab_n
    rm_n="$(remote_field 'after removed')"
    ab_n="$(remote_field 'after already absent')"
    ok "pruned $rm_n stale docroot file(s), $ab_n were already gone"
  fi

  step "5c. the three nginx changes, by hand, keeping the ParaID deny"
  remote "nginx edits" "$TS" "$NGINX_SITES" "$NGINX_BACKUP_DIR" "$NGINX_CONFS" <<'EOF'
set -euo pipefail
TS="$1"; SITES="$2"; NGBK="$3"; CONFS="$4"

# Resolve the two named confs to real files. A symlink is not the file.
TARGETS=""
for name in $CONFS; do
  link="$SITES/$name"
  if [ ! -e "$link" ]; then
    echo "FATAL named nginx conf $name does not exist in $SITES"
    exit 1
  fi
  t="$(readlink -f "$link")"
  echo "target $name -> $t"
  TARGETS="$TARGETS $t"
done

count() { grep -hcE -- "$1" $TARGETS 2>/dev/null | awk '{s+=$1} END{print s+0}'; }

SIGN_RE='location = /sign[[:space:]]*\{[^}]*auth_request'
COMP_RE='^[[:space:]]*location = /compliance(/(nis2|iec62443|nen7510))?[[:space:]]*\{'
DICOM_RE='location = /dicom[[:space:]]*\{[[:space:]]*try_files /dicom\.html'
PARAID_RE='paraid/issue'
OUT_RE='^[[:space:]]*location[[:space:]]*~[[:space:]]*\^/v2/outbound[[:space:]]*\{'
BUF_RE='proxy_buffer_size 32k'

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
echo "before compliance = $(count "$COMP_RE")"
echo "before dicom try_files = $(count "$DICOM_RE")"
echo "before paraid deny = $(count "$PARAID_RE")"
read -r _obt _obw <<< "$(count_blocks)"
echo "before outbound locations = $_obt"
echo "before outbound blocks with buffer = $_obw"

# Each edit must have something to do. A zero here means the server conf is not
# the shape the runbook describes, and guessing further would be editing blind.
for pair in "sign:$(count "$SIGN_RE")" "compliance:$(count "$COMP_RE")" "dicom:$(count "$DICOM_RE")"; do
  n="${pair#*:}"
  if [ "$n" -eq 0 ]; then
    echo "FATAL nothing to change for '${pair%%:*}': the server conf does not match the pattern the runbook names"
    exit 1
  fi
done
if [ "$(count "$PARAID_RE")" -eq 0 ]; then
  echo "FATAL the ParaID deny is not present; the 01-09 server edit this runbook relies on is gone"
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
  if ! cmp -s "$f" "/tmp/nginx-pre-3.1-$(basename "$f").$TS"; then
    echo "edited $(basename "$f")"
    edited=$((edited + 1))
  fi
done
echo "after edited files = $edited"
echo "after sign gated = $(count "$SIGN_RE")"
echo "after compliance = $(count "$COMP_RE")"
echo "after dicom try_files = $(count "$DICOM_RE")"
echo "after dicom 404 = $(count 'location = /dicom[[:space:]]*\{[[:space:]]*return 404')"
echo "after paraid deny = $(count "$PARAID_RE")"
read -r _oat _oaw <<< "$(count_blocks)"
echo "after outbound locations = $_oat"
echo "after outbound blocks with buffer = $_oaw"

restore() {
  for b in "$NGBK"/*.pre-3.1-"$TS"; do
    [ -f "$b" ] || continue
    name="$(basename "$b" ".pre-3.1-$TS")"
    cp -a "$b" "$(readlink -f "$SITES/$name")"
  done
}

if [ "$(count "$PARAID_RE")" -eq 0 ]; then
  echo "FATAL the ParaID deny disappeared; restoring"
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
  expect_count "after edited files" 2 "both named confs were really rewritten"
  expect_count "after sign gated" 0 "/sign is no longer behind auth_request"
  expect_count "after compliance" 0 "the /compliance locations are gone"
  expect_count "after dicom try_files" 0 "/dicom no longer serves the page"
  expect_min "after dicom 404" 1 "/dicom now returns 404"
  expect_min "before outbound locations" 1 "the /v2/outbound location the buffers go on exists"
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

  step "6h. the inline receipt opt-in really works end to end (#342)"
  remote "inline receipt config" "$COMPOSE_DIR" <<'EOF'
set -euo pipefail
cd "$1"
for svc in relay-main relay-iot; do
  printf 'inline %-12s ' "$svc"
  docker compose exec -T "$svc" sh -c 'v=$(printenv PARAMANT_INLINE_RECEIPT_HEADER); [ -n "$v" ] && echo "$v" || echo empty' 2>/dev/null || echo unreadable
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

# =============================================================== PHASE 7 =====

phase_7() {
  phase 7 "Summary" "Step 7, what to do after the deploy"

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
  remote "rollback preconditions" "$COMPOSE_DIR" "$ROLLBACK_TS" "$BACKUP_DIR" "$NGINX_BACKUP_DIR" "$NGINX_CONFS" <<'EOF'
set -euo pipefail
cd "$1"
TS="$2"; BK="$3"; NGBK="$4"; CONFS="$5"
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
for name in $CONFS; do
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
  remote "rollback nginx and docroot" "$ROLLBACK_TS" "$BACKUP_DIR" "$DOCROOT" "$NGINX_BACKUP_DIR" "$NGINX_SITES" "$NGINX_CONFS" "$DOCROOT_IGNORE" <<'EOF'
set -euo pipefail
TS="$1"; BK="$2"; DOCROOT="$3"; NGBK="$4"; SITES="$5"; CONFS="$6"; IGNORE="$7"

n=0
for name in $CONFS; do
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
  expect_count "restored nginx confs" 2 "both named nginx confs came back"
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
echo "rollback paraidAuth occurrences = $(docker exec "$cid" grep -c _paraidAuth /app/relay.js 2>/dev/null || echo 0)"
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

phase_0
phase_1

if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  echo
  hr
  echo "PREFLIGHT ONLY: phases 0 and 1 done, read-only. Nothing was written."
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
