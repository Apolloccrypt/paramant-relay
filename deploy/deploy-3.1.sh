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
#   bash deploy/deploy-3.1.sh --preflight-only phases 0 and 1, then stop
#   bash deploy/deploy-3.1.sh --rollback <TS>  phase 8, back to the <TS> backup
#   bash deploy/deploy-3.1.sh --dry-run        print every remote and gated
#                                              command instead of running it
#
# Flags combine: --dry-run --preflight-only, --dry-run --rollback <TS>.
#
# Secrets: this script never prints a key value. Environment variables are
# reported as "empty" or "set, prefix <first 5 chars>", which is the shape the
# runbook's own step 1 uses. No remote block runs under set -x.
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

DEPLOY_REF="${DEPLOY_REF:-origin/main}"
EXPECT_PROD_COMMIT="${EXPECT_PROD_COMMIT:-41501bb}"   # runbook: where we start
EXPECT_VERSION="3.1.0"
SERVICES="relay-main relay-health relay-finance relay-legal relay-iot admin"
HOSTS="paramant.app health.paramant.app legal.paramant.app finance.paramant.app iot.paramant.app relay.paramant.app"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SSH_OPTS=(-i "$PROD_KEY" -o BatchMode=yes -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
SSH_SHOWN="ssh -i <prod-key> -o BatchMode=yes -o IdentitiesOnly=yes $PROD_HOST 'bash -s'"

DRY_RUN=0
PREFLIGHT_ONLY=0
ROLLBACK_TS=""
REMOTE_OUT=""
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

# Evidence around a step that changes the server. Both lines always print, so
# the log shows the state the change was applied to and the state it produced.
evidence() { printf '  %-7s %s\n' "$1" "$2"; }

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

# remote: run a heredoc on the server over one ssh call. Arguments after the
# label are passed to the remote bash as $1, $2, ... so nothing has to be
# interpolated into the heredoc body locally.
remote() {
  local label="$1"; shift
  local body rc=0
  body="$(cat)"
  printf '\n  $ %s -- %s   # %s\n' "$SSH_SHOWN" "$*" "$label"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s\n' "$body" | sed 's/^/  [dry-run] > /'
    REMOTE_OUT=""
    return 0
  fi
  REMOTE_OUT="$(printf '%s\n' "$body" | ssh "${SSH_OPTS[@]}" "$PROD_HOST" 'bash -s' -- "$@" 2>&1)" || rc=$?
  printf '%s\n' "$REMOTE_OUT" | sed 's/^/  | /'
  return $rc
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
[ "$PREFLIGHT_ONLY" -eq 1 ] && MODE="preflight only (phases 0 and 1)"
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
      warn "prod drift guard reported drift or could not check; read the list above before phase 5 overwrites the docroot"
    fi
  fi

  step "0d. the timestamp this run is named by"
  printf '  TS = %s (rollback tags, backups and the manifest all carry it)\n' "$TS"
  ok "run timestamp fixed at $TS"
}

# =============================================================== PHASE 1 =====

phase_1() {
  phase 1 "Layout and environment (server, read-only, one write)" "Step 1"

  step "1a. checkout, compose project and container health"
  remote "layout and health" "$COMPOSE_DIR" "$SERVICES" <<'EOF'
set -uo pipefail
cd "$1" || { echo "FATAL cannot cd to $1"; exit 1; }
echo "checkout_head=$(git rev-parse --short HEAD)"
echo "checkout_dir=$PWD"
echo "compose_file_present=$([ -f docker-compose.yml ] && echo yes || echo no)"
docker compose ls 2>&1 | sed 's/^/compose_ls /'
for svc in $2; do
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  if [ -z "$cid" ]; then
    echo "container $svc MISSING"
    continue
  fi
  st=$(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealthcheck{{end}}' "$cid")
  echo "container $svc $st"
done
EOF

  expect "checkout_head=$EXPECT_PROD_COMMIT" \
    "production checkout is on $EXPECT_PROD_COMMIT, the commit the runbook measured"
  expect_not 'container [a-z-]+ MISSING' "all six services have a container"
  expect_not 'unhealthy' "no container reports unhealthy"

  step "1b. environment presence (never values)"
  remote "env presence" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
for v in BILLING_MODE MOLLIE_API_KEY MOLLIE_TEST_API_KEY INTERNAL_AUTH_TOKEN ADMIN_TOKEN PARAMANT_TOTP_MASTER_KEY RELAY_REDIS_URL; do
  printf 'env %-26s ' "$v"
  docker compose exec -T relay-main sh -c \
    "v=\$(printenv $v); if [ -z \"\$v\" ]; then echo empty; else echo \"set, prefix \$(printf %s \"\$v\" | cut -c1-5)\"; fi" \
    2>/dev/null || echo "unreadable"
done
echo "envfile INTERNAL_AUTH_TOKEN lines=$(grep -c '^INTERNAL_AUTH_TOKEN=' .env || true)"
echo "envfile BILLING_MODE lines=$(grep -c '^BILLING_MODE=.\+' .env || true)"
EOF

  expect 'env BILLING_MODE +empty' \
    "BILLING_MODE is empty in the running relay, so the recurring layer stays off"
  expect 'env MOLLIE_API_KEY +set, prefix live_' \
    "MOLLIE_API_KEY is set with a live_ prefix, unchanged since 08-08"

  step "1c. INTERNAL_AUTH_TOKEN (WRITE if absent: step 5 cannot read /v2/health/deep without it)"
  remote "internal auth token" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
before=$(grep -c '^INTERNAL_AUTH_TOKEN=.\+' .env || true)
echo "before INTERNAL_AUTH_TOKEN non-empty lines in .env = $before"
if [ "$before" -eq 0 ]; then
  cp -a .env ".env.bak-before-iat-$(date +%Y%m%d-%H%M%S)"
  sed -i '/^INTERNAL_AUTH_TOKEN=$/d' .env
  tok=$(openssl rand -hex 32)
  printf 'INTERNAL_AUTH_TOKEN=%s\n' "$tok" >> .env
  chmod 600 .env
  echo "action GENERATED a new INTERNAL_AUTH_TOKEN and appended it to .env"
  echo "action new token prefix $(printf %s "$tok" | cut -c1-5), length ${#tok}"
  echo "action the containers pick it up when phase 4 recreates them, nothing restarted now"
  unset tok
else
  echo "action none, INTERNAL_AUTH_TOKEN was already set"
fi
after=$(grep -c '^INTERNAL_AUTH_TOKEN=.\+' .env || true)
echo "after INTERNAL_AUTH_TOKEN non-empty lines in .env = $after"
EOF

  expect 'after INTERNAL_AUTH_TOKEN non-empty lines in \.env = 1' \
    "INTERNAL_AUTH_TOKEN present exactly once in .env"
  if [ "$DRY_RUN" -eq 0 ] && printf '%s\n' "$REMOTE_OUT" | grep -q 'action GENERATED'; then
    warn "a new INTERNAL_AUTH_TOKEN was generated on the server; note it in the deploy record"
  fi
}

# =============================================================== PHASE 2 =====

phase_2() {
  phase 2 "Rollback tags and backups (server, WRITE)" "Step 2"

  step "2a. tag the running images and write the manifest"
  remote "rollback tags" "$COMPOSE_DIR" "$TS" "$BACKUP_DIR" "$SERVICES" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
TS="$2"; BK="$3"; SVCS="$4"
mkdir -p "$BK"
MANIFEST="$BK/rollback-images-$TS.txt"
echo "before existing rollback tags = $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -c '^paramant-rollback/' || true)"
: > "$MANIFEST"
for svc in $SVCS; do
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  [ -z "$cid" ] && { echo "skip $svc (not running)"; continue; }
  img=$(docker inspect --format '{{.Config.Image}}' "$cid")
  docker tag "$img" "paramant-rollback/$svc:$TS"
  echo "$svc|$img|paramant-rollback/$svc:$TS" >> "$MANIFEST"
done
ln -sfn "$MANIFEST" "$BK/rollback-images-latest.txt"
echo "--- manifest $MANIFEST ---"
cat "$MANIFEST"
echo "--- end manifest ---"
echo "after manifest lines = $(wc -l < "$MANIFEST")"
echo "after existing rollback tags = $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -c '^paramant-rollback/' || true)"
EOF

  expect 'after manifest lines = 6' \
    "rollback manifest has six lines, one per service, so phase 8 can undo this deploy"

  step "2b. back up .env, compose state, docroot and the nginx confs"
  remote "backups" "$COMPOSE_DIR" "$TS" "$BACKUP_DIR" "$DOCROOT" "$NGINX_BACKUP_DIR" "$NGINX_SITES" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
TS="$2"; BK="$3"; DOCROOT="$4"; NGBK="$5"; NGSITES="$6"
mkdir -p "$BK" "$NGBK"

echo "before .env bytes = $(stat -c%s .env 2>/dev/null || echo missing)"
cp .env "$BK/.env-pre-3.1-$TS" && chmod 600 "$BK/.env-pre-3.1-$TS"
echo "after  .env backup = $BK/.env-pre-3.1-$TS ($(stat -c%s "$BK/.env-pre-3.1-$TS") bytes, mode $(stat -c%a "$BK/.env-pre-3.1-$TS"))"

docker compose ps > "$BK/state-pre-3.1-$TS.txt"
echo "after  compose state = $BK/state-pre-3.1-$TS.txt ($(wc -l < "$BK/state-pre-3.1-$TS.txt") lines)"

echo "before docroot files = $(find "$DOCROOT" -type f | wc -l)"
tar czf "$BK/docroot-pre-3.1-$TS.tgz" -C "$(dirname "$DOCROOT")" "$(basename "$DOCROOT")"
echo "after  docroot tar = $BK/docroot-pre-3.1-$TS.tgz ($(stat -c%s "$BK/docroot-pre-3.1-$TS.tgz") bytes, $(tar tzf "$BK/docroot-pre-3.1-$TS.tgz" | wc -l) entries)"

# Back up every enabled site conf, not only the public one: phase 5 edits
# whichever files actually carry the lines the runbook names.
n=0
for f in "$NGSITES"/*; do
  [ -f "$f" ] || continue
  cp -a "$f" "$NGBK/$(basename "$f").pre-3.1-$TS"
  n=$((n+1))
done
echo "after  nginx conf backups = $n file(s) in $NGBK with suffix .pre-3.1-$TS"
ls -1 "$NGBK" | grep -F "pre-3.1-$TS" | sed 's/^/nginxbackup /'

if [ -x deploy/ops/backup-full-state.sh ]; then
  echo "--- deploy/ops/backup-full-state.sh ---"
  bash deploy/ops/backup-full-state.sh 2>&1 | tail -25
  echo "fullstate exit=${PIPESTATUS[0]}"
else
  echo "fullstate deploy/ops/backup-full-state.sh not present or not executable, skipped"
fi
EOF

  expect "after  \\.env backup = $BACKUP_DIR/\\.env-pre-3\\.1-$TS" ".env backed up"
  expect "after  docroot tar = $BACKUP_DIR/docroot-pre-3\\.1-$TS\\.tgz" "docroot tarred"
  expect 'after  nginx conf backups = [1-9]' "at least one nginx conf backed up"
}

# =============================================================== PHASE 3 =====

phase_3() {
  phase 3 "Pull main, run the sanity gate, build (server, WRITE)" "Step 3"

  step "3a. pull $DEPLOY_REF fast-forward only"
  remote "git pull" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
echo "before HEAD = $(git rev-parse --short HEAD)"
echo "before status:"
git status --porcelain | sed 's/^/  dirty /'
if [ -n "$(git status --porcelain)" ]; then
  echo "FATAL working tree not clean; stash and note what it was before deploying"
  exit 1
fi
git fetch origin 2>&1 | sed 's/^/  fetch /'
git pull --ff-only origin main 2>&1 | sed 's/^/  pull /'
echo "after HEAD = $(git rev-parse --short HEAD)"
echo "after HEAD long = $(git rev-parse HEAD)"
EOF

  expect_not 'FATAL working tree not clean' "server working tree was clean before the pull"
  if [ "$DRY_RUN" -eq 0 ]; then
    local after_head; after_head="$(printf '%s\n' "$REMOTE_OUT" | sed -n 's/^after HEAD long = //p')"
    local want; want="$(git rev-parse "$DEPLOY_REF")"
    [ -n "$after_head" ] || die "could not read the server HEAD after the pull"
    [ "$after_head" = "$want" ] \
      || die "server is on $after_head after the pull, expected $want ($DEPLOY_REF, the commit phase 0 tested)"
    ok "server checkout is on ${after_head:0:7}, the commit phase 0 tested"
    printf '%s\n' "$REMOTE_OUT" | grep -q "before HEAD = $EXPECT_PROD_COMMIT" \
      || warn "server was not on $EXPECT_PROD_COMMIT before the pull; the rollback images are still correct, but the runbook's starting point was different"
  fi

  step "3b. static sanity on the server, same reading rule as phase 0"
  remote "static sanity" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
bash tests/static-sanity.sh 2>&1
echo "sanity exit=$?"
EOF
  [ "$DRY_RUN" -eq 1 ] && printf '  SKIP  assert (dry-run): static sanity on the server\n' \
    || sanity_verdict "$REMOTE_OUT" "server"

  step "3c. build the relays and admin from source (containers untouched)"
  remote "docker compose build" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
echo "before images:"
docker compose images 2>/dev/null | sed 's/^/  img /'
docker compose build 2>&1 | tail -40
echo "build exit=${PIPESTATUS[0]}"
echo "after images:"
docker compose images 2>/dev/null | sed 's/^/  img /'
EOF
  expect 'build exit=0' "docker compose build succeeded"
}

# =============================================================== PHASE 4 =====

phase_4() {
  phase 4 "Recreate, the canary relay first (server, WRITE)" "Step 4"

  step "4a. relay-iot alone, then read its two boot lines"
  remote "recreate relay-iot" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1

wait_healthy() {  # container id, max seconds
  local w=0
  while [ "$w" -lt "${2:-60}" ]; do
    s=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealthcheck{{end}}' "$1" 2>/dev/null || echo unknown)
    [ "$s" = healthy ] && { echo "healthy $1 after ${w}s"; return 0; }
    [ "$s" = nohealthcheck ] && { echo "healthy $1 (no healthcheck defined, running)"; return 0; }
    [ "$s" = unhealthy ] && { echo "UNHEALTHY $1"; docker logs "$1" 2>&1 | tail -20; return 1; }
    sleep 5; w=$((w+5))
  done
  echo "NOTHEALTHY $1 after ${2:-60}s"
  return 1
}

old=$(docker compose ps -q relay-iot 2>/dev/null)
echo "before relay-iot container = ${old:-none}"
[ -n "$old" ] && echo "before relay-iot image = $(docker inspect -f '{{.Image}}' "$old")"

docker compose up -d --no-deps relay-iot 2>&1 | sed 's/^/  up /'
cid=$(docker compose ps -q relay-iot)
[ -n "$cid" ] || { echo "FATAL relay-iot has no container after up"; exit 1; }
echo "after  relay-iot container = $cid"
echo "after  relay-iot image = $(docker inspect -f '{{.Image}}' "$cid")"

wait_healthy "$cid" 120 || exit 1

echo "--- relay-iot boot lines ---"
docker logs "$cid" 2>&1 | grep -E '"relay_started"|"billing_config"' | tail -4 | sed 's/^/bootline /'
echo "--- end boot lines ---"
EOF

  expect 'healthy [0-9a-f]+ after' "relay-iot reached healthy"
  expect 'bootline .*"billing_config"' "relay-iot logged a billing_config line"
  expect 'bootline .*"billing_config".*"recurring":false' \
    "billing_config says recurring:false, the brake is on"
  expect 'bootline .*"billing_config".*"mode_source":"inferred"' \
    "billing_config says mode_source:inferred, so BILLING_MODE is not set anywhere"
  expect_not '"billing_config".*"recurring":true' \
    "no relay reports recurring:true"
  expect "bootline .*\"relay_started\".*\"version\":\"$EXPECT_VERSION\"" \
    "relay_started reports version $EXPECT_VERSION"

  step "4b. relay-main, then the rest"
  remote "recreate the fleet" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1

wait_healthy() {
  local w=0
  while [ "$w" -lt "${2:-60}" ]; do
    s=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealthcheck{{end}}' "$1" 2>/dev/null || echo unknown)
    [ "$s" = healthy ] && { echo "healthy $1 after ${w}s"; return 0; }
    [ "$s" = nohealthcheck ] && { echo "healthy $1 (no healthcheck defined, running)"; return 0; }
    [ "$s" = unhealthy ] && { echo "UNHEALTHY $1"; docker logs "$1" 2>&1 | tail -20; return 1; }
    sleep 5; w=$((w+5))
  done
  echo "NOTHEALTHY $1 after ${2:-60}s"
  return 1
}

recreate() {
  local svc="$1"
  local old; old=$(docker compose ps -q "$svc" 2>/dev/null)
  echo "before $svc image = $([ -n "$old" ] && docker inspect -f '{{.Image}}' "$old" || echo none)"
  docker compose up -d --no-deps "$svc" 2>&1 | sed "s/^/  up /"
  local cid; cid=$(docker compose ps -q "$svc")
  [ -n "$cid" ] || { echo "FATAL $svc has no container after up"; return 1; }
  echo "after  $svc image = $(docker inspect -f '{{.Image}}' "$cid")"
  wait_healthy "$cid" 120 || return 1
  echo "recreated $svc"
}

recreate relay-main || exit 1
for svc in relay-health relay-finance relay-legal admin; do
  recreate "$svc" || exit 1
done

echo "--- billing stance on every relay ---"
for svc in relay-main relay-health relay-finance relay-legal relay-iot; do
  cid=$(docker compose ps -q "$svc")
  printf 'stance %-14s ' "$svc"
  docker logs "$cid" 2>&1 | grep '"billing_config"' | tail -1 | grep -o '"recurring":[a-z]*' || echo "no billing_config line"
done
echo "--- versions ---"
for svc in relay-main relay-health relay-finance relay-legal relay-iot; do
  cid=$(docker compose ps -q "$svc")
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

  step "5a. rsync the docroot, never with --delete"
  remote "rsync docroot" "$COMPOSE_DIR" "$DOCROOT" <<'EOF'
set -uo pipefail
SRC="$1/frontend/"; DST="$2/"
echo "before docroot files = $(find "$2" -type f | wc -l)"
echo "before would change:"
rsync -rinc --no-times "$SRC" "$DST" | sed 's/^/  wouldchange /' | head -60
echo "before would change count = $(rsync -rinc --no-times "$SRC" "$DST" | grep -c . || true)"
rsync -rc --no-times "$SRC" "$DST" 2>&1 | tail -5 | sed 's/^/  rsync /'
echo "rsync exit=${PIPESTATUS[0]}"
echo "after  docroot files = $(find "$2" -type f | wc -l)"
echo "after  would change count = $(rsync -rinc --no-times "$SRC" "$DST" | grep -c . || true)"
EOF
  expect 'rsync exit=0' "docroot rsync succeeded"
  expect 'after  would change count = 0' "docroot now matches the checkout frontend"

  step "5b. the three nginx changes, by hand, keeping the ParaID deny"
  remote "nginx edits" "$TS" "$NGINX_SITES" "$NGINX_BACKUP_DIR" <<'EOF'
set -uo pipefail
TS="$1"; SITES="$2"; NGBK="$3"

echo "--- before ---"
grep -rn 'paraid/issue' "$SITES" 2>/dev/null | sed 's/^/  paraid /' | head -20
echo "before paraid deny lines = $(grep -rc 'paraid/issue' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "before sign gated lines = $(grep -rc 'location = /sign.*auth_request' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "before compliance lines = $(grep -rcE '^[[:space:]]*location = /compliance(/(nis2|iec62443|nen7510))?[[:space:]]*\{' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "before dicom try_files lines = $(grep -rc 'location = /dicom.*try_files /dicom.html' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"

PARAID_BEFORE=$(grep -rc 'paraid/issue' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')

edited=0
for f in "$SITES"/*; do
  [ -f "$f" ] || continue
  cp -a "$f" "/tmp/nginx-pre-3.1-$(basename "$f").$TS"
  # 1. /sign leaves the auth_request gate (#317).
  sed -i -E 's|(location = /sign[[:space:]]*\{)[[:space:]]*auth_request /api/user/check; error_page 401 = @login_redirect;|\1|' "$f"
  # 2. the /compliance locations go (#323), redirect included.
  sed -i -E '/^[[:space:]]*location = \/compliance(\/(nis2|iec62443|nen7510))?[[:space:]]*\{/d' "$f"
  # 3. /dicom answers 404 instead of serving the page, exact match kept so
  #    nginx cannot auto-redirect it into the /dicom/ proxy.
  sed -i -E 's|(location = /dicom[[:space:]]*\{)[[:space:]]*try_files /dicom\.html[[:space:]]*=404;[[:space:]]*\}|\1 return 404; }|' "$f"
  if ! cmp -s "$f" "/tmp/nginx-pre-3.1-$(basename "$f").$TS"; then
    echo "edited $(basename "$f")"
    edited=$((edited+1))
  fi
done
echo "after  edited files = $edited"

echo "--- after ---"
echo "after  paraid deny lines = $(grep -rc 'paraid/issue' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "after  sign gated lines = $(grep -rc 'location = /sign.*auth_request' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "after  compliance lines = $(grep -rcE '^[[:space:]]*location = /compliance(/(nis2|iec62443|nen7510))?[[:space:]]*\{' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "after  dicom try_files lines = $(grep -rc 'location = /dicom.*try_files /dicom.html' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "after  dicom 404 lines = $(grep -rc 'location = /dicom.*return 404' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"

PARAID_AFTER=$(grep -rc 'paraid/issue' "$SITES" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
if [ "$PARAID_AFTER" -lt "$PARAID_BEFORE" ]; then
  echo "FATAL the ParaID deny lost $((PARAID_BEFORE - PARAID_AFTER)) line(s); restoring"
  for b in "$NGBK"/*.pre-3.1-"$TS"; do
    [ -f "$b" ] || continue
    cp -a "$b" "$SITES/$(basename "$b" ".pre-3.1-$TS")"
  done
  exit 1
fi

if nginx -t 2>&1 | sed 's/^/  nginxt /'; then
  systemctl reload nginx && echo "reloaded nginx"
else
  echo "FATAL nginx -t failed, restoring the backed up confs"
  for b in "$NGBK"/*.pre-3.1-"$TS"; do
    [ -f "$b" ] || continue
    cp -a "$b" "$SITES/$(basename "$b" ".pre-3.1-$TS")"
  done
  nginx -t 2>&1 | sed 's/^/  restoredtest /'
  systemctl reload nginx && echo "restored and reloaded the previous nginx conf"
  exit 1
fi
EOF

  expect_not 'FATAL' "nginx edits applied and the config tests clean"
  expect 'after  sign gated lines = 0' "/sign is no longer behind auth_request"
  expect 'after  compliance lines = 0' "the /compliance locations are gone"
  expect 'after  dicom try_files lines = 0' "/dicom no longer serves the page"
  expect 'reloaded nginx' "nginx reloaded"
  if [ "$DRY_RUN" -eq 0 ]; then
    local pb pa
    pb="$(printf '%s\n' "$REMOTE_OUT" | sed -n 's/^before paraid deny lines = //p')"
    pa="$(printf '%s\n' "$REMOTE_OUT" | sed -n 's/^after  paraid deny lines = //p')"
    if [ -n "$pb" ] && [ -n "$pa" ] && [ "$pa" -ge "$pb" ] && [ "$pa" -gt 0 ]; then
      ok "the ParaID deny survived the edit ($pa line(s), was $pb)"
    else
      die "the ParaID deny changed from ${pb:-?} to ${pa:-?} lines; the runbook keeps it in this round"
    fi
  fi
}

# =============================================================== PHASE 6 =====

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
    local h code
    for h in $HOSTS; do
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://$h/health" || echo 000)"
      printf '  health %-26s %s\n' "$h" "$code"
      [ "$code" = "200" ] || die "/health on $h answered $code, expected 200"
    done
    ok "/health is 200 on all six hosts"
    local ver
    ver="$(curl -s --max-time 15 https://paramant.app/health \
           | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version",""))' 2>/dev/null || echo "")"
    printf '  version reported by paramant.app/health = %s\n' "$ver"
    [ "$ver" = "$EXPECT_VERSION" ] || die "/health reports version '$ver', expected $EXPECT_VERSION"
    ok "/health reports version $EXPECT_VERSION"
  fi

  step "6c. /v2/health/deep, 401 without the token and 200 with it (server-local)"
  remote "deep health" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
# The token is read into a variable and never echoed; only the status codes
# and the parsed overall field are printed.
T=$(grep '^INTERNAL_AUTH_TOKEN=' .env | head -1 | cut -d= -f2-)
if [ -z "$T" ]; then echo "FATAL INTERNAL_AUTH_TOKEN empty in .env"; exit 1; fi
echo "deep token present, length ${#T}, prefix $(printf %s "$T" | cut -c1-5)"
echo "deep noauth code = $(curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://127.0.0.1:3000/v2/health/deep)"
echo "deep auth   code = $(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "X-Internal-Auth: $T" http://127.0.0.1:3000/v2/health/deep)"
curl -s --max-time 15 -H "X-Internal-Auth: $T" http://127.0.0.1:3000/v2/health/deep \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("deep overall =", d.get("overall") or d.get("status") or "unknown")' 2>/dev/null \
  || echo "deep overall = unparseable"
unset T
EOF
  expect 'deep noauth code = 401' "/v2/health/deep is 401 without X-Internal-Auth"
  expect 'deep auth   code = 200' "/v2/health/deep is 200 with X-Internal-Auth"

  step "6d. /v1/paraid/issue-document is 404 on all six hosts (#319)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ curl -s -o /dev/null -w %%{http_code} -X POST https://<host>/v1/paraid/issue-document   # six hosts\n'
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): issue-document is 404 on six hosts\n'
  else
    local h code
    for h in $HOSTS; do
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "https://$h/v1/paraid/issue-document" || echo 000)"
      printf '  paraid %-26s %s\n' "$h" "$code"
      [ "$code" = "404" ] || die "/v1/paraid/issue-document on $h answered $code, expected 404"
    done
    ok "/v1/paraid/issue-document is 404 on all six hosts"
  fi

  step "6e. /sign answers itself, 200 and no redirect to /auth/login (#317)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  $ curl -s -o /dev/null -w %%{http_code} https://paramant.app/sign\n'
    printf '  [dry-run] not executed\n'
    printf '  SKIP  assert (dry-run): /sign is 200 without a session\n'
  else
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://paramant.app/sign || echo 000)"
    printf '  sign code = %s\n' "$code"
    [ "$code" = "200" ] || die "/sign answered $code, expected 200 without a login"
    ok "/sign is 200 without a login"
  fi

  step "6f. the 3.0.0 verify suite, on the server (informational, exit 2 blocks)"
  remote "post-deploy-verify" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
bash scripts/post-deploy-verify.sh https://paramant.app http://127.0.0.1:3000 2>&1 | tail -40
echo "verify exit=${PIPESTATUS[0]}"
EOF
  if [ "$DRY_RUN" -eq 0 ]; then
    if printf '%s\n' "$REMOTE_OUT" | grep -q 'verify exit=2'; then
      die "post-deploy-verify.sh exited 2 (critical); the runbook rolls back on this (phase 8)"
    fi
    if printf '%s\n' "$REMOTE_OUT" | grep -q 'verify exit=0'; then
      ok "post-deploy-verify.sh passed"
    else
      warn "post-deploy-verify.sh exited non-zero but not 2; its /health/deep probe is known red (the route is /v2/health/deep), read the list above"
    fi
  fi

  step "6g. billing stance once more, from every relay log"
  remote "billing stance" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
for svc in relay-main relay-health relay-finance relay-legal relay-iot; do
  cid=$(docker compose ps -q "$svc")
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

  step "8a. the manifest and the saved images"
  remote "rollback manifest" "$COMPOSE_DIR" "$ROLLBACK_TS" "$BACKUP_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
TS="$2"; BK="$3"
M="$BK/rollback-images-$TS.txt"
[ -f "$M" ] || { echo "FATAL no manifest $M"; exit 1; }
echo "manifest lines = $(wc -l < "$M")"
cat "$M" | sed 's/^/  manifest /'
missing=0
while IFS='|' read -r svc image rbtag; do
  [ -z "${svc:-}" ] && continue
  if docker image inspect "$rbtag" >/dev/null 2>&1; then
    echo "  present $rbtag"
  else
    echo "  MISSING $rbtag"
    missing=$((missing+1))
  fi
done < "$M"
echo "missing rollback images = $missing"
EOF
  expect_not 'FATAL no manifest' "the manifest for $ROLLBACK_TS exists"
  expect 'missing rollback images = 0' "every rollback image from $ROLLBACK_TS is still on the host"

  step "8b. retag the saved images and recreate without rebuilding"
  remote "rollback images" "$COMPOSE_DIR" "$ROLLBACK_TS" "$BACKUP_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
TS="$2"; BK="$3"
M="$BK/rollback-images-$TS.txt"
SVCS=""
while IFS='|' read -r svc image rbtag; do
  [ -z "${svc:-}" ] && continue
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  echo "before $svc image = $([ -n "$cid" ] && docker inspect -f '{{.Image}}' "$cid" || echo none)"
  docker tag "$rbtag" "$image"
  SVCS="$SVCS $svc"
done < "$M"
docker compose up -d --no-deps --force-recreate $SVCS 2>&1 | sed 's/^/  up /'
for svc in $SVCS; do
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  echo "after  $svc image = $([ -n "$cid" ] && docker inspect -f '{{.Image}}' "$cid" || echo none)"
done
echo "recreated:$SVCS"
EOF
  expect 'recreated: ' "the saved images were retagged and the containers recreated"

  step "8c. restore .env, the nginx confs and the docroot"
  remote "restore state" "$COMPOSE_DIR" "$ROLLBACK_TS" "$BACKUP_DIR" "$DOCROOT" "$NGINX_BACKUP_DIR" "$NGINX_SITES" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
TS="$2"; BK="$3"; DOCROOT="$4"; NGBK="$5"; SITES="$6"

if [ -f "$BK/.env-pre-3.1-$TS" ]; then
  echo "before .env bytes = $(stat -c%s .env)"
  cp -a .env ".env.bak-rollback-$TS"
  cp "$BK/.env-pre-3.1-$TS" .env && chmod 600 .env
  echo "after  .env bytes = $(stat -c%s .env) (restored from $BK/.env-pre-3.1-$TS)"
else
  echo "WARN no .env backup for $TS, .env left as it is"
fi

n=0
for b in "$NGBK"/*.pre-3.1-"$TS"; do
  [ -f "$b" ] || continue
  target="$SITES/$(basename "$b" ".pre-3.1-$TS")"
  echo "before nginx $(basename "$target") bytes = $(stat -c%s "$target" 2>/dev/null || echo missing)"
  cp -a "$b" "$target"
  echo "after  nginx $(basename "$target") bytes = $(stat -c%s "$target")"
  n=$((n+1))
done
echo "restored nginx confs = $n"
if [ "$n" -gt 0 ]; then
  nginx -t 2>&1 | sed 's/^/  nginxt /'
  systemctl reload nginx && echo "reloaded nginx"
fi

if [ -f "$BK/docroot-pre-3.1-$TS.tgz" ]; then
  echo "before docroot files = $(find "$DOCROOT" -type f | wc -l)"
  tar xzf "$BK/docroot-pre-3.1-$TS.tgz" -C "$(dirname "$DOCROOT")"
  echo "after  docroot files = $(find "$DOCROOT" -type f | wc -l) (restored from the pre-3.1 tar)"
else
  echo "WARN no docroot tar for $TS, docroot left as it is"
fi

# .env changed, so the relays have to come back on the restored file.
docker compose up -d --no-deps --force-recreate relay-main 2>&1 | sed 's/^/  up /'
EOF

  step "8d. health after the rollback"
  remote "rollback health" "$COMPOSE_DIR" <<'EOF'
set -uo pipefail
cd "$1" || exit 1
ok=no
for _ in $(seq 1 30); do
  if curl -fs --max-time 3 http://127.0.0.1:3000/health >/dev/null 2>&1; then ok=yes; break; fi
  sleep 2
done
echo "rollback relay health = $ok"
echo "rollback version = $(curl -s --max-time 5 http://127.0.0.1:3000/health | grep -o '"version":"[^"]*"' || echo unknown)"
cid=$(docker compose ps -q relay-main)
echo "rollback paraidAuth occurrences in relay.js = $(docker exec "$cid" grep -c _paraidAuth /app/relay.js 2>/dev/null || echo 0)"
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
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://$h/health" || echo 000)"
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
  echo "PREFLIGHT ONLY: phases 0 and 1 done, stopping before any deploy write."
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
