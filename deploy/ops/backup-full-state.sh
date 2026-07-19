#!/usr/bin/env bash
# backup-full-state.sh — full signing-critical backup of the hosted docker relay stack.
#
# Scope: paramant.app's OWN hosted deployment (the docker-compose stack on the
# production Hetzner host). This captures the state that is UNRECOVERABLE on
# loss, which the older users.json-only backup did NOT cover:
#   - relay-identity.json    per relay: the relay signing/identity keys
#   - ct-log.json            per relay: the append-only CT log
#   - sth-log.jsonl          per relay: the Merkle Signed-Tree-Head log
#   - peer-sths/             per relay: cross-signed peer STHs
#   - paraid-*.json          per relay: ParaID issuer registry + demo authority key
#   - code-manifest.json     per relay: code-transparency manifest
#   - trial-keys.jsonl       per relay
#   - users.json             per relay: accounts (also covered by the old backup)
#   - redis dump.rdb + AOF   the ParaSign sessions/blobs/mutable state
#
# Method: snapshot the ENTIRE /data volume of each relay plus the whole redis
# data volume, hash every file into a manifest, bundle, and age-encrypt. This
# is deliberately whole-directory rather than an allowlist so a new state file
# is never silently missed.
#
# Consistency: files are copied live (no downtime). users.json is written
# atomically by the relay (tmp+rename) so it is always consistent. The
# append-only logs (ct-log.json, sth-log.jsonl) are at worst missing a trailing
# partial line, which is recoverable. Redis runs appendonly=yes (everysec), so
# its AOF is crash-consistent to within ~1s; a best-effort BGSAVE is attempted
# first for a cleaner point-in-time RDB.
#
# THE BUNDLE CONTAINS PRIVATE KEYS. It is age-encrypted to a public key; only
# the offline private key can decrypt it. Treat every artifact as secret.
#
# Usage (prod, as root, via cron or by hand):
#   /home/paramant/scripts/backup-full-state.sh
#
# Dry-run (no root, no age, no prune — proves the manifest):
#   PARAMANT_BACKUP_SOURCES=$'main\t/some/dir\nhealth\t/other/dir' \
#   REDIS_SRC_DIR=/some/redis \
#   ./backup-full-state.sh --dry-run
#
set -uo pipefail
umask 077

# ── Config (overridable via env) ──────────────────────────────────────────────
BACKUP_ROOT="${BACKUP_ROOT:-/home/paramant/backups/full-state}"
KEYFILE="${KEYFILE:-/root/.config/paramant-backup/key.txt}"
RELAY_FILTER="${RELAY_FILTER:-relay}"        # docker name grep for relay containers
REDIS_CONTAINER="${REDIS_CONTAINER:-paramant-relay-redis}"
LOG="${LOG:-/var/log/paramant-backup.log}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

# Fall back to /dev/null when the log path is not writable (e.g. non-root dry-run)
# so logging never leaks a redirection error to stderr.
touch "$LOG" 2>/dev/null || LOG=/dev/null

log()  { echo "[$(date -Iseconds)] $*" >> "$LOG" 2>/dev/null || true; }
say()  { echo "$*"; }
die()  { echo "ERROR: $*" >&2; log "ERROR: $*"; exit 1; }

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DAY=$(date +%d)

# ── Preflight ─────────────────────────────────────────────────────────────────
if [[ $DRY_RUN -eq 0 ]]; then
  [[ $EUID -eq 0 ]] || die "must run as root (reads root-owned volumes and 0600 keys)"
  command -v age >/dev/null 2>&1 || die "age not installed"
  [[ -r "$KEYFILE" ]] || die "key file not readable: $KEYFILE"
  PUBKEY=$(grep -m1 "^# public key:" "$KEYFILE" | cut -d: -f2 | tr -d " ")
  [[ -n "$PUBKEY" ]] || die "no public key line in $KEYFILE"
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/paramant-full-$TIMESTAMP"
mkdir -p "$STAGE"

say "Paramant full-state backup  ($TIMESTAMP)"
say "----------------------------------------"
[[ $DRY_RUN -eq 1 ]] && say "MODE: dry-run (no encryption, no prune)"

# ── Discover relay sources ────────────────────────────────────────────────────
# Each entry is "name<TAB>source_dir". In prod we derive them from docker
# volume mountpoints. PARAMANT_BACKUP_SOURCES overrides discovery (used by the
# dry-run harness).
declare -a SOURCES=()
if [[ -n "${PARAMANT_BACKUP_SOURCES:-}" ]]; then
  while IFS=$'\t' read -r nm dir; do
    [[ -n "$nm" ]] && SOURCES+=("$nm"$'\t'"$dir")
  done <<< "$PARAMANT_BACKUP_SOURCES"
else
  command -v docker >/dev/null 2>&1 || die "docker not available and no PARAMANT_BACKUP_SOURCES override"
  CONTAINERS=$(docker ps --format '{{.Names}}' | grep -E "$RELAY_FILTER" | grep -v "$REDIS_CONTAINER" | grep -v "admin" || true)
  [[ -n "$CONTAINERS" ]] || die "no relay containers match filter '$RELAY_FILTER'"
  for CONT in $CONTAINERS; do
    # Resolve the host mountpoint of the container's /data volume.
    MP=$(docker inspect "$CONT" \
      --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
    [[ -n "$MP" && -d "$MP" ]] || { say "  ! $CONT: no /data mount, skipped"; continue; }
    SOURCES+=("$CONT"$'\t'"$MP")
  done
fi

# ── Collect relay data ────────────────────────────────────────────────────────
RELAY_COUNT=0
for entry in "${SOURCES[@]}"; do
  nm="${entry%%$'\t'*}"
  dir="${entry#*$'\t'}"
  [[ -d "$dir" ]] || { say "  ! $nm: source dir missing ($dir), skipped"; continue; }
  dest="$STAGE/relay/$nm"
  mkdir -p "$dest"
  # cp -a preserves modes/timestamps; the dot copies dir contents.
  if cp -a "$dir/." "$dest/" 2>/dev/null; then
    n=$(find "$dest" -type f | wc -l)
    say "  + relay $nm  ($n file(s))"
    RELAY_COUNT=$((RELAY_COUNT+1))
  else
    say "  ! $nm: copy failed from $dir"
  fi
done

# Loud-fail guard: never write a false-safe empty backup.
[[ $RELAY_COUNT -gt 0 ]] || die "0 relay sources captured; refusing to write an empty backup"

# ── Collect redis ─────────────────────────────────────────────────────────────
REDIS_OK=0
REDIS_DIR=""
if [[ -n "${REDIS_SRC_DIR:-}" ]]; then
  REDIS_DIR="$REDIS_SRC_DIR"
elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$REDIS_CONTAINER"; then
  # Best-effort BGSAVE for a fresh point-in-time RDB. Non-fatal on failure:
  # the appendonly AOF is crash-consistent regardless.
  RPASS=$(docker inspect "$REDIS_CONTAINER" \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sed -n 's/^REDIS_PASSWORD=//p' | head -1)
  if [[ -n "$RPASS" ]]; then
    docker exec "$REDIS_CONTAINER" redis-cli -a "$RPASS" --no-auth-warning BGSAVE >/dev/null 2>&1 \
      && say "  + redis BGSAVE triggered" || say "  ! redis BGSAVE skipped (AOF still crash-consistent)"
    sleep 2
  else
    say "  ! redis password not found; relying on crash-consistent AOF"
  fi
  REDIS_DIR=$(docker inspect "$REDIS_CONTAINER" \
    --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
fi

if [[ -n "$REDIS_DIR" && -d "$REDIS_DIR" ]]; then
  mkdir -p "$STAGE/redis"
  if cp -a "$REDIS_DIR/." "$STAGE/redis/" 2>/dev/null; then
    n=$(find "$STAGE/redis" -type f | wc -l)
    say "  + redis data ($n file(s))"
    REDIS_OK=1
  else
    say "  ! redis: copy failed from $REDIS_DIR"
  fi
else
  say "  ! redis: no source dir resolved (not captured)"
fi

# ── Manifest (sha256 per file) ────────────────────────────────────────────────
MANIFEST="$STAGE/MANIFEST.txt"
{
  echo "# Paramant full-state backup manifest"
  echo "timestamp:   $TIMESTAMP"
  echo "host:        $(hostname)"
  echo "relays:      $RELAY_COUNT"
  echo "redis:       $([[ $REDIS_OK -eq 1 ]] && echo yes || echo no)"
  echo "dry_run:     $DRY_RUN"
  echo "# sha256  size  path (relative to bundle root)"
} > "$MANIFEST"
( cd "$STAGE" && find . -type f ! -name MANIFEST.txt -print0 \
  | sort -z \
  | while IFS= read -r -d '' f; do
      h=$(sha256sum "$f" | cut -d' ' -f1)
      s=$(stat -c%s "$f")
      printf '%s  %s  %s\n' "$h" "$s" "${f#./}"
    done ) >> "$MANIFEST"

FILE_COUNT=$(grep -c '^[0-9a-f]\{64\}  ' "$MANIFEST" || true)
say "  manifest: $FILE_COUNT file(s) hashed"

# ── Bundle ────────────────────────────────────────────────────────────────────
BUNDLE="$WORK/paramant-full-$TIMESTAMP.tar.gz"
tar -C "$WORK" -czf "$BUNDLE" "paramant-full-$TIMESTAMP" || die "tar failed"

if [[ $DRY_RUN -eq 1 ]]; then
  OUT_DIR="${BACKUP_ROOT:-$WORK}"
  # In dry-run keep artifacts in a predictable place for inspection.
  DRY_OUT="${DRYRUN_OUT:-$WORK/out}"
  mkdir -p "$DRY_OUT"
  cp "$BUNDLE" "$DRY_OUT/"
  cp "$MANIFEST" "$DRY_OUT/paramant-full-$TIMESTAMP.MANIFEST.txt"
  say ""
  say "DRY-RUN artifacts (UNENCRYPTED, delete after inspection):"
  say "  bundle:   $DRY_OUT/$(basename "$BUNDLE")"
  say "  manifest: $DRY_OUT/paramant-full-$TIMESTAMP.MANIFEST.txt"
  # Do not let the EXIT trap wipe the dry-run output.
  trap - EXIT
  say ""
  say "Manifest preview:"
  cat "$DRY_OUT/paramant-full-$TIMESTAMP.MANIFEST.txt"
  exit 0
fi

# ── Encrypt + store (prod) ────────────────────────────────────────────────────
mkdir -p "$BACKUP_ROOT/daily" "$BACKUP_ROOT/monthly"
chmod 700 "$BACKUP_ROOT" "$BACKUP_ROOT/daily" "$BACKUP_ROOT/monthly" 2>/dev/null || true

OUT="$BACKUP_ROOT/daily/paramant-full-$TIMESTAMP.tar.gz.age"
age -r "$PUBKEY" -o "$OUT" "$BUNDLE" || die "age encryption failed"
chmod 600 "$OUT"
# Keep a plaintext manifest next to the encrypted bundle for quick integrity
# checks without decrypting. sha256 hashes of secret files leak nothing usable.
cp "$MANIFEST" "$BACKUP_ROOT/daily/paramant-full-$TIMESTAMP.MANIFEST.txt"
chmod 600 "$BACKUP_ROOT/daily/paramant-full-$TIMESTAMP.MANIFEST.txt"

# Monthly permanent snapshot on the 1st.
if [[ "$DAY" == "01" ]]; then
  cp "$OUT" "$BACKUP_ROOT/monthly/paramant-full-$(date +%Y%m).tar.gz.age"
  cp "$MANIFEST" "$BACKUP_ROOT/monthly/paramant-full-$(date +%Y%m).MANIFEST.txt"
fi

# Rotate daily.
find "$BACKUP_ROOT/daily/" -type f -mtime +"$RETAIN_DAYS" -delete 2>/dev/null || true

SIZE=$(du -h "$OUT" | cut -f1)
say ""
say "OK: $RELAY_COUNT relay(s) + redis=$REDIS_OK, $FILE_COUNT file(s) -> $OUT ($SIZE)"
log "full-state backup OK: relays=$RELAY_COUNT redis=$REDIS_OK files=$FILE_COUNT -> $OUT ($SIZE)"

# Optional offsite (same hook as the users-json backup).
if [[ -x /home/paramant/scripts/backup-offsite.sh ]]; then
  /home/paramant/scripts/backup-offsite.sh "$OUT" || log "WARN: offsite copy failed for $OUT"
fi
