#!/usr/bin/env bash
# restore-full-state.sh — restore the full signing-critical state produced by
# backup-full-state.sh into the hosted docker relay stack.
#
# This is a DESTRUCTIVE operation: it overwrites live relay /data volumes and
# the redis data volume, then restarts the affected containers. It refuses to
# do anything without an explicit --confirm.
#
# Usage:
#   # Inspect only (decrypt + verify manifest, touch nothing live):
#   ./restore-full-state.sh --from /path/to/paramant-full-<ts>.tar.gz.age --inspect
#
#   # Real restore (as root, on the prod host):
#   ./restore-full-state.sh --from /path/to/paramant-full-<ts>.tar.gz.age --confirm
#
# If --from is omitted, the newest daily backup is used.
#
set -uo pipefail
umask 077

BACKUP_ROOT="${BACKUP_ROOT:-/home/paramant/backups/full-state}"
KEYFILE="${KEYFILE:-/root/.config/paramant-backup/key.txt}"
REDIS_CONTAINER="${REDIS_CONTAINER:-paramant-relay-redis}"

FROM=""
MODE="none"   # none | inspect | confirm
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM="$2"; shift 2 ;;
    --inspect) MODE="inspect"; shift ;;
    --confirm) MODE="confirm"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

[[ "$MODE" != "none" ]] || die "pass --inspect (safe) or --confirm (destructive)"
command -v age >/dev/null 2>&1 || die "age not installed"

if [[ -z "$FROM" ]]; then
  FROM=$(ls -t "$BACKUP_ROOT"/daily/paramant-full-*.tar.gz.age 2>/dev/null | head -1)
  [[ -n "$FROM" ]] || die "no backup found in $BACKUP_ROOT/daily and no --from given"
fi
[[ -r "$FROM" ]] || die "cannot read backup: $FROM"
[[ -r "$KEYFILE" ]] || die "cannot read key: $KEYFILE"

echo "Restore source: $FROM"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "Decrypting + extracting..."
age -d -i "$KEYFILE" "$FROM" | tar -xz -C "$WORK" || die "decrypt/extract failed"
ROOT=$(find "$WORK" -maxdepth 1 -type d -name 'paramant-full-*' | head -1)
[[ -n "$ROOT" ]] || die "unexpected bundle layout"

echo ""
echo "Bundle contents:"
[[ -f "$ROOT/MANIFEST.txt" ]] && sed -n '1,8p' "$ROOT/MANIFEST.txt" | sed 's/^/  /'

# Verify every file against the manifest before touching anything live.
echo ""
echo "Verifying manifest hashes..."
BAD=0
while read -r h _ path; do
  [[ "$h" =~ ^[0-9a-f]{64}$ ]] || continue
  actual=$(sha256sum "$ROOT/$path" 2>/dev/null | cut -d' ' -f1)
  if [[ "$actual" != "$h" ]]; then
    echo "  MISMATCH: $path"
    BAD=$((BAD+1))
  fi
done < "$ROOT/MANIFEST.txt"
[[ $BAD -eq 0 ]] && echo "  all hashes match" || die "$BAD file(s) failed hash verification; aborting"

RELAYS=$(find "$ROOT/relay" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)
echo ""
echo "Relays in bundle:"; echo "$RELAYS" | sed 's/^/  /'
[[ -d "$ROOT/redis" ]] && echo "Redis data: present" || echo "Redis data: absent"

if [[ "$MODE" == "inspect" ]]; then
  echo ""
  echo "INSPECT mode: nothing live was touched. Extracted at: $ROOT"
  trap - EXIT
  exit 0
fi

# ── Destructive restore ───────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "restore must run as root"
command -v docker >/dev/null 2>&1 || die "docker required for restore"

echo ""
echo "!!! DESTRUCTIVE RESTORE — this overwrites live volumes and restarts containers."
read -r -p "Type EXACTLY 'restore' to proceed: " ans
[[ "$ans" == "restore" ]] || die "not confirmed"

# Restore each relay by copying files into the container /data mount, then
# restart that container.
for rdir in $RELAYS; do
  nm=$(basename "$rdir")
  echo "-- restoring relay $nm"
  if ! docker ps --format '{{.Names}}' | grep -qx "$nm"; then
    echo "   ! container $nm not running; skipping (start it, then re-run)"
    continue
  fi
  MP=$(docker inspect "$nm" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}')
  [[ -n "$MP" && -d "$MP" ]] || { echo "   ! no /data mount for $nm; skipping"; continue; }
  cp -a "$rdir/." "$MP/" || { echo "   ! copy failed for $nm"; continue; }
  docker restart "$nm" >/dev/null && echo "   restored + restarted"
done

# Restore redis: it must be stopped so it does not overwrite the AOF on exit.
if [[ -d "$ROOT/redis" ]] && docker ps -a --format '{{.Names}}' | grep -qx "$REDIS_CONTAINER"; then
  echo "-- restoring redis"
  MP=$(docker inspect "$REDIS_CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}')
  if [[ -n "$MP" && -d "$MP" ]]; then
    docker stop "$REDIS_CONTAINER" >/dev/null
    # Clear existing state so a stale AOF file cannot shadow the restore.
    rm -rf "$MP"/appendonlydir "$MP"/dump.rdb 2>/dev/null || true
    cp -a "$ROOT/redis/." "$MP/"
    docker start "$REDIS_CONTAINER" >/dev/null && echo "   redis restored + restarted"
  else
    echo "   ! no /data mount for $REDIS_CONTAINER"
  fi
fi

echo ""
echo "Restore complete. Verify health:"
echo "  for c in \$(docker ps --format '{{.Names}}' | grep relay); do docker exec \$c wget -qO- http://127.0.0.1:3000/health 2>/dev/null; echo; done"
