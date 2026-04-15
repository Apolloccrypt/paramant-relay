#!/usr/bin/env bash
# paramant-backup — backup relay keys and CT log

BACKUP_BASE="/var/lib/paramant-backup"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}Paramant Backup${RESET}"
echo "──────────────────────────────────────"

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
DEST="${BACKUP_BASE}/${TIMESTAMP}"
mkdir -p "$DEST"

EXPORTED=0

for dir in /var/lib/paramant-relay /var/lib/paramant-relay-*; do
  [[ -d "$dir" ]] || continue
  name=$(basename "$dir")
  mkdir -p "${DEST}/${name}"

  for f in users.json ct-log ct_log keys.json; do
    SRC="${dir}/${f}"
    if [[ -f "$SRC" ]]; then
      cp "$SRC" "${DEST}/${name}/"
      SIZE=$(du -sh "$SRC" | cut -f1)
      echo -e "  ${GREEN}✓${RESET}  ${name}/${f}  (${SIZE})"
      EXPORTED=$((EXPORTED+1))
    fi
  done
done

# Also backup license (minus the key itself for security)
if [[ -f /etc/paramant/license ]]; then
  grep -v 'PLK_KEY' /etc/paramant/license > "${DEST}/license-meta.txt" 2>/dev/null || true
fi

{
  echo "Backup timestamp: $TIMESTAMP"
  echo "Hostname: $(hostname)"
  echo "Relay version: $(curl -sf --max-time 2 http://localhost:3000/health 2>/dev/null | jq -r '.version // "?"' 2>/dev/null || echo '?')"
  echo "Files: $EXPORTED"
} > "${DEST}/backup-info.txt"

echo ""
if [[ $EXPORTED -eq 0 ]]; then
  echo -e "  ${YELLOW}No data files found.${RESET} (RAM-only relay may have no persistent data)"
  rmdir "$DEST" 2>/dev/null || true
else
  echo -e "  ${GREEN}${BOLD}${EXPORTED} file(s) backed up to:${RESET}"
  echo -e "  ${DEST}"
  echo ""
  # Keep last 30 backups
  find "$BACKUP_BASE" -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true
  KEPT=$(find "$BACKUP_BASE" -maxdepth 1 -type d | wc -l)
  echo -e "  ${CYAN}Kept ${KEPT} backup(s) in ${BACKUP_BASE}${RESET}"
fi

echo ""
