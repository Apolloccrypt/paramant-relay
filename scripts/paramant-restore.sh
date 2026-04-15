#!/usr/bin/env bash
# paramant-restore — restore relay data from backup

BACKUP_BASE="/var/lib/paramant-backup"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}Paramant Restore${RESET}"
echo "──────────────────────────────────────"

if [[ ! -d "$BACKUP_BASE" ]]; then
  echo -e "${YELLOW}No backups found in ${BACKUP_BASE}${RESET}"
  echo "Run: paramant-backup  to create a backup first"
  exit 0
fi

BACKUPS=$(find "$BACKUP_BASE" -maxdepth 1 -mindepth 1 -type d | sort -r | head -20)
if [[ -z "$BACKUPS" ]]; then
  echo -e "${YELLOW}No backup directories found.${RESET}"
  exit 0
fi

MENU_ITEMS=()
while IFS= read -r dir; do
  name=$(basename "$dir")
  info=""
  if [[ -f "${dir}/backup-info.txt" ]]; then
    files=$(grep 'Files:' "${dir}/backup-info.txt" | awk '{print $2}')
    info="${files} file(s)"
  fi
  MENU_ITEMS+=("$name" "$info")
done <<< "$BACKUPS"

SELECTED=$(whiptail --title "Select Backup" \
  --menu "Choose backup to restore:" 20 60 12 \
  "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3) || exit 0

[[ -z "$SELECTED" ]] && { echo "Cancelled."; exit 0; }

RESTORE_FROM="${BACKUP_BASE}/${SELECTED}"

echo ""
if [[ -f "${RESTORE_FROM}/backup-info.txt" ]]; then
  echo -e "${CYAN}Backup info:${RESET}"
  cat "${RESTORE_FROM}/backup-info.txt" | sed 's/^/  /'
  echo ""
fi

if ! whiptail --title "Confirm Restore" \
  --yesno "Restore from backup '${SELECTED}'?\n\nThis will overwrite current data files.\nThe relay will be restarted." 12 60; then
  echo "Cancelled."
  exit 0
fi

echo -e "${YELLOW}Stopping relay...${RESET}"
sudo paramant-relay-ctl stop paramant-relay 2>/dev/null || true

RESTORED=0
for subdir in "${RESTORE_FROM}"/*/; do
  [[ -d "$subdir" ]] || continue
  name=$(basename "$subdir")
  dest="/var/lib/${name}"
  if [[ -d "$dest" ]]; then
    for f in users.json ct-log ct_log keys.json; do
      SRC="${subdir}${f}"
      if [[ -f "$SRC" ]]; then
        cp "$SRC" "${dest}/"
        chown paramant-relay:paramant-relay "${dest}/${f}" 2>/dev/null || true
        echo -e "  ${GREEN}✓${RESET}  Restored ${name}/${f}"
        RESTORED=$((RESTORED+1))
      fi
    done
  fi
done

echo -e "${YELLOW}Starting relay...${RESET}"
sudo paramant-relay-ctl start paramant-relay 2>/dev/null || true
sleep 2

STATUS=$(systemctl is-active paramant-relay 2>/dev/null || echo "unknown")
if [[ "$STATUS" == "active" ]]; then
  echo -e "${GREEN}✓ Relay restarted — ${RESTORED} file(s) restored${RESET}"
else
  echo -e "${RED}✗ Relay failed to start (status: ${STATUS})${RESET}"
  echo "Check: journalctl -u paramant-relay -n 20"
fi

echo ""
