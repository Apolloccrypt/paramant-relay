#!/usr/bin/env bash
# paramant-export — export ct-log and users.json to USB drive

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

DATA_DIR="/var/lib/paramant-relay"
EXPORT_DIR=""

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║           paramant-export                        ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}\n"

# ── Detect USB drives ─────────────────────────────────────────────────────────
echo -e "  ${CYAN}Detecting USB drives...${RESET}\n"

USB_DEVS=$(lsblk -o NAME,TRAN,TYPE,SIZE,MOUNTPOINT 2>/dev/null \
  | awk '$2=="usb" && $3=="part" {print $1,$4,$5}' || true)

if [[ -z "$USB_DEVS" ]]; then
  echo -e "  ${YELLOW}No USB partitions detected.${RESET}"
  echo ""

  # Offer manual path
  MANUAL=$(whiptail --title "Export Destination" \
    --inputbox "No USB found. Enter export path manually (e.g. /mnt/backup):" \
    10 70 "/tmp/paramant-export" 3>&1 1>&2 2>&3) || exit 0
  EXPORT_DIR="$MANUAL"
else
  # Build menu
  MENU_ITEMS=()
  while IFS= read -r line; do
    DEV=$(echo "$line" | awk '{print $1}')
    SIZE=$(echo "$line" | awk '{print $2}')
    MNT=$(echo "$line" | awk '{print $3}')
    MENU_ITEMS+=("$DEV" "${SIZE}  ${MNT:-(not mounted)}")
  done <<< "$USB_DEVS"
  MENU_ITEMS+=("manual" "Enter path manually")

  CHOICE=$(whiptail --title "Select Destination" \
    --menu "Select USB drive or enter path:" 16 60 8 \
    "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3) || exit 0

  if [[ "$CHOICE" == "manual" ]]; then
    MANUAL=$(whiptail --title "Export Path" \
      --inputbox "Enter export path:" 10 60 "/mnt/usb" 3>&1 1>&2 2>&3) || exit 0
    EXPORT_DIR="$MANUAL"
  else
    # Get mount point or mount it
    MNT=$(lsblk -o NAME,MOUNTPOINT -nr 2>/dev/null | awk -v dev="$CHOICE" '$1==dev{print $2}' || true)
    if [[ -z "$MNT" ]]; then
      MOUNT_POINT="/mnt/paramant-usb"
      mkdir -p "$MOUNT_POINT"
      if mount "/dev/${CHOICE}" "$MOUNT_POINT" 2>/dev/null; then
        echo -e "  ${GREEN}Mounted /dev/${CHOICE} at ${MOUNT_POINT}${RESET}"
        EXPORT_DIR="${MOUNT_POINT}/paramant-export"
        MOUNTED_AT="$MOUNT_POINT"
      else
        echo -e "  ${RED}Failed to mount /dev/${CHOICE}. Aborting.${RESET}"
        exit 1
      fi
    else
      EXPORT_DIR="${MNT}/paramant-export"
    fi
  fi
fi

# ── Create export directory ───────────────────────────────────────────────────
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
EXPORT_PATH="${EXPORT_DIR}/${TIMESTAMP}"
mkdir -p "$EXPORT_PATH"

echo -e "  ${CYAN}Exporting to: ${EXPORT_PATH}${RESET}\n"

# ── Copy data files ───────────────────────────────────────────────────────────
EXPORTED=0
for f in users.json ct-log ct_log; do
  SRC="${DATA_DIR}/${f}"
  if [[ -f "$SRC" ]]; then
    cp "$SRC" "${EXPORT_PATH}/"
    SIZE=$(du -sh "$SRC" | cut -f1)
    echo -e "  ${GREEN}✓${RESET}  ${f}  (${SIZE})"
    EXPORTED=$((EXPORTED+1))
  fi
done

# Also check sector data dirs
for dir in /var/lib/paramant-relay-*; do
  if [[ -d "$dir" ]]; then
    SECTOR_NAME=$(basename "$dir" | sed 's/paramant-relay-//')
    mkdir -p "${EXPORT_PATH}/${SECTOR_NAME}"
    for f in users.json ct-log ct_log; do
      SRC="${dir}/${f}"
      if [[ -f "$SRC" ]]; then
        cp "$SRC" "${EXPORT_PATH}/${SECTOR_NAME}/"
        SIZE=$(du -sh "$SRC" | cut -f1)
        echo -e "  ${GREEN}✓${RESET}  ${SECTOR_NAME}/${f}  (${SIZE})"
        EXPORTED=$((EXPORTED+1))
      fi
    done
  fi
done

# Export health snapshot
curl -sf http://localhost:3000/health 2>/dev/null > "${EXPORT_PATH}/health-snapshot.json" || true

# Write metadata
{
  echo "Export timestamp: $TIMESTAMP"
  echo "Hostname: $(hostname)"
  echo "Files exported: $EXPORTED"
} > "${EXPORT_PATH}/export-info.txt"

echo ""
if [[ $EXPORTED -eq 0 ]]; then
  echo -e "  ${YELLOW}No data files found in ${DATA_DIR}${RESET}"
  echo -e "  (Relay may be running in RAM-only mode with no persistent data)"
else
  echo -e "  ${GREEN}${BOLD}${EXPORTED} file(s) exported to:${RESET}"
  echo -e "  ${EXPORT_PATH}"
fi

# ── Unmount if we mounted it ──────────────────────────────────────────────────
if [[ -n "${MOUNTED_AT:-}" ]]; then
  sync
  umount "$MOUNTED_AT" 2>/dev/null && echo -e "\n  ${GREEN}USB safely unmounted.${RESET}" || \
    echo -e "\n  ${YELLOW}Unmount failed — eject manually.${RESET}"
fi

echo ""
