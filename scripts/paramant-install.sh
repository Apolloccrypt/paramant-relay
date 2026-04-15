#!/usr/bin/env bash
# paramant-install — interactive disk installer for ParamantOS
#
# Supports: UEFI (GPT + ESP) and BIOS/legacy (GPT + BIOS-boot partition)
# Auto-detects firmware type. Uses whiptail for interactive dialogs.
# Installs via nixos-install with the built-in ParamantOS configuration.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

MOUNT=/mnt

# ── Must run as root — check BEFORE creating any files ────────────────────────
# Do NOT use "exec sudo bash $0" — on NixOS the script lives in the Nix store
# and the wrapper cannot be re-executed that way. On the ISO, sudo is NOPASSWD
# for the paramant user; paramant-boot-choice already calls: sudo paramant-install
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}[✗]${RESET} This installer must run as root."
  echo ""
  echo "  Run:  sudo paramant-install"
  echo "  Or use the full TUI wizard:  sudo paramant-installer"
  echo ""
  exit 1
fi

LOGFILE="/tmp/paramant-install-$(date +%Y%m%d-%H%M%S).log"
touch "$LOGFILE" 2>/dev/null || LOGFILE="/root/paramant-install.log"

info()    { echo -e "${CYAN}[•]${RESET} $*" | tee -a "$LOGFILE"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*" | tee -a "$LOGFILE"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOGFILE"; }
err()     { echo -e "${RED}[✗]${RESET} $*" | tee -a "$LOGFILE"; }
heading() { echo -e "\n${BOLD}━━━ $* ━━━${RESET}\n" | tee -a "$LOGFILE"; }

die() {
  err "$*"
  echo ""
  echo -e "${YELLOW}Full install log: ${LOGFILE}${RESET}"
  echo ""
  exit 1
}

# ── Cleanup trap ───────────────────────────────────────────────────────────────
cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "" | tee -a "$LOGFILE"
    err "Installation aborted (exit code: ${exit_code})"
    echo -e "${YELLOW}Cleaning up mounts...${RESET}" | tee -a "$LOGFILE"
    umount "${MOUNT}/boot" 2>/dev/null || true
    umount "${MOUNT}/dev/pts" 2>/dev/null || true
    umount "${MOUNT}/dev" 2>/dev/null || true
    umount "${MOUNT}/proc" 2>/dev/null || true
    umount "${MOUNT}/sys" 2>/dev/null || true
    umount "${MOUNT}" 2>/dev/null || true
    echo -e "${YELLOW}Log saved to: ${LOGFILE}${RESET}"
  fi
}
trap cleanup EXIT

echo "ParamantOS install log — $(date)" >> "$LOGFILE"
echo "Kernel: $(uname -r)" >> "$LOGFILE"
echo "" >> "$LOGFILE"

# ── Must run from ISO ──────────────────────────────────────────────────────────
if ! command -v nixos-install &>/dev/null; then
  die "nixos-install not found. This script must be run from the ParamantOS installer ISO."
fi

# ── Enable nix-command + flakes; disable remote flake registry ────────────────
# flake-registry = (empty) suppresses channels.nixos.org DNS lookup so
# nixos-install works fully offline/airgapped without warning or hanging.
export NIX_CONFIG=$'experimental-features = nix-command flakes\nflake-registry = '

clear
echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║           ParamantOS Disk Installer                  ║"
echo "  ║      Post-Quantum Ghost Pipe Relay — v2.4.5          ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo "  This wizard installs ParamantOS to a local disk."
echo "  The selected disk will be COMPLETELY WIPED."
echo ""
echo -e "  Install log: ${BOLD}${LOGFILE}${RESET}"
echo ""
echo -e "  Press ${BOLD}Ctrl-C${RESET} at any time to abort without making any changes."
echo ""

# ── UEFI or BIOS? ─────────────────────────────────────────────────────────────
if [ -d /sys/firmware/efi ]; then
  FIRMWARE=uefi
  info "Firmware: UEFI detected"
else
  FIRMWARE=bios
  info "Firmware: BIOS/legacy detected"
fi
echo ""

# ── Select target disk ─────────────────────────────────────────────────────────
heading "Step 1 — Select target disk"

DISK_ITEMS=()
while IFS= read -r line; do
  DEV=$(echo "$line" | awk '{print $1}')
  SIZE=$(echo "$line" | awk '{print $4}')
  MODEL=$(echo "$line" | awk '{$1=$2=$3=$4=""; print $0}' | xargs)
  DISK_ITEMS+=("$DEV" "${SIZE}  ${MODEL}")
done < <(lsblk -d -o NAME,TYPE,ROTA,SIZE,MODEL --noheadings \
  | grep -v "^loop\|^sr\|^ram" \
  | awk '{print "/dev/"$1, $2, $3, $4, $5, $6, $7, $8}' \
  | awk '$2=="disk"')

if [ ${#DISK_ITEMS[@]} -eq 0 ]; then
  die "No suitable disk found. Make sure a disk is attached."
fi

TARGET=$(whiptail \
  --title "Select target disk" \
  --menu "Choose the disk to install ParamantOS on.\n\nWARNING: all data on this disk will be erased." \
  18 70 8 \
  "${DISK_ITEMS[@]}" \
  3>&1 1>&2 2>&3) || { echo "Aborted."; exit 1; }

info "Selected: ${BOLD}${TARGET}${RESET}"

# ── Hostname ───────────────────────────────────────────────────────────────────
heading "Step 2 — Hostname"

HOSTNAME=$(whiptail \
  --title "Hostname" \
  --inputbox "Enter a hostname for this relay node:" \
  9 50 "paramant" \
  3>&1 1>&2 2>&3) || { echo "Aborted."; exit 1; }

HOSTNAME=$(echo "$HOSTNAME" | tr -cs 'a-zA-Z0-9-' '-' | sed 's/^-//;s/-$//')
[ -z "$HOSTNAME" ] && HOSTNAME="paramant"
info "Hostname: ${BOLD}${HOSTNAME}${RESET}"

# ── Admin password ─────────────────────────────────────────────────────────────
heading "Step 3 — Admin password"

while true; do
  PASS1=$(whiptail --title "Admin password" --passwordbox \
    "Set password for the 'paramant' admin user:" 9 50 \
    3>&1 1>&2 2>&3) || { echo "Aborted."; exit 1; }
  PASS2=$(whiptail --title "Admin password" --passwordbox \
    "Confirm password:" 9 50 \
    3>&1 1>&2 2>&3) || { echo "Aborted."; exit 1; }
  if [ "$PASS1" = "$PASS2" ] && [ -n "$PASS1" ]; then
    ok "Password set."
    break
  fi
  whiptail --title "Error" --msgbox "Passwords do not match or are empty. Try again." 8 45
done

# ── SSH public key (optional) ─────────────────────────────────────────────────
heading "Step 4 — SSH public key (optional)"

SSH_KEY=$(whiptail --title "SSH public key" --inputbox \
  "Paste your SSH public key (leave empty to skip):\n\nYou can add keys later with: paramant-setup --force" \
  12 72 "" \
  3>&1 1>&2 2>&3) || SSH_KEY=""

# ── Confirmation ──────────────────────────────────────────────────────────────
heading "Confirmation"

PART_INFO="GPT + BIOS-boot (1 MB) + root ext4"
[ "$FIRMWARE" = "uefi" ] && PART_INFO="GPT + EFI (512 MB FAT32) + root ext4"

whiptail --title "Ready to install" --yesno \
  "The following will be written:\n\n\
  Disk     : ${TARGET}\n\
  Hostname : ${HOSTNAME}\n\
  Firmware : ${FIRMWARE^^}\n\
  Layout   : ${PART_INFO}\n\
  Bootloader: $([ "$FIRMWARE" = "uefi" ] && echo "systemd-boot" || echo "GRUB")\n\n\
ALL DATA ON ${TARGET} WILL BE ERASED.\n\nContinue?" \
  18 62 || { echo "Aborted — disk untouched."; exit 0; }

echo ""
info "Starting installation..."
info "Log file: ${LOGFILE}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT CHECKS
# ══════════════════════════════════════════════════════════════════════════════
heading "Pre-flight checks"

# Disk not mounted
if grep -q "^${TARGET}" /proc/mounts 2>/dev/null; then
  die "${TARGET} or one of its partitions is currently mounted. Unmount first."
fi

# Not in use by LVM
if command -v pvs &>/dev/null && pvs "$TARGET" &>/dev/null; then
  die "${TARGET} is part of an LVM volume group. Deactivate it first."
fi

# Minimum disk size: 8 GB
DISK_BYTES=$(lsblk -b -d -o SIZE --noheadings "$TARGET" 2>/dev/null | tr -d ' ' || echo 0)
MIN_BYTES=$(( 8 * 1024 * 1024 * 1024 ))
if [ "$DISK_BYTES" -lt "$MIN_BYTES" ] 2>/dev/null; then
  die "${TARGET} is smaller than 8 GB. ParamantOS requires at least 8 GB."
fi

# ParamantOS source files present
SRC=/etc/paramantos-src
if [ ! -d "$SRC" ]; then
  _nix_src=$(dirname "$(readlink -f "$(command -v paramant-help)")" 2>/dev/null || true)
  [ -d "$_nix_src" ] && SRC="$_nix_src" || SRC=/etc/nixos
fi
[ -f "${SRC}/configuration.nix" ] || die "ParamantOS config not found at ${SRC}. Is this the right ISO?"

ok "Disk ${TARGET} is free and large enough"
ok "ParamantOS source: ${SRC}"

# Network check (informational only — install works from ISO cache)
if curl -sf --max-time 3 https://cache.nixos.org >/dev/null 2>&1; then
  ok "Network: reachable (will use binary cache)"
else
  warn "Network: unreachable — installing from ISO cache only (offline mode)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# PARTITION + FORMAT
# ══════════════════════════════════════════════════════════════════════════════
heading "Partitioning ${TARGET}"

wipefs -a "$TARGET" >> "$LOGFILE" 2>&1 || true
dd if=/dev/zero of="$TARGET" bs=1M count=2 >> "$LOGFILE" 2>&1 || true

parted -s "$TARGET" -- mklabel gpt >> "$LOGFILE" 2>&1

if [ "$FIRMWARE" = "uefi" ]; then
  parted -s "$TARGET" -- mkpart ESP fat32 1MiB 513MiB >> "$LOGFILE" 2>&1
  parted -s "$TARGET" -- set 1 esp on >> "$LOGFILE" 2>&1
  parted -s "$TARGET" -- mkpart primary ext4 513MiB 100% >> "$LOGFILE" 2>&1
  ok "Partition table: GPT (EFI + root)"
else
  parted -s "$TARGET" -- mkpart primary 1MiB 2MiB >> "$LOGFILE" 2>&1
  parted -s "$TARGET" -- set 1 bios_grub on >> "$LOGFILE" 2>&1
  parted -s "$TARGET" -- mkpart primary ext4 2MiB 100% >> "$LOGFILE" 2>&1
  ok "Partition table: GPT (BIOS-boot + root)"
fi

# Derive partition device names
if [[ "$TARGET" =~ nvme|mmcblk ]]; then
  PART1="${TARGET}p1"
  PART2="${TARGET}p2"
else
  PART1="${TARGET}1"
  PART2="${TARGET}2"
fi

info "Waiting for kernel to register partitions..."
partprobe "$TARGET" 2>/dev/null || true
WAIT=0
until [ -b "$PART2" ] || [ $WAIT -ge 15 ]; do
  sleep 1
  partprobe "$TARGET" 2>/dev/null || true
  WAIT=$((WAIT + 1))
done
[ -b "$PART2" ] || die "Partition ${PART2} did not appear after 15s. Is the disk responding?"
ok "Partitions ready: ${PART1}, ${PART2}"

# ── Format ────────────────────────────────────────────────────────────────────
heading "Formatting"

if [ "$FIRMWARE" = "uefi" ]; then
  mkfs.fat -F 32 -n ESP "$PART1" >> "$LOGFILE" 2>&1 \
    || die "Failed to format EFI partition ${PART1}. Check disk health."
  ok "EFI partition: FAT32 (${PART1})"
fi

mkfs.ext4 -L nixos -F "$PART2" >> "$LOGFILE" 2>&1 \
  || die "Failed to format root partition ${PART2}. Check disk health."
ok "Root partition: ext4 (${PART2})"

# ══════════════════════════════════════════════════════════════════════════════
# MOUNT
# ══════════════════════════════════════════════════════════════════════════════
heading "Mounting"

mount "$PART2" "$MOUNT" \
  || die "Failed to mount ${PART2} on ${MOUNT}."
ok "Root mounted → ${MOUNT}"

if [ "$FIRMWARE" = "uefi" ]; then
  mkdir -p "${MOUNT}/boot"
  mount "$PART1" "${MOUNT}/boot" \
    || die "Failed to mount EFI partition ${PART1} on ${MOUNT}/boot."
  ok "EFI mounted → ${MOUNT}/boot"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GENERATE HARDWARE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
heading "Generating hardware configuration"

nixos-generate-config --root "$MOUNT" >> "$LOGFILE" 2>&1 \
  || die "nixos-generate-config failed. See: ${LOGFILE}"
ok "Hardware configuration generated"

# ══════════════════════════════════════════════════════════════════════════════
# INJECT PARAMANTOS CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
heading "Injecting ParamantOS configuration"

NIXCFG="${MOUNT}/etc/nixos"

for f in configuration.nix module.nix scripts.nix paramant-relay.nix flake.nix flake.lock; do
  if [ -f "${SRC}/${f}" ]; then
    cp "${SRC}/${f}" "${NIXCFG}/${f}" && ok "Copied ${f}"
  fi
done

if [ -d "${SRC}/scripts" ]; then
  cp -r "${SRC}/scripts" "${NIXCFG}/scripts"
  ok "Copied scripts/"
fi

cp "${NIXCFG}/hardware-configuration.nix" "${NIXCFG}/hardware.nix"
ok "hardware.nix ← hardware-configuration.nix"

# Patch hostname
sed -i "s/networking.hostName = \"[^\"]*\"/networking.hostName = \"${HOSTNAME}\"/" \
  "${NIXCFG}/configuration.nix" 2>/dev/null || true

# ── Bootloader patch — depends on firmware type ────────────────────────────
# Strategy: write a clean hardware.nix that *imports* hardware-configuration.nix
# (untouched, as generated by nixos-generate-config) and adds only the bootloader
# settings on top. This avoids fragile grep-based content merging that can produce
# broken Nix syntax and cause the "must set boot.loader" assertion to fire.
if [ "$FIRMWARE" = "uefi" ]; then
  cat > "${NIXCFG}/hardware.nix" <<'NIXEOF'
# Generated by paramant-install — UEFI/systemd-boot
{ config, lib, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  boot.loader.systemd-boot.enable        = lib.mkForce true;
  boot.loader.efi.canTouchEfiVariables   = lib.mkForce true;
  boot.loader.grub.enable                = lib.mkForce false;
  boot.loader.grub.efiSupport            = lib.mkForce false;
  boot.loader.grub.efiInstallAsRemovable = lib.mkForce false;
}
NIXEOF
  ok "Patched hardware.nix for UEFI / systemd-boot"
else
  # BIOS/legacy: GRUB must know which disk to install its MBR to.
  # Without boot.loader.grub.device nixos-install always fails with
  # "You must set boot.loader.grub.devices or boot.loader.systemd-boot".
  cat > "${NIXCFG}/hardware.nix" <<NIXEOF
# Generated by paramant-install — BIOS/legacy GRUB
{ config, lib, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  boot.loader.grub.enable                = lib.mkForce true;
  boot.loader.grub.device                = lib.mkForce "${TARGET}";
  boot.loader.grub.efiSupport            = lib.mkForce false;
  boot.loader.grub.efiInstallAsRemovable = lib.mkForce false;
  boot.loader.efi.canTouchEfiVariables   = lib.mkForce false;
  boot.loader.grub.useOSProber           = false;
  boot.loader.grub.splashImage           = null;
}
NIXEOF
  ok "Patched hardware.nix for BIOS/legacy GRUB (device: ${TARGET})"
fi

# ── Verify hostname is correctly set ──────────────────────────────────────
heading "Verifying patched configuration"

CFGFILE="${NIXCFG}/configuration.nix"

if grep -q "networking.hostName = \"${HOSTNAME}\"" "$CFGFILE"; then
  ok "networking.hostName = \"${HOSTNAME}\""
else
  warn "Hostname mismatch — reapplying sed patch"
  sed -i "s/networking\.hostName = \"[^\"]*\"/networking.hostName = \"${HOSTNAME}\"/" "$CFGFILE"
  ok "networking.hostName fixed → \"${HOSTNAME}\""
fi

# Verify bootloader key is present in hardware.nix (sanity check only)
if grep -q 'boot\.loader' "${NIXCFG}/hardware.nix"; then
  ok "Bootloader config confirmed in hardware.nix"
else
  die "hardware.nix is missing bootloader config — something went wrong during patching"
fi

# ══════════════════════════════════════════════════════════════════════════════
# INSTALL
# ══════════════════════════════════════════════════════════════════════════════
heading "Installing ParamantOS  (this takes a few minutes)"

info "Running ParamantOS installer — full output below"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Capture exit code without letting the pipe mask it.
# tee writes to log + terminal simultaneously.
# set +e so we can inspect the exit code ourselves.
set +e
nixos-install \
  --root "$MOUNT" \
  --flake "${MOUNT}/etc/nixos#paramant" \
  --no-root-passwd \
  --no-channel-copy \
  --option flake-registry "" \
  --option substituters "" \
  --option trusted-substituters "" \
  2>&1 | tee -a "$LOGFILE"
INSTALL_RC=${PIPESTATUS[0]}
set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$INSTALL_RC" -ne 0 ]; then
  echo ""
  err "ParamantOS installation failed (exit code: ${INSTALL_RC})"
  echo ""

  # Show the actual error lines first — far more useful than generic hints
  echo -e "${RED}── Errors from log ──────────────────────────────────────────────${RESET}"
  grep -i 'error:\|failed\|cannot\|undefined\|must set' "$LOGFILE" | tail -15 || true
  echo -e "${RED}─────────────────────────────────────────────────────────────────${RESET}"
  echo ""
  echo -e "${YELLOW}Last 20 lines of install output:${RESET}"
  tail -20 "$LOGFILE"
  echo ""
  echo -e "${YELLOW}Bootloader that was configured:${RESET}"
  if [ "$FIRMWARE" = "uefi" ]; then
    echo "  systemd-boot (UEFI)"
  else
    echo "  GRUB on ${TARGET} (BIOS/legacy)"
  fi
  echo ""
  echo -e "${BOLD}Full log: ${LOGFILE}${RESET}"
  echo -e "${BOLD}To retry: run paramant-install again${RESET}"
  exit 1
fi

ok "ParamantOS installation complete"

# ══════════════════════════════════════════════════════════════════════════════
# SET PASSWORD
# ══════════════════════════════════════════════════════════════════════════════
heading "Setting admin password"

echo "paramant:${PASS1}" | nixos-enter --root "$MOUNT" -- chpasswd \
  || die "Failed to set password. Installation may be incomplete."
ok "Password set for user 'paramant'"

# ── SSH key (optional) ────────────────────────────────────────────────────────
if [ -n "$SSH_KEY" ]; then
  SSH_DIR="${MOUNT}/home/paramant/.ssh"
  mkdir -p "$SSH_DIR"
  echo "$SSH_KEY" >> "${SSH_DIR}/authorized_keys"
  chmod 700 "$SSH_DIR"
  chmod 600 "${SSH_DIR}/authorized_keys"
  nixos-enter --root "$MOUNT" -- chown -R paramant:users /home/paramant/.ssh \
    || warn "Could not chown .ssh — fix manually after boot: chown -R paramant:users ~/.ssh"
  ok "SSH key added to authorized_keys"
fi

# ══════════════════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║          Installation complete!                      ║"
echo "  ║                                                      ║"
echo "  ║  Login: paramant / <your password>                   ║"
echo "  ║  First boot: setup wizard runs automatically         ║"
echo "  ║  Relay starts automatically on boot                  ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Install log saved to: ${BOLD}${LOGFILE}${RESET}"
echo ""

# Unmount cleanly
info "Unmounting..."
sync
[ "$FIRMWARE" = "uefi" ] && umount "${MOUNT}/boot" 2>/dev/null || true
umount "$MOUNT" 2>/dev/null || true
ok "All partitions unmounted."

# Disable trap (clean exit)
trap - EXIT

echo ""
whiptail --title "Done!" --yesno \
  "ParamantOS has been installed to ${TARGET}.\n\nReboot now? (remove the USB drive before/after reboot)" \
  10 60 && reboot || {
    echo ""
    echo -e "${CYAN}Type ${BOLD}reboot${RESET}${CYAN} when ready.${RESET}"
    echo ""
  }
