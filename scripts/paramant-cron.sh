#!/usr/bin/env bash
# paramant-cron — manage systemd timers for relay maintenance tasks

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

TIMERS=("backup" "watchdog" "license-alert")

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║           paramant-cron                          ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}\n"

# ── Show current timer status ─────────────────────────────────────────────────
echo -e "  ${CYAN}Current Paramant timers:${RESET}"
systemctl list-timers 'paramant-*' --no-legend 2>/dev/null \
  | awk '{printf "    %-40s next: %s %s\n", $NF, $3, $4}' \
  || echo "    (none)"
echo ""

# ── Menu ───────────────────────────────────────────────────────────────────────
CHOICE=$(whiptail --title "paramant-cron" \
  --menu "Select action:" 16 60 6 \
  "install-backup"       "Daily backup to /var/lib/paramant-backup" \
  "install-watchdog"     "5-min relay watchdog (auto-restart on failure)" \
  "install-license"      "Daily license expiry alert (email/journal)" \
  "list"                 "List all Paramant timers" \
  "remove"               "Remove a timer" \
  3>&1 1>&2 2>&3) || exit 0

write_and_enable() {
  local SERVICE_UNIT="$1"
  local TIMER_UNIT="$2"
  local SERVICE_NAME="$3"

  # M4: use /run/paramant-tmp instead of /tmp (world-writable) for temp unit files
  local TMPDIR
  mkdir -p /run/paramant-tmp
  chmod 700 /run/paramant-tmp
  TMPDIR=$(mktemp -d /run/paramant-tmp/paramant-cron-XXXXXX)

  echo "$SERVICE_UNIT" > "${TMPDIR}/${SERVICE_NAME}.service"
  echo "$TIMER_UNIT"   > "${TMPDIR}/${SERVICE_NAME}.timer"

  sudo install -m 644 -o root -g root "${TMPDIR}/${SERVICE_NAME}.service" \
    "/etc/systemd/system/${SERVICE_NAME}.service"
  sudo install -m 644 -o root -g root "${TMPDIR}/${SERVICE_NAME}.timer" \
    "/etc/systemd/system/${SERVICE_NAME}.timer"
  rm -rf "$TMPDIR"

  sudo paramant-relay-ctl daemon-reload
  sudo systemctl enable --now "${SERVICE_NAME}.timer"

  STATUS=$(systemctl is-active "${SERVICE_NAME}.timer" 2>/dev/null || echo "unknown")
  if [[ "$STATUS" == "active" ]]; then
    echo -e "  ${GREEN}✓${RESET}  ${SERVICE_NAME}.timer is active"
    systemctl status "${SERVICE_NAME}.timer" --no-pager -l 2>/dev/null | tail -5
  else
    echo -e "  ${RED}✗${RESET}  Timer status: ${STATUS}"
    echo -e "  Check: ${YELLOW}journalctl -u ${SERVICE_NAME}.timer${RESET}"
  fi
}

case "$CHOICE" in

  install-backup)
    BACKUP_DIR="/var/lib/paramant-backup"
    echo -e "  Installing daily backup timer..."
    echo -e "  Backup destination: ${BACKUP_DIR}"
    echo ""

    SVC=$(cat << 'EOF'
[Unit]
Description=Paramant relay data backup
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/bin/bash -c '\
  TS=$(date +%%Y%%m%%d-%%H%%M%%S); \
  DEST=/var/lib/paramant-backup/${TS}; \
  mkdir -p "$DEST"; \
  for d in /var/lib/paramant-relay /var/lib/paramant-relay-*; do \
    [ -d "$d" ] || continue; \
    name=$(basename "$d"); \
    mkdir -p "$DEST/$name"; \
    cp "$d"/users.json "$DEST/$name/" 2>/dev/null || true; \
    cp "$d"/ct-log     "$DEST/$name/" 2>/dev/null || true; \
  done; \
  echo "Backup complete: $DEST"; \
  find /var/lib/paramant-backup -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true'
EOF
)

    TIMER=$(cat << 'EOF'
[Unit]
Description=Daily Paramant relay data backup

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
)
    write_and_enable "$SVC" "$TIMER" "paramant-backup"
    ;;

  install-watchdog)
    echo -e "  Installing 5-minute relay watchdog timer..."
    echo ""

    SVC=$(cat << 'EOF'
[Unit]
Description=Paramant relay watchdog — auto-restart on failure

[Service]
Type=oneshot
User=root
ExecStart=/bin/bash -c '\
  STATUS=$(systemctl is-active paramant-relay 2>/dev/null || echo "unknown"); \
  if [ "$STATUS" != "active" ]; then \
    echo "paramant-relay is $STATUS — restarting"; \
    systemctl restart paramant-relay; \
    sleep 3; \
    systemctl is-active paramant-relay && echo "Relay restarted OK" || echo "Relay restart FAILED"; \
  fi'
EOF
)

    TIMER=$(cat << 'EOF'
[Unit]
Description=Paramant relay watchdog — every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
)
    write_and_enable "$SVC" "$TIMER" "paramant-watchdog"
    ;;

  install-license)
    echo -e "  Installing daily license expiry alert timer..."
    echo ""

    SVC=$(cat << 'EOF'
[Unit]
Description=Paramant license expiry check

[Service]
Type=oneshot
User=paramant
ExecStart=/bin/bash -c '\
  HEALTH=$(curl -sf --max-time 5 http://localhost:3000/health 2>/dev/null || echo ""); \
  if [ -z "$HEALTH" ]; then echo "License check: relay unreachable"; exit 0; fi; \
  EXPIRES=$(echo "$HEALTH" | jq -r '.license_expires // empty' 2>/dev/null || echo ""); \
  if [ -z "$EXPIRES" ]; then echo "License check: no expiry field (community or no key)"; exit 0; fi; \
  DAYS=$(( ( $(date -d "$EXPIRES" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 )); \
  [ "$DAYS" -lt 0 ] 2>/dev/null && DAYS=0; \
  if [ "$DAYS" = "?" ]; then echo "License check: could not parse expiry date"; exit 0; fi; \
  if [ "$DAYS" -lt 14 ] 2>/dev/null; then \
    echo "WARNING: Paramant license expires in $DAYS day(s) ($EXPIRES)"; \
  else \
    echo "License OK — expires in $DAYS day(s)"; \
  fi'
EOF
)

    TIMER=$(cat << 'EOF'
[Unit]
Description=Daily Paramant license expiry alert

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
)
    write_and_enable "$SVC" "$TIMER" "paramant-license-alert"
    ;;

  list)
    echo -e "  ${BOLD}All Paramant timers:${RESET}\n"
    systemctl list-timers 'paramant-*' 2>/dev/null || echo "  (none)"
    echo ""
    ;;

  remove)
    TIMER_CHOICE=$(whiptail --title "Remove Timer" \
      --menu "Select timer to remove:" 16 60 5 \
      "paramant-backup"        "Daily backup" \
      "paramant-watchdog"      "5-min watchdog" \
      "paramant-license-alert" "License expiry alert" \
      3>&1 1>&2 2>&3) || exit 0

    if whiptail --title "Confirm Remove" \
      --yesno "Remove ${TIMER_CHOICE} timer and service?" 10 60; then
      sudo systemctl disable --now "${TIMER_CHOICE}.timer" 2>/dev/null || true
      sudo rm -f "/etc/systemd/system/${TIMER_CHOICE}.timer" \
                 "/etc/systemd/system/${TIMER_CHOICE}.service"
      sudo paramant-relay-ctl daemon-reload
      echo -e "  ${GREEN}✓${RESET}  Removed ${TIMER_CHOICE}"
    fi
    ;;
esac

echo ""
