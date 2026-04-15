#!/usr/bin/env bash
# paramant-boot-choice — first-login menu on the installer ISO.
# Shows Install / Live session / Shell.
# On an installed system (no nixos-install) this runs paramant-setup instead.

# No set -e here — we loop and handle failures ourselves.

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Installed system: run setup wizard instead ────────────────────────────────
if ! command -v nixos-install &>/dev/null; then
  paramant-setup
  exit 0
fi

_banner() {
  clear
  echo ""
  echo -e "${GREEN}            *   *   *   *   *   *   *"
  echo "         *                           *"
  echo "       *                               *"
  echo "      *                                 *"
  echo "     *         P A R A M A N T           *"
  echo "     *       Post-Quantum Ghost Pipe       *"
  echo "     *         EU/DE  ·  BUSL-1.1         *"
  echo "      *                                 *"
  echo "       *                               *"
  echo "         *                           *"
  echo -e "            *   *   *   *   *   *   *${RESET}"
  echo ""
  echo -e "${BOLD}     ParamantOS v2.4.5 — Post-Quantum Ghost Pipe Relay${RESET}"
  echo -e "     EU/DE · ML-KEM-768 · RAM-only · BUSL-1.1"
  echo ""
}

# ── Main loop — always return here after install/live/shell ──────────────────
while true; do
  _banner

  CHOICE=$(whiptail \
    --title "ParamantOS v2.4.5 — Boot Menu" \
    --menu "\nWelcome! What would you like to do?\n" 16 64 3 \
    "1" "Install ParamantOS to disk  [TUI wizard]" \
    "2" "Run as live system          [no installation]" \
    "3" "Open shell                  [advanced]" \
    3>&1 1>&2 2>&3)

  WHIP_EXIT=$?
  # Esc / Ctrl-C on whiptail → go back to banner + menu
  if [ $WHIP_EXIT -ne 0 ]; then
    continue
  fi

  case "$CHOICE" in
    1)
      _banner
      echo -e "${CYAN}[•]${RESET} Launching installer — this requires root..."
      echo ""

      # NOPASSWD ALL is set in the ISO sudoers config for the paramant user,
      # so this never prompts for a password.
      sudo paramant-installer
      INSTALL_RC=$?

      if [ $INSTALL_RC -eq 0 ]; then
        # Installer itself handles the reboot prompt — we should never reach here
        # unless the user chose not to reboot. Go back to menu.
        continue
      else
        # Installation failed — show error and offer retry
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        echo -e "${YELLOW}  Installation did not complete successfully.${RESET}"
        echo -e "${YELLOW}  Check the log file shown above for details.${RESET}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        echo ""

        RETRY=$(whiptail \
          --title "Installation failed" \
          --menu "\nWhat would you like to do?" 12 60 3 \
          "1" "Try installing again" \
          "2" "Run as live system" \
          "3" "Open shell to investigate" \
          3>&1 1>&2 2>&3) || continue

        case "$RETRY" in
          1) continue ;;      # loop back → re-shows menu → install again
          2)
            echo -e "${CYAN}[•]${RESET} Starting live session."
            echo ""
            paramant-setup
            break
            ;;
          3)
            echo -e "${CYAN}[•]${RESET} Dropping to shell."
            echo -e "     Type ${BOLD}sudo paramant-installer${RESET} to retry."
            echo ""
            break
            ;;
        esac
      fi
      ;;

    2)
      _banner
      echo -e "${CYAN}[•]${RESET} Starting live session — relay active, nothing written to disk."
      echo ""
      paramant-setup
      break
      ;;

    3)
      _banner
      echo -e "${CYAN}[•]${RESET} Dropping to shell."
      echo -e "     ${BOLD}sudo paramant-installer${RESET}  — install to disk"
      echo -e "     ${BOLD}paramant-setup${RESET}           — configure live session"
      echo ""
      break
      ;;
  esac
done
