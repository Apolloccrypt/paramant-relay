#!/usr/bin/env bash
# paramant-verify — out-of-band fingerprint verification for Ghost Pipe devices
# Usage: paramant-verify <device-id>
#        paramant-verify --list
#        paramant-verify --clear <device-id>

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; DIM='\033[2m'; RESET='\033[0m'

RELAY_URL="http://localhost:3000"
KNOWN_KEYS="/home/paramant/.paramant/known_keys"

# ── helpers ────────────────────────────────────────────────────────────────────
die() { echo -e "${RED}ERROR: $*${RESET}" >&2; exit 1; }

require_relay() {
  curl -sf "${RELAY_URL}/health" >/dev/null 2>&1 || die "Relay not reachable at ${RELAY_URL}"
}

list_known() {
  if [ ! -f "$KNOWN_KEYS" ]; then
    echo -e "${DIM}No trusted devices yet.${RESET}"
    echo -e "Run: ${CYAN}paramant-verify <device-id>${RESET} to verify a device."
    exit 0
  fi
  echo -e "\n${BOLD}Trusted devices (known_keys)${RESET}\n"
  printf "${CYAN}%-36s %-26s %-24s${RESET}\n" "Device" "Fingerprint" "Registered"
  echo "$(printf '─%.0s' {1..90})"
  grep -v '^#' "$KNOWN_KEYS" | grep -v '^$' | while read -r did fp reg; do
    printf "%-36s ${GREEN}%-26s${RESET} ${DIM}%-24s${RESET}\n" "$did" "$fp" "$reg"
  done
  echo ""
}

clear_device() {
  local device="$1"
  [ -z "$device" ] && die "Usage: paramant-verify --clear <device-id>"
  [ ! -f "$KNOWN_KEYS" ] && { echo "No known_keys file found."; exit 0; }
  local tmp="${KNOWN_KEYS}.tmp"
  grep -v "^${device} " "$KNOWN_KEYS" > "$tmp" && mv "$tmp" "$KNOWN_KEYS"
  echo -e "${GREEN}✓${RESET} Removed ${BOLD}${device}${RESET} from trusted devices."
}

verify_device() {
  local device="$1"
  require_relay

  echo -e "\n${CYAN}Fetching pubkey for device: ${BOLD}${device}${RESET}\n"

  local response
  response=$(curl -sf "${RELAY_URL}/v2/fingerprint/${device}" 2>/dev/null)
  if [ $? -ne 0 ] || [ -z "$response" ]; then
    # Try with API key from config
    local api_key
    api_key=$(grep -oP '(?<=ADMIN_TOKEN=)[^\s]+' /etc/paramant/license 2>/dev/null | head -1)
    if [ -n "$api_key" ]; then
      response=$(curl -sf -H "X-Api-Key: ${api_key}" "${RELAY_URL}/v2/fingerprint/${device}" 2>/dev/null)
    fi
  fi

  if [ -z "$response" ] || echo "$response" | grep -q '"error"'; then
    die "Device not found: ${device}\nIs the device registered? Run the receiver first."
  fi

  local fp registered ct_index
  fp=$(echo "$response" | jq -r '.fingerprint // "?"')
  registered=$(echo "$response" | jq -r '.registered_at // "?"')
  ct_index=$(echo "$response" | jq -r 'if .ct_index != null then (.ct_index|tostring) else "N/A" end')

  echo -e "  ${DIM}Device:${RESET}       ${BOLD}${device}${RESET}"
  echo -e "  ${DIM}Fingerprint:${RESET}  ${GREEN}${BOLD}${fp}${RESET}"
  echo -e "  ${DIM}Registered:${RESET}   ${registered}"
  echo -e "  ${DIM}CT log index:${RESET} ${ct_index}"

  # Check TOFU
  local stored_fp=""
  if [ -f "$KNOWN_KEYS" ]; then
    stored_fp=$(grep "^${device} " "$KNOWN_KEYS" 2>/dev/null | awk '{print $2}')
  fi

  echo ""
  if [ -n "$stored_fp" ]; then
    if [ "$stored_fp" = "$fp" ]; then
      echo -e "  ${GREEN}✓ Fingerprint matches stored value — device trusted${RESET}"
    else
      echo -e "  ${RED}⚠  FINGERPRINT MISMATCH!${RESET}"
      echo -e "  ${DIM}Stored:${RESET}   ${RED}${stored_fp}${RESET}"
      echo -e "  ${DIM}Received:${RESET} ${RED}${fp}${RESET}"
      echo -e "\n  ${YELLOW}This may indicate a compromised relay or legitimate key rotation."
      echo -e "  Only trust if you verified with the device owner via a separate channel.${RESET}"
      echo ""
      read -r -p "  Override and trust new fingerprint? [y/N] " ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then
        mkdir -p "$(dirname "$KNOWN_KEYS")"
        local tmp="${KNOWN_KEYS}.tmp"
        (grep -v "^${device} " "$KNOWN_KEYS" 2>/dev/null; echo "${device} ${fp} ${registered}") > "$tmp"
        chmod 600 "$tmp" && mv "$tmp" "$KNOWN_KEYS"
        echo -e "\n  ${GREEN}✓ Updated trust for ${device}${RESET}"
      else
        echo -e "\n  ${DIM}Not trusted.${RESET}"
        exit 1
      fi
    fi
  else
    echo -e "  ${YELLOW}◈ First contact — no stored fingerprint${RESET}"
    echo -e "  ${DIM}Verify out-of-band: call or Signal the device owner and read the fingerprint aloud.${RESET}"
    echo ""
    read -r -p "  Mark as trusted? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      mkdir -p "$(dirname "$KNOWN_KEYS")"
      {
        if [ ! -f "$KNOWN_KEYS" ]; then
          echo "# PARAMANT known-keys — Trust On First Use (TOFU)"
          echo "# Format: device_id fingerprint registered_at"
        fi
        echo "${device} ${fp} ${registered}"
      } >> "$KNOWN_KEYS"
      chmod 600 "$KNOWN_KEYS"
      echo -e "\n  ${GREEN}✓ Trusted: ${device} (${fp})${RESET}"
    else
      echo -e "\n  ${DIM}Not trusted.${RESET}"
    fi
  fi
  echo ""
}

# ── main ───────────────────────────────────────────────────────────────────────
case "$1" in
  --list|-l)
    list_known
    ;;
  --clear)
    clear_device "$2"
    ;;
  --help|-h|"")
    echo -e "
${BOLD}paramant-verify${RESET} — Ghost Pipe fingerprint verification

${CYAN}Usage:${RESET}
  paramant-verify <device-id>       Verify device fingerprint (TOFU)
  paramant-verify --list            List all trusted devices
  paramant-verify --clear <device>  Remove device from trusted list

${CYAN}About fingerprints:${RESET}
  A fingerprint is SHA-256(kyber_pub || ecdh_pub) → 5 groups of 4 hex chars.
  Both sender and receiver compute it independently.
  Mismatch means the relay may be serving a different key (MITM).

  Verification methods:
  1. Phone/Signal: read fingerprint aloud to receiver, they confirm
  2. QR code: scan fingerprint QR shown in ParaShare
  3. Pre-shared secret: add PSS to gp.send(pss='...') for API transfers

${CYAN}Trusted devices are stored in:${RESET}
  ${KNOWN_KEYS}
"
    ;;
  *)
    verify_device "$1"
    ;;
esac
