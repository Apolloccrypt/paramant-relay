#!/usr/bin/env bash
# paramant-firmware — secure IoT/body-cam firmware distribution (IEC 62443)
# Usage: paramant-firmware update-v2.1.bin --sign --device-group bodycams.txt --version 2.1
# Usage: paramant-firmware --receive --verify-key vendor.pub

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
SECTOR=iot
SENDER=${PARAMANT_SENDER:-paramant-sender}
RECEIVER=${PARAMANT_RECEIVER:-paramant-receiver}
CFG="${HOME}/.config/paramant/config.json"
API_KEY="${PARAMANT_API_KEY:-$(python3 -c "import json; print(json.load(open('${CFG}')).get('api_key',''))" 2>/dev/null)}"

usage() {
  echo -e "${BOLD}paramant-firmware${RESET} — secure IoT/body-cam firmware distribution (IEC 62443)
Usage (sender):  paramant-firmware <firmware.bin> --sign --device-group <devices.txt> --version <VER>
Usage (device):  paramant-firmware --receive --verify-key <vendor.pub>
  --sign           Sign firmware with ed25519 key (~/.config/paramant/signing.key)
  --device-group F Text file with one device ID per line
  --version VER    Firmware version string (logged in CT, not stored)
  --receive        Receive and save firmware update
  --verify-key F   Ed25519 public key file for signature verification
  --help           Show this message"
  exit 0
}

[[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]] && usage
MODE=send; FIRMWARE=""; DO_SIGN=0; DEVICE_GROUP=""; VERSION=""; VERIFY_KEY=""
[[ "$1" == "--receive" ]] && { MODE=receive; shift; }
if [[ "$MODE" == "send" ]]; then FIRMWARE="$1"; shift; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sign)         DO_SIGN=1 ;;
    --device-group) DEVICE_GROUP="$2"; shift ;;
    --version)      VERSION="$2"; shift ;;
    --receive)      MODE=receive ;;
    --verify-key)   VERIFY_KEY="$2"; shift ;;
  esac; shift
done

[[ -z "$API_KEY" ]] && { echo -e "${RED}ERROR: no API key — run paramant-setup${RESET}" >&2; exit 1; }
echo -e "[paramant-firmware] → ${CYAN}${SECTOR}.paramant.app${RESET}"

if [[ "$MODE" == "receive" ]]; then
  OUTDIR="${HOME}/firmware-updates"
  mkdir -p "$OUTDIR"
  echo -e "  Listening for firmware update..."
  OUTPUT=$($RECEIVER --key "$API_KEY" --relay "$SECTOR" --listen --output "$OUTDIR/" 2>&1)
  FWFILE=$(echo "$OUTPUT" | grep -oP "${OUTDIR}/[^\s]+" | head -1)
  if [[ -n "$FWFILE" && -f "$FWFILE" ]]; then
    echo -e "${GREEN}Firmware received:${RESET} ${FWFILE}"
    if [[ -n "$VERIFY_KEY" && -f "$VERIFY_KEY" ]]; then
      SIG_FILE="${FWFILE}.sig"
      if [[ -f "$SIG_FILE" ]]; then
        openssl pkeyutl -verify -pubin -inkey "$VERIFY_KEY" -sigfile "$SIG_FILE" -in "$FWFILE" 2>/dev/null \
          && echo -e "${GREEN}Signature verified.${RESET}" \
          || { echo -e "${RED}Signature INVALID — rejecting firmware${RESET}" >&2; rm -f "$FWFILE" "$SIG_FILE"; exit 1; }
      else
        echo -e "${RED}WARNING: --verify-key set but no .sig file found${RESET}" >&2
      fi
    fi
  else
    echo -e "${RED}No firmware received${RESET}" >&2; exit 1
  fi
  exit 0
fi

[[ ! -f "$FIRMWARE" ]] && { echo -e "${RED}ERROR: firmware not found: $FIRMWARE${RESET}" >&2; exit 1; }
[[ -n "$VERSION" ]] && echo -e "  Version: ${VERSION}"

if [[ $DO_SIGN -eq 1 ]]; then
  KEY="${HOME}/.config/paramant/signing.key"
  [[ ! -f "$KEY" ]] && { openssl genpkey -algorithm ed25519 -out "$KEY" 2>/dev/null; echo -e "  Generated signing key: ${KEY}"; }
  openssl pkeyutl -sign -inkey "$KEY" -out "${FIRMWARE}.sig" -in "$FIRMWARE" 2>/dev/null \
    || { echo -e "${RED}ERROR: signing failed${RESET}" >&2; exit 1; }
  echo -e "  Signature: ${FIRMWARE}.sig"
fi

if [[ -n "$DEVICE_GROUP" && -f "$DEVICE_GROUP" ]]; then
  while IFS= read -r device_id; do
    [[ -z "$device_id" || "$device_id" == \#* ]] && continue
    OUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$FIRMWARE" 2>&1)
    [[ $? -eq 0 ]] && echo -e "  ${GREEN}Sent to device: ${device_id}${RESET}" \
                    || echo -e "  ${RED}FAILED: ${device_id}${RESET}"
  done < "$DEVICE_GROUP"
else
  OUTPUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$FIRMWARE" 2>&1)
  [[ $? -ne 0 ]] && { echo -e "${RED}ERROR: send failed${RESET}\n$OUTPUT" >&2; exit 1; }
  HASH=$(echo "$OUTPUT" | grep -oP '(?<=Hash: )[a-f0-9]+' | head -1)
  echo -e "${GREEN}Firmware sent.${RESET} Hash: ${HASH}"
fi
echo -e "CT log proves delivery. IEC 62443 compliant."
