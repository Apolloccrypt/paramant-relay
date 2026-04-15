#!/usr/bin/env bash
# paramant-notary — legal document transport (notary, KNB protocol)
# Usage: paramant-notary deed.pdf --sign --receipt

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
SECTOR=legal
SENDER=${PARAMANT_SENDER:-paramant-sender}
CFG="${HOME}/.config/paramant/config.json"
API_KEY="${PARAMANT_API_KEY:-$(python3 -c "import json; print(json.load(open('${CFG}')).get('api_key',''))" 2>/dev/null)}"

usage() {
  echo -e "${BOLD}paramant-notary${RESET} — legal document transport (notary, KNB protocol)
Usage: paramant-notary <file> [--sign] [--receipt]
  --sign      Sign file with local key (openssl SHA-256 digest)
  --receipt   Save CT proof to ./receipts/YYYY-MM-DD-<filename>.proof
  --help      Show this message
Example: paramant-notary deed.pdf --sign --receipt"
  exit 0
}

[[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]] && usage
FILE="$1"; shift
DO_SIGN=0; DO_RECEIPT=0
while [[ $# -gt 0 ]]; do
  case "$1" in --sign) DO_SIGN=1 ;; --receipt) DO_RECEIPT=1 ;; esac; shift
done

[[ ! -f "$FILE" ]] && { echo -e "${RED}ERROR: file not found: $FILE${RESET}" >&2; exit 1; }
[[ -z "$API_KEY" ]] && { echo -e "${RED}ERROR: no API key — run paramant-setup${RESET}" >&2; exit 1; }

echo -e "[paramant-notary] → ${CYAN}${SECTOR}.paramant.app${RESET}"

if [[ $DO_SIGN -eq 1 ]]; then
  command -v openssl >/dev/null 2>&1 || { echo -e "${RED}ERROR: openssl not found${RESET}" >&2; exit 1; }
  SIG_FILE="${FILE}.sha256sig"
  openssl dgst -sha256 -out "$SIG_FILE" "$FILE"
  echo -e "  Signed: ${SIG_FILE}"
fi

OUTPUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$FILE" 2>&1)
if [[ $? -ne 0 ]]; then echo -e "${RED}ERROR: send failed${RESET}\n$OUTPUT" >&2; exit 1; fi

HASH=$(echo "$OUTPUT" | grep -oP '(?<=Hash: )[a-f0-9]+' | head -1)
echo -e "${GREEN}Deed sent.${RESET} Hash: ${HASH}"

if [[ $DO_RECEIPT -eq 1 && -n "$HASH" ]]; then
  mkdir -p receipts
  PROOF="receipts/$(date '+%Y-%m-%d')-$(basename "$FILE").proof"
  printf '{"timestamp":"%s","relay":"%s.paramant.app","file_hash":"%s","blob_hash":"%s"}\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$SECTOR" \
    "$(sha256sum "$FILE" | cut -c1-64)" "$HASH" > "$PROOF"
  echo -e "CT proof saved: ${PROOF}"
fi
[[ $DO_SIGN -eq 1 ]] && echo -e "Signature: ${FILE}.sha256sig"
