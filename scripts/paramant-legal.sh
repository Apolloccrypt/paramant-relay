#!/usr/bin/env bash
# paramant-legal — court document relay (replaces Zivver, no storage)
# Usage: paramant-legal summons.pdf --case ROT-2026-1234 --proof

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
SECTOR=legal
SENDER=${PARAMANT_SENDER:-paramant-sender}
CFG="${HOME}/.config/paramant/config.json"
API_KEY="${PARAMANT_API_KEY:-$(python3 -c "import json; print(json.load(open('${CFG}')).get('api_key',''))" 2>/dev/null)}"

usage() {
  echo -e "${BOLD}paramant-legal${RESET} — court document relay (replaces Zivver, no storage)
Usage: paramant-legal <file> [--case CASENUMBER] [--ttl HOURS] [--proof]
  --case NUM   Tag transfer with case number (e.g. ROT-2026-1234)
  --ttl  HOURS Blob TTL in hours (default: 24)
  --proof      Save CT proof to ./proofs/YYYY-MM-DD-<file>.proof
  --help       Show this message
Example: paramant-legal summons.pdf --case ROT-2026-1234 --proof"
  exit 0
}

[[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]] && usage
FILE="$1"; shift
CASE=""; TTL=24; DO_PROOF=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) CASE="$2"; shift ;;
    --ttl)  TTL="$2";  shift ;;
    --proof) DO_PROOF=1 ;;
  esac; shift
done

[[ ! -f "$FILE" ]] && { echo -e "${RED}ERROR: file not found: $FILE${RESET}" >&2; exit 1; }
[[ -z "$API_KEY" ]] && { echo -e "${RED}ERROR: no API key — run paramant-setup${RESET}" >&2; exit 1; }

echo -e "[paramant-legal] → ${CYAN}${SECTOR}.paramant.app${RESET}"
[[ -n "$CASE" ]] && echo -e "  Case: ${BOLD}${CASE}${RESET}"
TTL_SEC=$(( TTL * 3600 ))

OUTPUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$FILE" --ttl "$TTL_SEC" 2>&1)
if [[ $? -ne 0 ]]; then echo -e "${RED}ERROR: send failed${RESET}\n$OUTPUT" >&2; exit 1; fi

HASH=$(echo "$OUTPUT" | grep -oP '(?<=Hash: )[a-f0-9]+' | head -1)
echo -e "${GREEN}Document sent.${RESET} Case: ${CASE:-untagged}. Hash: ${HASH}"

if [[ $DO_PROOF -eq 1 && -n "$HASH" ]]; then
  mkdir -p proofs
  PROOF="proofs/$(date '+%Y-%m-%d')-$(basename "$FILE").proof"
  printf '{"timestamp":"%s","relay":"%s.paramant.app","case":"%s","file_hash":"%s","blob_hash":"%s","ttl_hours":%d}\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$SECTOR" "$CASE" \
    "$(sha256sum "$FILE" | cut -c1-64)" "$HASH" "$TTL" > "$PROOF"
  echo -e "Proof saved: ${PROOF}"
fi
