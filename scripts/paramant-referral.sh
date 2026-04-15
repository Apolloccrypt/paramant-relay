#!/usr/bin/env bash
# paramant-referral — healthcare referral relay (NEN 7510, HL7 FHIR/DICOM)
# Usage: paramant-referral referral.json --type fhir --from gp-001 --to cardiology-umcg --patient-ref <sha256>

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
SECTOR=health
SENDER=${PARAMANT_SENDER:-paramant-sender}
CFG="${HOME}/.config/paramant/config.json"
API_KEY="${PARAMANT_API_KEY:-$(python3 -c "import json; print(json.load(open('${CFG}')).get('api_key',''))" 2>/dev/null)}"

usage() {
  echo -e "${BOLD}paramant-referral${RESET} — healthcare referral relay (NEN 7510, HL7 FHIR/DICOM)
Usage: paramant-referral <file> --type fhir|dicom|pdf --from <id> --to <id> [--patient-ref <sha256>] [--forward <url>]
  --type TYPE       Referral type: fhir, dicom, pdf
  --from ID         Sender identifier (e.g. gp-001)
  --to   ID         Receiver identifier (e.g. cardiology-umcg)
  --patient-ref H   SHA-256 hash of patient BSN (NOT the BSN itself)
  --forward URL     Auto-forward received file to PACS/EHR endpoint
  --help            Show this message
Example: paramant-referral ref.json --type fhir --from gp-001 --to cardiology-umcg \\
  --patient-ref \$(echo -n 123456789 | sha256sum | cut -c1-64)"
  exit 0
}

[[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]] && usage
FILE="$1"; shift
TYPE=""; FROM_ID=""; TO_ID=""; PATIENT_REF=""; FORWARD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)        TYPE="$2";        shift ;;
    --from)        FROM_ID="$2";     shift ;;
    --to)          TO_ID="$2";       shift ;;
    --patient-ref) PATIENT_REF="$2"; shift ;;
    --forward)     FORWARD="$2";     shift ;;
  esac; shift
done

[[ ! -f "$FILE" ]] && { echo -e "${RED}ERROR: file not found: $FILE${RESET}" >&2; exit 1; }
[[ -z "$TYPE" ]]   && { echo -e "${RED}ERROR: --type required (fhir|dicom|pdf)${RESET}" >&2; exit 1; }
[[ -z "$FROM_ID" || -z "$TO_ID" ]] && { echo -e "${RED}ERROR: --from and --to required${RESET}" >&2; exit 1; }
[[ -z "$API_KEY" ]] && { echo -e "${RED}ERROR: no API key — run paramant-setup${RESET}" >&2; exit 1; }

echo -e "[paramant-referral] → ${CYAN}${SECTOR}.paramant.app${RESET}"
echo -e "  Type: ${TYPE} | From: ${FROM_ID} → To: ${TO_ID}"
[[ -n "$PATIENT_REF" ]] && echo -e "  Patient ref (SHA-256): ${PATIENT_REF:0:16}..."
echo -e "  No patient data stored in relay. NEN 7510 compliant."

EXTRA_ARGS=""
[[ -n "$FORWARD" ]] && EXTRA_ARGS="--forward $FORWARD"

OUTPUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$FILE" $EXTRA_ARGS 2>&1)
if [[ $? -ne 0 ]]; then echo -e "${RED}ERROR: send failed${RESET}\n$OUTPUT" >&2; exit 1; fi

HASH=$(echo "$OUTPUT" | grep -oP '(?<=Hash: )[a-f0-9]+' | head -1)
echo -e "${GREEN}Referral sent.${RESET} Hash: ${HASH}"
[[ -n "$FORWARD" ]] && echo -e "  Forward target: ${FORWARD}"
