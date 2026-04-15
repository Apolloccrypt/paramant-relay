#!/usr/bin/env bash
# paramant-payslip — HR payslip distribution (GDPR/AVG compliant, no email/storage)
# Usage: paramant-payslip --bulk employees.csv --dir ./payslips/april/

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
SECTOR=relay
SENDER=${PARAMANT_SENDER:-paramant-sender}
CFG="${HOME}/.config/paramant/config.json"
API_KEY="${PARAMANT_API_KEY:-$(python3 -c "import json; print(json.load(open('${CFG}')).get('api_key',''))" 2>/dev/null)}"

usage() {
  echo -e "${BOLD}paramant-payslip${RESET} — HR payslip distribution (GDPR/AVG compliant)
Usage: paramant-payslip --bulk <employees.csv> --dir <payslips-dir>
  --bulk FILE   CSV columns: email,device_id (header row skipped)
  --dir  DIR    Folder with PDFs named <device_id>.pdf
  --help        Show this message
Example: paramant-payslip --bulk employees.csv --dir ./payslips/april/
Note: log written to ./sent-YYYY-MM-DD.log (device IDs only, no file content)"
  exit 0
}

[[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]] && usage
CSV=""; PAYDIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in --bulk) CSV="$2"; shift ;; --dir) PAYDIR="$2"; shift ;; esac; shift
done

[[ -z "$CSV" ]]   && { echo -e "${RED}ERROR: --bulk required${RESET}" >&2; exit 1; }
[[ -z "$PAYDIR" ]] && { echo -e "${RED}ERROR: --dir required${RESET}" >&2; exit 1; }
[[ ! -f "$CSV" ]] && { echo -e "${RED}ERROR: file not found: $CSV${RESET}" >&2; exit 1; }
[[ ! -d "$PAYDIR" ]] && { echo -e "${RED}ERROR: directory not found: $PAYDIR${RESET}" >&2; exit 1; }
[[ -z "$API_KEY" ]] && { echo -e "${RED}ERROR: no API key — run paramant-setup${RESET}" >&2; exit 1; }

echo -e "[paramant-payslip] → ${CYAN}${SECTOR}.paramant.app${RESET}"
LOG="sent-$(date '+%Y-%m-%d').log"

tail -n +2 "$CSV" | while IFS=',' read -r _email device_id _rest; do
  device_id=$(echo "$device_id" | tr -d ' \r\n')
  [[ -z "$device_id" ]] && continue
  PDF="${PAYDIR}/${device_id}.pdf"
  if [[ ! -f "$PDF" ]]; then
    echo -e "  ${RED}SKIP${RESET}: no payslip PDF for device: ${device_id}"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') SKIP device=${device_id} reason=no_file" >> "$LOG"
    continue
  fi
  OUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$PDF" 2>&1)
  if [[ $? -eq 0 ]]; then
    echo -e "  ${GREEN}Payslip sent to device: ${device_id}${RESET}"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') SENT device=${device_id}" >> "$LOG"
  else
    echo -e "  ${RED}FAILED${RESET}: device=${device_id}"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') FAILED device=${device_id}" >> "$LOG"
  fi
done

echo -e "\nLog saved: ${LOG}"
echo "No payslip content stored on relay. Burn-on-read. GDPR compliant."
