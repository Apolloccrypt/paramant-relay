#!/usr/bin/env bash
# paramant-ticket — one-time transit ticket issuer/verifier (burn-on-read)
# Usage (issuer): paramant-ticket --issue --route 'AMS-RTD' --valid '2026-04-14T09:00/10:00' --device traveler-456
# Usage (gate):   paramant-ticket --verify --device traveler-456

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
SECTOR=iot
SENDER=${PARAMANT_SENDER:-paramant-sender}
RECEIVER=${PARAMANT_RECEIVER:-paramant-receiver}
CFG="${HOME}/.config/paramant/config.json"
API_KEY="${PARAMANT_API_KEY:-$(python3 -c "import json; print(json.load(open('${CFG}')).get('api_key',''))" 2>/dev/null)}"

usage() {
  echo -e "${BOLD}paramant-ticket${RESET} — one-time transit ticket issuer/verifier (burn-on-read)
Usage (issuer): paramant-ticket --issue --route 'AMS-RTD' --valid 'FROM/TO' --device <id>
Usage (gate):   paramant-ticket --verify --device <id>
  --issue       Generate and send a signed ticket blob
  --verify      Receive and validate a ticket (one-time, burn-on-read)
  --route ROUTE Route string (e.g. AMS-RTD)
  --valid RANGE Validity window ISO 8601: FROM/TO
  --device ID   Traveler device ID
  --help        Show this message"
  exit 0
}

[[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]] && usage
MODE=""; ROUTE=""; VALID=""; DEVICE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --issue)  MODE=issue ;;
    --verify) MODE=verify ;;
    --route)  ROUTE="$2"; shift ;;
    --valid)  VALID="$2"; shift ;;
    --device) DEVICE="$2"; shift ;;
  esac; shift
done

[[ -z "$MODE" ]]   && { echo -e "${RED}ERROR: --issue or --verify required${RESET}" >&2; exit 1; }
[[ -z "$DEVICE" ]] && { echo -e "${RED}ERROR: --device required${RESET}" >&2; exit 1; }
[[ -z "$API_KEY" ]] && { echo -e "${RED}ERROR: no API key — run paramant-setup${RESET}" >&2; exit 1; }

echo -e "[paramant-ticket] → ${CYAN}${SECTOR}.paramant.app${RESET}"

if [[ "$MODE" == "issue" ]]; then
  [[ -z "$ROUTE" || -z "$VALID" ]] && { echo -e "${RED}ERROR: --route and --valid required${RESET}" >&2; exit 1; }
  VALID_FROM="${VALID%%/*}"; VALID_UNTIL="${VALID##*/}"
  SIG=$(printf '%s:%s:%s:%s' "$DEVICE" "$ROUTE" "$VALID_FROM" "$VALID_UNTIL" | sha256sum | cut -c1-64)
  TMPFILE=$(mktemp /tmp/ticket-XXXXXX.json)
  printf '{"device":"%s","route":"%s","valid_from":"%s","valid_until":"%s","sig":"%s","issued":"%s"}\n' \
    "$DEVICE" "$ROUTE" "$VALID_FROM" "$VALID_UNTIL" "$SIG" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$TMPFILE"
  OUTPUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$TMPFILE" 2>&1)
  RC=$?; rm -f "$TMPFILE"
  [[ $RC -ne 0 ]] && { echo -e "${RED}ERROR: send failed${RESET}\n$OUTPUT" >&2; exit 1; }
  HASH=$(echo "$OUTPUT" | grep -oP '(?<=Hash: )[a-f0-9]+' | head -1)
  echo -e "${GREEN}Ticket issued.${RESET} Route: ${ROUTE} | Device: ${DEVICE} | Hash: ${HASH}"
  echo -e "Receive command: paramant-ticket --verify --device ${DEVICE}"
else
  TMPDIR=$(mktemp -d /tmp/ticket-verify-XXXXXX)
  OUTPUT=$($RECEIVER --key "$API_KEY" --relay "$SECTOR" --listen --output "$TMPDIR/" 2>&1)
  TICKET_FILE=$(ls -t "$TMPDIR"/*.json 2>/dev/null | head -1)
  if [[ -n "$TICKET_FILE" && -f "$TICKET_FILE" ]]; then
    ROUTE=$(python3 -c "import json; d=json.load(open('$TICKET_FILE')); print(d.get('route','?'))" 2>/dev/null)
    VALID_UNTIL=$(python3 -c "import json; d=json.load(open('$TICKET_FILE')); print(d.get('valid_until','?'))" 2>/dev/null)
    echo -e "${GREEN}VALID ticket.${RESET} Route: ${ROUTE} | Valid until: ${VALID_UNTIL}"
    rm -rf "$TMPDIR"
  else
    rm -rf "$TMPDIR"
    echo -e "${RED}No ticket found for device: ${DEVICE}${RESET}" >&2; exit 1
  fi
fi
