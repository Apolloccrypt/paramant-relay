#!/usr/bin/env bash
# paramant-key-add — add a new API key

LICENSE_FILE="/etc/paramant/license"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

ADMIN_TOKEN=""
if [[ -f "$LICENSE_FILE" ]]; then
  ADMIN_TOKEN=$(grep -oP '(?<=ADMIN_TOKEN=)\S+' "$LICENSE_FILE" 2>/dev/null || true)
fi

if [[ -z "$ADMIN_TOKEN" ]]; then
  echo -e "${RED}No ADMIN_TOKEN configured.${RESET}"
  echo "Run: paramant-setup --force  (step 3 generates an admin token)"
  exit 1
fi

echo -e "\n${BOLD}Add API Key${RESET}"
echo "──────────────────────────────────────"

LABEL=$(whiptail --title "Add API Key" \
  --inputbox "Label (e.g. 'customer-acme', 'iot-device-1'):" 10 60 "" 3>&1 1>&2 2>&3) || exit 0
[[ -z "$LABEL" ]] && { echo "Cancelled."; exit 0; }

PLAN=$(whiptail --title "Plan" \
  --menu "Select plan:" 12 50 3 \
  "free"       "Community — limited features" \
  "pro"        "Pro — full features" \
  "enterprise" "Enterprise" \
  3>&1 1>&2 2>&3) || exit 0

EMAIL=$(whiptail --title "Email (optional)" \
  --inputbox "Contact email (leave blank to skip):" 10 60 "" 3>&1 1>&2 2>&3) || true

PAYLOAD=$(jq -n --arg label "$LABEL" --arg plan "$PLAN" --arg email "$EMAIL" \
  'if $email != "" then {label:$label,plan:$plan,email:$email} else {label:$label,plan:$plan} end')

RESP=$(curl -sf --max-time 5 \
  -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  http://localhost:3000/v2/admin/keys 2>/dev/null || echo "")

if [[ -z "$RESP" ]]; then
  echo -e "${RED}No response from relay.${RESET}"
  exit 1
fi

# Check for error
ERR=$(echo "$RESP" | jq -r '.error // ""' 2>/dev/null || true)
if [[ -n "$ERR" ]]; then
  echo -e "${RED}Error: ${ERR}${RESET}"
  exit 1
fi

KEY=$(echo "$RESP" | jq -r '.key // .api_key // "?"' 2>/dev/null || echo "?")

echo -e "${GREEN}✓ API key created:${RESET}"
echo ""
echo "  Label: ${LABEL}"
echo "  Plan:  ${PLAN}"
echo "  Key:   ${KEY}"
echo ""
echo -e "${YELLOW}Save this key — it cannot be retrieved later.${RESET}"
echo ""
