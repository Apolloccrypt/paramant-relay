#!/usr/bin/env bash
# paramant-key-revoke — revoke an API key

LICENSE_FILE="/etc/paramant/license"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

ADMIN_TOKEN=""
if [[ -f "$LICENSE_FILE" ]]; then
  ADMIN_TOKEN=$(grep -oP '(?<=ADMIN_TOKEN=)\S+' "$LICENSE_FILE" 2>/dev/null || true)
fi

if [[ -z "$ADMIN_TOKEN" ]]; then
  echo -e "${RED}No ADMIN_TOKEN configured.${RESET}"
  echo "Run: paramant-setup --force"
  exit 1
fi

echo -e "\n${BOLD}Revoke API Key${RESET}"
echo "──────────────────────────────────────"

# Fetch key list
RESP=$(curl -sf --max-time 5 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://localhost:3000/v2/admin/keys 2>/dev/null || echo "")

if [[ -z "$RESP" ]]; then
  echo -e "${RED}Could not reach relay.${RESET}"
  exit 1
fi

# Build whiptail menu from key list
MENU_ITEMS=$(echo "$RESP" | jq -r '
  (if type == "object" then .keys // [] else . end) as $keys |
  if ($keys | length) == 0 then "EMPTY"
  else $keys[] | "\(.key // .api_key // .id // "")\t\(.label // "unlabeled") (\(.plan // "?"))"
  end
' 2>/dev/null || echo "EMPTY")

if [[ "$MENU_ITEMS" == "EMPTY" ]] || [[ -z "$MENU_ITEMS" ]]; then
  echo "No API keys to revoke."
  exit 0
fi

# Convert to whiptail args
ARGS=()
while IFS=$'\t' read -r key_id label; do
  ARGS+=("$key_id" "$label")
done <<< "$MENU_ITEMS"

SELECTED=$(whiptail --title "Revoke Key" \
  --menu "Select key to revoke:" 20 70 10 \
  "${ARGS[@]}" 3>&1 1>&2 2>&3) || exit 0

[[ -z "$SELECTED" ]] && { echo "Cancelled."; exit 0; }

LABEL=$(echo "$RESP" | jq -r --arg sel "$SELECTED" '
  (if type == "object" then .keys // [] else . end)[] |
  select((.key // .api_key // .id // "") == $sel) |
  .label // "unlabeled"
' 2>/dev/null | head -1 || echo "$SELECTED")

if ! whiptail --title "Confirm Revoke" \
  --yesno "Revoke key '${LABEL}'?\n\nThis cannot be undone." 10 60; then
  echo "Cancelled."
  exit 0
fi

DEL=$(curl -sf --max-time 5 \
  -X DELETE \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "http://localhost:3000/v2/admin/keys/${SELECTED}" 2>/dev/null || echo "")

if echo "$DEL" | jq -e '.ok == true or .deleted == true' 2>/dev/null; then
  echo -e "${GREEN}✓ Key '${LABEL}' revoked.${RESET}"
else
  echo -e "${YELLOW}Response: ${DEL}${RESET}"
fi
echo ""
