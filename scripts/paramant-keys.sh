#!/usr/bin/env bash
# paramant-keys — list all API keys

LICENSE_FILE="/etc/paramant/license"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

ADMIN_TOKEN=""
if [[ -f "$LICENSE_FILE" ]]; then
  ADMIN_TOKEN=$(grep -oP '(?<=ADMIN_TOKEN=)\S+' "$LICENSE_FILE" 2>/dev/null || true)
fi

if [[ -z "$ADMIN_TOKEN" ]]; then
  echo -e "${RED}No ADMIN_TOKEN configured.${RESET}"
  echo "Run: paramant-setup --force  (step 3 generates an admin token)"
  exit 1
fi

echo -e "\n${BOLD}API Keys${RESET}"
echo "──────────────────────────────────────"

RESP=$(curl -sf --max-time 5 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  http://localhost:3000/v2/admin/keys 2>/dev/null || echo "")

if [[ -z "$RESP" ]]; then
  echo -e "${RED}Could not reach relay. Is it running?${RESET}"
  exit 1
fi

echo "$RESP" | jq -r '
  (if type == "object" then .keys // [] else . end) as $keys |
  if ($keys | length) == 0 then "  (no API keys)"
  else
    "  \("Label" | .[0:20] | . + (" " * (20 - length)))  \("Plan" | .[0:12] | . + (" " * (12 - length)))  \("Status" | .[0:10] | . + (" " * (10 - length)))  Key (prefix)",
    "  \("-" * 20)  \("-" * 12)  \("-" * 10)  \("-" * 20)",
    ($keys[] |
      (.label // "?")[0:20] as $lbl |
      (.plan // "?")[0:12] as $pln |
      (if (.active // true) then "active" else "inactive" end) as $st |
      (.key // .api_key // "?") as $k |
      (if ($k | length) > 16 then $k[0:16] + "..." else $k end) as $pfx |
      "  \($lbl + (" " * (20 - ($lbl | length))))  \($pln + (" " * (12 - ($pln | length))))  \($st + (" " * (10 - ($st | length))))  \($pfx)"
    ),
    "",
    "  Total: \($keys | length) key(s)"
  end
' 2>/dev/null || echo "  Unexpected response format"

echo ""
