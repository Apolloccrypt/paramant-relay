#!/usr/bin/env bash
# paramant-dashboard — live TUI for relay status (2s refresh)
# Keys: q=quit  r=restart  l=logs  k=keys  ?=help

LICENSE_FILE="/etc/paramant/license"
REFRESH=2

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ── Read ADMIN_TOKEN ───────────────────────────────────────────────────────────
ADMIN_TOKEN=""
if [[ -f "$LICENSE_FILE" ]]; then
  ADMIN_TOKEN=$(grep -oP '(?<=ADMIN_TOKEN=)\S+' "$LICENSE_FILE" 2>/dev/null || true)
fi

# ── Helper: relay health ───────────────────────────────────────────────────────
get_health() {
  local port=$1
  curl -sf --max-time 1 "http://localhost:${port}/health" 2>/dev/null || echo ""
}

get_keys() {
  if [[ -z "$ADMIN_TOKEN" ]]; then echo "no token"; return; fi
  curl -sf --max-time 1 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "http://localhost:3000/v2/admin/keys" 2>/dev/null \
    | jq -r '
      (if type == "object" then .keys // [] else . end) as $keys |
      "\($keys | length) key(s)",
      ($keys[:5][] | "  \(.label // "?") (\(.plan // "?"))"),
      (if ($keys | length) > 5 then "  ... +\(($keys | length) - 5) more" else empty end)
    ' 2>/dev/null || echo "unavailable"
}

relay_status() {
  systemctl is-active paramant-relay 2>/dev/null || echo "unknown"
}

draw() {
  clear
  local now
  now=$(date '+%Y-%m-%d %H:%M:%S')
  local status
  status=$(relay_status)
  local status_color="$RED"
  [[ "$status" == "active" ]] && status_color="$GREEN"

  echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}║              ParamantOS Dashboard                            ║${RESET}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
  echo -e "  ${DIM}Updated: ${now}   Refresh: ${REFRESH}s${RESET}"
  echo ""

  # Service status
  echo -e "  ${BOLD}Relay service:${RESET}  ${status_color}${status}${RESET}"
  echo ""

  # Sector health table
  declare -A SECTORS=([3000]="main" [3001]="health" [3002]="finance" [3003]="legal" [3004]="iot")
  echo -e "  ${BOLD}Sector endpoints:${RESET}"
  for port in 3000 3001 3002 3003 3004; do
    local name="${SECTORS[$port]}"
    local json
    json=$(get_health "$port")
    if [[ -z "$json" ]]; then
      echo -e "    ${RED}✗${RESET} :${port}  ${name}  ${RED}unreachable${RESET}"
    else
      local ok version edition
      ok=$(echo "$json" | jq -r '.ok // "?"' 2>/dev/null || echo "?")
      version=$(echo "$json" | jq -r '.version // "?"' 2>/dev/null || echo "?")
      edition=$(echo "$json" | jq -r '.edition // ""' 2>/dev/null || true)
      if [[ "$ok" == "True" ]] || [[ "$ok" == "true" ]]; then
        local extra=""
        [[ -n "$edition" ]] && extra="  ${DIM}[${edition}]${RESET}"
        echo -e "    ${GREEN}✓${RESET} :${port}  ${name}  v${version}${extra}"
      else
        echo -e "    ${YELLOW}?${RESET} :${port}  ${name}  ${YELLOW}${json:0:60}${RESET}"
      fi
    fi
  done

  echo ""

  # API keys (admin)
  echo -e "  ${BOLD}API keys:${RESET}"
  local keys_out
  keys_out=$(get_keys)
  while IFS= read -r line; do
    echo -e "    ${line}"
  done <<< "$keys_out"

  echo ""

  # Network
  local ip
  ip=$(ip -4 addr show scope global | grep -oP '(?<=inet )[0-9.]+' | head -1 || echo "unknown")
  echo -e "  ${BOLD}IP:${RESET}  ${ip}"

  echo ""
  echo -e "  ${DIM}Keys: [q] quit  [r] restart relay  [l] live logs  [k] key list  [?] help${RESET}"
}

# ── Main loop ──────────────────────────────────────────────────────────────────
stty -echo 2>/dev/null || true

cleanup() {
  stty echo 2>/dev/null || true
  tput cnorm 2>/dev/null || true
  clear
}
trap cleanup EXIT

tput civis 2>/dev/null || true

while true; do
  draw

  # Non-blocking read with timeout
  if read -r -s -n 1 -t "$REFRESH" key 2>/dev/null; then
    case "$key" in
      q|Q)
        break
        ;;
      r|R)
        clear
        echo -e "${YELLOW}Restarting paramant-relay...${RESET}"
        sudo paramant-relay-ctl restart paramant-relay
        echo -e "${GREEN}Done.${RESET} Resuming dashboard in 2s..."
        sleep 2
        ;;
      l|L)
        stty echo 2>/dev/null || true
        tput cnorm 2>/dev/null || true
        clear
        echo -e "${CYAN}Live logs — press Ctrl-C to return to dashboard${RESET}"
        journalctl -u paramant-relay -f --no-pager || true
        tput civis 2>/dev/null || true
        stty -echo 2>/dev/null || true
        ;;
      k|K)
        clear
        echo -e "${BOLD}API Keys:${RESET}"
        if [[ -z "$ADMIN_TOKEN" ]]; then
          echo "No ADMIN_TOKEN configured. Run paramant-setup to generate one."
        else
          curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
            "http://localhost:3000/v2/admin/keys" 2>/dev/null \
            | jq . 2>/dev/null || echo "Could not fetch keys."
        fi
        echo ""
        echo -e "${DIM}Press any key to return...${RESET}"
        read -r -s -n 1
        ;;
      "?")
        clear
        echo -e "${BOLD}Dashboard Help${RESET}"
        echo ""
        echo "  q / Q    Quit dashboard"
        echo "  r / R    Restart paramant-relay service"
        echo "  l / L    Open live log stream (Ctrl-C to return)"
        echo "  k / K    Show API key list"
        echo "  ?        This help screen"
        echo ""
        echo -e "${DIM}Press any key to return...${RESET}"
        read -r -s -n 1
        ;;
    esac
  fi
done
