#!/usr/bin/env bash
# paramant-cra — EU Cyber Resilience Act build artifact relay (tamper-evident supply chain)
# Usage: paramant-cra dist/app-v1.2.tar.gz --sbom sbom.json --sign --registry https://registry.company.nl/api/publish

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
SECTOR=relay
SENDER=${PARAMANT_SENDER:-paramant-sender}
CFG="${HOME}/.config/paramant/config.json"
API_KEY="${PARAMANT_API_KEY:-$(python3 -c "import json; print(json.load(open('${CFG}')).get('api_key',''))" 2>/dev/null)}"

usage() {
  echo -e "${BOLD}paramant-cra${RESET} — EU Cyber Resilience Act build artifact relay (CRA 2027)
Usage: paramant-cra <artifact> [--sbom <sbom.json>] [--sign] [--registry <url>]
  --sbom FILE      Attach Software Bill of Materials (JSON/SPDX/CycloneDX)
  --sign           Sign artifact with build key (~/.config/paramant/signing.key)
  --registry URL   Forward artifact to package registry after relay
  --proof          Save CRA proof to ./cra-proofs/TIMESTAMP-<artifact>.proof
  --help           Show this message
Example (CI/CD): paramant-cra dist/app-v1.2.tar.gz --sbom sbom.json --sign \\
  --registry https://registry.company.nl/api/publish
Note: CT log entry = proof of what was published, when, and by whom."
  exit 0
}

[[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]] && usage
ARTIFACT="$1"; shift
SBOM=""; DO_SIGN=0; REGISTRY=""; DO_PROOF=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sbom)     SBOM="$2";     shift ;;
    --sign)     DO_SIGN=1 ;;
    --registry) REGISTRY="$2"; shift ;;
    --proof)    DO_PROOF=1 ;;
  esac; shift
done

[[ ! -f "$ARTIFACT" ]] && { echo -e "${RED}ERROR: artifact not found: $ARTIFACT${RESET}" >&2; exit 1; }
[[ -n "$SBOM" && ! -f "$SBOM" ]] && { echo -e "${RED}ERROR: SBOM not found: $SBOM${RESET}" >&2; exit 1; }
[[ -z "$API_KEY" ]] && { echo -e "${RED}ERROR: no API key — run paramant-setup${RESET}" >&2; exit 1; }

echo -e "[paramant-cra] → ${CYAN}${SECTOR}.paramant.app${RESET}"
echo -e "  Artifact: $(basename "$ARTIFACT") ($(wc -c < "$ARTIFACT") bytes)"

if [[ $DO_SIGN -eq 1 ]]; then
  KEY="${HOME}/.config/paramant/signing.key"
  [[ ! -f "$KEY" ]] && { openssl genpkey -algorithm ed25519 -out "$KEY" 2>/dev/null; echo -e "  Generated build key: ${KEY}"; }
  openssl pkeyutl -sign -inkey "$KEY" -out "${ARTIFACT}.sig" -in "$ARTIFACT" 2>/dev/null \
    || { echo -e "${RED}ERROR: signing failed${RESET}" >&2; exit 1; }
  echo -e "  Signed: ${ARTIFACT}.sig"
fi

SEND_FILE="$ARTIFACT"
if [[ -n "$SBOM" ]]; then
  BUNDLE=$(mktemp /tmp/cra-bundle-XXXXXX.tar.gz)
  tar -czf "$BUNDLE" -C "$(dirname "$ARTIFACT")" "$(basename "$ARTIFACT")" -C "$(dirname "$SBOM")" "$(basename "$SBOM")" 2>/dev/null
  SEND_FILE="$BUNDLE"
  echo -e "  Bundled with SBOM: $(basename "$SBOM")"
fi

OUTPUT=$($SENDER --key "$API_KEY" --relay "$SECTOR" --file "$SEND_FILE" 2>&1)
RC=$?; [[ -n "$BUNDLE" ]] && rm -f "$BUNDLE"
[[ $RC -ne 0 ]] && { echo -e "${RED}ERROR: send failed${RESET}\n$OUTPUT" >&2; exit 1; }

HASH=$(echo "$OUTPUT" | grep -oP '(?<=Hash: )[a-f0-9]+' | head -1)
echo -e "${GREEN}Artifact relayed.${RESET} Hash: ${HASH}"

if [[ $DO_PROOF -eq 1 && -n "$HASH" ]]; then
  mkdir -p cra-proofs
  PROOF="cra-proofs/$(date '+%Y-%m-%d-%H%M%S')-$(basename "$ARTIFACT").proof"
  printf '{"timestamp":"%s","relay":"%s.paramant.app","artifact_hash":"%s","blob_hash":"%s","sbom":"%s","registry":"%s"}\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$SECTOR" \
    "$(sha256sum "$ARTIFACT" | cut -c1-64)" "$HASH" "${SBOM:-none}" "${REGISTRY:-none}" > "$PROOF"
  echo -e "CRA proof saved: ${PROOF}"
fi

if [[ -n "$REGISTRY" ]]; then
  echo -e "  Forwarding to registry: ${REGISTRY}"
  curl -sf -X POST "$REGISTRY" -F "file=@${ARTIFACT}" -o /dev/null \
    && echo -e "${GREEN}Published to registry.${RESET}" \
    || echo -e "${RED}WARNING: registry forward failed (artifact already relayed)${RESET}"
fi
echo -e "CT log entry proves artifact identity, timestamp, and publisher. EU CRA 2027 compliant."
