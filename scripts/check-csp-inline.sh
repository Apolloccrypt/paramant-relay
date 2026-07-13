#!/usr/bin/env bash
# CI-poort: de site draait onder script-src 'self'. Elk inline script en elke
# inline event-handler is daarmee DOOD in de browser. Deze check faalt de build
# voor ze live kan gaan. Achtergrond: signup/login lag hierdoor plat (juli 2026).
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

INLINE=$(grep -rnoE '<script([[:space:]][^>]*)?>' --include=*.html frontend/ | grep -v 'src=' || true)
if [ -n "$INLINE" ]; then
  echo "FOUT: inline <script> gevonden (CSP script-src 'self' weigert dit):"
  echo "$INLINE"
  FAIL=1
fi

HANDLERS=$(grep -rnoiE ' on(click|submit|change|input|load|keyup|keydown|mouseover)="' --include=*.html frontend/ || true)
if [ -n "$HANDLERS" ]; then
  echo "FOUT: inline event-handler gevonden (CSP weigert dit):"
  echo "$HANDLERS"
  FAIL=1
fi

JSHREF=$(grep -rnoi 'href="javascript:' --include=*.html frontend/ || true)
if [ -n "$JSHREF" ]; then
  echo "FOUT: javascript:-href gevonden (CSP weigert dit):"
  echo "$JSHREF"
  FAIL=1
fi

[ "$FAIL" = "0" ] && echo "OK: geen inline JS onder de CSP" || echo "Zet de code in een extern bestand onder frontend/js/."
exit $FAIL
