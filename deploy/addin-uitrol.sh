#!/usr/bin/env bash
#
# addin-uitrol.sh - zet de Outlook-add-in uit deze checkout op addin.paramant.app.
#
# nginx serveert de taskpane uit /home/paramant/addin
# (deploy/nginx/addin.paramant.app.conf). Daar stond nog de build van 1 juni,
# die /parashare-links maakt; ontvangers kwamen dan op /auth/login uit
# (fase 1, EXT-16-H en EXT-18-A). Dit script:
#
#   1. bouwt en controleert het pakket (scripts/build-store-packages.sh);
#   2. zet het naast de live map neer (/home/paramant/addin.new);
#   3. bewaart de live map als /home/paramant/addin.prev-<TS> en wisselt om;
#   4. meet daarna publiek: taskpane.html laadt de nieuwe gehashte taskpane.js,
#      die maakt /get-links en geen /parashare-links meer.
#
# Faalt stap 4, dan zet het script de vorige map terug.
#
# Gebruik:
#   bash deploy/addin-uitrol.sh             uitrollen
#   bash deploy/addin-uitrol.sh --dry-run   alleen bouwen en tonen wat er gebeurt
#   bash deploy/addin-uitrol.sh --verify    alleen stap 4, tegen wat live staat
#   bash deploy/addin-uitrol.sh --rollback <TS>   terug naar addin.prev-<TS>
#
# Het manifest (manifest.xml) verandert niet van adres: Outlook haalt de nieuwe
# build bij de volgende keer openen van de taskpane, zonder herinstallatie.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROD_HOST="${PARAMANT_PROD_HOST:-root@116.203.86.81}"
PROD_KEY="${PARAMANT_PROD_KEY:-$HOME/.ssh/paramant_prod_claude}"
LIVE=/home/paramant/addin
URL="${ADDIN_URL:-https://addin.paramant.app}"
MODE=run TS_BACK=""
case "${1:-}" in
  --dry-run) MODE=dry ;;
  --verify) MODE=verify ;;
  --rollback) MODE=rollback; TS_BACK="${2:?--rollback <TS>}" ;;
  "") ;;
  *) echo "onbekende optie: $1" >&2; exit 2 ;;
esac
SSH=(ssh -i "$PROD_KEY" -o BatchMode=yes "$PROD_HOST")

verify() {
  local html js
  html="$(curl -fsS "$URL/taskpane.html")" || { echo "FAIL: $URL/taskpane.html niet bereikbaar"; return 1; }
  js="$(printf '%s' "$html" | grep -oE 'src="taskpane\.[0-9a-f]{8}\.js"' | head -1 | sed 's/src="//; s/"$//' || true)"
  [ -n "$js" ] || { echo "FAIL: taskpane.html laadt geen gehashte taskpane.js (oude build)"; return 1; }
  local body; body="$(curl -fsS "$URL/$js")" || { echo "FAIL: $URL/$js niet bereikbaar"; return 1; }
  if printf '%s' "$body" | grep -q 'parashare?t='; then echo "FAIL: $js maakt nog /parashare-links"; return 1; fi
  printf '%s' "$body" | grep -q 'paramant.app/get' || { echo "FAIL: $js maakt geen /get-links"; return 1; }
  printf '%s' "$body" | grep -q 'parasend/token' || { echo "FAIL: $js kent de inlog met e-mail + code niet"; return 1; }
  echo "OK: $URL serveert $js (/get-links, e-mail + code)"
}

if [ "$MODE" = verify ]; then verify; exit $?; fi
if [ "$MODE" = rollback ]; then
  "${SSH[@]}" "set -e; test -d $LIVE.prev-$TS_BACK; mv $LIVE $LIVE.failed-\$(date -u +%Y%m%dT%H%M%SZ); mv $LIVE.prev-$TS_BACK $LIVE"
  echo "teruggezet naar $LIVE.prev-$TS_BACK"; exit 0
fi

bash "$ROOT/scripts/build-store-packages.sh"
PKG="$(ls "$ROOT"/extensions/store/out/paramant-outlook-addin-*.tar.gz | head -1)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
REMOTE="set -e
rm -rf $LIVE.new && mkdir -p $LIVE.new
tar -xzf /tmp/addin-$TS.tar.gz -C $LIVE.new --no-same-owner
chown -R --reference=$LIVE $LIVE.new
test -f $LIVE.new/taskpane.html && test -f $LIVE.new/manifest.xml
mv $LIVE $LIVE.prev-$TS && mv $LIVE.new $LIVE
rm -f /tmp/addin-$TS.tar.gz"

if [ "$MODE" = dry ]; then
  echo "scp $PKG -> $PROD_HOST:/tmp/addin-$TS.tar.gz"
  echo "ssh $PROD_HOST:"; printf '%s\n' "$REMOTE" | sed 's/^/  /'
  exit 0
fi

scp -i "$PROD_KEY" -o BatchMode=yes "$PKG" "$PROD_HOST:/tmp/addin-$TS.tar.gz"
"${SSH[@]}" "$REMOTE"
echo "uitgerold, vorige build in $LIVE.prev-$TS"
if ! verify; then
  echo "meting faalt, terugzetten" >&2
  "${SSH[@]}" "set -e; mv $LIVE $LIVE.failed-$TS; mv $LIVE.prev-$TS $LIVE"
  exit 1
fi
