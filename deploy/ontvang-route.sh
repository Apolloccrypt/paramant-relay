#!/usr/bin/env bash
# ZET DE ROUTE WAAROP EEN ONTVANGER BINNENKOMT.
#
# De uitnodiging linkt naar https://paramant.app/ontvang/<token>, en de pagina
# die dat moet opvangen heet ophalen.html. Zonder een location-blok krijgt
# iedere ontvanger daar een 404: de hele functie werkt dan voor niemand, en
# niets in de uitrol merkt het, want de relay is gezond en de mail is bezorgd.
#
# deploy-3.1.sh maakt alleen backups van de nginx-confs; het schrijft ze niet.
# Daarom staat deze stap hier apart, in git, en niet in het hoofd van wie hem
# ooit heeft uitgevoerd.
#
#   bash deploy/ontvang-route.sh [--dry-run]
#
# Idempotent: staat het blok er al, dan gebeurt er niets. Keurt nginx de nieuwe
# conf af, dan gaat de oude terug en blijft de site draaien zoals hij was.
set -euo pipefail

HOST="${PARAMANT_PROD_HOST:-root@116.203.86.81}"
KEY="${PARAMANT_PROD_KEY:-$HOME/.ssh/paramant_prod_claude}"
CONF="${PARAMANT_SITE_CONF:-/etc/nginx/sites-enabled/paramant.conf}"
DRY=""
[ "${1:-}" = "--dry-run" ] && DRY="ja"

ssh -i "$KEY" -o BatchMode=yes -o IdentitiesOnly=yes "$HOST" \
  "bash -s -- '$CONF' '${DRY}'" <<'REMOTE'
set -euo pipefail
CONF="$1"; DRY="${2:-}"

if grep -q 'location \^~ /ontvang/' "$CONF"; then
  echo "de route staat er al; niets te doen"
  exit 0
fi

if [ ! -f /home/paramant/app/ophalen.html ]; then
  echo "STOP: /home/paramant/app/ophalen.html bestaat niet."
  echo "Die pagina komt mee met de uitrol. Rol eerst uit, dan deze stap."
  exit 1
fi

if [ ! -f /etc/nginx/snippets/paramant-security-headers.conf ]; then
  echo "STOP: het snippet met de beveiligingsheaders ontbreekt."
  echo "Zonder dat zou juist deze location zijn headers laten vallen."
  exit 1
fi

if [ -n "$DRY" ]; then
  echo "[dry-run] zou het /ontvang/-blok invoegen voor de laatste } van $CONF"
  grep -c '' "$CONF" | sed 's/^/[dry-run] huidige conf is nu /;s/$/ regels/'
  exit 0
fi

TS=$(date +%Y%m%d-%H%M%S)
mkdir -p /etc/nginx/backups
BAK="/etc/nginx/backups/$(basename "$CONF").pre-ontvang-$TS"
cp -a "$CONF" "$BAK"
echo "reservekopie: $BAK"

# Invoegen voor de laatste sluitende accolade van het server-blok.
LAATSTE=$(grep -n '^}' "$CONF" | tail -1 | cut -d: -f1)
if [ -z "$LAATSTE" ]; then echo "STOP: geen sluitende } gevonden in $CONF"; exit 1; fi

BLOK=$(mktemp)
cat > "$BLOK" <<'NGINX'

    # /ontvang/<token> is waar een ontvanger binnenkomt, en dat is met opzet
    # NIET achter de inlogpoort. Wie hem opent heeft een link uit zijn eigen
    # postvak en verder niets: een ontvanger is iemand aan wie iets is
    # gestuurd, niet iemand die zich eerst moet aanmelden. Het bewijs gebeurt
    # op de pagina zelf, waar een code naar datzelfde postvak gaat.
    #
    # ^~ zodat elk token eronder op dezelfde pagina uitkomt, en noindex omdat
    # een token in een zoekresultaat een token in andermans handen is.
    location ^~ /ontvang/ {
        # De include is NIET optioneel. nginx erft add_header niet in een
        # location die zelf een add_header zet, dus zonder deze regel vielen
        # CSP, X-Frame-Options, nosniff, Referrer-Policy en Permissions-Policy
        # weg. Juist op de pagina waarvan de URL het geheim IS en die nooit in
        # een frame mag staan.
        include snippets/paramant-security-headers.conf;
        add_header X-Robots-Tag "noindex, nofollow" always;
        try_files /ophalen.html =404;
    }
NGINX

{ head -n $((LAATSTE - 1)) "$CONF"; cat "$BLOK"; tail -n +"$LAATSTE" "$CONF"; } > "$CONF.nieuw"
rm -f "$BLOK"
mv "$CONF.nieuw" "$CONF"

if ! nginx -t; then
  echo "nginx keurt de nieuwe conf af; de oude gaat terug"
  cp -a "$BAK" "$CONF"
  nginx -t
  exit 1
fi

systemctl reload nginx
echo "de route staat, nginx herladen"
REMOTE
