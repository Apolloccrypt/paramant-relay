#!/usr/bin/env bash
# End-to-end toets tegen een draaiende Paramant: relay op $API, frontend op $WEB.
API="${1:?relay-url}"; WEB="${2:?frontend-url}"
fout=0
ok()  { printf "  %-52s %s\n" "$1" "$2"; }
bad() { printf "  %-52s %s  << %s\n" "$1" "$2" "$3"; fout=$((fout+1)); }
code(){ curl -s -m 8 -o /dev/null -w '%{http_code}' "$@"; }
# Commentaar eruit voordat we toetsen. Elk van deze pagina's beschrijft in een
# comment de fout die eruit gehaald is, en een toets die dat meeleest struikelt
# over zijn eigen documentatie. Dezelfde valkuil als in pricing-page.test.js.
strip(){ perl -0777 -pe "s/<!--.*?-->//gs; s|/\\*.*?\\*/||gs" ; }
is()  { [ "$2" = "$3" ] && ok "$1" "$3" || bad "$1" "$3" "verwacht $2"; }
has() { if echo "$3" | grep -qi "$2"; then ok "$1" "ja"; else bad "$1" "nee" "moest '$2' bevatten"; fi; }
hasnt(){ if echo "$3" | grep -qi "$2"; then bad "$1" "ja" "mocht '$2' NIET bevatten"; else ok "$1" "weg"; fi; }

echo "== de kritieke auditbevinding van 21-07: ParaID tekende zonder auth =="
is "issue-document zonder header" 401 "$(code -X POST $API/v1/paraid/issue-document -H 'Content-Type: application/json' -d '{"holder_binding":"aaaaaaaaaaaaaaaaaaaaaaaaaa","mrz_line1":"x","mrz_line2":"y"}')"
is "issue-document met verzonnen bearer" 401 "$(code -X POST $API/v1/paraid/issue-document -H 'Authorization: Bearer psk_verzonnen' -d '{}')"

echo "== AVG: het wis-endpoint bestaat en is dicht =="
is "keys/erase zonder admin-token" 401 "$(code -X POST $API/v2/admin/keys/erase -H 'Content-Type: application/json' -d '{"key":"pgp_x"}')"

echo "== het koop pad =="
is "checkout zonder sleutel" 401 "$(code -X POST $API/v2/billing/checkout -H 'Content-Type: application/json' -d '{"product":"parasend","plan":"pro","interval":"monthly"}')"
P=$(curl -s -m 8 "$WEB/pricing.html" | strip)
is "prijspagina bereikbaar" 200 "$(code $WEB/pricing.html)"
has "toont het bedrag dat echt afgeschreven wordt" "incl. 21" "$P"
hasnt "geen 30-dagen-trial naast forever-free" "30 days" "$P"
n=$(echo "$P" | grep -c "data-billing-product"); [ "$n" -ge 6 ] && ok "zes koopknoppen bedraad" "$n" || bad "zes koopknoppen bedraad" "$n" "verwacht >=6"
J=$(curl -s -m 8 "$WEB/js/pricing-billing.js")
has "koopintentie wordt bewaard voor de omweg" "rememberIntent" "$J"
has "en hervat na terugkomst" "takeIntent" "$J"
K=$(curl -s -m 8 "$WEB/js/passkey.js" | strip)
has "registratie respecteert next" "safeNext" "$K"
# Alleen de knop die na registratie doorstuurt. Regel 107 stuurt ook naar het
# dashboard, maar dat is een foutafhandeling voor een pagina zonder de juiste
# elementen, en die hoort daar te blijven.
has "registratieknop gebruikt safeNext" "finishBtn.addEventListener..click.* => . window.location = safeNext" "$K"

echo "== ParaID uit de etalage, pagina blijft bestaan =="
S=$(curl -s -m 8 "$WEB/sitemap.xml")
hasnt "sitemap zonder paraid" "paraid" "$S"
has "sitemap kent de terms-pagina" "/terms" "$S"
is "paraid-pagina blijft bereikbaar" 200 "$(code $WEB/paraid.html)"
has "en draagt noindex" "noindex" "$(curl -s -m 8 $WEB/paraid.html)"
has "eerlijk assurance-label" "never seen or authenticated" "$(curl -s -m 8 $WEB/js/paraid-app.js)"

echo "== de teruggehaalde Terms of Service =="
is "terms-pagina bereikbaar" 200 "$(code $WEB/terms.html)"
has "navlink naar terms" 'href="/terms"' "$P"
hasnt "geen terms-link middenin een zin" "sign the <a href=./dpa.>Data Processing Agreement</a>.<a href=./terms" "$(curl -s -m 8 $WEB/government.html | strip | tr -d '\n')"

echo "== gezondheid =="
is "health" 200 "$(code $API/health)"
v=$(curl -s -m 8 "$API/health" | grep -oE '"version":"[^"]+"' | cut -d'"' -f4); ok "versie" "$v"

echo
[ "$fout" = 0 ] && echo "ALLE CONTROLES GOED" || echo "$fout GEFAALD"
exit $fout
