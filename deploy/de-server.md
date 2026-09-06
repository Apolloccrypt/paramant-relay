# De server komt uit de repo

De maatstaf: je moet productie van nul kunnen opbouwen uit deze repo en er moet
precies hetzelfde uitkomen. Lukt dat niet, dan is er geen controle maar een
gewoonte. Dit bestand schrijft op hoe ver we daarvan af staan, wat er gemeten
is, en welke stappen die afstand kleiner maken.

Naast dit bestand horen `deploy/de-server.json` (de afspraak, machineleesbaar),
`scripts/meet-de-server.mjs` (de meting) en
`tests/de-server-komt-uit-de-repo.test.mjs` (de poort).

## 1. Wat productie vandaag werkelijk stuurt

*Bevestigd.* `deploy/deploy-3.1.sh` installeert geen enkele nginx-conf uit de
repo. Het patcht de confs die op de server staan, met `sed` en `awk` op
ankerregels. Het enige bestand dat het echt kopieert is
`deploy/nginx/snippets/paramant-limit-req.conf`. Het commentaar in het script
zegt het zelf, op regel 1556: *"repo only, because 5c edits the live confs by
anchor and never copies a repo file over them"*.

Gevolg: van de zeven conf-bestanden in de repo heeft er één een deploypad. Twee
worden indirect geraakt doordat het script hun serverkopie patcht. Vier raken
productie nooit.

| bestand | pad naar productie |
|---|---|
| `deploy/nginx/snippets/paramant-limit-req.conf` | ja, fase 5d kopieert het |
| `deploy/nginx-paramant-public.conf` | nee; fase 5c patcht de serverkopie |
| `deploy/nginx-paramant-live.conf` | nee; idem, en op de server heet hij `paramant.conf` |
| `deploy/nginx/addin.paramant.app.conf` | geen |
| `deploy/nginx/snippets/paramant-security-headers.conf` | geen, terwijl de live conf hem wel `include`t |
| `deploy/nginx-selfhost.conf` | geen, sjabloon voor zelf-hosters |
| `nginx-selfhost.conf` (in de wortel) | geen, en al uiteengelopen met de vorige |

*Bevestigd, zelf gemeten op 2026-09-05.* De gevolgen daarvan zijn van buitenaf
te zien. Alle zes publieke hosts weigeren een verzoek boven 10485760 bytes,
precies 10 MiB. De repo zegt sinds `d8bf7a71` op alle zes `client_max_body_size
12M`. Dat getal heeft productie nooit bereikt en kan het ook niet bereiken,
want de richtlijn is geen ankerregel van fase 5c. De 413 komt van nginx, met
zijn eigen foutpagina.

*Waarschijnlijk.* De 10 MiB staat in een `http`-blok in de `nginx.conf` op de
server zelf, met de hand gezet en buiten git. Dat is exact de situatie die op
2026-09-04 voor de vijf `limit_req_zone`-regels is opgelost: het commentaar in
het snippet zegt dat die *"typed straight into /etc/nginx/nginx.conf by hand, so
nothing in git said what they were"*. Iemand heeft dat probleem voor de zones
opgelost en de bodygrens erbij laten liggen.

## 2. Wat er draait dat niemand heeft opgeschreven

*Bevestigd, gemeten.* Er staat een **Caddy** voor nginx, en hij is de laag waar
het internet mee praat.

- poort 80 antwoordt met `HTTP/1.1 308 Permanent Redirect` en `Server: Caddy`.
  nginx zou 301 sturen; de repo-conf schrijft ook 301 voor.
- poort 443 zet `via: 1.1 Caddy` en `alt-svc: h3=":443"` op elk antwoord.
- een onbekende SNI wordt geweigerd zonder certificaat.
- bij een 200 staat `Strict-Transport-Security` er twee keer: eenmaal van nginx,
  eenmaal van Caddy. Bij de 413-foutpagina staat hij er één keer, want nginx
  zet zijn `add_header` niet op foutantwoorden en Caddy wel.

*Bevestigd.* Caddy komt in geen enkel bestand in de repo voor, en in geen enkele
regel van de 48 deploylogboeken onder `deploy/logs/`. De deploy weet niet dat
hij bestaat.

*Waarschijnlijk.* De opstelling is Caddy op 80 en 443, die TLS afsluit en
doorzet naar nginx, die naar de containers op 3000 tot 3004 en 4200 gaat. Dat
past bij `deploy/nginx-paramant-live.conf`, dat op `127.0.0.1:8080` en verder
luistert. Het betekent ook dat de `listen 443 ssl` en de
`ssl_certificate /etc/letsencrypt/...` in `deploy/nginx-paramant-public.conf`
een beschrijving zijn van de wereld van vóór Caddy.

Verder buiten de repo, uit de deploylogboeken:

- *Bevestigd.* De **ParaID-deny**, een blok van 18 regels in de live conf, met de
  hand op de server gezet op 9 januari. `deploy-3.1.sh` hangt eraan als anker en
  stopt met `FATAL` als het weg is.
- *Bevestigd.* De serverkopie van `paramant-live.conf` is tussen 3 september
  01:33 en 02:16 met de hand hernoemd naar `paramant.conf`. De deploy viel erover
  en is aangepast om beide namen te accepteren.
- *Bevestigd.* Een **tweede, ongelinkt beheerscherm** (`/admin.html`,
  `/js/admin.page.js`) stond open op het web tot het op 2026-09-04 met een
  nginx-404 is dichtgezet.
- *Bevestigd.* Vier bestanden in de docroot die alleen op de server bestaan en
  die de deploy met rust moet laten: `dist`, `paramant-mark.svg`, `developer.js`,
  `docs/paramant-investor-brief.html`.
- *Bevestigd.* Een **redis-container** van vier maanden oud met een naamloze
  image, buiten de bouw-, tag- en terugrolcyclus van de andere zes. `RELAY_REDIS_URL`
  is leeg in de `.env` op productie.
- *Bevestigd.* Certificaten: geen enkele fase van de deploy raakt ze aan, en
  `certbot`, `acme` en `letsencrypt` komen in geen enkel logboek voor. Er is één
  certificaat voor alle zeven hosts, van Let's Encrypt, geldig tot 2026-10-13.
  Wat het vernieuwt staat nergens opgeschreven.
- *Bevestigd.* `/v2/health/deep` meldt `overall = red` in elk van de 34 runs sinds
  2026-09-03, en de deploy kijkt er niet naar.
- *Bevestigd.* Geen timers, geen cron: in geen enkel logboek staat een `.timer`,
  een `crontab` of een `at`. De enige systemd-eenheid die voorkomt is `nginx`.

## 3. Wat er in de repo staat dat niet draait

*Bevestigd.* Drie relays doen niets. `legal`, `finance` en `iot` hebben
`tree_size: 0`: ze hebben nooit iets ondertekend. `relay.js` vertakt nergens op
`SECTOR`; de vijf containers draaien hetzelfde beeld met een ander label.

*Bevestigd.* Verder dood of losgekoppeld: `docker-compose.server.yml` (19 regels,
allemaal commentaar), `monitoring/prometheus.yml` (niets start Prometheus),
`deploy/server-fix.sh` (roept `scripts/fix-nginx-ports.py` aan, dat pad bestaat
niet), `deploy/signup-fix-deploy.sh` (noemt zichzelf eenmalig),
`deploy/docker-entrypoint.sh` (geen Dockerfile kopieert hem), `install.sh` in de
wortel (111 regels uiteengelopen met `frontend/install.sh`, dat de echte is), en
de `docker compose stop nginx` in de installers, want er is geen nginx-dienst in
compose.

## 4. De weg terug, op volgorde van waarde gedeeld door risico

Elke stap is apart uit te rollen en apart terug te draaien. Geen enkele stap
raakt in één keer meer dan één ding.

**Stap 1. Meten voordat je iets verandert.** Wat er in deze PR zit: de meting,
de afspraak en de poort. Verandert er niets aan productie, en het maakt elk
verschil zichtbaar en telbaar. Terugdraaien is de PR terugdraaien. *Klaar.*

**Stap 2. De meting aan de deploy hangen.** `deploy-3.1.sh` fase 6 roept
`scripts/meet-de-server.mjs` aan, na de rooktesten, als waarschuwing en nog niet
als stop. Dan wordt elk verschil bij elke deploy gezien in plaats van een keer
per jaar. Risico: geen, het is alleen lezen. Terugdraaien: de regel weghalen.

**Stap 3. De bodygrens uit de gok halen.** Zet `client_max_body_size` expliciet
in elk serverblok van de conf op de server, met dezelfde waarde die er nu geldt,
zodat er niets verandert, en haal daarna pas de waarde uit het `http`-blok. Doe
dat via een nieuwe ankerregel in fase 5c, zoals de zes edits die er al zijn.
Daarna staat de grens in git en is het bekende verschil uit
`deploy/de-server.json` weg. De poort merkt dat en wordt rood tot het bestand
bijgewerkt is; dat is de bedoeling. Risico: laag, één richtlijn, `nginx -t` ervoor,
terugrollen is fase 8c.

**Stap 4. De conf ophalen in plaats van beschrijven.** Voordat er ook maar iets
geïnstalleerd wordt: laat de deploy de serverkopie van beide confs ophalen en
vergelijken met de repokopie, en laat hem het verschil afdrukken. Eerst als
waarschuwing. Zolang dat verschil niet nul is, is installeren gevaarlijk, en
precies daarom moet je het eerst kunnen zien. Risico: geen.

**Stap 5. Van patchen naar installeren, één conf tegelijk.** Als het verschil uit
stap 4 nul is, is de repokopie de serverkopie en verandert `cp` niets. Dán pas:
vervang fase 5c voor één bestand door een kopie uit de repo, met `nginx -t`
ervoor en de bestaande back-up erachter. De zes `sed`-edits mogen dan uit het
script, want ze staan al in het bestand. Begin met `paramant-public.conf`, want
die is het kleinst en het best begrepen. Risico: middel, dus alleen na een groene
stap 4, en met de rooktesten van fase 6 erachter.

**Stap 6. Wat er met Caddy moet gebeuren.** Niet weghalen. Hij doet het werk dat
de repo denkt dat nginx doet: TLS, poort 80, h3. Hem weghalen is de zwaarste
ingreep van deze lijst en levert niets op. Hem *opnemen* is het antwoord, in deze
volgorde: eerst zijn configuratie ophalen en ongewijzigd in `deploy/caddy/` zetten
als verslag, dan de meting uitbreiden met wat hij bepaalt, dan pas installeren
zoals stap 5. Tot dat moment staat hij in `deploy/de-server.json` als een bewust
verklaarde laag met een reden, zodat zijn verdwijnen een besluit is en geen
verrassing. *De keuze is dus: opnemen, in drie stappen, en tot die tijd
verklaard buiten de repo.*

**Stap 7. De drie lege relays opruimen, zonder oude ontvangstbewijzen te breken.**
De valkuil is bewezen en hij zit niet waar je hem zoekt. Een ontvangstbewijs
draagt de hostnaam van de relay die hem tekende (`relay/relay.js:6083`), en
`/verify` controleert hem volledig offline tegen de vastgezette sleutels in
`frontend/js/relay-trust-anchors.js`. Er wordt niets opgevraagd. **Een relay
uitzetten breekt dus geen enkel oud bewijs. De sleutel uit de lijst halen wel.**

De volgorde die dat veilig maakt:

1. Draai eerst `tests/verify-knows-the-fleet.test.mjs` om. Die eist nu
   `fleet.length >= 5` uit `docker-compose.yml`. Kleiner maken van de vloot maakt
   die test rood, en dat zet druk om de sleutels weg te halen, wat precies de
   enige handeling is die wél breekt. De test moet gaan eisen dat elke sleutel
   die er ooit was blijft staan, los van wat er in compose staat.
2. Zet dan een week toegangslogboek op `legal`, `finance` en `iot`, want dat
   niemand ze gebruikt is gemeten aan de logboeken en niet aan het verkeer.
3. Zet daarna de containers uit, laat de nginx-blokken en de sleutels staan.
4. Haal de nginx-blokken pas weg als de hosts een maand niets meer kregen.
5. De sleutels blijven staan. Altijd. Ze kosten niets en ze zijn het enige wat
   een oud bewijs nog nodig heeft.

**Stap 8. De zes ongebruikte confs.** `nginx-selfhost.conf` in de wortel weg, hij
is de uiteengelopen kopie en de documentatie wijst naar de verkeerde. De
zelf-host-conf in `deploy/` blijft, als sjabloon, met dat woord erboven.
`addin.paramant.app.conf` en het security-headers-snippet krijgen een deploypad
via stap 5 of ze gaan weg; nu zijn ze geen van beide. Dit raakt productie niet
en kan wachten tot stap 5 werkt.

## 5. Wat deze poort wel en niet ziet

Wel: DNS, het certificaat en zijn vervaldatum, de randlaag, wie de hosts bedient,
de doorverwijzing van 80 naar 443, HSTS, de grens op de verzoekgrootte per host,
de sector die elke relay van zichzelf zegt, de draaiende versie tegen
`package.json`, en de vastgezette sleutel tegen wat de relay publiceert.

Niet: alles achter de rand. Containers, volumes, netwerken, timers, de inhoud van
de `nginx.conf`, en wat Caddy precies doet. Daar komt geen meting van buitenaf
bij; dat vraagt om stap 4 en 5. Wat niet gemeten wordt staat in
`deploy/de-server.json` onder `nietGemeten`, zodat de grens van deze poort
zelf ook opgeschreven is.
