# De inhaalslag, 5 september 2026

`scripts/check-landen.mjs` vindt **64 van de 71 takken op origin** niet terug in
main. Dit is de triage van die 64 in drie stapels. De methode staat in
`deploy/landen.md`; de uitkomst is machineleesbaar in
`deploy/landen-uitstel.json` en wordt door `tests/landen-poort.test.mjs`
compleet gehouden.

| stapel | takken | wat het betekent |
|---|---:|---|
| de inhoud zit al in main, langs een andere weg | 34 | opruimen, geen werk |
| achterhaald | 16 | opruimen, geen werk |
| hier ligt werk met waarde | 11 | de winst, hieronder op volgorde |
| **totaal** | **61** | |

Drie takken staan hier niet bij: `fix/koper-hele-weg` (#457),
`het-product-voldoet-aan-de-tekst` (#458) en `de-server-komt-uit-de-repo`
(#461). Dat zijn open pull requests van vandaag, geen restanten. Ze staan
bewust niet in de uitstellijst: over zeven dagen maken ze de poort rood, en dat
is precies de bedoeling.

Van de elf waardevolle takken zijn er drie dezelfde reparatie.
`feat/parasign-pdf-preview` en `feat/parasign-document-intelligence` hebben een
identieke boom (`git diff` tussen de twee is leeg) en
`feat/privacy-statement-v2` is diezelfde diff plus een privacyherschrijving die
main al langs een andere weg heeft. Land er een, gooi de andere twee weg. Er
liggen dus **negen stukken werk**, niet elf.

---

## De volgorde

Gesorteerd op wat er kapot is maal wat het kost. Elke datum staat als `tot` in
`landen-uitstel.json`; loopt hij af zonder landing, dan wordt de poort rood.

### 1. `fix/sector-port-drift` (10 juni, 87 dagen) - 12 september

De aanleiding voor deze hele poort. `admin/server.js:40-44` op main:

```
health:  process.env.RELAY_HEALTH  || 'http://relay-health:3005',
legal:   process.env.RELAY_LEGAL   || 'http://relay-legal:3002',
finance: process.env.RELAY_FINANCE || 'http://relay-finance:3003',
iot:     process.env.RELAY_IOT     || 'http://relay-iot:3004',
```

Elke relaycontainer luistert intern op `3000`; 3001 tot 3004 bestaan alleen als
host-side mapping (`docker-compose.yml:114,160,188,216,245`). Vier van de vijf
terugvalwaarden wijzen dus naar een poort waar op het compose-netwerk niets
luistert. In productie maskeert de compose-omgeving het, wat verklaart waarom
het er nooit gebeten heeft en waarom het drie maanden kon blijven staan.

**Bestaat vandaag nog:** ja, letterlijk, op `origin/main`. Deze fout is op 5
september door een tweede onderzoek opnieuw gevonden en opnieuw gerepareerd.

**Omvang:** klein. Vier waarden in een blok dat sinds de tak niet verschoven is.
De nginx-helft van de tak laat je vallen: `nginx-selfhost.conf` en
`deploy/nginx-selfhost.conf` op main gebruiken inmiddels `127.0.0.1:3001-3004`,
en dat is het juiste host-poortmodel voor die opzet.

### 2. `sec/relay-scope-enforcement` (16 juli, 51 dagen) - 19 september

Een v2-API-sleutel kan als read-only of send-only uitgegeven worden. De relay
slaat die scope op (`relay.js:6733` accepteert `d.scope`, `:6758` schrijft hem
weg) en toont hem in de lijsten (`:6793`, `:6831`), maar controleert hem nooit.
`requireScope`, `scopeActionFor` en `insufficient_scope` komen in 9080 regels
`relay.js` nul keer voor, en `relay/lib/keys-table.js:14` zegt het zelf: "the
relay does not yet gate on them".

**Bestaat vandaag nog:** ja. Elke read-only sleutel heeft in werkelijkheid
volledige schrijfrechten over het hele v2-datavlak, `/v2/admin/*` inbegrepen.
Dat is privilege-escalatie, en het staat in de UI als een beveiligingsfunctie.
De /v1 psk_-laag heeft wel een eigen scopecontrole; de v2-laag niet.

**Omvang:** middel. De poort zelf is ongeveer zes regels in `relay.js` plus een
pure matrix in `keys-table.js`. Maar dat bestand groeide van 180 naar 370
regels en kent nu ook een `parasign`-scope, dus de routetabel moet opnieuw
langs de huidige v2-routes. Hertoetsen, niet cherry-picken.

### 3. `feat/close-anon-inbound` (20 juli, 47 dagen) - 19 september

`relay.js:5767` draagt nog `POST /v2/anon-inbound`, met de comment "No API key
required. Rate limited by IP" en een teller op `:1852`. `frontend/docs.html:471`
adverteert de route met Auth `n/a`. De handler leest alleen een per-IP-limiet
(`ANON_RATE_PER_HOUR`, standaard 10) en raakt `getEntitlements` en
`gateTransfer` nergens aan.

**Bestaat vandaag nog:** ja. Sleutelloze uploads, buiten de entitlement- en
quotapoort om. Dat is een omzeiling van de transfer-paywall en een
misbruikvector. De Sunset-header in de code staat op 31 december 2026, dus de
route staat bewust nog open; de vraag is of dat nog klopt met een betalend
product.

**Omvang:** middel. Vooral schrappen (96 regels weg) plus een alias naar de
geauthenticeerde `/v2/inbound`. Maar `relay.js` groeide van ~7000 naar 9080
regels en die handler kreeg er entitlement- en quotalogica bij, dus de alias
moet opnieuw gecontroleerd. Let ook op de `SECTORS`-tabellen op `:235` en `:243`
die `/v2/anon-inbound` nog in hun padlijst hebben.

### 4. `fix/core-pin` (20 juli, 47 dagen) - 12 september

`relay/Dockerfile:31` (`ARG PARAMANT_CORE_COMMIT=b90b3c52...`) en
`.github/workflows/test.yml:162` (`PARAMANT_CORE_SHA: b90b3c52...`) pinnen de
crypto-engine allebei met de hand. De waardes zijn vandaag gelijk, dus de
concrete drift die de tak vond is weg. De structuur die hem toeliet staat er
nog: twee kopieen, geen bewaking, en `tests/core-pin.test.mjs` bestaat niet op
main.

**Bestaat vandaag nog:** het gat wel, het symptoom niet. CI kan tegen een andere
crypto-engine testen dan het productie-image bouwt zonder dat er iets afgaat.

**Omvang:** klein. 59 regels, drie bestanden die nauwelijks verschoven zijn.

### 5. `chore/eslint-guardrail` (20 juli, 47 dagen) - 12 september

De CI-poort landde langs een andere weg: main heeft `eslint.config.mjs` en een
lint-job (`test.yml:97`). Met precies een regel: `no-undef`. `no-sequences`,
`eqeqeq` en `no-cond-assign` komen nergens in de repo voor.

**Bestaat vandaag nog:** ja. `no-sequences` is de regel die de komma-operator
vangt die de create-envelope auth-gate op elke POST liet matchen (commit
`83dc453`). Die bug is met de hand gerepareerd, de bewaking ontbreekt nog.

**Omvang:** klein, mits je alleen de regellijst overneemt: `no-sequences`,
`no-cond-assign`, `no-fallthrough`, `no-unsafe-negation`,
`no-constant-condition`. De 892 regels `package-lock.json` en de
npm-devDependency uit de tak zijn overbodig, main draait `npx --yes eslint@9`.
`eqeqeq` geeft waarschijnlijk veel treffers; laat die liggen.

### 6. `feat/parasign-pdf-preview` (24 juni, 73 dagen) - 26 september

Drie takken, een reparatie. `frontend/sign-flow.js:2297` op main is nog steeds:

```
const targetW = Math.min(340, Math.floor(pane.clientWidth || 340));
```

De `|| 340`-vangst redt alleen een exacte 0; een breedte van 1 tijdens een
transitie glipt erdoor en levert een canvas van 1 pixel. Regels 700 en 3430 zijn
`Math.min(820, Math.floor(window.innerWidth * 0.88))` zonder ondergrens. Er is
ook geen generatieteller: `__previewGen`, `nextFrame` en `previewTargetWidth`
komen nul keer voor op main, terwijl `:2439` `renderDocPreview()` fire-and-forget
aanroept, zodat een oude render in een al geleegde pane kan doortekenen.

**Bestaat vandaag nog:** ja. Blanco of misplaatste documentvoorbeelden op iOS
Safari, in de reviewstap van het tekenpad. De verkeerde canvasbreedte voedt ook
de klik-naar-coordinaten-ratio, dus de zegel landt fout.

**Omvang:** middel. De fix is 65 regels op drie renderpaden, maar `sign-flow.js`
groeide van ~1100 naar 3790 regels. Met de hand aanbrengen.

### 7. `feat/outlook-402` (20 juli, 47 dagen) - 26 september

Twee dingen. `extensions/outlook-addin/manifest.xml:69-71` en `:81-83` gebruiken
`<bt:Image size="16" resource="Icon.16"/>`. Het Office-manifestschema eist
`resid=`, zoals `<bt:Images>` op `:98-101` zelf laat zien. En de relay stuurt op
vier plekken een 402 boven de maandcap (`relay.js:3425, 6179, 6741, 8013`), maar
geen enkele extensie-client herkent die status.

**Bestaat vandaag nog:** beide, op main. Met dat attribuut zakt het manifest door
schemavalidatie, dus de add-in is niet in te dienen en niet te sideloaden.

**Omvang:** klein tot middel. De extensiebestanden staan sinds 20 juli stil op
main, dus de patch landt vrijwel schoon; alleen `scripts/post-deploy-verify.sh`
is doorgelopen. De manifest-fix alleen is een losse, kleine landing en kan
vooruit.

### 8. `test/sdk-relay-conformance` (29 mei, 99 dagen) - 3 oktober

`tests/conformance/` bestaat niet op main. Wat er wel staat,
`relay/crypto/wire-format.test.js` en de integratievariant, draait op een
nep-registry (`sign: () => Buffer.alloc(3309)`, `verify: () => true`). Geen
enkele toets op main laat echte crypto van de ene implementatie door de andere
lopen.

**Bestaat vandaag nog:** ja. `docs/wire-format-v1.md` staat op main als het
contract, `docs/cross-repo-coordination.md:50-52` noemt sdk-js en sdk-py als
levende afnemers, en niets bewijst dat die drie het over elke byte eens zijn.

**Omvang:** middel. 936 regels in een nieuwe map, nul conflicten met main. Het
werk zit niet in mergen maar in draaiend krijgen: `@paramant/core/index.node`,
sdk-js node_modules, python-pqcrypto, plus inhaken in CI.

### 9. `feat/parasign-ios-render` (24 juni, 73 dagen) - 3 oktober

WebKit kapt een canvas-backingstore boven ongeveer 4096 pixels per dimensie stil
af en levert een blanco bitmap terwijl `page.render()` gewoon slaagt. Op main
staat geen oppervlaktecap, geen blanco-bitmapcontrole en geen lazy render:
`webkit`, `Mpx`, `4096` en `getImageData` geven nul treffers in `sign-flow.js`
en `co-sign.js`.

**Bestaat vandaag nog:** het gat wel. Op een 390px-iPhone geeft `fitScaleFor`
(`:699`) een cssScale van ~0,56, maal zoom 4 (`setPlaceZoom`-cap) maal
`hiDpiScale()` 3 komt de viewport op 6,7 en het canvas op ruwweg 4113 x 5322,
over de cap. Dat main geen cap heeft is nagemeten; dat een gebruiker het vandaag
ziet is afgeleid, niet waargenomen.

**Omvang:** groot, en daarom als laatste. Alleen de diagnose en het idee van een
gedeelde `renderPageToCanvas` zijn overdraagbaar. `frontend/vendor/pdfjs/pdfjs-loader.js`
op main is een heel ander bestand (15 regels ESM-loader tegen 265 regels
renderhelper op de tak) en `sign.html` verschilt 1009 regels. Opnieuw schrijven
tegen de huidige `ready.js`-architectuur.

---

## De 34 die er al in zitten, en de 16 die dood zijn

Beide stapels vragen hetzelfde: de tak van origin verwijderen. Dat staat in
`landen-uitstel.json` op 19 september. Ze staan hier niet stuk voor stuk
uitgeschreven; de onderbouwing per tak staat in het `reden`-veld van die lijst,
met het bestand en de regel waarop het is nagekeken.

Vier dingen zijn in die stapels blijven liggen en zijn los een paar minuten
werk. Ze zijn te klein voor een eigen tak maar te concreet om te vergeten:

- `README.md:263` claimt nog "Legal & Notary - eIDAS compatible"
  (uit `fix/claims-truth-groupb`).
- `.gitignore` mist het bredere patroon `deploy/*token*`; alleen `deploy/token`
  staat er (uit `chore/security-retire-leaked-admin-token`).
- Het nav-merk `frontend/paramant-mark.svg` bestaat niet op main
  (uit `feat/new-logo`), al raakte dat vooral geschrapte pagina's.
- Main labelt de handtekening als `'Post-quantum, zero-knowledge. Not
  eIDAS-qualified.'` op vijf plekken, zonder het niveau AES te benoemen
  (uit `integ/parasign-editor`).

## Wat deze triage niet vaststelt

- Of de 34 in `in-main-anders` werkelijk 34 zijn. Elke post is nagekeken op een
  bestand en een regel op `origin/main`, maar een tak kan een detail dragen dat
  bij die controle niet opviel. De vier restjes hierboven zijn precies zulke
  details, en ze zijn gevonden doordat er per tak gekeken is en niet per getal.
- Of de negen waardevolle stukken werk het waard zijn om nu te doen. Dat is een
  besluit van de board, niet van deze lijst. Wat hier staat is: het probleem
  bestaat vandaag nog op main, en zo groot is de klus.
