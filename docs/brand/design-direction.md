# Paramant design direction 2026

Status: uitgerold op de app-schermen en op de homepage, niet op de rest van de
marketingsite. Datum 3 september 2026.

Dit document beschrijft de richting zoals hij **gemerged op `main` staat**, niet
zoals hij bij het jurybesluit bedoeld was. Tussen dat besluit en vandaag zitten
elf pull requests die hem op drie punten hebben teruggedraaid en op de rest
scherper hebben gemaakt. Elk besluit hieronder staat met zijn PR erbij, zodat je
van elke regel terug kunt naar de meting die hem opleverde.

De richting leeft in **vier lagen**, en dat is de belangrijkste correctie op de
oorspronkelijke tekst:

| Laag | Bestand | Waar | Donker |
|---|---|---|---|
| gedeeld | `frontend/design-system.css` v4.1 | alle 58 pagina's | nee, licht only |
| nav | `frontend/nav.css` | alle pagina's | volgt de laag eronder |
| app | `frontend/app-2026.css` | 11 app-pagina's | ja, als keuze |
| homepage | kritieke CSS in `frontend/index.html` (`--hp-*`) | `/` | nee |

Er is geen enkele globale tokenlaag die deze vier verenigt. Dat was wel het plan
en het is niet gebeurd; zie sectie 5.

---

## 1. De keuze, en wat de reviews eraf haalden

### 1.1 De kern is STIL

Van drie prototypes (STIL, LEVEND, WARM) is STIL de kern geworden, met de beacon
en de registerrij van LEVEND en een graad papierwarmte van WARM erop geënt.

Bij een post-quantum e-sign product is het product zelf onzichtbaar. Wat je
verkoopt is rust en controleerbaarheid. De pagina zegt: versleuteld in je
browser, weg na de laatste lezing, servers in Duitsland, elke regel met een
verify-link. Elke gradient eromheen verzwakt precies die claim.

Wat daarvan gemerged is, in vier regels die overal gelden:

1. **Eén gevuld accentvlak betekent één handeling.** Kobalt is dat accent.
2. **Hairlines in plaats van dozen.** Dat geeft de pagina de precisie van een
   document, en de uitkomst van dit product is een ondertekend document.
3. **Eén donker object per scherm**, en dat is het Community-blok. Dat is geen
   decoratie maar de hiërarchie: de gift gaat voor, de rest is de betaalde helft.
4. **Geen versiering die iets voorwendt.** Geen grafiek zonder data, geen beacon
   waar niets gemeten wordt, geen buildnummer dat niet klopt.

WARM viel af op zijn eigen beste vondst: koppen in een systeem-serif verschillen
5 tot 10 procent per platform, en `tests/first-screen.test.mjs` forceert bewust
DejaVu Sans omdat een gate waarvan de getallen van de runner afhangen geen gate
is. LEVEND viel af op de decoratieve grafiek in de hero: op een site waar elke
regel een verify-link heeft is een datavisualisatie zonder data het enige echte
risico op ongeloofwaardigheid.

### 1.2 Het besluitenregister

Alles op 3 september 2026, in de volgorde waarin het landde.

| PR | Besluit | Reden |
|---|---|---|
| #377 | Homepage krijgt hero links uitgelijnd, één gevulde en één hairline-knop, de oprichter op het eerste scherm, en een CSS-only kunstobject: een document dat getekend, verzegeld en dan tot stof opgelost wordt. De gift-sectie is het enige donkere object. | "Products, three steps, prices and rules keep their words; boxes and uppercase kickers become hairlines and air." Het object draagt geen script, geen extern asset, geen derde partij. |
| #382 | Vertrouwensronde op dezelfde pagina: een brief van de oprichter in dat donkere blok, een ontvangstbewijs naast het oplossende document, en een nieuwe sectie *Five things you can check yourself, today*. | "People who look for trust do not buy claims; they buy a person who puts a name to the promise, and facts they can look up outside the site." |
| #386 | De technische meta-strip boven de navigatie is uit de markup van alle 40 pagina's. | De eerste regel op 40 pagina's was `build 3.0.0 aes-256-gcm / post-quantum eu/de ram only`, met een buildnummer dat fout stond sinds 3.1.0. Op `/pricing` en `/security` was dat het eerste wat een koper las, en het beantwoordde niets van wat hij vroeg. |
| #381 | De app-schermen krijgen `frontend/app-2026.css`: het 2026-palet plus een aliaslaag die de v4-namen naar de nieuwe waarden wijst. Donker is een keuze op `/account`, standaard licht, sleutel `paramant.theme.v1`. | Gemeten: met een donker besturingssysteem en zonder keuze bleven `/index` en `/pricing` licht terwijl `/dashboard`, `/sign`, `/parashare`, `/account` en `/auth/login` op `rgb(10,15,22)` opkwamen. Inloggen was een sprong van crème naar zwart, in één klik, zonder manier om nee te zeggen. |
| #380 | `design-system.css` gaat naar v4.1. Precies één tokenwaarde verandert: `--ink-dim`, `--lime-dim` en `--black-dim` wijzen naar `--ink-2` (`#40505F`). De donkere laag op marketing wordt in zijn geheel teruggetrokken. | Zie 1.3, punt 3. |
| #389 / #390 | `--hp-ink-3` op de homepage van `#66727F` naar `#5F6B78`; de mono-kicker gaat van `KNOWN_LIGHT` af. | 4.31:1 op het tweede papier `#F3F0E8`, net onder de 4.5 van AA. Niet met het oog te zien, wel het verschil tussen voldoen en niet voldoen. |
| #388 / #391 | Burn-on-read wordt per plan én per client geformuleerd, in de bodytekst (#388) en in de heads, og-, twitter- en JSON-LD-velden (#391). | `relay/lib/tiers.js` geeft 1 lezing op Community, 10 op Pro, 25 op Business, 100 op Enterprise, en het readgetal is een API-parameter die de web-app en de extensies nooit sturen. |
| #393 | De screenshot-suite schrijft naar een tempmap, tenzij `PARAMANT_WRITE_BRAND_SHOTS=1`. | "Rewriting the reference images is a deliberate act, not a side effect of running the tests." |
| #392 | De navigatie gaat van mono-hoofdletters naar zinsopmaak in de leesletter, de gevulde knop wordt kobalt, en onder 700px verhuizen Sign in en Help naar een strip onder de la. | Twee koperreviews noemden de gedeelde balk als de grootste resterende afleiding. Op 390px stonden vijf elementen, met knop en hamburger allebei op x=330. |

### 1.3 Wat verworpen is, en waarom

**1. De STIL-balk: mono hoofdletters in de navigatie.** Verworpen in #392.
`PRODUCT SECURITY PRICING DOCS` is de stem van een terminal, boven een pagina
die in papier, inkt, zinnen en één kobaltknop gezet is. Het kostte bovendien
ruimte: Help was daardoor het vijfde element in de balk, teruggeschaald naar 9px
type om te passen. Nu: Product, Security, Pricing, Docs, Help, Sign in, Create
account, 14px, zinsopmaak, geen letterspatiëring, 16px in de la.

**2. Lime als primaire knop.** Verworpen in #392. De gevulde knop in de balk was
lime. Lime is de leestekenkleur van dit merk en niet de kleur van zijn primaire
handeling; naast de kobalt-heroknop las hij als een tweede, concurrerend aanbod.
Nu kobalt met witte tekst, 6.3:1, dezelfde `.hp-btn-fill` als de homepage.
`app-2026.css` forceerde `#0A1626` op lime met `!important` en volgt nu op
hetzelfde gewicht. Lime blijft: een lijn, een streepje voor een label, een
onderstreping. Nooit een vlak met tekst erop, op één combinatie na (`#0A1626` op
`#B2FF3F`, 14.94:1).

**3. Donker op de marketingsite.** Verworpen in #380, om drie gemeten redenen:

- hij stond achter `[data-theme]` zonder schakelaar in de nav, dus geen bezoeker
  kon hem bereiken;
- in die stand was hij onleesbaar op `/security`, `/pricing` en het dashboard:
  wit op lime, 1.07:1;
- hij kostte 31 KB op alle 58 pagina's, en geen enkele nginx-conf in `deploy/`
  zet gzip aan.

Marketing is dus licht, punt. Donker bestaat alleen op de app-schermen, en daar
alleen na een keuze. Komt donker terug op marketing, dan komt hij terug met een
schakelaar en met nul open contrastgevallen; de tweede helft van
`tests/theme-contrast.test.mjs` wacht daarop.

**4. Een foto van de oprichter.** Overwogen in #382 en niet gedaan: het sterkste
vertrouwenssignaal dat er is, en er staat er geen in de repo. Wat er wel staat is
de naam, de rol, de B.V., de plaats en het KvK-nummer.

**5. `frontend/design-tokens-2026.css` als globale tokenlaag.** Verwijderd in
deze PR. Het bestand werd door geen enkele pagina, build, test of nginx-conf
geladen; de vijf verwijzingen ernaar stonden in zijn eigen header en in dit
document. Erger dan ongebruikt was het in tegenspraak met wat er wél draait:

- het schreef donker als `:root:not([data-theme="light"])`, dus een donker
  besturingssysteem maakt de app donker tenzij je expliciet licht kiest. Dat is
  precies de sprong die #381 heeft weggehaald, en het breekt de belofte die
  `docs/site-claims.md` rij 28 en `tests/app-theme.test.mjs` bewaken;
- zijn aliaslaag mapte `--space-8/9/10` van 64/96/128px op 72/112/160px en liet
  `--space-10` en `--space-11` ongedefinieerd;
- `--navy: var(--ink)` zou elke navy op de marketingsite in één keer van
  `#0B3A6A` naar `#0C1B2A` zetten, op alle 58 pagina's tegelijk;
- het was al uit sync met `app-2026.css`, dat dezelfde richting wél implementeert
  (`--ink-1` daar tegen `--ink` hier, en `--mark-on`, `--sig-stop-line` en
  `--paper-blur` ontbraken).

Twee bronnen van waarheid voor één palet, waarvan er één niets aandreef. De
levende bron is `frontend/app-2026.css`.

**6. De type- en ruimteschaal van 2026 op de gedeelde laag.** Niet overgenomen.
`app-2026.css` gebruikt de `--text-*` en `--space-*` van `design-system.css`, niet
een eigen `--t-*` / `--s-*`. De geklemde koppenschaal uit het oorspronkelijke
voorstel bestaat nergens als token.

---

## 2. Tokens

Alle contrastwaarden zijn berekend met de WCAG 2.1 relatieve-luminantieformule
tegen de genoemde achtergrond, en worden bewaakt door
`tests/theme-contrast.test.mjs` (licht, 16 marketingpagina's) en
`tests/app-contrast.test.mjs` (11 app-schermen, licht en donker).

### 2.1 De gedeelde laag: `design-system.css` v4.1

Vier kleuren: bone, navy, cobalt, lime. Nul radius. Sans plus mono.

| Token | Waarde | Rol |
|---|---|---|
| `--bone` | `#F8FAFC` | de pagina |
| `--bone-2` | `#EEF2F6` | voet, ingelegd vlak |
| `--navy` / `--ink` | `#0B3A6A` | koppen en primaire tekst |
| `--ink-2` | `#40505F` | de leeskleur voor alles wat niet primair is |
| `--ink-dim`, `--lime-dim`, `--black-dim` | `var(--ink-2)` | v4.1 |
| `--ink-hair` | `rgba(11,58,106,.15)` | hairline |
| `--cobalt` | `#1D4ED8` | het enige accent |
| `--lime` | `#B2FF3F` | leesteken, nooit tekst |

De enige wijziging in v4.1 is `--ink-dim`. De oude waarde `rgba(11,58,106,.65)`
haalde 4.09:1 op het papier, 3.96:1 op de voet en 4.18:1 op een witte kaart: drie
keer net onder AA, en drie keer onder de tekst die de prijs en de kleine letter
draagt. `#40505F` haalt 7.95:1 op het papier en 7.35:1 op de voet. De site ging
daarmee van 82 naar 5 unieke paren onder AA; na #389/#390 zijn er vier over.

### 2.2 De app-laag: `app-2026.css`, licht

Geladen als laatste stylesheet in de head van elf pagina's: `dashboard`, `sign`,
`parashare`, `signup`, `signup/verified`, `account`, en de vijf onder `auth/`.

| Token | Waarde | Rol | Contrast op `--paper` |
|---|---|---|---|
| `--paper` | `#FBFAF7` | de pagina | vlak |
| `--surface` | `#FFFFFF` | kaart, tabel, dialoog | vlak |
| `--surface-sunk` | `#F4F4F1` | ingelegd vlak, tabelkop | vlak |
| `--surface-ink` | `#0C1622` | het ene omgekeerde vlak | vlak |
| `--ink-1` | `#0C1B2A` | koppen, primaire tekst | 16.68 |
| `--ink-2` | `#40505F` | lopende tekst | 7.95 |
| `--ink-3` | `#5C6A78` | meta en mono-labels | 5.31 |
| `--accent` | `#1D4ED8` | het enige accent, kobalt | 6.42 |
| `--accent-ink` | `#FFFFFF` | tekst op kobalt | 6.70 op `#1D4ED8` |
| `--line` / `--line-2` / `--line-ghost` | `rgba(12,27,42,.11 / .20 / .05)` | hairlines | vlak |
| `--mark` | `#B2FF3F` | lime, alleen als lijn | 1.17, dus nooit tekst |
| `--mark-ink` | `#5C7A12` | leesbare lime voor tekst | 4.90 |
| `--mark-on` | `#0A1626` | de enige tekst op een lime vlak | 14.94 op `#B2FF3F` |
| `--sig-wait` | `#79600F` | wacht | 5.76 |
| `--sig-move` | `#1D4ED8` | loopt | 6.42 |
| `--sig-done` | `#1B6B45` | klaar | 6.22 |
| `--sig-stop` | `#8C3A34` | gestopt | 7.26 |

Statuskleuren krijgen een achtergrond op 9 procent van dezelfde tint.

Daaronder staat een **aliaslaag**: `--bone`, `--navy`, `--ink`, `--ink-hair`,
`--cobalt`, `--lime` en de rest van de v4-namen wijzen binnen deze elf pagina's
naar de 2026-waarden. Dat is wat een donkere modus op tien schermen betaalbaar
maakte: elke regel die ooit tegen `--ink` geschreven is volgt het thema zonder
herschreven te worden.

### 2.3 De app-laag, donker

Eigen set, geen filter. Papier `#0A0F16`, kaart `#10161F`, ingelegd `#151C26`,
omgekeerd `#060A0F`.

| Token | Waarde | Contrast op papier |
|---|---|---|
| `--ink-1` | `#EDF1F6` | 16.94 |
| `--ink-2` | `#B4C1D0` | 10.50 |
| `--ink-3` | `#8D9CAD` | 6.86 |
| `--accent` | `#7FA6FF` | 8.05 |
| `--accent-ink` | `#061020` | tekst op accent |
| `--mark` | `#B2FF3F` | 15.80 |
| `--sig-wait` | `#E3C169` | wacht |
| `--sig-move` | `#90AEFF` | loopt |
| `--sig-done` | `#6FD3A2` | klaar |
| `--sig-stop` | `#F09A92` | gestopt |

Lijnen worden `rgba(237,241,246,.10 / .20 / .05)`. Statusachtergronden gaan van 9
naar 12 procent, omdat een donker vlak minder tint doorlaat.

**Hoe donker aan gaat.** De set staat twee keer geschreven: onder
`@media (prefers-color-scheme: dark) { :root[data-theme="auto"] }` en onder
`:root[data-theme="dark"]`. Geen kleur bestaat alleen binnen een media query, en
even belangrijk: de systeemvoorkeur telt alleen onder `[data-theme="auto"]`.

```
geen keuze  -> licht, wat het besturingssysteem ook zegt
'light'     -> licht, wat het besturingssysteem ook zegt
'dark'      -> donker, wat het besturingssysteem ook zegt
'auto'      -> het besturingssysteem beslist, omdat iemand daarom vroeg
```

`frontend/js/theme.js` schrijft dat attribuut. Het is een gewoon blokkerend
`<script>` aan het eind van de `<head>`, want de site draait onder
`script-src 'self'` en een inline script is daar dood. Zonder keuze schrijft het
niets, dus de lichte standaard hangt niet af van javascript. De sleutel is
`localStorage['paramant.theme.v1']` met waarden `auto`, `light`, `dark`; alles
anders, en een browser die opslag weigert, leest als geen keuze. De sleutel staat
op `/privacy` in de local-storage-lijst en in `docs/site-claims.md`, en
`tests/ui-truthfulness.test.mjs` pint de naam, de drie waarden en de drie zinnen
naast de schakelaar.

De schakelaar zelf staat op **`/account`**, drieweg: *Follow my system, Light,
Dark*. Geen opslaanknop; de pagina waarop je staat hertekent als eigen preview.
De radio-input is 0x0, het label draagt het 44px-doel.

### 2.4 De homepagelaag

`/` draagt sinds #382 zijn eigen palet in de kritieke CSS, met een `--hp-` prefix,
omdat de pagina daar een warmer papier gebruikt dan de gedeelde bone.

| Token | Waarde |
|---|---|
| `--hp-paper` | `#FAF8F3` |
| `--hp-paper-2` | `#F3F0E8` |
| `--hp-ink` | `#0C1B2A` |
| `--hp-ink-2` | `#3F4D5C` |
| `--hp-ink-3` | `#5F6B78` (was `#66727F`, #389) |
| `--hp-line` / `--hp-line-2` | `rgba(12,27,42,.12 / .22)` |
| `--hp-night` / `--hp-night-2` | `#0C1622` / `#13233A` |
| `--hp-cobalt` / `--hp-cobalt-2` | `#1D4ED8` / `#173FB3` |
| `--hp-lime` / `--hp-lime-ink` | `#B2FF3F` / `#5C7A12` |

Dit is een vierde palet naast de drie hierboven en dat is bewust noch mooi. Het
staat er omdat de vorm van #377 en #382 niet uit `design-system.css` te halen was
zonder alle 58 pagina's te raken. Het hoort op termijn op te gaan in de gedeelde
laag; zie sectie 8.

### 2.5 Typografie

Systeemstack, twee families, nul externe fonts. De schaal is die van
`design-system.css` (`--text-*`), niet een eigen 2026-schaal.

```
--sans: ui-sans-serif, system-ui, -apple-system, "Inter",
        "Segoe UI", Helvetica, Arial, sans-serif
--mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas,
        "Liberation Mono", monospace
```

Mono-labels staan op 11px met +0.14em letterspatie. Koppen op de homepage zijn
geklemd (`clamp`) in het style-blok van de pagina zelf. `tabular-nums` staat op
alles wat een bedrag of een teller draagt.

### 2.6 Radius

Nul is de merkkeuze en zacht is alleen wat je aanraakt. De schaal bestaat als
token **alleen in `app-2026.css`**:

| Token | Waarde | Wat |
|---|---|---|
| `--r-0` | 0 | mono-labels, chips, registercellen, buildbar, meters |
| `--r-1` | 3px | knoppen en velden |
| `--r-2` | 10px | kaarten |
| `--r-3` | 16px | panelen en dialogen |
| `--r-pill` | 999px | filters en de plan-pil |

Eerlijk over de gedeelde laag: `design-system.css` claimt nul radius en zet
`border-radius: 0` op `*, *::before, *::after`, maar breekt die regel op drie
plekken (`.product-tag--lime` en `.product-tag--cobalt` op 2px,
`.pa-quota-upsell` op 14px), en `nav.css` zet 3px op de kobaltknop. Nul is dus de
regel en niet de meting.

### 2.7 Schaduw en licht

Bijna niets. Diepte komt van hairlines en vlakverschil.

```
--sh-1  0 1px 2px rgba(12,27,42,.04)
--sh-2  0 1px 2px rgba(12,27,42,.05), 0 8px 24px -12px rgba(12,27,42,.14)
--sh-3  0 24px 64px -24px rgba(12,27,42,.28)   alleen dialogen
--ring  0 0 0 2px var(--paper), 0 0 0 4px var(--accent-ring)
```

In donker worden de schaduwen zwart met hogere alfa. Eén focusring, overal
dezelfde, in beide modi. Geen textuur: het weefsel van WARM via
`repeating-linear-gradient` is afgewezen omdat het bij een niet-gehele
devicePixelRatio moiré kan geven. De warmte zit in `--paper`.

### 2.8 Motion

Drie duren, twee curves.

```
--d-1  110ms   toestand van een control
--d-2  180ms   verplaatsing binnen beeld
--d-3  260ms   iets dat komt of gaat
--e-standard  cubic-bezier(.2, 0, 0, 1)
--e-enter     cubic-bezier(.16, 1, .3, 1)
```

Beweging is bevestiging, niets anders. In `app-2026.css` loopt niets oneindig;
op `/parashare` verloren acht `.dot`-elementen hun puls in #381, omdat de beacon
alleen klopt waar iets echt gemeten wordt. Alleen `#waiting-dot` houdt hem.
`prefers-reduced-motion: reduce` wordt gemeten door
`tests/motion-safety.test.mjs`, sinds #380 binnen één paginalading:
opname A, dan `emulateMedia({ reducedMotion: 'reduce' })`, opname B, dan terug
voor opname C als controle. Het oude meetpunt met twee ladingen deugde niet, door
de WebGL-globe op `/parashare`.

### 2.9 Tikdoel en focus

`--tap: 44px` is de basis voor knop, nav-link, filter en kaart. Kleine controls
groeien onder `@media (pointer: coarse)` alsnog naar 44px, met één bewuste
uitzondering: een tekstlink in een lopende alinea, die onder de leesregel met
onderstreping valt en niet onder de knoppenregel. Elk bedienbaar element heeft
een zichtbare `:focus-visible`.

---

## 3. Componentregels

Alles onder `.ax-` in `app-2026.css`. Het prefix bestaat zodat niets hier kan
botsen met een klassenaam van een pagina of met een selector die een test pint.

**Knop** (`.ax-btn`). Vier smaken: `primary` (gevuld accent), kaal met hairline,
`bare` (tekst), `warn` (hairline die rood wordt, nooit een gevulde rode knop,
want dan is de enige gevulde knop op het scherm de gevaarlijkste). `--r-1`,
44px, drukt 1px in bij actief.

**Gemarkeerde link** (`.ax-link`). Pijl die 3px schuift op hover. Dit is de
leesbare "verder"-vorm en vervangt een tweede knop.

**Mono-label** (`.ax-label`). 11px, +0.14em, `--ink-3`, met een streepje ervoor.
Het streepje is lime in de merkvariant (`.mark`). Radius nul.

**Statuschip** (`.ax-chip`). Pill, stip, statuskleur op 9 procent achtergrond.
Vier staten, en ze heten precies wat `dashboard.js` rendert: `waiting`,
`in_progress`, `completed`, `cancelled`.

**Meter** (`.ax-meter`). 3px hoog, radius nul, vult eenmaal in `--d-3`. Nooit een
percentage zonder het getal ernaast.

**Skelet** (`.ax-skel`, `.ax-skel-row`). De laadtoestand van het dashboard, met
de kolombreedtes van de echte rij. Dat is de vorm die CLS van 0.236 naar 0.005
bracht.

**Veld** (`.ax-field`, `.ax-input`, `.ax-error`). `--r-1`, hairline; hover
verzwaart de lijn, focus kleurt hem accent en zet de ring eromheen. Een fout
staat onder het veld met een icoon, nooit alleen kleur, en zet
`aria-invalid="true"`.

**Beacon.** Eén statuslicht, en het staat alleen waar iets echt gemeten wordt.
Nooit als versiering, nooit met een verzonnen getal ernaast, en binnen een lijst
staat de hartslag uit.

**Nav** (`nav.css`). Sticky, 56px, hairline eronder. Zinsopmaak, 14px, geen
letterspatiëring. Eén gevulde kobaltknop. Onder 700px: la op `details`/`summary`
zonder javascript, met Sign in en Help in een strip van 48px eronder, waar een
duim ze bereikt. Boven 700px staan die twee terug in de balk. Een `gap` op de
balk zet een vloer van 12px tussen elk paar elementen. De uitgelogde en
ingelogde staat moeten dezelfde hoogte hebben, anders verspringt de balk als
`nav-auth.js` klaar is; `tests/navigation-shell.test.mjs` bewaakt dat, en leest
sinds #392 elke `.html` in `frontend/` in plaats van alleen de 51 die de
generator schrijft.

---

## 4. Per scherm

### home (`frontend/index.html`): omgezet, #377, #382, #386, #389, #392
Hero links uitgelijnd. Eén gevulde kobaltknop naar `/sign`, één hairline-knop
naar `/pricing`. De oprichtersregel staat op het eerste scherm. Rechts een
CSS-only object: een document dat getekend, verzegeld en dan van onderaf tot stof
oplost, met het ontvangstbewijs ernaast op desktop. Het draagt geen script en
geen extern asset; onder `prefers-reduced-motion` staat het stil. Het
Community-blok is het enige donkere object en draagt de brief van de oprichter.
Daaronder *Five things you can check yourself, today*: KvK-register, servers in
Duitsland, het publieke log, de meldtermijn uit de DPA, en de code zelf. Elke
tegel noemt de plek waar je het opzoekt.
Let op: `tests/first-screen.test.mjs` pint op 390x844 negen claims op hun
bodemrand. Meer wit boven de vouw is precies wat die test rood maakt.

### app-schermen: omgezet, #381
`dashboard`, `sign`, `parashare`, `signup`, `signup/verified`, `account` en de
vijf onder `auth/` laden `app-2026.css` en hebben een donkere modus na keuze.

Eén bewuste uitzondering: **`/sign` gebruikt daar geen thematoken voor het
document en het zegel**. Een PDF-pagina is wit papier in elk thema, en het zegel
is een gedrukt artefact. Onder een donker thema lost `--cobalt` op naar lichtblauw,
en een wit-op-lichtblauw zegel zou een stempel voorspiegelen die geen printer ooit
maakt.

`tests/app-contrast.test.mjs` (876 kleurparen over elf schermen, twee breedtes,
twee thema's), `tests/app-theme.test.mjs` (acht checks, met een sabotage die
`[data-theme="auto"]` terugzet naar `:not([data-theme="light"])`) en
`tests/user-dashboard-documents.test.mjs` kijken hier mee. De statuslabels blijven
letterlijk wat `dashboard.js` rendert.

### pricing (`frontend/pricing.html`): niet omgezet
De strengste pagina van de site. `tests/pricing-fold.test.mjs` pint op 390x844 de
bodemrand van h1, de wat-regel, `€0 a month, forever`, de limietregel,
`€15 a month`, `€49 a month`, de doelgroepregel, de volledige oprichtersregel met
KvK, en de CTA naar `/signup`, plus de volgorde: wat, dan prijs, dan doelgroep,
dan actie. De kaarten mogen op 320, 390, 768, 1024 en 1280 niet breder zijn dan
hun grid. Verticaal ritme mag alleen strakker, nooit ruimer. Zie sectie 8: deze
pagina draagt nu zeven gevulde kobaltknoppen.

### parasign, parasend, security, about, docs, rules: niet omgezet
Deze draaien op `design-system.css` v4.1 zoals hij is. `tests/first-screen.test.mjs`
pint op parasign `p.ps-who`, de eerste actie naar `/sign`, de zin "Simple
Electronic Signature (SES)" op y=815 en `p.ps-fine`; op parasend `p.ps-who`, de
eerste actie naar `/parashare` en `p.ps-sub` met "10 transfers a month". De
mobiele media query die die zin op 815 houdt blijft ongewijzigd overeind.

---

## 5. Wat er nog niet omgezet is

De oorspronkelijke uitrolvolgorde ging uit van één globale tokenlaag die pagina
voor pagina zou worden aangezet. Dat is niet gebeurd en het bestand dat het zou
doen is verwijderd. Wat er in plaats daarvan staat, en wat er nog ligt:

1. **Gedaan.** De app-laag, als eigen stylesheet met een aliaslaag naar de
   v4-namen, zonder de marketingpagina's te raken. (#381)
2. **Gedaan.** De homepage, in zijn eigen kritieke CSS. (#377, #382, #389)
3. **Gedaan.** De navigatie, gedeeld over alle pagina's. (#392)
4. **Gedaan.** De meta-strip weg, overal. (#386)
5. **Open.** `/pricing`, `/parasign`, `/parasend`, `/security`, `/about`,
   `/docs`, `/rules` in de nieuwe vorm. Elke pagina met zijn eigen
   geometriemeting vooraf: `pricing-fold` op vijf breedtes, `first-screen` op
   390x844.
6. **Open.** De vier paletten terugbrengen naar één. Pas als geen pagina de oude
   tokennamen meer noemt, kunnen de aliaslaag en de `--hp-*` set weg en wordt
   `design-system.css` v5.

De donkere modus was in het oude plan "de val": zodra `prefers-color-scheme`
leeft moet elke pagina mee. Die val is omzeild in plaats van gelopen. Donker
bestaat alleen waar een schakelaar hem aanzet, en marketing doet niet mee. Wie
hem daar alsnog wil, doet dat met een schakelaar en met nul open contrastgevallen,
niet met een media query.

---

## 6. De verboden

1. **Geen externe fonts.** Geen `@font-face` naar een derde, geen Google Fonts,
   geen gehost bestand in de repo dat de laadtijd opblaast. De CSP en de
   subresource-scan verbieden derden en dat is een productbelofte, geen
   technische voorkeur.
2. **Geen externe scripts en geen framework.** CSS-first. Wat zonder javascript
   kan (de mobiele la, disclosure, filters als links) gebeurt zonder javascript.
3. **Geen gimmicks.** Geen gradient zonder functie. Geen stockfoto's. Geen
   decoratieve datavisualisatie: een grafiek zonder data is op deze site een
   leugen. Geen versienummer of statusregel die niet uit de code komt; daar is
   de meta-strip aan gestorven.
4. **Geen tekstwijziging.** Geen woord in een gepinde tekst verandert. De tests
   zeggen welke: `ui-truthfulness`, `site-claims`, `pricing-page`,
   `pricing-fold`, `seo-contract`, `first-screen`, `links`, `navigation-shell`,
   `frontend-loading-contract`. Structuur en stijl zijn vrij, claims niet. Ook
   een andere kop-hiërarchie mag nooit op een element dat een geometrietest op
   zijn bodemrand pint.
5. **Eén gevuld accentvlak per scherm.** Kobalt is dat accent. Lime is een lijn,
   nooit een vlak met tekst erop, behalve de ene toegestane combinatie
   (`#0A1626` op `#B2FF3F`, 14.94:1). Zie sectie 8: `/pricing` voldoet hier
   vandaag niet aan.
6. **Geen contrast onder AA.** 4.5:1 voor tekst, 3:1 voor grote tekst
   (>=24px, of >=18.66px vetgedrukt) en voor randen en iconen die betekenis
   dragen. Elke nieuwe kleur wordt gerekend voordat hij in het systeem komt, in
   licht en in donker. De `KNOWN_LIGHT`-lijst in `tests/theme-contrast.test.mjs`
   mag korter worden en nooit langer.
7. **Geen beweging die niets bevestigt.** Geen parallax, geen scroll-gedreven
   animatie, geen oneindige beweging behalve waar iets echt gemeten wordt.
   `prefers-reduced-motion` wordt gemeten, niet aangenomen.
8. **Geen `color-mix` op iets dat je moet kunnen meten.** Doorschijnende
   achtergronden zijn rgba-tokens, zodat een contrastscanner en oudere Safari
   hetzelfde zien. De ene uitzondering is `text-decoration-color`, die geen
   contrast draagt.
9. **Geen radius op wat het merk draagt.** Mono-labels, chips, registercellen,
   de buildbar en de meter blijven op nul.
10. **Geen donkere modus zonder schakelaar.** Een donkere laag achter een media
    query of een attribuut dat niemand kan zetten is geen functie maar 31 KB.
    Dat is #380, en het is de duurste les van deze reeks.
11. **Geen verzonnen data in een screenshot dat als bewijs dient.** De
    documentrijen in de app-screenshots zijn stubdata uit `scripts/app-shots.mjs`
    en mogen nooit als bewijs van werking gelden.

---

## 7. Bewijs

### 7.1 De twee beelden

De elf beelden van de prototypes zijn weg: ze toonden pagina's die niet bestaan
en tokens die niet geladen worden. Wat er staat is de gemergede homepage,
geschoten van `frontend/index.html` zelf.

| Beeld | Bestand | Wat het toont |
|---|---|---|
| home 390x844, licht, eerste scherm | `home-390x844-light.png` | de nav in zinsopmaak met één kobaltknop (#392), de hero met één gevulde en één hairline-knop, de oprichter op het eerste scherm (#377), geen technische strip (#386) |
| home 1440x900, licht, hele pagina | `home-1440x900-light.png` | het ene donkere object met de brief erin (#382), het ontvangstbewijs naast het oplossende document (#377, #382), de vijf nakijkbare feiten (#382), hairlines in plaats van dozen |

Beide in `docs/brand/assets/design-direction-2026/`, licht, met
`reducedMotion: 'reduce'` zodat het beeld reproduceerbaar is. Het telefoonbeeld
staat op deviceScaleFactor 2, het paginabeeld op 1: dat laatste is 6289px hoog en
op 2x een bestand van 2 MB in een getrackte map, en wat het moet tonen is de
volgorde van de secties, niet de scherpte van de letter.

Beide worden geschoten door `scripts/brand-shots-direction.mjs`, dat de regel van
#393 volgt: een tempmap standaard, de getrackte map alleen met
`PARAMANT_WRITE_BRAND_SHOTS=1`. Het hergebruikt de vlag en de docs-check uit
`scripts/brand-shots-dir.mjs` in plaats van er een tweede kopie van te houden.

```
node scripts/brand-shots-direction.mjs                              tempmap
PARAMANT_WRITE_BRAND_SHOTS=1 node scripts/brand-shots-direction.mjs  referenties
BRAND_SHOTS_DRY_RUN=1 node scripts/brand-shots-direction.mjs         zeg alleen waar
```

De app-schermen hebben hun eigen 36 referentiebeelden in
`docs/brand/assets/app-2026/`, geschoten door `scripts/app-shots.mjs` onder
dezelfde vlag.

### 7.2 Wat gemeten is, en waar

| Wat | Gate | Stand |
|---|---|---|
| contrast, marketing, licht | `tests/theme-contrast.test.mjs` | 4452 tekstparen over 16 pagina's op 390 en 1440; vier bekende gevallen, alle vier in het style-blok van een pagina en niet in het ontwerpsysteem |
| contrast en tikdoel, app, licht en donker | `tests/app-contrast.test.mjs` | 876 paren over elf schermen; niets onder AA |
| donker is een keuze | `tests/app-theme.test.mjs` | acht checks, plus een sabotage die de gate eruit haalt en de schermen weer donker ziet worden |
| beweging | `tests/motion-safety.test.mjs` | één paginalading, A/B/C |
| geometrie boven de vouw | `tests/first-screen.test.mjs` | negen claims op 390x844, 9/9 |
| prijsgeometrie | `tests/pricing-fold.test.mjs` | vijf breedtes |
| de balk | `tests/navigation-shell.test.mjs` | 39 checks over elke `.html` in `frontend/` |
| screenshots blijven opt-in | `tests/brand-shots-optin.test.mjs`, `tests/static-sanity.sh` check 12 | drie lagen: resolver, dry run, statische scan |

De vier bekende contrastgevallen die openstaan: `/about a.btn.btn-primary`
(kobalt op kobalt, 1:1), `/security span.check` (lime vinkje op papier, 1.16:1;
bullet en geen inhoud, en lime vervangen is een merkbesluit en geen herstel),
en twee op `/docs` (`code` en `a` op gekleurde blokken zonder de tekstkleur mee
te kantelen).

**Lighthouse.** Accessibility 100 op alle zeven gemeten app-schermen (#381).
Dashboard CLS van 0.236 naar 0.005. De 100/100/100/100 uit de oorspronkelijke
jurytekst kwam van het STIL-prototype en is nooit op de echte site herhaald; die
claim is uit dit document gehaald in plaats van overgeschreven.

---

## 8. Wat open staat

Twee daarvan zijn **merkbesluiten** en geen herstelwerk. Ze staan hier open omdat
ze een keuze vragen en niet een fix.

**Open 1: één gevuld accent per scherm, en `/pricing`.** Sectie 6 verbod 5 zegt
één gevuld kobaltvlak per scherm. Sinds de balkknop in #392 van lime naar kobalt
ging, draagt `/pricing` er meer: zeven `btn-primary` in de pagina plus de knop in
de balk, en op het eerste scherm staan er twee naast elkaar. #392 heeft dat
erkend en bewust laten liggen: "That is the cost of moving the bar button from
lime to cobalt, and the fix belongs with the page, not with the bar." De keuze is
of de tierkaarten hun gevulde knop houden (en de regel wordt "één gevuld accent
per *sectie*"), of dat alleen de aanbevolen tier gevuld blijft en de rest
hairline wordt. Het tweede is de regel zoals hij geschreven staat; het eerste is
wat elke prijstabel doet.

**Open 2: de koele naad tussen balk en papier.** De navigatiebalk staat op
`rgb(248, 250, 252)`, het homepagepapier op `#FAF8F3`. Koud blauwgrijs op warm
crème, met een zichtbare naad op de hairline eronder. `.home-hero` verbergt hem
nu met een gradient van `#F8FAFC` naar `--hp-paper` over de eerste 160px, wat een
pleister is en geen besluit. De balkkleur is gepind door
`tests/navigation-shell.test.mjs` ("mobile navigation is opaque before opening
the menu", `rgb(248, 250, 252)`), dus veranderen betekent die pin verzetten en
opnieuw contrast meten over alle 58 pagina's. De keuze is of de balk het papier
volgt (warm, per pagina anders) of dat het papier de balk volgt (koel, en de
warmte van #377 valt weg).

Verder open, als werk en niet als besluit:

- De vier paletten terug naar één, en `design-system.css` naar v5. Zie sectie 5,
  punt 6.
- De marketingpagina's die nog niet omgezet zijn. Zie sectie 5, punt 5.
- Twee `aria-label`-waarden op de startkaarten van het dashboard komen niet
  overeen met de zichtbare kop (label-content-name-mismatch). Dat is een
  wijziging in de toegankelijke naam en hoort een eigen besluit te krijgen, niet
  mee te liften op een stijlronde.
- Lighthouse opnieuw draaien tegen een lokale server voor performance en SEO;
  alleen accessibility is op de echte site gemeten.
