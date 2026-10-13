# Ontwerpvoorstel: boomtoppen van de CT-log buiten Paramant bewaren

Status: voorstel. Niets hiervan is gebouwd.
Aanleiding: het CT-onderzoek van 6 oktober 2026 (`paramant-bewijs/ct-onderzoek-2026-10-06/RAPPORT.md`, paragraaf 3 en 5).

## Het probleem

De wiskunde van de log klopt (bevestigd: boom, STH's, inclusie- en consistentiebewijzen nagerekend met eigen code). Wat ontbreekt is de buitenwereld:

- De ondertekende boomtoppen (STH's) staan alleen op Paramants eigen servers. `/v2/sth/history` gaat 100 heads terug, de RSS-feed 20. (bevestigd)
- Niemand buiten Paramant bewaart ze of vergelijkt ze. (bevestigd)
- Alle relays draaien op één host van één beheerder. (bevestigd in code, waarschijnlijk voor de host)

Gevolg: Paramant kan elke klant een eigen, intern kloppende boom laten zien (een gespleten weergave, split view). De klant kan met `scripts/klant-controle.py` aantonen dat zijn blad in de boom staat die hij krijgt. Of anderen dezelfde boom krijgen, kan hij nergens nagaan. En als het volume met sleutel, boom en heads verloren gaat, weet buiten Paramant niemand dat er ooit een andere boom was.

De vaste regel van transparantielogs is: een boomtop telt pas als iemand anders hem ook heeft. Dit voorstel regelt die iemand anders.

## Wat er gepubliceerd wordt

Alleen boomtoppen. Nooit bladen.

Een boomtop bevat `relay_id`, `tree_size`, `sha3_root`, een op het uur afgeronde `timestamp`, `version` en de ML-DSA-65-handtekening. Daarin zit geen klantgegeven. De bladen blijven waar ze zijn; die zijn ongezouten en raadbaar (ADR R021 is niet gebouwd), dus die horen niet op nog meer plekken.

Wel een kanttekening. Elke append maakt een nieuwe boomtop. Wie élke boomtop publiceert, publiceert ook het aantal gebeurtenissen per uur. Dat is nu al openbaar via `/v2/ct/log`, maar een externe kopie is niet meer in te trekken. Daarom: per relay alleen de **laatste** boomtop per publicatiemoment.

## Drie opties

### A. Dagelijks in een openbare git-repository

Een geplande GitHub-workflow haalt elke dag (of elk uur) van alle vijf relays `/v2/sth` op, controleert de handtekening tegen de pin in `frontend/js/relay-trust-anchors.js` en het consistentiebewijs vanaf de vorige gepubliceerde boomtop, en commit het resultaat in een aparte openbare repository (bijvoorbeeld `paramant-ct-heads`, één bestand per relay per dag).

- Kosten: ongeveer een halve dag bouwen. GitHub Actions is gratis voor een openbare repo. Onderhoud vrijwel nul.
- Wat het oplevert: een openbaar, gedateerd spoor van boomtoppen buiten de Paramant-servers. Elke afwijking (een kleinere boom, een andere root bij dezelfde grootte, een consistentiebewijs dat niet klopt) breekt de workflow zichtbaar.
- Zwakte: de repository is van Paramant. Paramant kan een force-push doen. Dat is te beperken met beschermde branches, getekende commits, en vooral met kopieën die Paramant niet beheert: wie de repo kloont of forkt, of het automatische archief van Software Heritage, houdt de oude stand vast. (waarschijnlijk: Software Heritage archiveert openbare GitHub-repo's, maar niet op een vast moment)
- De workflow leest alleen. Hij schrijft niets op productie. Hij sluit aan op de geplande monitor uit `scripts/paramant-verify-peers` (zie de workflow voor dagelijkse controle).

### B. Een anker in Sigstore Rekor

Elke dag gaat de SHA-256 van het bestand met boomtoppen uit optie A als `hashedrekord` naar de openbare Rekor-log van Sigstore, ondertekend met een aparte publicatiesleutel.

- Kosten: ongeveer een dag bouwen bovenop A (`rekor-cli` of `cosign` in dezelfde workflow, sleutel als GitHub-secret). Rekor is gratis voor openbaar gebruik.
- Wat het oplevert: een onafhankelijke, append-only log die Paramant niet beheert, met een eigen inclusiebewijs per dag. Een force-push in repo A valt dan op, want de oude hash staat onherroepelijk in Rekor.
- Zwakte: Rekor bewaart een hash, geen inhoud. Wie wil controleren, heeft het bestand uit A nodig. Rekor heeft gebruiksgrenzen en geeft geen garantie voor eeuwige bewaring van de openbare instantie. (waarschijnlijk; voor de bouw de actuele voorwaarden nalezen)
- Rekor accepteert geen ML-DSA-65 als handtekening op de entry. (vermoeden; te toetsen) De publicatiesleutel wordt dan een gewone Ed25519- of ECDSA-sleutel. Dat is geen verzwakking van de log: de ML-DSA-handtekeningen van de relays zitten ongewijzigd in het bestand zelf.

### C. Medeondertekening door onafhankelijke witnesses

De relays publiceren hun boomtop ook als checkpoint in het C2SP-formaat (`tlog-checkpoint`, een signed note) en vragen bestaande witnesses om die mede te ondertekenen volgens het C2SP-witnessprotocol (`tlog-witness`). Een witness tekent alleen als het nieuwe checkpoint consistent is met het vorige dat hij zag. Rond Sigstore en het transparency-dev-project draait zo'n netwerk (omniwitness, en de hardware-witnesses van de Armored Witness).

- Kosten: drie tot vijf dagen bouwen (checkpoint-endpoint, Ed25519-checkpointsleutel naast de ML-DSA-identiteit, een add-checkpoint-client met consistentiebewijzen), plus overleg met witness-beheerders, waarvan de doorlooptijd niet in onze hand ligt.
- Wat het oplevert: de echte oplossing. Een klant kan dan eisen dat een boomtop door minstens N onafhankelijke partijen is medeondertekend. Een gespleten weergave is dan alleen nog mogelijk als die witnesses meedoen.
- Zwaktes:
  - Het formaat is eigen (SHA3-256, eigen JSON). Witnesses verwachten het checkpointformaat en rekenen consistentie met de RFC 6962-structuur na. De boom zelf is RFC 6962 van vorm, maar met SHA3-256. Of bestaande witnesses een andere hashfunctie accepteren, is onbekend. (vermoeden; te toetsen. Zo niet, dan is dit een groter werk: een tweede, SHA-256-boom naast de huidige)
  - Witnesses tekenen met Ed25519. ML-DSA-65 wordt in dat netwerk niet ondersteund. (waarschijnlijk) De post-kwantumbelofte geldt dan voor de log, niet voor de medeondertekening.
  - Een witness kan wegvallen of stoppen. Daarom meerdere, en een drempel (bijvoorbeeld 2 van 3) in plaats van één.

## Risico's die voor alle drie gelden

| Risico | Gevolg | Maatregel |
|---|---|---|
| Publicatie lekt gebruikspatroon | Aantal gebeurtenissen per periode wordt onuitwisbaar | Alleen de laatste boomtop per moment; geen bladen; uur-afronding blijft |
| Publicatiesleutel lekt (B, C) | Iemand publiceert namens Paramant | Aparte sleutel, alleen voor publicatie, als secret; rotatie beschreven in de runbook; de relay-handtekening blijft het eigenlijke bewijs |
| Externe dienst valt weg | Een gat in het spoor | Gat is zichtbaar en niet erg; A blijft de basis; bij C meerdere witnesses |
| Workflow faalt door vervuiling | Vals alarm, alarmmoeheid | Eerst gossip repareren (relay_id binden aan de pin, vreemde sleutels weigeren), dan pas alarmeren |
| Paramant herschrijft repo A | Spoor lijkt schoon | Rekor-anker (B) en kopieën buiten Paramant |
| Volume met sleutel en boom gaat verloren | Nieuwe boom zonder verband met de oude | Precies wat publicatie zichtbaar maakt: de laatste externe boomtop spreekt de nieuwe boom tegen. Dat moet dan eerlijk gemeld worden, niet weggepoetst |

## Aanbeveling

1. **Nu: A**, met de controle die erbij hoort (handtekening tegen de pin, consistentie vanaf de vorige publicatie). Klein, goedkoop, direct zichtbaar resultaat.
2. **Daarna: B** in dezelfde workflow. Eén dag werk en het zwakke punt van A (Paramant beheert de repo) is weg.
3. **Onderzoeken: C.** Eerst bij twee witness-beheerders navragen of SHA3-256 en het eigen formaat bespreekbaar zijn. Pas bouwen als dat zo is, of als we een SHA-256-checkpoint naast de huidige boom willen.
4. Pas als A draait de site-teksten verruimen. Tot die tijd zegt de site niet dat "iedereen" het kan zien of dat het "zo werkt als de CT-logs van HTTPS".

## Stappen voor A en B

1. Gossip eerst schoon (relay_id gebonden aan de pin, vervuiling opgeruimd), anders begint de publicatie met ruis.
2. Openbare repo `paramant-ct-heads` aanmaken, branch beschermd, getekende commits.
3. Workflow (dagelijks, alleen lezen): per relay `/v2/sth` ophalen, handtekening tegen de pin controleren, consistentiebewijs vanaf de vorige boomtop in de repo narekenen, bestand `heads/<relay>/<JJJJ-MM-DD>.json` committen. Faalt een controle, dan geen commit en een rode run.
4. Daarna: SHA-256 van het dagbestand naar Rekor, de Rekor-index en het inclusiebewijs mee in de commit.
5. `docs/klant-controle.md` en `scripts/klant-controle.py` uitbreiden: de klant kan de boomtop die hij ziet vergelijken met de gepubliceerde van die dag. Pas dan wordt een gespleten weergave voor een klant zelf te ontdekken.
6. Runbook: wat te doen als de workflow rood wordt (eerst uitzoeken, dan eerlijk melden).

## Wat dit niet oplost

- Ongezouten bladen (R021). Publicatie van boomtoppen maakt bladen niet minder raadbaar.
- Eén host, één beheerder. Witnesses maken een gespleten weergave zichtbaar, maar houden een uitval niet tegen.
- ParaSign. Zolang de verificatie van een envelope niet in de log kijkt, helpt een externe boomtop daar niet.
