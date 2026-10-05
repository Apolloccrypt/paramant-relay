# Directiesignalen

`scripts/directie/signalen.py` meet de staat van Paramant en zegt wat rood is.
Geen model, geen oordeel achteraf: een vaste lijst vragen aan GitHub (via `gh`)
en aan productie (via `curl`), en per vraag een ernst, een meting en een
voorstel van een zin. Bedoeld voor een mens die in tien seconden wil weten of er
iets aan de hand is, en voor een latere ronde die op de exitcode kan sturen.

## Draaien

```
python3 scripts/directie/signalen.py            # JSON naar stdout
python3 scripts/directie/signalen.py --tekst    # leesbare tekst
python3 scripts/directie/signalen.py --repo eigenaar/repo
```

Exitcode 0 als niets rood is, 1 als er iets rood is, 2 als het script zelf
struikelt. Een volledige run duurde op 2026-09-02 gemeten 7 seconden met het
uurlijkse alarm uit, vrijwel helemaal wachten op GitHub. Dat loopt op met het
aantal open pull requests, en met een uur of twee extra API-aanroepen zodra de
heartbeat aan staat: de runlijst, de artefactlijst en het bewijsartefact zelf.

De stubtest ernaast raakt GitHub niet:

```
python3 tests/test_directie_signalen.py
```

Die vervangt `gh_json` en `gh_bytes` door een tabel met antwoorden en legt beide
standen van de heartbeat vast, plus de gevallen waarin een groene tik niet
verdiend is.

Nodig: Python 3, `gh` (ingelogd) en `curl`. Verder niets, met opzet. Zonder
`gh`-login sterft het script niet, maar worden de GitHub-signalen oranje met
"niet gemeten" als meting.

## Wat het meet

| Signaal | Vraag | Rood als |
| --- | --- | --- |
| `pr-<nummer>` | Elke open pull request: leeftijd in uren en de status van zijn checks. | Een check is gefaald. |
| `dependabot` | Hoeveel dependabot-PRs staan open en hoe oud is de oudste. | De oudste staat langer dan 14 dagen open. |
| `workflow-runs` | Gefaalde workflow-runs van de laatste 24 uur (`gh run list`). | Er faalde iets op `main`. |
| `heartbeat` | Staat het uurlijkse alarm aan? Alleen zichtbaar zolang het uit staat. | Nooit rood; uit is oranje, want dan valt er niets te meten. |
| `heartbeat-surface` | De stap `surface` van de laatste afgeronde run van `heartbeat.yml`, met conclusie en tijdstip uit het bewijsartefact. | De stap faalde, of de laatste uitslag is ouder dan 2 uur. |
| `heartbeat-parasend` | Idem voor `parasend`: het bestand gaat er echt door en is daarna weg. | Idem. |
| `heartbeat-parasign` | Idem voor `parasign-receipt` en `parasign-public-sign` samen. | Idem, in een van de twee. |
| `heartbeat-issue` | Staat er een open issue `Heartbeat rood`? Die opent en sluit de workflow zelf. | Ja, met het nummer en de url erbij. |
| `pr-gate-heartbeat` | `product-heartbeat.yml`, de browsergate op pull requests: staat hij er, draait hij en is de laatste run groen. | Nooit rood; dit is een gate, geen uitspraak over productie. |
| `productie-health` | Statuscode van `https://paramant.app/health`. | Niet 2xx of 3xx, of onbereikbaar. |
| `productie-homepage` | Responstijd en statuscode van de homepage. | Boven 2,5 s of een foutstatus. |
| `paraid-deny-<host>` | `POST` met een lege JSON-body naar `/v1/paraid/issue-document` op `paramant.app`, `relay.`, `health.`, `legal.`, `finance.` en `iot.paramant.app`. | De host antwoordt met iets anders dan 404, 401, 403, 405 of 410. |

Oranje betekent bijna overal hetzelfde: het is niet kapot, maar het is ook niet
gemeten of het staat te lang stil. Een signaal dat het script niet kon meten is
oranje, nooit groen. Groen betekent: gemeten en in orde.

## Waarom de ParaID-ingangen erin zitten

ParaID is uit het product gehaald. De route `/v1/paraid/issue-document` hoort op
alle zes de hosts een kale 404 te geven. Antwoordt er een host anders, dan
draait daar oude code of stuurt een proxy verkeer naar iets wat er niet meer
hoort te zijn. Dat is de reden dat dit zes losse signalen zijn en niet een: je
wilt weten welke host afwijkt, niet dat er ergens een afwijkt.

## Hoe de heartbeat gelezen wordt

De drie kanariestappen bestonden tot PR #338 in de `live`-job van
`product-heartbeat.yml`. Die job is verhuisd naar `.github/workflows/heartbeat.yml`
en de checks zelf staan nu in `scripts/heartbeat/`, met andere stapnamen. Het
script zocht daarna nog naar de oude namen en meldde drie keer oranje "geen
uitslag" terwijl er niets stuk was. Nu is de volgorde:

1. **Staat het alarm aan?** De job draait alleen bij een handmatige start of als
   de repositoryvariabele `HEARTBEAT_ENABLED` op `true` staat. Staat hij uit,
   dan is er een signaal en niet drie: `heartbeat`, oranje, met de stand van de
   variabele en welke van de twee kanarie-sleutels nog ontbreken. Dat laatste is
   gemeten, niet aangenomen: GitHub geeft de namen van secrets terug, nooit de
   waarden. De volgorde waarin je het aanzet staat in
   [docs/heartbeat.md](heartbeat.md).
2. **Staat hij aan, dan de laatste afgeronde run** van `heartbeat.yml` op
   `schedule` of `workflow_dispatch`, want alleen daar draait de job.
3. **De uitslag per stap komt uit het bewijsartefact**, niet uit de jobs-API.
   Dat is het hart van deze meting. De proefstap draait met
   `continue-on-error: true`, zodat de browserhelft en de upload daarna nog
   gebeuren, en GitHub meldt zo'n stap daarna als `conclusion: success`. Run
   33656533245 staat in de API dus groen op de stap "Proof run", terwijl
   `summary.json` in `heartbeat-evidence-33656533245` `parasend` en beide
   `parasign`-stappen rood noemt met de naam van de ontbrekende sleutel. Wie de
   jobs-API gelooft, meldt een dode kanarie groen. Het script haalt daarom het
   artefact op (`gh api .../artifacts/<id>/zip`, uitgepakt met `zipfile` uit de
   standaardbibliotheek) en leest `summary.json`.

Regels bij de uitslag: een gefaalde stap is rood met de oorzaak erbij. Een
uitslag ouder dan `HEARTBEAT_ROOD_UREN` is rood, ook als de stap groen was: het
alarm draait per uur, dus twee uur stilte betekent dat er een ronde is
overgeslagen. Een dry run is nooit groen, want die heeft niets over productie
bewezen. Is elke stap groen maar de run toch gevallen, dan is het oranje met de
mededeling dat de storing buiten de drie proefstappen zat, in de browserhelft of
de linkcheck. Is er geen bewijsartefact of ontbreekt de stap in `summary.json`,
dan is het oranje, of rood als de run zelf faalde. Nooit stilletjes groen.

`product-heartbeat.yml` blijft in beeld als `pr-gate-heartbeat`, maar niet meer
als kanarie: het is de browsergate op pull requests en zegt niets over
productie. Verdwijnt de gate, verliest hij zijn `pull_request`-trigger of krijgt
hij weer een `schedule` (twee uurlijkse alarmen), dan wordt dat signaal oranje.

## Drempels

De grenzen staan als constanten bovenaan het script, met een regel uitleg per
stuk: `PR_OUD_UREN` (72), `DEPENDABOT_OUD_UREN` (14 dagen), `RUNS_VENSTER_UREN`
(24), `HEARTBEAT_ROOD_UREN` (2),
`HOMEPAGE_ORANJE_S` (1,0) en `HOMEPAGE_ROOD_S` (2,5). Discussie over wanneer
iets rood is hoort daar gevoerd te worden, niet verspreid over de code.

## JSON

De JSON-uitvoer heeft `gegenereerd` (UTC), `repo`, `wortel` (het pad naar de
werkkopie waarin `.github/workflows` gelezen is), `samenvatting` (aantallen
per ernst) en `signalen`. Elk signaal heeft `sleutel`, `naam`, `ernst`, `meting`,
`voorstel` en `details`. In `details` staat onder meer `bron`: het commando
waar de meting vandaan komt, zodat elke regel terug te leiden is naar iets wat
je zelf kunt nadraaien.
