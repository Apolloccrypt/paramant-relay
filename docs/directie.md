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
struikelt. Een volledige run duurt ongeveer twintig seconden, vrijwel helemaal
wachten op GitHub.

Nodig: Python 3, `gh` (ingelogd) en `curl`. Verder niets, met opzet. Zonder
`gh`-login sterft het script niet, maar worden de GitHub-signalen oranje met
"niet gemeten" als meting.

## Wat het meet

| Signaal | Vraag | Rood als |
| --- | --- | --- |
| `pr-<nummer>` | Elke open pull request: leeftijd in uren en de status van zijn checks. | Een check is gefaald. |
| `dependabot` | Hoeveel dependabot-PRs staan open en hoe oud is de oudste. | De oudste staat langer dan 14 dagen open. |
| `workflow-runs` | Gefaalde workflow-runs van de laatste 24 uur (`gh run list`). | Er faalde iets op `main`. |
| `kanarie-transfer-kanarie` | De laatste uitslag van de transfer-kanarie tegen de live relay, met tijdstip. | De stap faalde, of de laatste uitslag is ouder dan 24 uur. |
| `kanarie-parasign-kanarie` | Idem voor de ParaSign-kanarie. | Idem. |
| `kanarie-heartbeat` | Idem voor de heartbeat tegen `paramant.app` (de productievariant, niet die tegen de checkout). | Idem. |
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

## Hoe de kanaries gevonden worden

De drie kanaries zijn geen losse workflows. Ze zijn stappen in de `live`-job van
`.github/workflows/product-heartbeat.yml`. Het script leest daarom de
workflowbestanden, zoekt op naam naar de stappen, pakt per kanarie de laatste
afgeronde run waarin die stap echt een uitslag gaf (een overgeslagen stap telt
niet mee), en rapporteert die conclusie met het tijdstip. Wordt een kanarie ooit
een eigen workflow, dan blijft dat werken. Verdwijnt hij helemaal, dan wordt het
signaal oranje in plaats van stilletjes groen.

## Drempels

De grenzen staan als constanten bovenaan het script, met een regel uitleg per
stuk: `PR_OUD_UREN` (72), `DEPENDABOT_OUD_UREN` (14 dagen), `RUNS_VENSTER_UREN`
(24), `KANARIE_ORANJE_UREN` (6) en `KANARIE_ROOD_UREN` (24),
`HOMEPAGE_ORANJE_S` (1,0) en `HOMEPAGE_ROOD_S` (2,5). Discussie over wanneer
iets rood is hoort daar gevoerd te worden, niet verspreid over de code.

## JSON

De JSON-uitvoer heeft `gegenereerd`, `repo`, `samenvatting` (aantallen per
ernst) en `signalen`. Elk signaal heeft `sleutel`, `naam`, `ernst`, `meting`,
`voorstel` en `details`. In `details` staat onder meer `bron`: het commando
waar de meting vandaan komt, zodat elke regel terug te leiden is naar iets wat
je zelf kunt nadraaien.
