# De waakhonden

Elke poort in deze repo, en per stuk het enige antwoord dat telt: **kan hij
vandaag afgaan?**

Een controle die per ongeluk niets meer toetst is erger dan geen controle, want
hij geeft rust. In de nacht van 2 op 3 september bleken er drie tegelijk zo te
staan, en alle drie zagen er in de code uit alsof ze werkten.

## Het patroon, vier keer

| | wat er stond | waarom hij niets deed |
| --- | --- | --- |
| 1 | de uurlijkse zelftest die bewijst dat het product werkt | uit achter een repository-variabele, en het alarm dat dat moest melden was een stap *in* de job die de variabele uitzet |
| 2 | de geheimencontrole in de bouwstraat | zeven weken rood om twee gemaskeerde voorbeeldsleutels, dus geen enkele wijziging kon er groen op worden |
| 3 | de geheugenbewaking van relay-health | drempel 8704 MB in een container van 8192 MB, dus de kernel greep altijd eerder in |
| 4 | een uitzonderingsregel in de geheimenscanner | `condition = "AND"` wordt geaccepteerd en genegeerd, dus `paths` naast `regexes` stelde het hele bestand vrij |

Eén vorm, vier keer: **een controle die niet kan afgaan**. Punt 1 bleef drie
dagen onopgemerkt omdat een overgeslagen run bij GitHub grijs is, niet rood, en
niemand een melding geeft. Negentien geplande runs op rij.

## Wat dit nu tegenhoudt

### `scripts/check-guards.mjs`, de poort op de poorten

Leest alle workflows en zoekt naar alles wat een poort stil kan zetten. De regel
is overgenomen van `relay/test/_requires.js`, één niveau hoger: **wat een poort
kan uitschakelen is een harde fout, tenzij het bij naam gedeclareerd staat**, met
de reden én met datgene wat het meldt zolang het uit staat. Andersom net zo: een
declaratie die niet meer voorkomt is ook rood, zodat de lijst niet volloopt met
geruststellingen over dingen die er niet meer zijn.

Wat hij herkent:

| regel | wat hij vangt |
| --- | --- |
| `switch` | een job achter `vars.X` of `secrets.X`: niet gezet betekent overgeslagen, en overgeslagen is grijs |
| `circular-alarm` | het alarm staat *in* de job die de schakelaar uitzet, dus het kan zijn eigen stilte niet melden |
| `unsettled-soft-failure` | een `continue-on-error`-stap waarvan niets de uitkomst leest of een oordeel herafleidt |
| `evidence-optional` | bewijs uploaden met `if-no-files-found: warn`: een run die niets vastlegde slaagt alsnog |
| `optional-tool` | een gereedschap dat de runner mag missen, met een waarschuwing in plaats van rood |
| `no-change-trigger` | een workflow die op geen enkele wijziging draait |
| `pipe-without-pipefail` | `a \| tee b` onder `bash -e` geeft de exitcode van `tee`, en `tee` slaagt altijd |

Plus drie invarianten waar geen uitzondering op bestaat, en die dus geen
declaratie kennen:

- `.gitleaks.toml` bevat geen `paths` en geen enkelvoudige `[allowlist]`
- voor elke relay geldt `RAM_LIMIT_MB + RAM_RESERVE_MB` < de containerlimiet
- `guards.yml` bestaat, heeft geen schakelaar, en draait op schedule én pull request

### `.github/workflows/guards.yml`, de waakhond die van buiten kijkt

Dagelijks om 07:11, en op elke push en pull request. **Zonder eigen
uitschakelaar**, en dat wordt afgedwongen: `check-guards.mjs` maakt de bouw rood
zodra een job hier een `if:` op een variabele of secret krijgt, of de schedule of
de pull request-trigger verdwijnt.

Hij stelt de vraag over de **job**, niet over de run. `security-posture.yml`
meldt namelijk "success" voor een run waarin de productiescan werd overgeslagen
en alleen de zelftest liep.

Staat er een waakhond stil, dan gaat de dagelijkse run rood en komt er één issue
open dat wordt bijgewerkt tot het opgelost is. Bewust dagelijks en niet uurlijks:
deze repo heeft die les al andersom geleerd, een alarm dat elk uur om een bekende
reden afgaat leert men negeren, en zo stierf de vorige bewaking.

Op een pull request meldt hij wel en faalt hij niet. Zolang de schakelaar uit
staat en alleen Mick hem aan kan zetten, zou een harde fout elke pull request
blokkeren op iets dat geen pull request kan repareren.

## De stand vandaag

| waakhond | kan hij vandaag afgaan? |
| --- | --- |
| `test.yml`, 9 jobs (static-sanity, shell-syntax, undefined-names, deploy-dryrun, cache-bust, relay-crypto, relay-unit, admin-unit, gitleaks) | ja, kaal, geen `if:` en geen `continue-on-error` |
| `csp-inline-check.yml` | ja |
| `product-heartbeat.yml` | ja, op elke push en PR |
| `sign-e2e.yml` | ja |
| `build-image.yml` | ja, als `relay/**` wijzigt |
| `docker-publish.yml` | ja, na merge naar main |
| `security-posture.yml` zelftest | ja, op elke PR |
| **`heartbeat.yml` productie** | **nee.** `HEARTBEAT_ENABLED` bestaat niet, `PARAMANT_CANARY_KEY` en `PARASIGN_CANARY_KEY` bestaan niet |
| **`security-posture.yml` productie** | **nee.** `SECURITY_POSTURE_ENABLED` bestaat niet |
| `guards.yml` | ja, en hij meldt de twee hierboven |

De twee die niet kunnen afgaan zijn nu niet meer stil: ze kosten vanaf nu een rode
dagelijkse run en een open issue.

## Aanzetten

De sleutels kan alleen Mick zetten.

```bash
gh secret set PARAMANT_CANARY_KEY
gh secret set PARASIGN_CANARY_KEY
gh variable set HEARTBEAT_ENABLED --body true
gh variable set SECURITY_POSTURE_ENABLED --body true
gh label create guards --description "een waakhond blaft niet" --color B60205
```

Zet de variabele alleen aan als de secrets er zijn. Zet je alleen de variabele,
dan blijft `guards.yml` terecht rood: hij eist een geslaagde run van de job zelf,
niet een aangezette schakelaar. Dat is met opzet, want anders is de waakhond af
te kopen met een vinkje.

## Zelf draaien

```bash
node scripts/check-guards.mjs          # de statische helft, rood op een vondst
node scripts/check-guards.mjs --list   # alles wat hij vond, gedeclareerd of niet
node --test tests/guards-can-fire.test.mjs

GH_TOKEN=$(gh auth token) GITHUB_REPOSITORY=Apolloccrypt/paramant-relay \
  node scripts/guards-live.mjs         # de live helft
```

## Verwant

- [heartbeat.md](heartbeat.md): wat de uurlijkse zelftest bewijst en waarom hij herbouwd is
- [`relay/test/_requires.js`](../relay/test/_requires.js): dezelfde regel, een niveau lager. Een testsuite die zijn voorwaarde niet haalt faalt, tenzij de runner hem bij naam vrijgeeft
- `.github/workflows/test.yml`: de "asserted nothing in this job"-poorten waar dit op voortbouwt
