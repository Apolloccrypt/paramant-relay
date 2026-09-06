# Landen

Werk telt pas als het op `main` staat. Dit bestand legt uit hoe we meten of dat
zo is, welke termijn geldt, en wat de inhaalslag van 5 september 2026 opleverde.
De poort erop is `scripts/check-landen.mjs`, bewaakt door
`tests/landen-poort.test.mjs`.

## Waarom

Op 10 juni 2026 stond `fix/sector-port-drift` klaar. Die tak repareert vier
terugvalpoorten in `admin/server.js`: `relay-health:3005`, `relay-legal:3002`,
`relay-finance:3003` en `relay-iot:3004`, terwijl elke relaycontainer intern op
`3000` luistert (`docker-compose.yml`, `127.0.0.1:300X:3000`). De tak is nooit
gemergd. PR #199 is gesloten zonder merge. Op 5 september 2026 vond een tweede
onderzoek dezelfde fout opnieuw en repareerde hem opnieuw.

Dat is de kostenpost. Niet rommel, niet netheid: wij betalen twee keer om
dezelfde bug te vinden omdat we een keer niet betalen om hem te mergen.

Gemeten op origin op 5 september 2026: 71 takken, waarvan de poort er **64** niet
op main terugvindt en **50** langer dan zeven dagen buiten main. De oudste is 100
dagen. In dezelfde dertig dagen staan er 189 unieke commits op alle takken van
origin en 152 op main, met **nul** merge-commits.

## Hoe we meten of iets geland is

`git branch --merged` is hier onbruikbaar. Deze repo squash-merget: de merge
schrijft een nieuwe commit met een nieuwe hash en gooit de takhistorie weg, dus
git ziet de tak daarna nog steeds als ongemerged terwijl de inhoud er wel in
zit. Wie op `--merged` afgaat telt de hele lijst dubbel. Dat is precies wat er
op 30 augustus gebeurde: 455 ongelande commits gemeld, en dat getal klopte niet.

De poort bepaalt "geland" daarom in vier lagen, van goedkoop naar duur. De
eerste laag die ja zegt, wint, en de meting meldt per tak welke laag dat was.

| laag | test | vangt |
|---|---|---|
| 1. `voorouder` | `git merge-base --is-ancestor <tip> origin/main` | echte merge, fast-forward |
| 2. `pr-merged` | een pull request met deze tak als head staat op MERGED | **squash-merge**, de laag waar het hier om draait |
| 3. `patch-id` | `git cherry origin/main <tip>` geeft alleen `-`-regels | cherry-pick, rebase, en squash van een tak van precies een commit |
| 4. `inhoud` | de netto diff van de tak ten opzichte van zijn merge-base laat zich omgekeerd toepassen op de boom van main | de tak is met de hand overgeschreven, of main is daarna doorgelopen maar de hunks staan er al |

Laag 1, 3 en 4 kunnen alleen ja zeggen, nooit nee. Ze bewijzen dat inhoud er
staat; ze bewijzen niet dat inhoud er niet staat. Geen enkele laag ja betekent
dus **waarschijnlijk ongeland**, en het getal dat de poort noemt is een
bovengrens, geen exact aantal.

Laag 2 is de enige die netwerk nodig heeft. Zonder `gh`, zonder token of zonder
net valt de poort terug op laag 1, 3 en 4 en zegt dat in de kop
(`github-laag uit`). Hij gaat dan niet stuk en hij gaat ook niet stil groen: hij
meldt hooguit iets als ongeland dat via een squash toch geland was, en dat is de
kant waarop een poort hoort te falen. Draai hem met `--geen-github` om die laag
bewust uit te zetten.

Wat overblijft is met de hand na te lopen. `chore/security-retire-leaked-admin-token`
is daar het voorbeeld van: alle vier de lagen zeggen nee, en toch is de inhoud
langs een andere weg allang op main. Zulke gevallen horen in
`landen-uitstel.json` met stapel `in-main-anders`.

## De termijn: zeven dagen

Een tak die ouder is dan zeven dagen en niet geland is, maakt de poort rood.
De knop heet `LANDEN_TERMIJN_DAGEN` en staat standaard op 7.

Zeven dagen, om deze reden: het is de termijn waarbinnen de schrijver van een
reparatie zich hem nog herinnert. Daarna wordt hij niet meer opgepakt maar
opnieuw gevonden, door een tweede paar ogen, en opnieuw geschreven. Tussen 10
juni en 5 september zat precies dat: 87 dagen, twee onderzoeken, twee keer
dezelfde reparatie. De termijn is niet gekozen op netheid maar op het punt
waarop dubbel werk begint. De board zette hem op 30 augustus 2026 al vast; deze
poort is wat hem afdwingt.

De grens staat in `scripts/check-landen.mjs` en is te verzetten met
`LANDEN_TERMIJN_DAGEN`. Verzet hem niet om de poort groen te krijgen. Daar is
de uitstellijst voor, en die heeft datums.

## De uitstellijst

`deploy/landen-uitstel.json` is de enige manier om een tak buiten de termijn
groen te houden. Elke post heeft:

- `tak`: de naam op origin
- `stapel`: `in-main-anders`, `achterhaald` of `waarde`
- `tot`: de datum waarop het uitstel afloopt, JJJJ-MM-DD
- `reden`: waarom, in een zin die iets zegt

Een post waarvan `tot` verstreken is, telt niet meer en de tak wordt weer rood.
Uitstel zonder afloopdatum is afstel, dus dat kan hier niet.

De drie stapels betekenen iets verschillends voor wat je met de datum doet:

- `in-main-anders`: de inhoud staat al op main, de meting kan het alleen niet
  zien. De datum is de dag waarop de tak van origin wordt verwijderd.
- `achterhaald`: de wijziging slaat nergens meer op. De datum is de dag waarop
  de tak van origin wordt verwijderd.
- `waarde`: hier ligt werk dat nog telt. De datum is de dag waarop het geland
  moet zijn, en die dag komt uit de volgorde in `landen-inhaalslag.md`.

## De inhaalslag

De volledige triage van 5 september 2026, met per tak de stapel, de
onderbouwing en de volgorde waarin het waardevolle werk geland moet worden,
staat in `deploy/landen-inhaalslag.md`.

## Draaien

```
node scripts/check-landen.mjs             # tabel, exitcode 1 als er iets rood is
node scripts/check-landen.mjs --json      # dezelfde meting als JSON
node scripts/check-landen.mjs --geen-github   # zonder laag 2
node --test tests/landen-poort.test.mjs   # de poort op de poort
```

De poort leest `refs/remotes/origin/*`. Een ondiepe of gefilterde clone ziet
minder takken dan er zijn, dus haal ze eerst binnen:

```
git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*'
```
