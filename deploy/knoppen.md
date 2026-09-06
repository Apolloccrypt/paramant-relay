# Elke knop op een plek

Wat het gedrag van Paramant verandert staat hier, of in `deploy/.env.example`. Nergens anders.

- **99 omgevingsvariabelen** die de relay en de admin lezen staan in
  [`.env.example`](.env.example), met per naam een uitleg en een `read in:`-regel.
  `tests/env-documented.test.mjs` bewaakt dat bestand en faalt als een naam er niet in staat.
- **176 knoppen** staan hieronder: alles wat die poort niet ziet.
  `tests/knoppen-compleet.test.mjs` bewaakt deze pagina op dezelfde manier.

Samen zijn dat twee bestanden. Dat is een meer dan een, en de reden is dat `.env.example`
al bestaat, al bewaakt wordt en al gebruikt wordt om een `.env` mee te vullen. Deze pagina
herhaalt hem niet, hij vult hem aan.

Gemeten op 2026-09-05. Bevindingen zijn gelabeld: *bevestigd* als ik de bron zag,
*waarschijnlijk* als ik hem afleidde, *vermoeden* als hij nog te toetsen is.

## Waarom deze pagina bestaat

Vijf dingen die in een nacht boven kwamen, en die geen van alle in een lijst stonden.

1. Een geheugengrens van 5 MB, vijf keer los opgeschreven in de relay en nog eens drie keer
   in de browser en de extensie. Een ervan is instelbaar, de rest niet. Wie `MAX_BLOB`
   verhoogt, verhoogt vier van de acht.
2. Een grens per bestand die de opvulgrootte bleek te zijn. `PADDED_BLOCK` in de extensie
   is echt een blok; `MAX_BLOB` in de relay is echt een grens; ze zijn allebei 5 MB en ze
   staan nergens naast elkaar. *Bevestigd:* er wordt in de relay niets opgevuld, ondanks
   wat `/health` erover zegt (`relay/relay.js:3177`, `padding: '5MB fixed (DPI-masking)'`).
3. Een nginx-limiet die nergens in de repo stond. *Bevestigd door meting:* productie
   accepteert 10485760 bytes en weigert 10486000 met een 413 van nginx, op alle vijf de
   hosts. Geen enkel bestand in deze repo zegt `10m`. De conf die de vijf hosts bedient
   zet helemaal geen `client_max_body_size` (zie de nginx-tabel), en nginx valt dan stil
   terug op zijn eigen 1 MB. De 10 MB komt dus van een http-blok op de server zelf,
   buiten git. *Waarschijnlijk:* dat is met de hand ingetypt, net als de vijf
   `limit_req_zone`-regels waarvoor `deploy/nginx/snippets/paramant-limit-req.conf` in
   dezelfde situatie is aangelegd.
4. Een schakelaar voor de zelftest die uit stond. `HEARTBEAT_ENABLED` is een
   repository-variabele die niet bestaat, dus het uurlijkse `cron` draait, slaat de taak
   over, en de run kleurt groen.
5. Vijf relays met elk een eigen instelling, waarvan drie nooit iets deden. Zie
   de meting van 5 september: vijf relays, een echte.

## Wat stil terugvalt

De gevaarlijkste knop is de knop die je niet hoort als hij ontbreekt. Deze doen dat.

| knop | waar | wat er stil gebeurt |
|---|---|---|
| `client_max_body_size` | `nginx-selfhost.conf`, `deploy/nginx/addin.paramant.app.conf` | nginx neemt zijn eigen 1 MB, zonder waarschuwing. Dit is hoe de limiet onzichtbaar werd. `deploy/nginx-paramant-public.conf` had hem tot d8bf7a71 ook niet en zet nu 12M |
| `HEARTBEAT_ENABLED` | `.github/workflows/heartbeat.yml:56` | de variabele bestaat niet, de taak slaat over, de run is groen |
| `FLEET_LIVE` | `tests/verify-knows-the-fleet.test.mjs:320` | de test die de gepinde sleutels tegen de live relays houdt, staat in geen enkele workflow en heeft dus nooit gedraaid |
| `CLEVERBASE_SANDBOX` | `tests/qes-cleverbase-live.test.mjs:31` | de hele QES-suite slaat over, overal |
| `RELAY_SELF_URL` | `relay/relay.js:114` | `registerSelf()` keert meteen terug, zonder logregel. Federatie is uit en niets zegt het |
| `RELAY_PRIMARY_URL` | `relay/relay.js:115` | valt terug op `http://localhost:PORT`: de relay meldt zich bij zichzelf aan over loopback en logt dat als succes |
| `RELAY_MODE` | `relay/relay.js:108` en `:109` | afwezig betekent `full`, ongeldig betekent `ghost_pipe`. De setup-wizard schrijft `RELAY_MODE=domain`, wat ongeldig is: na de eerstvolgende herstart staat de relay in `ghost_pipe` |
| `PARASIGN_STORE_KEY` | `relay/relay.js:1620` | een waarschuwing bij het opstarten, daarna een opslag in het geheugen; getekende documenten verdwijnen bij elke herstart |
| `REDIS_URL` | `relay/relay.js:85` | geen client, alles valt terug op maps in het proces; de vlootbrede limiet wordt per container |
| `CT_FILE` | `relay/relay.js:361` | het transparantielog staat alleen in het geheugen en is bij een herstart weg; `CT_MAX_SIZE` wordt daarmee dode configuratie |
| `INTERNAL_AUTH_TOKEN` | `admin/server.js:515` | de admin stuurt een lege `X-Internal-Auth` mee en wordt door de relay geweigerd; `ADMIN_TOKEN` ernaast stopt het proces wel |
| `MONEYBIRD_TOKEN` | `relay/lib/moneybird.js:140` | de planner start niet, er komt geen timer en geen logregel |
| `PARASIGN_QES_PROVIDER` | `relay/lib/qes/index.js:26` | een typefout wordt tot leeg gemaakt en zet QES uit in plaats van te klagen |
| `QES_TSA_URL=""` | `relay/lib/qes/index.js:129` | de test is `!== undefined`, dus een lege waarde zet tijdstempels uit in plaats van terug te vallen |
| `AUDIT_RETENTION_DAYS=0` | `admin/lib/audit.js:10` | ongecontroleerde `parseInt`: de eerstvolgende schrijfactie wist het hele auditlog |
| `RESEND_API_KEY` | `relay/relay.js:1740`, `admin/server.js:86` | elke mail geeft stil `false`; een aanmelding die zijn bevestigingslink nooit verstuurt ziet er geslaagd uit |

## Wat op twee plekken staat

*Bevestigd, alle regels nagelopen in de bron.*

| waarde | plek A | plek B | staat het uiteen? |
|---|---|---|---|
| 5 MB | `MAX_BLOB` `relay/relay.js:105` | `BLOB_SIZE_MB` `:1339`, `ANON_MAX` `:5360`, `TRIAL_MAX_SIZE` `:5545`, `tiers.js:47,56,65`, `parashare.page.js:829`, `paramant-core.js:30` | acht kopieen, een instelbaar |
| sector naar poort | `admin/server.js:39-45` (alle vijf 3000) | `docker-compose.yml:311-315` (alle vijf 3000) | nee, gepind door `tests/sector-fallback-ports.test.mjs` |
| `RELAY_HEALTH` | `admin/server.js:41` → `:3000` | de compose-listener staat op 3000 | nee, rechtgezet; stond op `:3005`, een poort die nergens in de repo bestaat |
| `nginx-selfhost.conf` | de kopie in de wortel: geen bodygrens, `inbound` 10r/m | `deploy/nginx-selfhost.conf`: 35M, `inbound` 5r/m | **ja, twee bestanden met dezelfde naam** |
| `install.sh` | de kopie in de wortel, 535 regels | `frontend/install.sh`, 466 regels, dit is de kopie die op paramant.app staat | **ja, 111 regels verschil** |
| admin-paneel JS | `admin/public/app.js`, 895 regels | `frontend/js/admin.page.js`, 742 regels | **ja, 343 regels verschil** |
| versie | `deploy/deploy-3.1.sh:121` `3.1.0` | `install.sh:24` `v3.0.0`, `.env.example` `v3.0.0` | **ja** |
| standaardwaarden | `admin/lib/config-schema.js` (25 sleutels) | `deploy/.env.example` | **ja, drie**, zie de tabel afwijkingen |
| MFA-vertraging 10 / 300000 | `relay/lib/auth-throttle.js:24,26` | `admin/lib/login-ratelimit.js:150-152` | nee, gepind door `tests/redis-deadline-parity.test.mjs` |
| tarieftabel | `relay/lib/tiers.js` | `frontend/js/quota-upgrade.js:54-57` | nee, gepind door `relay/test/quota-upgrade-render.test.js` |
| tarieven in proza | dezelfde getallen | `frontend/pricing.html:278,469,490`, `admin/server.js:95` | **ja, niet gepind** |
| planwoordenschat | `admin/lib/cli-commands.js:60` `free\|pro\|enterprise` | overal elders `community\|pro\|business\|enterprise` | **ja** |
| ondertekenrelay | `sign-flow.js:23`, `co-sign.js:25` → health | `parasign-verify.js:10` → relay | **ja, tekenen en controleren wijzen naar verschillende relays** |
| 1000 ms | `DEFAULT_DEADLINE_MS` `redis-deadline.js:59` | de functie ernaast geeft een los getypte `1000`, en `totp.js:120` een derde | **ja, de geexporteerde constante is niet degene die gebruikt wordt** |

## Wat in productie staat, publiek vastgesteld

*Bevestigd, zelf gemeten op 2026-09-05 vanaf buiten. Productie is niet aangeraakt.*

| knop | gemeten waarde | hoe |
|---|---|---|
| versie | `3.1.0` op alle vijf | `/health` |
| edition | `licensed`, op naam van paramant.app, tot 2027-01-01 | `/health` |
| `SECTOR` | `relay`, `health`, `legal`, `finance`, `iot` | `/health` |
| nginx bodygrens | **10485760 bytes**, identiek op alle vijf | POST van 10485760 geeft 405, van 10486000 een 413 met `server: nginx` |
| voorschakeling | er staat een Caddy voor nginx | `via: 1.1 Caddy` in de antwoordkop |
| `limit_req` op `/health` | geen | veertig verzoeken achter elkaar, alle veertig 200 |
| `MAX_BLOB` | niet vast te stellen | de sleutelcontrole komt voor de groottecontrole; `/v2/inbound` geeft 401 voor elke bodygrootte |

## Omgevingsvariabelen buiten `relay/` en `admin/`

`tests/env-documented.test.mjs` leest alleen die twee mappen. Deze worden gelezen in
`frontend/`, `scripts/`, `tests/`, `extensions/`, `monitoring/`, `bron-seo/` en
`crypto-wasm/`, en staan in geen enkel `.env.example`.

<!-- knoppen:env-buiten -->

| naam | gelezen in | standaard | wat hij doet |
|---|---|---|---|
| `ADMIN_URL` | `scripts/dev-local-proxy.js` | `'http://127.0.0.1:4200'` | waar de dev-proxy de admin zoekt |
| `APP_SHOTS_ONLY` | `scripts/app-shots.mjs` | geen | beperkt de schermafdrukronde tot de app-paginas |
| `CHECK_EXTERNAL_LINKS` | `tests/links.test.mjs` | geen | zet de externe-linkcontrole aan; staat alleen aan in heartbeat.yml, en die workflow is uit |
| `CLEVERBASE_SANDBOX` | `tests/qes-cleverbase-live.test.mjs` | `test op '1'` | zet de live QES-suite aan; staat in geen enkele workflow, draait dus nergens |
| `DEV_PORT` | `scripts/dev-local-proxy.js` | `'8080'` | poort van de dev-proxy |
| `FAKE_MOLLIE_URL` | `tests/helpers/mollie-intercept.cjs` | geen | stuurt https-verkeer naar api.mollie.com door naar de nagebouwde Mollie van de koperspoort; leeg (productie) doet de preload niets |
| `FAKE_RESEND_URL` | `tests/helpers/mollie-intercept.cjs` | geen | zelfde omleiding voor api.resend.com, zodat een test de facturen en waarschuwingsmails kan lezen die anders ongezien vertrekken |
| `FLEET_LIVE` | `tests/verify-knows-the-fleet.test.mjs` | geen | zet de test aan die de gepinde sleutels tegen de live relays houdt; staat in geen enkele workflow, draait dus nergens |
| `GH_TOKEN` | `scripts/guards-live.mjs` | valt terug op `GITHUB_TOKEN`, dan leeg | token waarmee de waarborgcontrole de GitHub-API leest |
| `GITHUB_OUTPUT` | `scripts/guards-live.mjs` | geen | pad waar de waarborgcontrole zijn uitkomst voor de workflow neerlegt; ontbreekt hij, dan schrijft hij niets en meldt dat niet |
| `GITHUB_REPOSITORY` | `scripts/guards-live.mjs` | `'Apolloccrypt/paramant-relay'` | welke repo de waarborgcontrole bekijkt |
| `GITHUB_TOKEN` | `scripts/guards-live.mjs` | `''` | de terugval van `GH_TOKEN` |
| `GUARDS_ENFORCE` | `scripts/guards-live.mjs` | geen, test op `'1'` | zonder deze meldt de waarborgcontrole een stille waarborg wel, maar kleurt de taak niet rood |
| `GITHUB_RUN_ID` | `scripts/heartbeat/lib.mjs`, `scripts/heartbeat/run.mjs` | geen | runnummer in het heartbeat-bewijs |
| `GITHUB_SHA` | `scripts/heartbeat/lib.mjs` | geen | commit in het heartbeat-bewijs |
| `GITHUB_STEP_SUMMARY` | `scripts/heartbeat/run.mjs` | geen | pad waar de heartbeat zijn samenvatting schrijft |
| `HEARTBEAT_DRY_RUN` | `scripts/heartbeat/lib.mjs` | `test op '1'` | heartbeat meet wel, meldt niet |
| `HEARTBEAT_EVIDENCE_DIR` | `scripts/heartbeat/lib.mjs` | `'heartbeat-evidence'` | map waar het heartbeat-bewijs landt |
| `HEARTBEAT_SLOW_MS` | `scripts/heartbeat/lib.mjs` | `2500` | drempel waarboven een heartbeat-stap traag heet |
| `HEARTBEAT_SLOW_SIGN_MS` | `scripts/heartbeat/lib.mjs` | `15000` | zelfde drempel, maar voor het tekenpad |
| `HEARTBEAT_TEST_SECRET` | `tests/heartbeat-lib.test.mjs` | geen | fixture, wordt door de test zelf gezet en weer weggehaald |
| `KOPER_REDIS_DB` | `tests/helpers/koper-stack.cjs` | `11` | welke redisdatabase de koperspoort gebruikt en als enige leegt, zodat hij een server kan delen met de routesuites zonder hun sleutelruimte te raken |
| `LANDEN_GEEN_GITHUB` | `scripts/check-landen.mjs` | geen, test op `'1'` | zet laag 2 (pull requests) van de landingspoort uit; hij draait dan op git alleen en meldt hooguit te streng |
| `LANDEN_MAIN` | `scripts/check-landen.mjs` | `'origin/main'` | waartegen de landingspoort meet |
| `LANDEN_ROOT` | `scripts/check-landen.mjs` | de repowortel | welke repo de landingspoort meet; `tests/landen-poort.test.mjs` wijst hem hiermee naar een wegwerp-repo |
| `LANDEN_TERMIJN_DAGEN` | `scripts/check-landen.mjs` | `7` | hoeveel dagen een tak ongeland mag blijven voordat de poort rood wordt; verzet hem niet om groen te worden, daar is `deploy/landen-uitstel.json` voor |
| `PARAMANT_BASE_URL` | `scripts/heartbeat/lib.mjs`, `tests/links.test.mjs` en 1 meer | `'https://paramant.app'` | welke site de heartbeat en de linkcontrole meten |
| `PARAMANT_COSIGN_SCREENSHOT_PATH` | `tests/cosign-document-delivery.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_DASHBOARD_DETAIL_SCREENSHOT_PATH` | `tests/user-dashboard-documents.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_DASHBOARD_SCREENSHOT_PATH` | `tests/user-dashboard-documents.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_FRONTEND` | `scripts/ui-contrast-sweep.mjs` | geen | welke frontendmap de contrastveger leest |
| `PARAMANT_HOME_IN_SCREENSHOT_DIR` | `tests/signed-in-home.test.mjs` | `''` | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_HOME_SCREENSHOT_PATH` | `tests/navigation-shell.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_INTERNAL_AUTH_TOKEN` | `scripts/heartbeat/surface.mjs` | `''` | zonder dit token bewijst de heartbeat alleen dat de diepe gezondheidspoort dicht zit, niet wat erachter zit; ontbreekt in de repo-secrets |
| `PARAMANT_OPERATOR_IPS` | `scripts/access-log-visitors.mjs` | `''` | welke IP-adressen niet als bezoeker tellen in de toegangslogtelling |
| `PARAMANT_PLACE_SHOT_DIR` | `tests/sign-place-toolbar.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_RELAY_URL` | `scripts/heartbeat/lib.mjs` | `'https://relay.paramant.app'` | welke relay de heartbeat aanspreekt |
| `PARAMANT_SCREENSHOT_PATH` | `tests/developer-parasign-dashboard.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_SETTINGS_SCREENSHOT_PATH` | `tests/navigation-shell.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_SIGN_SCREENSHOT_PATH` | `tests/sign-invite-delivery.test.mjs` | geen | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `PARAMANT_SWEEP_PROGRESS` | `scripts/ui-contrast-sweep.mjs` | geen | voortgangsregels tijdens de contrastveger |
| `PLAYWRIGHT_CHROMIUM_PATH` | `scripts/shot-dashboard.mjs`, `scripts/ui-contrast-sweep.mjs` en 35 meer | geen | pad naar de browser voor elke Playwright-test |
| `RECEIPT_SHOTS_DIR` | `tests/receipt-verify.test.mjs` | `''` | pad waar een test zijn schermafdruk neerzet; leeg betekent geen afdruk |
| `RELAY_URL` | `scripts/dev-local-proxy.js` | `'http://127.0.0.1:3001'` | waar de dev-proxy de relay zoekt |
| `SHOT_LABEL` | `scripts/shot-dashboard.mjs` | geen | label onder een schermafdruk |
| `TMPDIR` | `tests/parasend-send-a-link.test.mjs` | `'/tmp'` | werkdir voor een tijdelijk bestand in de test |

## Knoppen in de schelp

De vorm `${VAR:-standaard}` in `deploy/` en `scripts/`: alles wat een operator kan
overschrijven zonder de code aan te raken.

<!-- knoppen:shell -->

| naam | gelezen in | standaard | wat hij doet |
|---|---|---|---|
| `BACKUP_DIR` | `scripts/cli/paramant-backup.sh`, `scripts/rollback-3.0.0.sh` | `/var/log/paramant/backups` / `/home/paramant/backups` | back-upmap van de relay-CLI en van het terugrolscript |
| `BACKUP_ROOT` | `deploy/ops/backup-full-state.sh`, `deploy/ops/restore-full-state.sh` | `/home/paramant/backups/full-state` / `$WORK` | waar de volledige-staatback-up landt |
| `CASE` | `scripts/paramant-legal.sh` | `untagged` | dossiernummer in het juridische script |
| `COMPOSE_CMD` | `scripts/cli/paramant-logs.sh`, `scripts/cli/paramant-restart.sh` | `docker compose` | welk compose-commando de CLI gebruikt |
| `COMPOSE_DIR` | `scripts/rollback-3.0.0.sh` | `/home/paramant/app` | waar het terugrolscript het compose-bestand zoekt; wijkt af van het deployscript |
| `CONFIRM` | `install.sh` | `Y` | slaat de bevestigingsvraag van de installateur over |
| `DEPLOY_REF` | `deploy/deploy-3.1.sh` | `origin/main` | welke tak de deploy uitrolt |
| `DEV_EMAIL` | `scripts/dev-local.sh` | `dev@localhost` | welk adres de lokale ontwikkelstack aanmaakt |
| `DISPLAY` | `install.sh` | leeg | omgevingsherkenning, geen Paramant-knop |
| `DOMAIN` | `deploy/docker-entrypoint.sh`, `install.sh` | `localhost` | domein in de nginx-entrypoint van een container die niet in compose staat |
| `DRYRUN_OUT` | `deploy/ops/backup-full-state.sh` | `$WORK/out` | waar een proefback-up naartoe schrijft |
| `EXPECT_PROD_COMMIT` | `deploy/deploy-3.1.sh` | `41501bb` | de vaste startcommit uit het draaiboek, gebruikt als er geen marker is |
| `FLAKY_WATCH_REPEATS` | `scripts/flaky-watch.sh` | `3` | hoe vaak de bouwstraat de route-suites herhaalt om een wisselvallige test te laten zien |
| `GITHUB_ACTIONS` | `scripts/check-test-declarations.sh` | leeg | omgevingsherkenning, geen Paramant-knop |
| `HEALTH_URL` | `scripts/rollback-3.0.0.sh` | `http://127.0.0.1:3000/health` | welke URL het terugrolscript als gezond beschouwt |
| `KEYFILE` | `deploy/ops/backup-full-state.sh`, `deploy/ops/restore-full-state.sh` | `/root/.config/paramant-backup/key.txt` | sleutelbestand waarmee de back-up versleuteld wordt |
| `KNOWN_FLAKY_MAX_DAYS` | `scripts/check-flaky-register.sh` | `14` | hoeveel dagen een regel in `tests/known-flaky.tsv` mag blijven staan voor hij zelf een fout wordt |
| `LATEST_ENV` | `scripts/rollback-3.0.0.sh` | leeg | welk env-bestand het terugrolscript terugzet |
| `LC_ALL` | `scripts/check-commit-style.sh` | `C.UTF-8` | omgevingsherkenning, geen Paramant-knop |
| `LE_EMAIL` | `install.sh` | `(n/a in localhost mode)` | adres voor Let's Encrypt |
| `LOG` | `deploy/deploy-3.1.sh`, `deploy/ops/backup-full-state.sh` | `<none>` / `/var/log/paramant-backup.log` | logbestand van de deploy en van de back-up |
| `MANIFEST` | `scripts/rollback-3.0.0.sh` | leeg | manifest dat het terugrolscript leest |
| `MNT` | `scripts/paramant-export.sh` | `(not mounted)` | koppelpunt in het exportscript |
| `MOUNTED_AT` | `scripts/paramant-export.sh` | leeg | waar het exportscript denkt gekoppeld te zijn |
| `NATS_MONITOR_URL` | `scripts/cli/paramant-nats-status.sh` | `http://nats:8222` | waar de NATS-status wordt opgehaald |
| `PARAMANT_API_KEY` | `scripts/paramant-cra.sh`, `scripts/paramant-firmware.sh` en 5 meer | `$(python3 -c "import json; print(json.load(open('${CFG` | sleutel voor de losse sectorscripts |
| `PARAMANT_APP` | `scripts/security/audit.sh` | `https://paramant.app` | welke site het beveiligingsauditscript meet |
| `PARAMANT_BACKUP_DIR` | `deploy/deploy-3.1.sh` | `/home/paramant/backups` | waar de deploy zijn back-ups zet |
| `PARAMANT_BACKUP_SOURCES` | `deploy/ops/backup-full-state.sh` | leeg | welke paden de volledige-staatback-up meeneemt |
| `PARAMANT_CI_WAIT_SECONDS` | `deploy/deploy-3.1.sh` | `900` | hoe lang de deploy op een lopende CI wacht |
| `PARAMANT_COMPOSE_DIR` | `deploy/deploy-3.1.sh` | `/opt/paramant-relay` | waar het compose-bestand op de server staat |
| `PARAMANT_DEPLOYED_HEAD_FILE` | `deploy/deploy-3.1.sh` | `$BACKUP_DIR/deployed-head` | het bestand waarin de deploy zijn eigen commit vastlegt |
| `PARAMANT_DIR` | `install.sh` | `/opt/paramant` | installatiemap van de zelf-installateur |
| `PARAMANT_DOCROOT` | `deploy/deploy-3.1.sh`, `scripts/check-prod-drift.sh` | `/home/paramant/app` | waar de frontend op de server staat |
| `PARAMANT_DOMAIN` | `install.sh` | `${1:-` | domein waarvoor de installateur een certificaat vraagt |
| `PARAMANT_EXPECTED_HEAD` | `deploy/deploy-3.1.sh` | leeg | welke commit op de server verwacht wordt voor de deploy begint |
| `PARAMANT_LIMIT_REQ_DEST` | `deploy/deploy-3.1.sh` | `/etc/nginx/conf.d/paramant-limit-req.conf` | waar het snelheidslimiet-snippet heen gaat |
| `PARAMANT_NGINX_CONFS` | `deploy/deploy-3.1.sh` | `paramant-public.conf paramant-live.conf\|paramant.conf` | welke nginx-bestanden op de server het deployscript patcht |
| `PARAMANT_PRIMARY` | `scripts/paramant-scan.sh` | `https://health.paramant.app` | welke relay het scanscript als hoofdrelay neemt |
| `PARAMANT_PROD_HOST` | `deploy/deploy-3.1.sh`, `scripts/check-prod-drift.sh` | staat in `deploy/deploy-3.1.sh:46` | de productieserver waar het deployscript op inlogt; het adres staat hardgecodeerd in het script en wordt hier niet herhaald |
| `PARAMANT_PROD_KEY` | `deploy/deploy-3.1.sh`, `scripts/check-prod-drift.sh` | `$HOME/.ssh/paramant_prod_claude` | de ssh-sleutel voor die server |
| `PARAMANT_RECEIVER` | `scripts/paramant-firmware.sh`, `scripts/paramant-ticket.sh` | `paramant-receiver` | ontvangeridentiteit in de sectorscripts |
| `PARAMANT_RELAY` | `scripts/security/audit.sh` | `https://relay.paramant.app` | welke relay datzelfde script meet |
| `PARAMANT_REPO` | `scripts/security/audit.sh` | `$HOME/paramant-relay` | welke repo dat script leest |
| `PARAMANT_REQUIRED_WORKFLOWS` | `deploy/deploy-3.1.sh` | `test.yml csp-inline-check.yml sign-e2e.yml product-heartbeat` | welke CI-workflows groen moeten zijn voor de deploy start |
| `PARAMANT_SENDER` | `scripts/paramant-cra.sh`, `scripts/paramant-firmware.sh` en 5 meer | `paramant-sender` | afzenderidentiteit in de sectorscripts |
| `PARAMANT_SMOKE_API_KEY` | `deploy/deploy-3.1.sh` | leeg | sleutel voor de rooktest na de deploy |
| `PARAMANT_TMPDIR` | `scripts/paramant-cra.sh`, `scripts/paramant-crypto-audit.sh` en 3 meer | `/run/paramant-tmp` | werkmap van de sectorscripts |
| `PARAMANT_VERIFY_HEAD` | `deploy/deploy-3.1.sh` | leeg | welke commit --verify-only controleert |
| `PARAMANT_VERIFY_HTTP_RETRIES` | `scripts/post-deploy-verify.sh` | `1` | hoe vaak de nacontrole een HTTP-meting herhaalt |
| `PARAMANT_VERIFY_HTTP_RETRY_DELAY` | `scripts/post-deploy-verify.sh` | `3` | seconden tussen die herhalingen |
| `POSTURE_CURL` | `scripts/security/posture.sh` | `curl` | vervangt curl in de beveiligingsmeting; de zelftest zet er een stub voor in de plaats |
| `POSTURE_CURL_TIMEOUT` | `scripts/security/posture.sh` | `20` | hoe lang die meting op een antwoord wacht |
| `POSTURE_DIG` | `scripts/security/posture.sh` | `dig` | idem voor dig |
| `POSTURE_NPM` | `scripts/security/posture.sh` | `npm` | idem voor npm |
| `POSTURE_OPENSSL` | `scripts/security/posture.sh` | `openssl` | idem voor openssl |
| `PREV_HEAD` | `deploy/deploy-3.1.sh` | `$EXPECT_PROD_COMMIT` | de commit waar naar terug wordt gerold |
| `REDIS_CONTAINER` | `deploy/ops/backup-full-state.sh`, `deploy/ops/restore-full-state.sh` | `paramant-relay-redis` | welke container de back-up als Redis beschouwt |
| `REDIS_SRC_DIR` | `deploy/ops/backup-full-state.sh` | leeg | waar de Redis-bestanden vandaan komen |
| `REGISTRY` | `scripts/paramant-cra.sh` | `none` | containerregister in het CRA-script |
| `RELAY_FILTER` | `deploy/ops/backup-full-state.sh` | `relay` | op welke naam de back-up relay-containers herkent |
| `RELAY_LOCAL` | `scripts/post-deploy-verify.sh` | `<not provided>` | lokale relay-URL voor de nacontrole; zonder deze slaat de diepe gezondheidscontrole over |
| `RELAY_SECTORS` | `scripts/cli/paramant-doctor.sh`, `scripts/cli/paramant-relay-list.sh` | `primary=${RELAY_URL:-http://localhost:3000` | sectorlijst voor de relay-CLI |
| `RELAY_URL` | `scripts/cli/paramant-audit-recent.sh`, `scripts/cli/paramant-backup.sh` en 4 meer | `http://localhost:3000` | nog niet beschreven |
| `RETAIN_DAYS` | `deploy/ops/backup-full-state.sh` | `30` | hoe lang back-ups blijven staan |
| `SBOM` | `scripts/paramant-cra.sh` | `none` | pad naar de stuklijst in het CRA-script |
| `SECTORS_INPUT` | `install.sh` | `health legal finance iot` | welke sectoren de installateur vraagt; het antwoord wordt nergens gebruikt, compose start altijd alle vijf |
| `VERSION_ID` | `install.sh` | leeg | omgevingsherkenning, geen Paramant-knop |
| `WAYLAND_DISPLAY` | `install.sh` | leeg | omgevingsherkenning, geen Paramant-knop |
| `XTERM_VERSION` | `scripts/paramant-update-vendor.sh` | `5` | omgevingsherkenning, geen Paramant-knop |

## nginx

Zeven conf-bestanden. **Geen enkel script installeert er een**, op
`deploy/nginx/snippets/paramant-limit-req.conf` na: `deploy/deploy-3.1.sh` fase 5c patcht
de bestanden die al op de server staan, met `awk` en `sed` op ankerregels. De confs in
deze repo zijn dus een verslag en geen bron. *Bevestigd:* het enige `cp` van een conf in
het hele deployscript is een back-up (`deploy/deploy-3.1.sh:1775`).

`afwezig` is hier een waarde en geen leegte. Een ontbrekende `client_max_body_size` laat
nginx zonder een woord op zijn eigen 1 MB terugvallen, en dat is precies de stilte die
deze regels doorbreken.

<!-- knoppen:nginx -->

| bestand | richtlijn | waarde |
|---|---|---|
| `deploy/nginx-paramant-live.conf` | `client_max_body_size` | `4k / 64k / 16k / 16k / 50M / 30M / 12M / 35M / 12M / 12M / 12M` |
| `deploy/nginx-paramant-live.conf` | `limit_req_zone` | `afwezig` |
| `deploy/nginx-paramant-live.conf` | `limit_conn` | `afwezig` |
| `deploy/nginx-paramant-live.conf` | `proxy_read_timeout` | `3600s / 3600s / 3600s / 3600s / 3600s` |
| `deploy/nginx-paramant-live.conf` | `client_body_timeout` | `afwezig` |
| `deploy/nginx-paramant-public.conf` | `client_max_body_size` | `12M / 12M / 12M / 12M / 12M / 12M` |
| `deploy/nginx-paramant-public.conf` | `limit_req_zone` | `afwezig` |
| `deploy/nginx-paramant-public.conf` | `limit_conn` | `afwezig` |
| `deploy/nginx-paramant-public.conf` | `proxy_read_timeout` | `3600s / 3600s / 3600s / 3600s / 3600s / 30s / 3600s / 3600s / 3600s` |
| `deploy/nginx-paramant-public.conf` | `client_body_timeout` | `300s` |
| `deploy/nginx-selfhost.conf` | `client_max_body_size` | `35M / 35M` |
| `deploy/nginx-selfhost.conf` | `limit_req_zone` | `$binary_remote_addr zone=inbound:10m rate=5r/m / $binary_remote_addr zone=pubkey:10m rate=20r/m / $binary_remote_addr zone=auth:10m rate=10r/m / $binary_remote_addr zone=api:10m rate=60r/m / $binary_remote_addr zone=health_chk:10m rate=6r/m / $binary_remote_addr zone=sign_dpa:1m rate=3r/m` |
| `deploy/nginx-selfhost.conf` | `limit_conn` | `conn 20` |
| `deploy/nginx-selfhost.conf` | `proxy_read_timeout` | `10s / 10s / 3600s / 30s / 30s / 15s / 30s / 10s / 30s / 3600s` |
| `deploy/nginx-selfhost.conf` | `client_body_timeout` | `60s` |
| `deploy/nginx/addin.paramant.app.conf` | `client_max_body_size` | `afwezig` |
| `deploy/nginx/addin.paramant.app.conf` | `limit_req_zone` | `afwezig` |
| `deploy/nginx/addin.paramant.app.conf` | `limit_conn` | `afwezig` |
| `deploy/nginx/addin.paramant.app.conf` | `proxy_read_timeout` | `afwezig` |
| `deploy/nginx/addin.paramant.app.conf` | `client_body_timeout` | `afwezig` |
| `deploy/nginx/snippets/paramant-limit-req.conf` | `client_max_body_size` | `afwezig` |
| `deploy/nginx/snippets/paramant-limit-req.conf` | `limit_req_zone` | `$binary_remote_addr zone=relay_auth:10m rate=10r/m / $binary_remote_addr zone=api:10m rate=60r/m / $binary_remote_addr zone=relay_inbound:10m rate=5r/m / $binary_remote_addr zone=relay_outbound:10m rate=60r/m / $binary_remote_addr zone=relay_trial:1m rate=3r/m` |
| `deploy/nginx/snippets/paramant-limit-req.conf` | `limit_conn` | `afwezig` |
| `deploy/nginx/snippets/paramant-limit-req.conf` | `proxy_read_timeout` | `afwezig` |
| `deploy/nginx/snippets/paramant-limit-req.conf` | `client_body_timeout` | `afwezig` |
| `deploy/nginx/snippets/paramant-security-headers.conf` | `client_max_body_size` | `afwezig` |
| `deploy/nginx/snippets/paramant-security-headers.conf` | `limit_req_zone` | `afwezig` |
| `deploy/nginx/snippets/paramant-security-headers.conf` | `limit_conn` | `afwezig` |
| `deploy/nginx/snippets/paramant-security-headers.conf` | `proxy_read_timeout` | `afwezig` |
| `deploy/nginx/snippets/paramant-security-headers.conf` | `client_body_timeout` | `afwezig` |
| `nginx-selfhost.conf` | `client_max_body_size` | `afwezig` |
| `nginx-selfhost.conf` | `limit_req_zone` | `$binary_remote_addr zone=inbound:10m rate=10r/m / $binary_remote_addr zone=api:10m rate=60r/m / $binary_remote_addr zone=health:10m rate=6r/m` |
| `nginx-selfhost.conf` | `limit_conn` | `conn 20` |
| `nginx-selfhost.conf` | `proxy_read_timeout` | `10s / 3600s / 3600s` |
| `nginx-selfhost.conf` | `client_body_timeout` | `afwezig` |

## Constanten die instellingen zijn

Een getal dat bepaalt wat het product doet is een instelling, of hij nu uit de omgeving
te veranderen is of niet. Deze zijn gepind op bestand, naam, waarde en aantal: `x3` betekent dat het getal op
drie regels hoort te staan. Verander er een zonder deze pagina bij te werken en de
controle valt om.

<!-- knoppen:constanten -->

| bestand | naam | waarde | wat hij doet |
|---|---|---|---|
| `relay/relay.js` | `MAX_BLOB` | `5242880` | de enige instelbare bovengrens per blob, 5 MB; niet in enige compose environment-blok, dus in productie altijd deze |
| `relay/relay.js` | `readBody` | `MAX_BLOB * 2` | de werkelijke globale body-grens, 10 MB; afgeleid, niet los instelbaar |
| `relay/relay.js` | `BLOB_SIZE_MB` | `5 x2` | de RAM-bewaking rekent met 5 MB per slot; verhoog MAX_BLOB en deze blijft staan |
| `relay/relay.js` | `ANON_MAX` | `5 * 1024 * 1024` | eigen 5 MB voor de anonieme route, niet van MAX_BLOB afgeleid |
| `relay/relay.js` | `TRIAL_MAX_SIZE` | `5 * 1024 * 1024` | eigen 5 MB voor de proefroute, niet van MAX_BLOB afgeleid |
| `relay/lib/tiers.js` | `file_mb` | `: 500, x3` | de tarieftabel verkoopt 500 MB per bestand; sinds d8bf7a71 is dit bewust niet meer hetzelfde getal als MAX_BLOB, en het bestand zegt dat er zelf bij |
| `frontend/js/parashare.page.js` | `LINK_MAX_BLOB` | `5 * 1024 * 1024` | dezelfde 5 MB, nu in de browser |
| `extensions/shared/paramant-core.js` | `PADDED_BLOCK` | `5 * 1024 * 1024` | hier is 5 MB wel een blokgrootte en geen grens; dit is de opvulling |
| `relay/lib/qes/pades.js` | `DEFAULT_CONTENTS_BYTES` | `16384` | de echte reserveringsgrootte in het PDF-handtekeningveld; geen grens |
| `relay/lib/parasign-open-api.js` | `PARASIGN_MAX_PDF_BYTES` | `20 * 1024 * 1024` | 20 MB voor de v1-PDF, boven de 10 MB die readBody doorlaat |
| `relay/relay.js` | `CT_MAX` | `10000` | venster in het geheugen, geteld in regels; niet instelbaar |
| `relay/relay.js` | `CT_MAX_SIZE` | `100 * 1024 * 1024` | rotatiegrens op schijf, geteld in bytes; wel instelbaar, en dood zonder CT_FILE |
| `relay/relay.js` | `TTL_MS` | `300000` | standaardlevensduur van een blob, 5 minuten |
| `relay/relay.js` | `RAM_LIMIT_MB` | `512` | plafond van de RAM-bewaking; compose zet 1024 voor vier relays en 8192 hardgecodeerd voor health |
| `relay/relay.js` | `COMMUNITY_KEY_LIMIT` | `5` | vaste licentiegrens, bewust niet instelbaar |
| `relay/lib/auth-throttle.js` | `FAIL_THRESHOLD` | `10` | aantal mislukkingen voor de vertraging inzet; staat ook in admin/lib/login-ratelimit.js |
| `relay/lib/redis-deadline.js` | `DEFAULT_DEADLINE_MS` | `1000` | geexporteerde constante; de functie ernaast geeft een los getypte 1000 terug |
| `relay/envelope.js` | `DEFAULT_TTL_DAYS` | `30 x2` | bewaartermijn van een envelop; parasign-store telt zijn eigen 30 dagen |
| `relay/lib/entitlements.js` | `ENTERPRISE_MONTHLY_CEILING` | `1_000_000` | wat onbeperkt in de praktijk betekent |
| `admin/lib/audit.js` | `AUDIT_RETENTION_DAYS` | `400` | bewaartermijn van het auditlog; ongecontroleerde parseInt, 0 wist het log |
| `admin/server.js` | `RELAY_HEALTH` | `3000` | terugvalpoort voor de health-relay; de container-interne listener, gepind aan docker-compose.yml |
| `frontend/crypto-bridge.js` | `WASM_SHA256` | `30f1ae35` | integriteitspin op de wasm-module; verandert bij elke herbouw |
| `deploy/deploy-3.1.sh` | `EXPECT_VERSION` | `3.1.0` | welke versie de deploy verwacht aan te treffen; niet instelbaar |
| `deploy/deploy-3.1.sh` | `EXPECT_PROD_COMMIT` | `41501bb` | de startcommit uit het draaiboek |
| `install.sh` | `PARAMANT_VERSION` | `v3.0.0` | welke tag de zelf-installateur kloont; een minor achter op de deploy |

## Afwijkingen die mogen blijven staan

`admin/lib/config-schema.js` en `deploy/.env.example` schrijven allebei een standaard op.
Ze zijn met de hand geschreven en niets vergeleek ze ooit. Drie lopen uiteen. Ze staan
hier zodat de vierde opvalt. Deze ronde is bewust geen enkele waarde veranderd.

<!-- knoppen:afwijkingen -->

| naam | de twee waarden | waarom hij mag blijven |
|---|---|---|
| `RELAY_SELF_URL` | `''` in config-schema.js:46, `https://relay.paramant.app` in .env.example | de schema-waarde is de code-terugval (leeg), de voorbeeldwaarde is wat productie zet; nog niet besloten welke van de twee de standaard heet |
| `RAM_LIMIT_MB` | `512` in config-schema.js:94, `1024` in .env.example | de code valt terug op 512, compose zet 1024 voor vier relays en 8192 voor health; drie waarden, geen van drie fout, geen van drie de standaard |
| `NATS_URL` | `''` in config-schema.js, `tls://your-nats-server:4222` in .env.example | de voorbeeldwaarde is een invulplaats, geen standaard; NATS is opt-in en uit |

## Wat hier nog niet in staat

Eerlijk, want een lijst die doet alsof hij compleet is, is de fout die hij moest voorkomen.

- De nginx-conf die werkelijk op de server draait. Niet in git, niet publiek leesbaar.
  De 10 MB is gemeten, niet gelezen. *Niet vastgesteld* waar hij staat.
- De Caddy-laag ervoor. Gemeten aan de antwoordkop, verder onbekend.
- De waarden in `users.json` van legal, finance en iot. Alleen binnen de container leesbaar.
- De GitHub-secrets en -variabelen. `gh secret list` en `gh variable list` geven de namen,
  niet de waarden; de vier bestaande secrets zijn Docker Hub en Thunderbird.
- Poortnummers, `listen`- en `proxy_pass`-regels in de nginx-confs. Die veranderen gedrag,
  maar de tabel hierboven bewaakt vijf richtlijnen en niet alle. Uitbreiden kan door
  `WATCHED` in `tests/knoppen-compleet.test.mjs` aan te vullen en deze pagina mee te laten
  groeien; de controle wijst dan zelf aan wat er ontbreekt.
- De betekeniskolom is niet overal ingevuld. `nog niet beschreven` staat er waar ik de knop
  wel vond maar zijn bedoeling niet met zekerheid kon vaststellen. Dat is geen sieraad,
  het is een openstaande taak.
