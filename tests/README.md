# Regression test suite

Guards the auth + TOTP stack against the class of breakage that hit production repeatedly.

## Scripts

| Script | When it runs | What it checks |
|---|---|---|
| `tests/static-sanity.sh` | `test.yml` job `static-sanity` (every push to main and every pull request), pre-commit hook, `deploy.sh` step 1, `deploy/deploy-3.1.sh` phase 0b | Twelve numbered checks: Node syntax, redisClient init, TOTP helpers, unsafe req.body access, orphan code, 410 in source, DID-auth replay protection, the open-mode envelope signer binding, installer release pinning, the commit and GitHub style guard (`check-commit-style.sh`), the test-scope guard (`check-test-declarations.sh`) and the brand-screenshot opt-in. No secrets, no server, no network |
| `tests/redis-deadline-parity.test.mjs` | Root integration suites | `relay/lib/redis-deadline.js` and `admin/lib/redis-deadline.js` are one file. They exist twice because each Dockerfile copies only its own `lib/`, and the duplication is watched rather than hoped about. Also asserts both services really wrap their redis client with it |
| `relay/test/redis-deadline.test.js` | Relay unit suite | The bound itself, with no redis: the outage classifier, the deadline, the proxy that puts it on every command, and the connection rebuild after two unanswered commands |
| `relay/test/route-redis-outage.test.js` | Route suites (need redis) | A booted relay with its store behind a proxy the suite cuts and then black-holes. Every redis-backed route answers 503 inside the deadline, `/health` stays 200, `/v2/health/deep` goes red, and the relay heals by itself |
| `admin/test/_admin-server.js` | (helper) | Boots the real `admin/server.js` against a stub relay and speaks HTTP to it. The admin counterpart of `relay/test/_relay-server.js`; before it, no admin suite ever started the server |
| `admin/test/login-http.test.js` | Admin unit suite (needs redis) | The login limiter scenario against the real handler: ten wrong codes from three addresses, then the owner with a real 2^18 proof-of-work. Fails against the pre-#368 admin, which the module-level suite next to it does not |
| `admin/test/login-timing.test.js` | Admin unit suite (needs redis) | Measures a 401 for an address that exists against one that does not, at 0, 12 and 20 prior failures, with the shipped floor and the real throttle values, and asserts the medians do not separate and the ranges overlap. A level of zero on its own passes over an oracle three orders of magnitude wider. It does the same for `/api/user/login-with-backup` against a REAL relay, because there the oracle is ten argon2 verifications and a stub would be measuring the stub. `login-timing.bench.js` next to it is the instrument, not a test |
| `admin/test/ratelimit-ttl.test.js` | Admin unit suite (needs redis) | A counter whose INCR outlived the redis deadline must still get a window. The proxy delivers commands and drops replies, which is the only shape that strands a counter at TTL -1: a full outage never executes the INCR either |
| `admin/test/redis-outage.test.js` | Admin unit suite (needs redis) | The same two sabotages as the relay suite, against a booted admin: every redis-backed route 503 inside the deadline, `/health` 200 and honest about it, and recovery without a restart |
| `tests/frontend-loading-contract.test.mjs` | Root integration suites | Readiness must be sticky, not a one-shot event; entry points use absolute paths. Both rules exist because a page kept loading fine while the product was dead — see [docs/frontend-loading-contract.md](../docs/frontend-loading-contract.md) |
| `tests/product-heartbeat.test.mjs` | product-heartbeat workflow (pull requests), heartbeat workflow (hourly against production) | Opens each core page in Chromium and fails on uncaught errors, console errors, 404s on our own assets, and, for pages where the user has to get somewhere, on the page not actually progressing |
| `tests/heartbeat-lib.test.mjs` | Root integration suites | Guards the hourly monitor itself: the ML-DSA-65 argument order (a swapped one throws rather than returning false), the recipe-v4 sign message, that `runStep` fails a step which recorded no evidence, that a missing secret is a named failure and never a skip, and that a dry run cannot exit 0. Nothing watched `scripts/heartbeat/` before this |
| `tests/test_directie_signalen.py` | by hand | The directie signals (`scripts/directie/signalen.py`) with a stubbed `gh`: both states of the hourly heartbeat (off gives one orange signal, on reads surface, parasend and parasign out of the run's evidence artifact), plus every case where a green tick would not be earned: an expired or missing artifact, a dry run, an outcome older than two hours, and a run that failed outside the three proof steps. No network |
| `tests/crypto-claims.test.mjs` | Root integration suites | Every claim on the site about a cryptographic algorithm, against what the code does with it. The facts are read out of `crypto-wasm/src/lib.rs`, `relay/crypto/bootstrap.js`, `relay/crypto/impls/*.js`, `frontend/js/parashare.page.js`, `frontend/vault.js` and `extensions/shared/paramant-core.js` at run time, so a block whose footing moves fails rather than passing quietly. Eight rules: the per-client register on /crypto-agility matches each client's source; the encryption is never called post-quantum without saying it is hybrid; no page says a sent file is signed while neither send path signs; no page claims the pre-shared secret protects the ciphertext; no page has the whole NIST suite running while core mode loads two algorithms; no page dates an algorithm earlier than the CHANGELOG does; no page names a primitive no source file contains; /vault does not borrow the post-quantum story. Link-preview text (meta, og, twitter, JSON-LD) counts as what a page says, because that is where four copies of "post-quantum encryption end to end" lived and where the two existing claim gates never looked |
| `tests/koper-hele-weg.test.mjs` | test.yml job `relay-crypto-tests`, step `The whole way of a paying customer` (selected by `browser-suites.mjs --stack`) | The whole path of a paying customer in a real browser against a real backend: two relay.js processes (main and health, each with its own users.json, as in production), the admin server, the frontend behind the dev proxy, redis, and a virtual WebAuthn authenticator. Only api.mollie.com and api.resend.com are stand-ins, reached by redirecting the https layer, so `lib/mollie.js`, the checkout route and the webhook route run untouched and the payment is made by clicking Betaal rather than by calling the webhook by hand. Nine checks: the till charges what the button says, the four screens agree afterwards, both relays know the same right and it is what the plan promises, the buyer can use what the plan sells him, the invoice adds up and its number runs on, cancelling really stops the collection, a refund produces a credit note that matches, a chargeback removes the right on BOTH relays, and the term ends the way the site announces. Written for poort 6 of the sellable list, after five measured gaps of which the worst was a chargeback that relay-health undid one second later by reseeding its own still-paid record |
| `tests/auth-smoke.sh` | `deploy.sh` step 4 | 21 live HTTP assertions against production |
| `deploy.sh` | manual deploy | Chains: sanity → build → health wait → smoke |
| `tests/version-consistency.test.mjs` | Root integration suites | One version in one place: root `package.json` versus the relay and admin packages, both lockfiles, both image labels, the `VERSION` read in `relay.js`, the CHANGELOG section and the deploy check. Four places once gave three answers; see [docs/RELEASE.md](../docs/RELEASE.md) |
| `tests/brand-shots-optin.test.mjs` | Root integration suites, and `tests/static-sanity.sh` (pre-commit) | The reference screenshots under `docs/brand/assets/app-2026/` are opt-in. `scripts/app-shots.mjs` used to write 36 tracked PNGs on every run, so `git status` was never clean after a browser suite and the next `git commit -a` shipped them. Three layers: the resolver's own rules, a real dry run of `scripts/app-shots.mjs` that has to name a directory outside the repo and leave the references byte-identical, and a scan so no other suite hardcodes the path. See [Refreshing the app screenshots](#refreshing-the-app-screenshots) |
| `tests/env-documented.test.mjs` | Root integration suites | Every `process.env` name the relay or admin reads must be in [deploy/.env.example](../deploy/.env.example) with a purpose, a default and the file that reads it. Nothing may be documented there that no code reads, and every `read in:` pointer must name a file that exists and mentions the variable. 40 of 57 were undocumented on 2026-09-02 |
| `tests/end-screen-calm.test.mjs` | sign-e2e job `Browser suites` (selected by its playwright import) | The four end screens of the product (ParaSend live and Send-a-link, ParaSign after signing and after sending invitations, and both receiving pages) held to one shape at 390x844: no algorithm name on the face of the screen, exactly one button with the loud paint, the answer fitting a phone with the `<details>` shut, and that fold closed on arrival. Written after the owner read the ParaSend end screen on a phone on 4 September 2026 and found the same fact stated four times in jargon, one statement of it untrue of a live hand-over |
| `tests/signed-in-home.test.mjs` | sign-e2e job `Browser suites` (selected by its playwright import) | The signed-in homepage at 390x844, in five states (open requests, only finished documents, a brand new account, every route down, and documents waiting for the reader's own signature), with the API mocked the way `navigation-shell` mocks it. Holds three things: the big figure on screen is the number in the mocked API, no state leaves the reader with three buttons over a hole (measured as the gap between the last thing drawn in `<main>` and the top of the footer, 120px), and no relay vocabulary reaches the words. Written after the owner read his own homepage on a phone on 4 September 2026 and got a heading, one paragraph, three buttons and an empty screen: "I see ONLY 3 buttons, as if it were a test page". The fifth state also presses "Send me the link again" and holds that it asks once, says which address the mail went to, and turns a capped resend into a sentence rather than a status code |
| `relay/test/parasign-party-index.test.js` | relay job `Route suites` (needs redis and `@paramant/core`) | The party worklist index behind "Waiting for your signature", against a real store: `create()` puts an email-bound envelope on every invited party's list, the row carries no invite token and no document hash, index membership is not authority (a hand-written member shows nobody anything), signing or withdrawing takes the row off, the resend hands back the token that was already stored rather than minting one, and the backfill fills the index for older envelopes, is idempotent, and does not resurrect a row that signing removed |
| `relay/test/route-parasign-inbox.test.js` | relay job `Route suites` (needs redis and `@paramant/core`) | The same two routes over HTTP, for the one property the store cannot show: the address is derived from the authenticated key, so asserting somebody else's hash on the wire buys nothing, and the resend is internal-auth only and answers the same 404 for a wrong address as for a missing envelope |
| `tests/no-uncaught-errors.test.mjs` | sign-e2e job `Browser suites` (selected by its playwright import) | Every page in the `theme-contrast` list plus the app and auth screens, 25 pages and 32 session states, in light and dark, at 390 and 1440: 128 visits that each load the page, wait for network idle plus 1500ms so the animations have run, perform the first obvious interaction (hamburger on a phone, else the first tab, else the first button that neither navigates nor destroys anything), and fail on any uncaught page error, unhandled promise rejection or `console.error`. Written after PR #431 moved `GLOBE_ACCENT_RGB` inside `initGlobe()` while two other functions read it, so /parashare threw on every animation tick. Note what this does and does not fix: `product-heartbeat` already caught that one on the pull request and went red at 10:41:28Z, and #431 was merged 15 seconds later past a required check that `enforce_admins: false` does not enforce. This suite adds breadth (heartbeat sees 7 pages, signed out, one width, on load only), not the missing gate. The `KNOWN` list of deliberately ignored messages carries a reason per line and may only ever get shorter |

## Running manually

```bash
# Static analysis only (no network)
./tests/static-sanity.sh

# Live smoke tests against production
./tests/auth-smoke.sh

# Full safe deploy (builds admin container)
./deploy.sh admin

# Smoke against staging / local
PARAMANT_BASE=http://localhost:4200/admin ./tests/auth-smoke.sh
```

## Screenshots

### A screenshot is not a gate

`scripts/app-shots.mjs` renders every app screen at 390x844 and 1440x900, in
light and dark, and writes 36 PNGs. It lives in `scripts/`, next to
`brand-shots-direction.mjs` and `shot-dashboard.mjs`, and it is deliberately not
in `tests/`.

It used to be `tests/app-shots.mjs`, and that is a real scar. The sign-e2e
workflow's `Browser suites` step runs every `tests/*.mjs` that imports
playwright, selected by import so a new browser suite is picked up the day it is
written. This generator imports playwright, so it was picked up too. It asserts
nothing, so a green run proved nothing, but a red one blocked everything: on
2026-09-03 `page.screenshot: Timeout 30000ms exceeded` in this file took sign-e2e
red on main (run 33746496749) and with it the deploy, which needs sign-e2e green
in phase 0a. The same flake had already been seen on a pull request.

Moving the file changes nothing about the workflow's selection line. The real
browser suites it selects are the same sixteen minus this one:

```bash
# What the sign-e2e Browser suites step runs:
node scripts/browser-suites.mjs --browser-no-stack | grep -vE 'sign-full|product-heartbeat'
```

### Which half a suite belongs to is decided by the import graph

That selection line used to be `grep -l "from 'playwright'" tests/*.mjs`, which
reads the test file and nothing it imports. `tests/ui-elements-contrast.test.mjs`
imports `scripts/ui-contrast-sweep.mjs`, and the sweep is what imports
playwright, so the grep called it a no-browser suite. On 2026-09-04 that sent it
to the `Root integration suites (no browser)` job in test.yml, which installs no
Chromium on purpose. `chromium.launch()` rejected, the sweep's static server was
already listening and nothing closed it, and `node --test` waited for an event
loop that would never drain: three runs on main and a pull request hung in that
step for hours instead of failing in seconds. The suite also ran in no browser
job at all, so the only new gate of that pull request was measuring nothing.

`scripts/browser-suites.mjs` answers the same question by walking the relative
imports from each suite as deep as they go. A helper that grows a browser
dependency takes its suites with it on the next run, with no list to keep.

The rule this leaves behind: a file under `tests/` is a gate and asserts
something. A file that only produces artefacts belongs in `scripts/`, whether or
not it drives a browser.

### A browser is not the only thing a suite can need

The same blind spot came back one question further along on 2026-09-05.
`tests/koper-hele-weg.test.mjs` drives a browser AND boots two real relay.js
processes plus the admin server, and sign-e2e is self-contained on purpose: it
serves `frontend/`, stubs `/api`, and installs no relay dependencies, no
`@paramant/core` and no redis. Importing playwright was enough to send it to the
one job that could not possibly run it, and all nine of its checks failed with
`Cannot find module .../admin/node_modules/redis`.

So the walk answers a second question. A suite needs the full stack when
anything it reaches names `relay.js` as a process to spawn, which is the honest
signal and lives in the helper rather than in a list:

```bash
node scripts/browser-suites.mjs --browser-no-stack   # sign-e2e, stubbed backend
node scripts/browser-suites.mjs --stack              # test.yml relay-crypto-tests
```

Those two partition the browser suites, so a suite cannot fall out of both, and
the `--stack` step fails when its list comes back empty rather than reporting
green over nothing. The full-stack suite runs in `relay-crypto-tests` because
that is the only job that builds `@paramant/core` and has a redis service, for
the same reason the route suites live there. It takes its own redis database
(`KOPER_REDIS_DB`, 11) and flushes only that one, so it shares a server with the
route suites without sharing a keyspace.

### Every screenshot goes through one helper

`scripts/stable-screenshot.mjs`. It waits for network quiet and
`document.fonts.ready` first (both bounded, both best-effort, so a page that is
*meant* to be pending is still photographable), passes `animations: 'disabled'`
so the capture is not waiting on a frame that never settles, and gives the shot
60 s instead of Playwright's 30, with one retry at 120 s.

The retry is measured, not guessed. Ten runs of the generator under sixteen busy
cores put one capture past 60 s, and its call log read `taking page screenshot /
disabled all CSS animations`: the page had settled and the raster itself was
starved of CPU. No wait condition fixes that, only more budget does. A screenshot
has no side effect, so taking it twice is safe; the retry warns on stderr, and a
second timeout is thrown rather than swallowed.

`animations: 'disabled'` and not `page.emulateMedia({ reducedMotion: 'reduce' })`,
on purpose. Playwright freezes animations for the capture only; the media
emulation changes what the page renders from that point on, which would silently
move the ground under assertions taken after the shot and would make the
reduced-motion pair in `app-shots.mjs` identical to the normal pair.

The suites that write a screenshot as a byproduct call it too: `navigation-shell`,
`cosign-document-delivery`, `user-dashboard-documents`, `sign-invite-delivery`,
`signed-in-home` and `developer-parasign-dashboard`. Those calls are gated on a
`PARAMANT_*_SCREENSHOT_PATH` variable (`signed-in-home` takes a directory, in
`PARAMANT_HOME_IN_SCREENSHOT_DIR`, because it photographs four states) and never
fire in CI, but a builder taking
one by hand on a busy laptop hits the same wall the runner did.

### Refreshing the app screenshots

The copies under `docs/brand/assets/app-2026/` are tracked, so writing them is a
deliberate act and never a side effect of running the tests.

```bash
# Default: a temp directory. The repo stays clean.
node scripts/app-shots.mjs

# Only where would it write, no browser, no files.
APP_SHOTS_DRY_RUN=1 node scripts/app-shots.mjs

# Refresh the tracked reference images. Review the diff before committing:
# a screenshot that changed by two pixels of antialiasing still looks like a
# screenshot, so a careless `git commit -a` is exactly the failure this guards.
PARAMANT_WRITE_BRAND_SHOTS=1 node scripts/app-shots.mjs

# One screen only, and an explicit destination.
APP_SHOTS_ONLY=dashboard APP_SHOTS_DIR=/tmp/shots node scripts/app-shots.mjs
```

`APP_SHOTS_DIR` wins over the default, with one rule: a path pointing back
inside `docs/` is refused unless `PARAMANT_WRITE_BRAND_SHOTS=1` is set too.
Otherwise the opt-in would be one environment variable away from meaning
nothing. Where the decision is made: `scripts/brand-shots-dir.mjs`.

CI never consumes these images, and since 2026-09-03 no workflow runs the
generator at all. `tests/brand-shots-optin.test.mjs` still spawns it in dry-run
mode, so the opt-in is measured against the file that does the writing rather
than against a second copy of its rules.

## Pre-commit hook

`tests/static-sanity.sh` is installed as `.git/hooks/pre-commit`. Commits that introduce syntax errors, undefined redisClient, or a missing 410 on /request-key are blocked automatically. `.githooks/pre-push` runs the commit-style guard on its own; it needs `git config core.hooksPath .githooks` once per clone.

The hook is a convenience, not the gate. Until 2026-09-03 it was the only thing
that ran this script, together with `deploy.sh`, so a clone without the hook or a
single `git commit --no-verify` sailed straight past all twelve checks and no
pull request ever noticed. `test.yml` job `static-sanity` now runs the same
`bash tests/static-sanity.sh` on ubuntu, with no secrets and no server.

One difference between the two, and it is deliberate. Check 10 delegates to
`scripts/check-commit-style.sh`, which locally scans the **last commit**. On a
pull request GitHub checks out `refs/pull/N/merge`, and that merge commit has a
generated message and no diff of its own, so the local default would scan an
empty commit and pass over a branch full of em-dashes. The script therefore
scans `origin/$GITHUB_BASE_REF..HEAD` when that variable is set, which is why the
job uses `fetch-depth: 0`. It prints the range it scanned. Set
`PARAMANT_STYLE_RANGE` to choose one yourself.

## Adding new checks

- **Static checks** go in `tests/static-sanity.sh`. Exit 1 on failure so the pre-commit hook blocks and `test.yml` job `static-sanity` goes red. Keep them free of secrets, servers and network: that is what lets the job be a checkout, a node setup and one line.
- **Live checks** go in `tests/auth-smoke.sh`. Use `check`/`check_not` helpers. Never hardcode credentials.
