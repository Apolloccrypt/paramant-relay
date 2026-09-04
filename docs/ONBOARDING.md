# Onboarding

The one document you read on day one. Everything in it was executed in a clean
clone on 2026-09-02 against `origin/main` at `faf599e`; the numbers below are
what that run printed. Every claim names the file it comes from.

If a step here disagrees with what your terminal says, the terminal is right and
this file is a bug. Fix it in the same PR.

---

## 1. What Paramant is

Five sentences, quoted from `docs/brand/messaging.md`:

1. Paramant is for small professional firms that would rather not put client
   files on an American cloud: legal, finance and healthcare practices in the EU
   (`docs/brand/messaging.md:308-312`).
2. You send a contract out for signature, or send a file that is gone the moment
   it has been read; everything runs on servers in Germany (same lines).
3. The promise, in one line: "Anyone in the EU can sign and send securely for
   free, forever. Organisations pay for volume, never for security"
   (`docs/brand/messaging.md:59-60`).
4. Technically that is ML-KEM-768 + AES-256-GCM client-side encryption relayed
   through RAM (ParaSend, burn-on-read) and ML-DSA-65 signatures generated in
   the browser with a public append-only proof log (ParaSign) (`README.md:12`,
   `docs/brand/messaging.md:177-181`).
5. A ParaSign signature is a Simple Electronic Signature under eIDAS, not an
   advanced or qualified one, and the site says so in those words
   (`docs/brand/messaging.md:209-211`).

The free plan is called **Community**. Not Free, not Starter, not Basic
(`docs/brand/messaging.md:85-87`). See section 5.

---

## 2. The repo map

What is in each directory, and which test or workflow fails when you break it.

| Directory | What is in it | Guarded by |
|---|---|---|
| `relay/` | `relay.js`, one ~6500-line HTTP server with ~68 routes: auth gate, ParaSend transfer and burn, ParaSign envelope lifecycle, billing and entitlements, CT log, rate limits. `envelope.js` holds the envelope recipe (v4 binds the signer pubkey). `lib/` is 29 extracted pure modules. `crypto/` is the pluggable-algorithm registry and wire format. | `test.yml` jobs `relay-unit-tests` and `relay-crypto-tests`; `test.yml` job `undefined-names` (eslint `no-undef`); `build-image.yml` (drift gate, path-gated on `relay/**`) |
| `relay/test/` | 56 suites plus two helpers. `_requires.js` is the precondition gate (`requireEngine`, `requireRedis`, `summary`); a missing precondition is a hard failure unless named in `RELAY_TEST_SKIP`. `_relay-server.js` boots a real `relay.js` on a free port, which is what the five `route-*.test.js` suites drive over HTTP. | `test.yml`, split across two jobs (section 4) |
| `relay/crypto/` | 7 test files, the algorithm registry and byte-format gates. | `test.yml` job `relay-crypto-tests`, step "Relay crypto suite" |
| `admin/` | `server.js`, an Express 5 operator panel: admin console, developer gate, signup lock, user and plan management, CLI proxy. `lib/` is 20 modules, `public/` the served SPA. | `test.yml` job `admin-unit-tests`; `tests/static-sanity.sh` checks 1, 2, 4 and 6 target `admin/server.js` by name |
| `frontend/` | The static site: ~45 HTML pages plus `js/` (41 extracted scripts), `auth/`, `docs/`, `help/`, `billing/`, `security/`, `assets/`, `pkg/` (the wasm build). Served under `script-src 'self'`, so no inline JS anywhere. | `csp-inline-check.yml`; `test.yml` job `frontend-cache-bust`; `sign-e2e.yml` (11 browser suites); `product-heartbeat.yml` |
| `bron-seo/` | Two Python generators. `build_sitemap.py` regenerates `frontend/sitemap.xml` from what is on disk; `apply_seo_head.py` stamps the head-level SEO contract idempotently. Both take `--check`. | Nothing directly: no Python runs in CI at all. Its **output** is guarded by `tests/seo-contract.test.mjs`. Run the generator, do not hand-edit the output. |
| `scripts/directie/` | `signalen.py`: a no-model status meter. Asks GitHub over `gh` and production over `curl`, turns each answer into red/orange/green with the command it measured with. | Nothing. Documented in `docs/directie.md`. |
| `scripts/heartbeat/` | `run.mjs` and its lib: the four hourly production proofs (`surface`, `parasend`, `parasign-receipt`, `parasign-public-sign`). Every step runs even after one fails, on purpose: a dead page must never hide a dead signer. | Its logic by `tests/heartbeat-lib.test.mjs` (runs on every push); its execution by `heartbeat.yml` (hourly) |
| `deploy/` | `DEPLOY-3.1.md` is the runbook; `deploy-3.1.sh` executes it phase by phase and refuses to continue when a measurement disagrees. `.env.example` is the canonical env inventory (81 variables, names and purposes, no values). Plus the three nginx configs and `ops/backup-*.sh`. | `tests/env-documented.test.mjs` (every `process.env` name must be documented there, and nothing documented that no code reads); `test.yml` job `shell-syntax` (`bash -n`); `test.yml` job `deploy-dryrun` runs `tests/deploy-3.1-dryrun.test.sh` on every push and pull request, with no server and no secrets. |
| `tests/` | 27 `node:test` `.mjs` suites (16 node-only, 11 browser), plus `static-sanity.sh`, `auth-smoke.sh`, `e2e-auth-flow.sh` and the deploy dry-run self-test. | `test.yml` (node-only set), `sign-e2e.yml` (browser set), `product-heartbeat.yml`. Of the `.sh` files, `deploy-3.1-dryrun.test.sh` runs in CI (`test.yml` job `deploy-dryrun`) and `static-sanity.sh` does too (`test.yml` job `static-sanity`, twelve checks, no secrets and no server); `auth-smoke.sh` and `e2e-auth-flow.sh` need a live target and run at deploy time only. |

Selection of browser vs node-only suites is done **by what a file imports**, never
by a hand-kept name list (`.github/workflows/test.yml:290-296`,
`.github/workflows/sign-e2e.yml`). Write a new browser suite and it is picked up
the day you write it.

### Guarded by nothing

State this honestly rather than discover it. `bron-seo/*.py`,
`scripts/directie/signalen.py`, `tests/test_paramant_admin_paths.py`,
`tests/deploy-3.1-dryrun.test.sh`, `build.sh`, and
`relay/test/koop-pad-intentie.test.mjs` (11 cases, missed because the unit job
globs `test/*.test.js` and this is the only `.mjs` in that directory).

---

## 3. Local setup, step by step

Node must satisfy `engines: ">=22 <25"` (`package.json:5-7`); `.nvmrc` says `24`,
which is what every workflow uses. Docker is needed for the route suites only.
Measured below on Node v22.22.2, npm 10.9.7, Docker 29.6.1.

### 3.1 Clone, and clone the sibling too

`relay/package.json` declares `@paramant/core` as
`file:../../paramant-core/crates/paramant-core-node`: a **sibling repo that is
not in this monorepo**. `npm ci` in `relay/` does not fail without it, it just
leaves a dangling symlink, and then `relay.js` crashes on boot because
`relay/crypto/bootstrap.js` loads the ML-KEM-768 / ML-DSA-65 impls eagerly and
there is no pure-JS fallback (`AGENTS.md:56-70`). Clone both as siblings:

```bash
mkdir paramant && cd paramant
git clone https://github.com/Apolloccrypt/paramant-relay.git
git clone --no-checkout https://github.com/Apolloccrypt/paramant-core.git
```

Then build the binding at the commit CI pins
(`PARAMANT_CORE_SHA` in `.github/workflows/test.yml`). Needs `cmake`, `ninja`,
`clang` and a Rust toolchain:

```bash
cd paramant-core
git checkout b90b3c52af5c3c30053766bfa108924aff4f9eec
cargo build -p paramant-core-node --release
cp target/release/libparamant_core_node.so crates/paramant-core-node/index.node
```

Measured: 29 seconds with a warm cargo registry. Cold, budget several minutes;
liboqs is a C build.

You only need this for the crypto, engine, integration and route suites. The
unit suites and the whole frontend side run without it.

### 3.2 Install

```bash
cd paramant-relay
npm ci                      # root: ~109 packages
cd relay  && npm install    # npm install, not ci: this is what links @paramant/core
cd ../admin && npm ci
```

`npm install` in `relay/` is what CI uses too
(`.github/workflows/test.yml`, step "Install relay deps (incl. file-linked
@paramant/core)"). Root and admin report a handful of advisories today; that is
known, not something you introduced.

### 3.3 Turn the committed hooks on

Committed hooks do not activate themselves (`AGENTS.md:24-30`). Once, per clone:

```bash
git config core.hooksPath .githooks
```

Without this, `.githooks/pre-push` never runs the commit-style scan and you find
out about section 5 from a red PR instead of from your own machine.

### 3.4 The suites, and what they print

Run these in order. The commands are the ones CI runs, copied from
`.github/workflows/test.yml`; the counts are what a clean clone printed on
2026-09-02.

**Static gates** (no dependencies, seconds):

```bash
bash tests/static-sanity.sh
#   12 numbered checks, ends with "PASS (all hard checks clear)".  ~1.5s
#   Same command as test.yml job static-sanity runs on every push and pull request.

npx --yes eslint@9 .
#   silent on success.  ~5s

scripts/check-cache-bust.sh
#   cache-bust guard: OK - 340 local css/js/mjs link(s), all carry a single consistent ?v=

scripts/check-csp-inline.sh
#   OK: geen inline JS onder de CSP

find . -name '*.sh' -not -path '*/node_modules/*' -not -path '*/.git/*' -print0 \
  | xargs -0 -n1 bash -n
#   silent on success
```

**Relay unit suite** (no native deps, no redis):

```bash
cd relay
RELAY_TEST_SKIP=redis node --test --test-reporter=tap $(ls test/*.test.js | grep -vE \
  'inbound-hash-verify|deep-health-gate|billing-stance-boot|parasign-sandbox|parasign-open-api-e2e|parasign-envelope-index|parasign-signs-quota|route-')
#   # tests 199   # pass 199   # fail 0     ~1.5s
```

The exclusion list is not arbitrary and the reporter is not decoration: see
section 6.

**Admin unit suite:**

```bash
cd admin && node --test test/*.test.js
#   # tests 67   # pass 67   # fail 0      ~1m50s
```

Four of those suites boot a real `admin/server.js` (`login-http`,
`login-timing`, `redis-outage`, `ratelimit-ttl`), so this job now needs a redis
and the admin's own `node_modules`, which the CI job deliberately did not
install. `login-timing` additionally boots a real `relay.js` for its
backup-code case, because the oracle there is ten argon2 verifications and a
stub would be measuring the stub. That needs `@paramant/core`, which relay.js
refuses to start without, so the admin CI job declares it (`ADMIN_TEST_SKIP=relay`)
and the `relay-crypto-tests` job, the one that builds the binding, runs that
suite for real and fails if it skips there. They declare their precondition the way the relay suites do: without it
the run fails by name, unless the runner says `ADMIN_TEST_SKIP=redis`.

Most of those two minutes are deliberate waiting rather than work.
`login-timing` measures at 0, 12 and 20 prior failures, and by design an answer
at twenty failures is held for 2.25 seconds; its backup-code case is held for at
least 1.5 seconds per request, because that floor has to sit above ten argon2
verifications. Every request past the failure threshold also has to carry a real
2^18 proof-of-work, which `login-http` pays as well.

**Root integration suites** (node builtins plus the root deps, no browser):

```bash
node --test $(node scripts/browser-suites.mjs --no-browser)
#   # tests 190   # pass 188   # skipped 2   # fail 0    ~1.2s
```

The two skips are the external-link checks in `tests/links.test.mjs`; they need
`CHECK_EXTERNAL_LINKS=1` and run hourly against production, not on a pull
request.

**Crypto suite** (needs the sibling binding from 3.1):

```bash
cd relay && node --test $(find crypto -name '*.test.js')
#   # tests 144   # pass 144   # fail 0     ~21s
```

**ParaSign engine suites and the boot integration suites** (binding, no redis):

```bash
cd relay
RELAY_TEST_SKIP=redis node --test test/parasign-sandbox.test.js \
  test/parasign-sandbox-live-guard.test.js test/parasign-open-api-e2e.test.js \
  test/parasign-envelope-index.test.js
#   # tests 4   # pass 4

node --test test/inbound-hash-verify.test.js test/deep-health-gate.test.js \
  test/billing-stance-boot.test.js
#   # tests 11   # pass 11        ~1.3s   (each of these boots a real relay.js)
```

These three boot a real `relay.js` and wait for it to become healthy, so they are
the only suites here that are sensitive to a loaded machine: one run in ten failed
on a busy laptop and the other nine were clean. Rerun before you go looking for a
cause. Every other suite in this section was deterministic across repeated runs.

**Route suites** (need redis; the envelope store is redis-only, so without a
server every `/v2/envelopes` route answers 503 and the ParaSign lifecycle is
untestable):

```bash
docker run --rm -d --name paramant-test-redis -p 6399:6379 redis:7.4.8-alpine

cd relay
REDIS_URL=redis://127.0.0.1:6399 \
  node --test --test-reporter=tap test/route-*.test.js test/parasign-signs-quota.test.js
#   # tests 91   # pass 91   # fail 0      ~21s

docker rm -f paramant-test-redis
```

Same image tag `docker-compose.yml` runs in production. If 6399 is taken, pick
another port and set `REDIS_URL` to match: every suite reads
`process.env.REDIS_URL` first. Watch out for
`relay/test/parasign-envelope-index.test.js`, whose built-in default is **6396**,
not 6399; CI overrides it with `REDIS_URL` and so should you.

**Browser suites** (Playwright, Chromium only):

```bash
npx playwright install chromium

node tests/sign-full.test.mjs
#   33/33 passed                          ~4s

node --test $(node scripts/browser-suites.mjs --browser | grep -vE 'sign-full|product-heartbeat')
#   # tests 12   # pass 12   # fail 0     ~7s
```

You do not need to serve the frontend yourself. Each browser suite starts its own
`http.createServer` over `frontend/` on an OS-assigned port and stubs `/api`, so
there is no backend and no fixed port to remember. `PLAYWRIGHT_CHROMIUM_PATH`
overrides the binary if you would rather use a system Chrome.

**Deploy dry run** (touches nothing, needs no ssh key):

```bash
bash deploy/deploy-3.1.sh --dry-run --preflight-only
#   ends with "PREFLIGHT ONLY: phases 0 and 1 done." and "Warnings: 0", exit 0
```

`--dry-run` prints every remote heredoc as `[dry-run] > ` instead of running it,
prints every assertion as `SKIP assert (dry-run)`, and never calls `gh`, ssh,
docker or rsync (`deploy/deploy-3.1.sh:254-257`, `:281-330`). It does write one
local file, `deploy/logs/deploy-3.1-<TS>.log`, which is gitignored. Read the
whole nine-phase printout with `--dry-run` alone.

### 3.5 Running the stack

For development use `bash scripts/dev-local.sh`, not `docker compose up`
(`AGENTS.md:47-54`). It boots relay-health on `:3001`, admin on `:4200` and a
single-origin proxy on `http://localhost:8080`, prints a passkey setup URL, and
tails to `/tmp/paramant-dev-*.log`. Redis must be reachable: `redis-cli ping`
returns `PONG`. The `docker compose up -d` path in `README.md` is the
production-like one.

---

## 4. Which job runs which suite

`test.yml` (workflow name `tests`) has seven jobs, all on Node 24. The split
matters because it is what the exclusion list in 3.4 encodes:

- `relay-unit-tests` installs **nothing** for the relay. Pure-JS units only. It
  then `npm ci`s the root deps and runs the 16 node-only root suites.
- `relay-crypto-tests` builds `@paramant/core` from the pinned sibling commit and
  has a `redis:7.4.8-alpine` service on 6399. It runs the crypto suite, the four
  ParaSign engine suites, the three boot-integration suites, and the five route
  suites plus `parasign-signs-quota`.
- `admin-unit-tests`, `shell-syntax`, `undefined-names`, `frontend-cache-bust`,
  `gitleaks` are one command each.

`sign-e2e.yml`, `product-heartbeat.yml` and `csp-inline-check.yml` are
deliberately **not** path-gated: they are required status checks, and a skipped
required check never reports, so a PR would wait on it forever. Only the two
Docker workflows are path-gated, both on `relay/**`.

### The silent-suite gate

Both the unit job and the route step pipe TAP through `tee` and then grep for
`# <suite>: SKIPPED - 0 checks ran`, the line `summary()` in
`relay/test/_requires.js` prints. The expected set is **empty** in both. A suite
that runs and asserts nothing fails the job by name. This exists because four
ParaSign suites once reported "ok 24" while asserting nothing at all for weeks.
The instruction in the error message is the rule: *fix the suite, do not add it
to a list* (`.github/workflows/test.yml:183-186`).

---

## 5. The rules of the house

These are hard. Each one has a gate that will find you.

**No AI attribution, anywhere.** Commit messages, PR bodies and GitHub comments
are all in Mick's name: no co-author trailer in any spelling, no generated-with
line, no AI attribution at all. Also no em-dashes (U+2014), no emoji, and never
a real person or company name in code, comments, commits, tests or branch names
(use `acct_demo`, `demo@example.com`, signer `Demo`, company `Acme`).
Source: `AGENTS.md:8-16`. Gate: `scripts/check-commit-style.sh`, which scans both
the commit message and the added `+` diff lines, and runs from both
`tests/static-sanity.sh` and `.githooks/pre-push`. Default tooling adds these
trailers for you; turn them off before your first commit.

**static-sanity is twelve checks, and check 10 is the style guard.**
`tests/static-sanity.sh` runs twelve numbered checks: syntax, redisClient
initialisation, TOTP helpers (warn), unsafe `req.body` access (warn), orphan code
(warn), `/request-key` still returning 410, DID-auth replay protection, the
open-mode envelope signer binding, installer release pinning, check 10, the
commit and GitHub style guard delegating to `check-commit-style.sh`, check 11,
the test-scope guard delegating to `check-test-declarations.sh`, and check 12,
the opt-in on the tracked brand screenshots. Exit code is the number of hard
failures.

It runs in CI as `test.yml` job `static-sanity`, on every push to main and every
pull request. That is new. Until then it ran in **no** workflow at all: its only
callers were the pre-commit hook and `deploy.sh:25`, `security-posture.yml`
named it in a comment and nowhere else, and every "static-sanity PASS" on record
came from somebody's laptop. If your hook is not installed, or you committed
with `--no-verify`, the pull request now says so.

Which commits check 10 reads depends on where it runs, and it has to. Locally
and on a push it is the **last commit**, so on a branch with a non-conforming
commit checks 1 to 9 pass and the script still exits 1;
`deploy/DEPLOY-3.1.md:197-204` documents that this state does not block a deploy.
On a pull request the checkout is `refs/pull/N/merge`, whose HEAD is a merge
commit with no diff of its own, so the script scans
`origin/$GITHUB_BASE_REF..HEAD` instead: the commits the pull request adds. That
is why the job checks out with `fetch-depth: 0`, and why it prints which range it
scanned. `PARAMANT_STYLE_RANGE` overrides the choice. Do not rewrite history to
make it green.

**Every claim on the site is tied to a test.** The rule, from
`docs/brand/messaging.md:14-18`: a sentence may only go on the site if it is
already true on the site or in the code, and there is a test that fails when it
stops being true. The inventory of all 38 public pages and their pins is
`docs/site-claims.md`; the enforcing suite is `tests/site-claims.test.mjs`, which
reads the number or constant from the source that enforces it and then checks the
page says the same thing, and asserts the **absence** of claims the repository
cannot show. `tests/ui-truthfulness.test.mjs` carries the rest. Adding a claim is
a five-step procedure written down at `docs/brand/messaging.md:500-513`.

**Pins hang off `tiers.js` and the code, never off another page.**
`relay/lib/tiers.js` is the single declared source of truth for plans and limits;
`relay.js` turns its rows into a 402 and a 413. Tests read tiers.js and compare
the page to it. The reason is written in the test itself
(`relay/test/pricing-page.test.js:494-497`): pinning one page to another only
proves the two agree, it cannot catch both being wrong together, which is exactly
what happened when /pricing and index.html carried the same wrong upload figure.

**The free plan is called Community.** Not Free, not Starter, not Basic
(`docs/brand/messaging.md:85-87`). `tests/ui-truthfulness.test.mjs:415-447` runs
ten regex shapes that can only be a plan name over every `.html` under
`frontend/`, recursively, with exactly two exempted files, each with its reason
in the test.

**Two more that fail a first PR.** Every local css/js link must carry exactly one
`?v=` cache-bust, and the same asset may never appear with two different values
(`scripts/check-cache-bust.sh`; nginx serves those paths `immutable, max-age=1y`).
And the site runs under `script-src 'self'`, so any inline `<script>` or inline
event handler is dead in the browser, not merely ugly; only
`application/ld+json` is exempt (`scripts/check-csp-inline.sh`). Signup and login
were down for a week over this in July 2026.

**Nav and footer are stamped by `frontend/apply-nav.py`.** Do not hand-edit them,
and do not touch `frontend/js/nav-auth.js` (`docs/brand/messaging.md:512-513`).

**From `CONTRIBUTING.md`:** one fix per PR, include a test where applicable,
update `CHANGELOG.md` under `[Unreleased]`, English only in code and comments.
Never open a public issue for a vulnerability.

---

## 6. Release and deploy

Not duplicated here. Read the two documents.

- **`docs/RELEASE.md`** is the release process. The rule it exists to enforce:
  a release is a tag, the tag builds the image, and production runs that image.
  Root `package.json` is the only version source of truth; every other copy is
  hand-carried and policed by `tests/version-consistency.test.mjs`. The CHANGELOG
  section gets written from `git log v3.0.0..origin/main` **before** any version
  number moves. Lines 94-111 are the local CI mirror, which is the same set of
  commands as section 3.4 above.
- **`deploy/DEPLOY-3.1.md`** is the production runbook, and
  `deploy/deploy-3.1.sh` executes it. Preflight is read-only; rollback is
  `--rollback <TS>`. The commit the production checkout must stand on before
  phase 3 is a **parameter**, not a constant: `PARAMANT_EXPECTED_HEAD` wins,
  otherwise the `deployed-head` marker the previous deploy wrote on the server,
  otherwise the runbook's starting commit. That is what makes a second deploy,
  and a resume of a failed one, possible at all.

Two layout facts that catch everyone once: `/opt/paramant-relay` is the checkout
and the compose directory, `/home/paramant/app` is the nginx docroot and only a
copy. `docs/RUNBOOK-DEPLOY-3.0.0.md` describes the older reality (server builds
from `git pull`, no registry) and is superseded.

---

## 7. How the monitoring works

Two workflows with similar names, and they are not the same thing.

- **`.github/workflows/heartbeat.yml`** is the hourly production alarm.
  `cron: '17 * * * *'` plus manual dispatch, no push trigger. It is gated on a
  GitHub repository **variable**: `if: github.event_name == 'workflow_dispatch'
  || vars.HEARTBEAT_ENABLED == 'true'` (`heartbeat.yml:56`). It runs
  `scripts/heartbeat/run.mjs` against production, then the browser heartbeat
  suite, then the external link check, and uploads the evidence directory. On
  red it opens or reopens **one** issue titled `Heartbeat rood` with label
  `heartbeat` and comments on it; on green it closes every open one. The
  procedure for switching it on is in `docs/heartbeat.md:124-171`: set the
  secrets, dispatch it by hand once, and only then
  `gh variable set HEARTBEAT_ENABLED --body true`. Note that
  `tests/site-claims.test.mjs:385` asserts the flag in both directions, so
  flipping it off fails the `/sla` claim test until the page is rewritten.
- **`.github/workflows/product-heartbeat.yml`** is the pull-request gate against
  your checkout, not against production.

A step that records no proof is failed by `runStep` even if nothing threw, and a
`HEARTBEAT_DRY_RUN=1` run can never be green by construction. There is
deliberately no skip path: a missing secret is a named hard failure.

**`scripts/directie/signalen.py`** is the wider status meter, and it uses no
language model. It asks GitHub over `gh` and production over `curl` and turns
each answer into red, orange or green with the command it measured with in
`details.bron`, so every line is reproducible.

```bash
python3 scripts/directie/signalen.py --tekst
```

Exit 0 means nothing red, 1 means something red, 2 means the script itself broke.
Without a `gh` login the GitHub signals go orange rather than failing. Thresholds
are constants at the top of the file, each with its reason. Full table in
`docs/directie.md`. One staleness warning: `docs/directie.md:53-59` still
describes the three canaries as steps in `product-heartbeat.yml`; they moved to
`heartbeat.yml` on 2026-09-02.

---

## 8. Where production runs, and who has the key

One Hetzner VM in Germany, `116.203.86.81`, reached as root over SSH
(`deploy/DEPLOY-3.1.md:12`, `deploy/deploy-3.1.sh:36`). On it: five sector relays
(`relay-main` :3000, `relay-health` :3001, `relay-finance` :3002, `relay-legal`
:3003, `relay-iot` :3004), the admin panel on :4200, redis, all bound to
`127.0.0.1`, with system nginx as the TLS terminator in front. Six hostnames
resolve there. There is no staging environment (`docs/RELEASE.md:238-239`).

Where things live on that host, paths only:

| Path | What |
|---|---|
| `/opt/paramant-relay` | the checkout and `docker-compose.yml` |
| `/opt/paramant-relay/.env` | all runtime secrets, mode 600 |
| `/home/paramant/app` | the frontend docroot nginx serves (a copy) |
| `/home/paramant/backups/` | rollback manifests, `.env` copies, docroot tarballs, the `deployed-head` marker |
| `/data/relay-identity.json` | the relay's own signing key, per relay volume, 0600 |
| `/root/.config/paramant-backup/key.txt` | the age key for the encrypted backups, root only |
| `/etc/nginx/sites-enabled/paramant-{public,live}.conf` | the two confs a deploy edits, and only those two |

Off the host: the production SSH key is `~/.ssh/paramant_prod_claude` on the NUC,
and the deploy scripts hard-fail anywhere else with "run this from the NUC". The
heartbeat credentials are GitHub Actions repository secrets.

**Who has the key: one person.** `deploy/DEPLOY-3.1.md:12-14` says it plainly:
Mick runs the deploy by hand over SSH, from the NUC, where the production key
lives. There is no second holder documented anywhere in this repo, and the backup
age key is root-only on the box the backups sit on. If you are the second
developer reading this, that is the first thing to change, not the last.

The hygiene rule the scripts follow and you must too: environment variables are
reported as `empty` or `set, prefix <first 5 chars>`, never as values. No remote
block runs under `set -x`. No read of `.env` reaches stdout.

---

## 9. Things you will hit in your first week

**The relay crashes on boot and you did not touch it.** `@paramant/core` is
missing. `npm ci` in `relay/` leaves a dangling symlink rather than failing, so
the error surfaces much later as "relay did not become healthy in time". Build
the sibling, section 3.1.

**A test reporter that quietly disarms a gate.** Node's default `--test` reporter
for a non-TTY changed from `tap` to `spec` between Node 20 and Node 24, and spec
drops the `# ` prefix. Two CI gates parse those TAP diagnostic lines, so under
spec the grep matches nothing, the silent set comes back empty, and the gate
passes **for the wrong reason**. That is why `--test-reporter=tap` is written out
in both jobs rather than inherited. Keep it when you copy a command. Its sibling:
`node:test` counts a skip as a pass, so `ok N - name # SKIP reason` lands in
`# pass` (`docs/heartbeat.md:8-33`).

**You add a variable to `.env` and nothing happens.** There is no `env_file` in
the compose stack, anywhere. `.env` only substitutes `${VAR}` into
`docker-compose.yml`, so a variable without a line in the `x-relay-env` anchor
never reaches a container (`docker-compose.yml:62-64`). This bit for real: the
four receipt variables from #342 had no line, so setting them in `.env` alone
would have done nothing. Second half of the trap: containers pick up a new value
only when **recreated**, not on restart.

**gitleaks version, and why it is pinned.** `GITLEAKS_VERSION: "8.28.0"` in
`test.yml`, with the action itself pinned to a commit SHA rather than a tag. The
action's own default resolved to 8.24.3, which parses a `[[allowlists]]` table in
`.gitleaks.toml` and then ignores it: no error, no warning. Measured on the same
branch with the same config, 8.24.3 reports 2 findings and 8.28.0 reports 0. A
config that is silently skipped is worse than one that fails to load.

**Two green PRs that merge into a red main.** This is the one that will cost you
an afternoon, and it happened on 2026-09-02. Two pull requests touched
`relay/test/pricing-page.test.js` and `tests/ui-truthfulness.test.mjs` at the same
time and each added a top-level `const` near the end of the file. Each PR was
green, because CI ran each branch against the base it was cut from, not against
the merged result. Merged, the files carried `const tiers` twice and
`const pricingVisible` twice: a hard `SyntaxError` that takes the whole file down
before a single assertion runs, so the suite does not fail one check, it fails to
load. eslint does not save you here either, because the config carries exactly one
rule and it is `no-undef`, not `no-redeclare`.

What to do about it: if your branch and another open PR touch the same test file,
rebase on `main` and run the suite once more before you ask for a merge, and read
a red `tests` job on `main` as everyone's problem rather than the last merger's.
The files most exposed are the long append-only ones, `pricing-page.test.js`,
`ui-truthfulness.test.mjs` and `site-claims.test.mjs`, where the convention is to
add a new block at the bottom with its own helpers. #359 cleaned up both
collisions and put its new blocks in function scope, which is the durable fix: a
block that owns its names cannot collide with the next one.

**A PR whose checks do not run.** Do not read an empty check list as green. A PR
that has been open a while with **zero** checks is an explicit orange signal in
`scripts/directie/signalen.py:255-258`, with the instruction attached: find out
why it has no checks before you judge it. The usual causes are a merge state that
never triggered a run, and a path-gated workflow that was skipped, which is why
the three required checks in this repo are deliberately not path-gated. Two
documented cousins of the same failure: a skipped required check never reports,
so the PR waits forever; and an `in_progress` run is not a pass, which is how two
still-running runs were waved through the old deploy gate on 2026-09-02
(`deploy/deploy-3.1.sh:120-125`).

**Tests that fail locally on purpose.** `tests/auth-smoke.sh` asserts *production*
semantics (`/request-key` returns 410, the captcha shape, the signup route);
several of its checks fail against the local dev stack and that is expected, not
a regression (`AGENTS.md:79-95`). Same file: the `EACCES ... mkdir '/data'`
warning in dev is harmless, account email validation rejects dotless domains so
`dev@localhost` returns a harmless 400 (use `alice@example.com`), and the browser
apps hardcode the production relay hosts so they will not target your local relay
without code edits.

**A healthcheck that returns 200 over a broken container.**
`docs/regression-watchlist.md` records three bug classes that reached production
that way: a changed response shape, orphan code throwing a `ReferenceError`
inside a handler, and an uninitialised `redisClient`. An HTTP ping cannot tell a
working container from one that crashes on specific paths. That is what
`tests/e2e-auth-flow.sh` is for.

**eslint here has exactly one rule.** `no-undef`, scoped to `relay/` and `admin/`
server code (`eslint.config.mjs`). It is not a style linter and it will not catch
a duplicate declaration in a test file. The comment above the job says why the
one rule exists: an hourly `setInterval` swept a Map that no longer existed and
took production down 425 times before anyone looked.

---

## 10. Where to look next

- `AGENTS.md` for the commit and PR rules and the environment caveats.
- `docs/PROJECT-STATUS.md` is now a pointer table, not a snapshot. Follow it.
- `docs/adrs/` for the 19 architecture decision records: the reasoning is written
  down, which is rare.
- `deploy/.env.example` for every environment variable the code reads, with a
  purpose, a default and the file that reads it. `tests/env-documented.test.mjs`
  keeps it honest in both directions.
- `tests/README.md` for where a new check belongs: static ones go in
  `static-sanity.sh`, live ones in `auth-smoke.sh`.
- `docs/cross-repo-coordination.md` for how this repo and `paramant-core` move
  together.
