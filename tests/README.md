# Regression test suite

Guards the auth + TOTP stack against the class of breakage that hit production repeatedly.

## Scripts

| Script | When it runs | What it checks |
|---|---|---|
| `tests/static-sanity.sh` | pre-commit hook, `deploy.sh` step 1 | Eleven numbered checks: Node syntax, redisClient init, TOTP helpers, unsafe req.body access, orphan code, 410 in source, DID-auth replay protection, the open-mode envelope signer binding, installer release pinning, the commit and GitHub style guard (`check-commit-style.sh`) and the test-scope guard (`check-test-declarations.sh`) |
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
| `tests/auth-smoke.sh` | `deploy.sh` step 4 | 21 live HTTP assertions against production |
| `deploy.sh` | manual deploy | Chains: sanity → build → health wait → smoke |
| `tests/version-consistency.test.mjs` | Root integration suites | One version in one place: root `package.json` versus the relay and admin packages, both lockfiles, both image labels, the `VERSION` read in `relay.js`, the CHANGELOG section and the deploy check. Four places once gave three answers; see [docs/RELEASE.md](../docs/RELEASE.md) |
| `tests/brand-shots-optin.test.mjs` | Root integration suites, and `tests/static-sanity.sh` (pre-commit) | The reference screenshots under `docs/brand/assets/app-2026/` are opt-in. `tests/app-shots.mjs` used to write 36 tracked PNGs on every run, so `git status` was never clean after a browser suite and the next `git commit -a` shipped them. Three layers: the resolver's own rules, a real dry run of `tests/app-shots.mjs` that has to name a directory outside the repo and leave the references byte-identical, and a scan so no other suite hardcodes the path. See [Refreshing the app screenshots](#refreshing-the-app-screenshots) |
| `tests/env-documented.test.mjs` | Root integration suites | Every `process.env` name the relay or admin reads must be in [deploy/.env.example](../deploy/.env.example) with a purpose, a default and the file that reads it. Nothing may be documented there that no code reads, and every `read in:` pointer must name a file that exists and mentions the variable. 40 of 57 were undocumented on 2026-09-02 |

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

## Refreshing the app screenshots

`tests/app-shots.mjs` renders every app screen at 390x844 and 1440x900, in
light and dark, and writes 36 PNGs. The copies under
`docs/brand/assets/app-2026/` are tracked, so writing them is a deliberate act
and never a side effect of running the tests.

```bash
# Default: a temp directory. The repo stays clean.
node tests/app-shots.mjs

# Only where would it write, no browser, no files.
APP_SHOTS_DRY_RUN=1 node tests/app-shots.mjs

# Refresh the tracked reference images. Review the diff before committing:
# a screenshot that changed by two pixels of antialiasing still looks like a
# screenshot, so a careless `git commit -a` is exactly the failure this guards.
PARAMANT_WRITE_BRAND_SHOTS=1 node tests/app-shots.mjs

# One screen only, and an explicit destination.
APP_SHOTS_ONLY=dashboard APP_SHOTS_DIR=/tmp/shots node tests/app-shots.mjs
```

`APP_SHOTS_DIR` wins over the default, with one rule: a path pointing back
inside `docs/` is refused unless `PARAMANT_WRITE_BRAND_SHOTS=1` is set too.
Otherwise the opt-in would be one environment variable away from meaning
nothing. Where the decision is made: `scripts/brand-shots-dir.mjs`.

CI never consumes these images. The sign-e2e workflow runs `tests/app-shots.mjs`
because it picks up every suite that imports playwright, and no workflow uploads
or reads the result, so nothing there sets the flag.

## Pre-commit hook

`tests/static-sanity.sh` is installed as `.git/hooks/pre-commit`. Commits that introduce syntax errors, undefined redisClient, or a missing 410 on /request-key are blocked automatically. `.githooks/pre-push` runs the commit-style guard on its own; it needs `git config core.hooksPath .githooks` once per clone.

## Adding new checks

- **Static checks** go in `tests/static-sanity.sh`. Exit 1 on failure so the pre-commit hook blocks.
- **Live checks** go in `tests/auth-smoke.sh`. Use `check`/`check_not` helpers. Never hardcode credentials.
