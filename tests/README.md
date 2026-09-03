# Regression test suite

Guards the auth + TOTP stack against the class of breakage that hit production repeatedly.

## Scripts

| Script | When it runs | What it checks |
|---|---|---|
| `tests/static-sanity.sh` | pre-commit hook, `deploy.sh` step 1 | Node syntax, redisClient init, TOTP helpers, unsafe req.body access, orphan code, 410 in source |
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

`tests/static-sanity.sh` is installed as `.git/hooks/pre-commit`. Commits that introduce syntax errors, undefined redisClient, or a missing 410 on /request-key are blocked automatically.

## Adding new checks

- **Static checks** go in `tests/static-sanity.sh`. Exit 1 on failure so the pre-commit hook blocks.
- **Live checks** go in `tests/auth-smoke.sh`. Use `check`/`check_not` helpers. Never hardcode credentials.
