# Deploy v3.0.0 Report

- Time: 2026-05-27 (stamp 20260527-2304)
- Status: **LIVE_WITH_NON_CRITICAL_ISSUES**
- Smoke-test exit: **1** (non-critical failures; CRITICAL=0 -> no rollback)
- Backup stamp: 20260527-2304
- Executed: autonomous pipeline (merges + deploy + smoke), no rollback triggered

## Outcome

paramant.app backend is **live on 3.0.0** with the R006 "core" crypto profile
active (single KEM ML-KEM-768). All relay sectors and admin are healthy. Three
non-critical smoke failures remain, all traced to the **static frontend root not
being synced** (separate deploy artifact). No critical failure, so no rollback.

## PRs merged in this deploy

Already merged before this run: #58 (admin debug CLI), #59 (M11 static serving),
#60 (deploy runbook + smoke + rollback).

Merged in this run:

- #28: chore(deps): bump actions/setup-python from 5 to 6
- #29: chore(deps): bump ws from 8.20.0 to 8.20.1 in /relay
- #62: ops: pre-deploy snapshot for v3.0.0 (rollback reference)
- #61: docs: site content refresh for v3.0.0 release

main after merges: `bbceb72`.

## Deploy

- Server: 116.203.86.81 (host paramant-relay), COMPOSE_DIR `/opt/paramant-relay`
  (git checkout on `main`, SSH remote).
- git pull moved server `e62fbf4 -> bbceb72`.
- `.env`: appended `CRYPTO_MODE=core` (was unset).
- `docker compose build` succeeded; `docker compose up -d` recreated all relay
  sectors + admin (redis unchanged).
- relay-main healthy 4s after restart.

### Container state (post-deploy)

```
admin           Up (healthy)
relay-main      Up (healthy)
relay-health    Up (healthy)
relay-finance   Up (healthy)
relay-legal     Up (healthy)
relay-iot       Up (healthy)
redis           Up (healthy)
```

## Live production checks

### /health

```
{"ok":true,"version":"3.0.0","sector":"relay","edition":"licensed","max_keys":null,"license_expires":"2027-01-01T00:00:00.000Z","license_issued_to":"paramant.app"}
```

### /v2/capabilities (R006 core)

- wire_version: 1
- KEMs: 1 (ML-KEM-768)
- SIGs: 2 (none + ML-DSA-65)

This matches the R006 "core" expectation: one KEM loaded.

## Smoke-test results (https://paramant.app)

```
== CRITICAL: relay /health ==
PASS: /health HTTP (200)
PASS: /health version (3.0.0)
== CRITICAL: /v2/capabilities (R006 core = 1 KEM) ==
PASS: /v2/capabilities KEM count (1)
PASS: /v2/capabilities KEM[0] name (ML-KEM-768)
PASS: /v2/capabilities sig count (none + ML-DSA-65) (2)
== relay deep health (server-local only) ==
SKIP: /health/deep (no RELAY_LOCAL_URL given)
== frontend pages ==
FAIL: /setup reachable (expected '200', got '404')
PASS: /docs reachable (200)
FAIL: /dashboard renders cards (missing 'cards-grid')
PASS: homepage advertises PQC (found 'ML-KEM')
== admin pages ==
PASS: /admin/settings.html reachable (200)
PASS: /admin/cli.html reachable (200)
== well-known / hygiene ==
FAIL: PGP placeholder still live
------------------------------------------------------------
PASS=9  FAIL=3  SKIP=1  CRITICAL=0
```

## Non-critical findings + root cause

All three failures share one root cause: the **static frontend is served from a
separate location that this deploy did not update**. nginx serves `/.well-known/`
and static pages from `/home/paramant/app` (a plain artifact directory, NOT a git
checkout), and routes `/`, `/dashboard`, `/docs` to a host service on `:8080`.
The authorized deploy procedure updated only the compose backend at
`/opt/paramant-relay` (relay + admin), so site-content (#61) and the PGP
placeholder cleanup (#53, already in main) are not reflected on the live static
root.

1. **PGP placeholder still live** -- `/.well-known/openpgp-key.asc` on the live
   static root still contains the placeholder block. The fix exists in git
   (PR #53, commit `fb3caf2`) but the `frontend/.well-known/` files were never
   copied to `/home/paramant/app`. Remediation: sync the frontend artifact (run
   the site build/deploy step that populates `/home/paramant/app`).
2. **/dashboard missing cards-grid** -- page returns HTTP 200 with title
   "PARAMANT - Developer Dashboard" but renders the sign-in state; the cards grid
   is injected client-side after auth, so an unauthenticated curl never sees
   `cards-grid`. Largely expected for an anonymous probe; will also pick up #54
   dashboard content once the static root is synced.
3. **/setup -> 404** -- the M11 setup wizard is first-run/opt-in (relay serves it
   only in setup mode; static frontend has no `/setup`). On a configured
   production with keys loaded, 404 is expected. Not a regression.

### Recommended follow-up (NOT done autonomously - out of authorized scope)

- Sync the static frontend artifact to `/home/paramant/app` (site build/deploy
  step), then re-run: `bash scripts/post-deploy-verify.sh https://paramant.app`.
  Expect the PGP and dashboard checks to flip to PASS; `/setup` 404 is expected.

## Rollback readiness

Not triggered (no critical failure). Pre-deploy backup tagged all 6 service
images and wrote the manifest consumed by `scripts/rollback-3.0.0.sh`:

- `/home/paramant/backups/rollback-images-20260527-2304.txt`
  (-> symlinked as `rollback-images-latest.txt`)
- `.env` backup: `/home/paramant/backups/.env-pre-3.0.0-20260527-2304`

If a rollback is ever needed: on the server,
`cd /opt/paramant-relay && COMPOSE_DIR=/opt/paramant-relay bash scripts/rollback-3.0.0.sh`.
