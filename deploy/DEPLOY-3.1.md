# Deploy runbook: main (3.1.0) to production

> `deploy/deploy-3.1.sh` executes this runbook. One command from the NUC
> (`bash deploy/deploy-3.1.sh`) runs every step below, prints the command and
> the measurement for each one, and stops at the first result the runbook did
> not predict. `--preflight-only` does the checks and nothing else,
> `--dry-run` prints every remote command instead of running it, and
> `--rollback <TS>` is step 8. This file stays the readable source: the script
> follows it, it does not replace it, and a step that is argued out here is
> argued out here only.

Target: `116.203.86.81` (Hetzner). Mick runs this by hand over SSH, from the
NUC, where the production key lives (`~/.ssh/paramant_prod_claude`, see
`scripts/check-prod-drift.sh`). Nothing in this file runs on its own. Every
step says what it changes; the read-only steps say so.

This runbook supersedes `docs/RUNBOOK-DEPLOY-3.0.0.md` on one point: that file
assumed the compose checkout lived in `/home/paramant/app`. On production
`/home/paramant/app` is the **frontend docroot** that nginx serves, and the
relay checkout with `docker-compose.yml` is `/opt/paramant-relay`
(`scripts/check-prod-drift.sh`; vault sessions of 2026-06-24, 2026-07-17 and
2026-09-01). Confirm it in step 1 before trusting either.

## Where we start

Measured on 2026-09-01 from the NUC, read-only (vault: *Bevinding - een deploy
van main zou tegen de echte Mollie draaien*, *Bevinding - de
ParaID-uitgifteroute staat open op productie*):

| what | production now | main |
|---|---|---|
| relay checkout | `41501bb`, 8 August 2026 | `0fc8648` and later, 3.1.0 |
| relay containers | image of 8 August (`grep -c _paraidAuth /app/relay.js` gives 0) | rebuilt from source |
| `BILLING_MODE` | empty, in every relay container | may stay empty, see step 3 |
| `MOLLIE_API_KEY` | present, prefix `live_` | unchanged |
| `MOLLIE_TEST_API_KEY` | not set | there is none, and none is coming for now |
| `/v1/paraid/issue-*` | 404 from nginx, all six server blocks (server-side edit of 01-09) | route removed in the relay (#319) |
| `/v2/health/deep` | `{"error":"Not available in this relay mode"}` | 200 behind `X-Internal-Auth` (#322) |

What main brings that touches the deploy, with the PR that did it:

- **#314** release 3.1.0, ParaID auth, billing with an end date.
- **#315** `paid_until` survives a restart, Mollie mandate and subscription layer.
- **#316** ParaSign canary. **Replaced by #338**: that suite never ran (its secret does not exist, and node:test counts a skip as a pass), so it lives on as `scripts/heartbeat/parasign.mjs`, which fails by name when the key is missing. Still needs a `psk_test_` key, now as `PARASIGN_CANARY_KEY`, plus `PARAMANT_CANARY_KEY`.
- **#317** `/sign` served without login (nginx change in `deploy/nginx-paramant-live.conf`).
- **#319** ParaID removed: 3339 lines, 26 files.
- **#322** `/v2/health/deep` in `ghost_pipe` and `iot`, behind `INTERNAL_AUTH_TOKEN`.
- **#323** seventeen norms and sector pages removed (nginx: the `/compliance/*` locations go).
- this PR: the recurring layer needs an explicit `BILLING_MODE`.

`docker-compose.yml` is byte-identical between `41501bb` and main
(`git diff 41501bb origin/main -- docker-compose.yml` is empty). Every
environment variable this runbook mentions already has its line in the
`x-relay-env` block; nothing has to be added to the compose file, only to `.env`.

## The brake, and why the deploy is now allowed

Before this PR a deploy of main with `BILLING_MODE` empty and a `live_` key
would have created a Mollie customer, a `sequenceType: first` payment and a
subscription on the first sale, against the real account, with code that has
never seen a real Mollie answer. `billingMode()` inferred `live` from the key
prefix and that inference was enough for the new layer.

Now (`relay/lib/mollie.js`, `billingStance()`): the recurring layer runs only
when `BILLING_MODE` is set by hand to `live` or `test`. With it empty the relay
bills exactly as the 08-08 code did: a one-off payment, no customer, no
`sequenceType`, no subscription, and the webhook grants and stops there. The
one-off path itself has been live since 08-08 and is not new code.

The three stances, pinned by `relay/test/billing-stance.test.js` and
`relay/test/billing-stance-boot.test.js`:

| `.env` | mode | recurring | boot line level |
|---|---|---|---|
| `BILLING_MODE=` (empty) + `MOLLIE_API_KEY=live_...` | live | off | `warn` |
| `BILLING_MODE=test` + `MOLLIE_TEST_API_KEY=test_...` | test | on | `info` |
| `BILLING_MODE=live` + `MOLLIE_API_KEY=live_...` | live | on | `info` |

An explicit mode without its key boots at `error` and no checkout works, which
is the existing `mollie_key_missing` contract.

So: **leave `BILLING_MODE` empty for this deploy.** Turning the recurring
layer on is a separate decision, taken when there is a Mollie test key to
prove it against first. That is step 3 in the vault's order (deny, then
test key plus mode, then deploy) collapsed to: deploy now, decide later.

## A second brake: the delivery receipt moved out of the download header

**This precondition is dropped, and the version in it was wrong. It used to
read: `Apolloccrypt/paramant-sdk` PR #5 must be released to PyPI before main
reaches production. The release in question is **3.3.0**, not 3.2.1, and it
cannot reach PyPI: the project has no trusted publisher configured, which is a
setting in PyPI and not something this repository can fix. Reported
2026-09-02; not measured here. Waiting on it would hold the deploy for an
unknown time, so the deploy is decoupled from it and takes the first of the
two ways out below. `deploy/deploy-3.1.sh` does that automatically.**

Relay PR #342 takes the signed ParaSend delivery receipt out of the
`X-Paramant-Receipt` response header. It had to go: 18551 bytes for that one
header, over Node's 16 KB limit and over the default nginx proxy buffer, so a
client using `fetch()` could not download at all. The receipt is now fetched
from `GET /v2/transfers/:receipt_id/receipt`.

The out-of-tree Python SDK reads that header (`sdk-py/paramant_sdk.py:681`) and
turns an absent one into `receipt = None`, without an error. So a `3.2.0`
client against a deployed main keeps working and silently stops getting proof
of delivery. `paramant-sdk` 3.3.0 reads both shapes and fails loudly; that is
the release this deploy no longer waits for.

Two ways out if the release is not ready and the deploy cannot wait:

- Set `PARAMANT_INLINE_RECEIPT_HEADER=1` in the relay containers for this
  deploy. The old header comes back alongside the new reference, so old clients
  keep working. It then also needs `proxy_buffer_size` raised on the
  `/v2/outbound` locations in nginx, or the download is a 502; the repo copy of
  `deploy/nginx-paramant-public.conf` already carries that setting with a
  comment, the production conf does not.
- Or hold main. The default is off on purpose, because on a default nginx the
  fat header is a 502 rather than a feature.

This deploy takes the first way out, so the follow-up is a real step and not a
footnote: **once 3.3.0 is on PyPI, take `PARAMANT_INLINE_RECEIPT_HEADER` back
out of `/opt/paramant-relay/.env` and recreate the relays.** That is one line
and a `docker compose up -d --no-deps`, no deploy. The raised
`proxy_buffer_size` may stay; #342 calls it a margin rather than a fix.

Either way the flag is temporary: the old header is removed after
**2026-12-01**. While it is off, every download carries
`X-Paramant-Receipt-Deprecated` naming the new url, so a client that looks
finds out.

## Before you start (laptop or NUC, read-only)

1. CI on main is green: `gh run list --branch main -L 5`.
2. Local suites on the commit you will deploy, from the repo root:
   ```bash
   tests/static-sanity.sh                                   # the gate deploy.sh runs first
   cd relay && RELAY_TEST_SKIP=redis node --test $(ls test/*.test.js | grep -vE 'inbound-hash-verify|deep-health-gate|billing-stance-boot|parasign-sandbox|parasign-open-api-e2e|parasign-envelope-index')
   node --test test/billing-stance-boot.test.js             # needs relay/node_modules
   ```
   Expected on 2026-09-02: static sanity checks 1 to 9 `OK` and check 10
   `FAIL`, units 176 pass, boot suite 4 pass.

   **Check 10 is red on main and stays red for this deploy.** It runs
   `scripts/check-commit-style.sh` on the last commit only, and the squash
   commits of #322 and #323 (and of this PR) carry `Co-Authored-By` trailers
   that the guard flags; #323 also has an em-dash in an added line. Measured
   on `0fc8648`: exit 1, 36 `OK` lines, the one `FAIL` is check 10. So the
   gate for this deploy is checks 1 to 9: every one of them `OK`, and the
   only `FAIL` line the one under `10. Commit/GitHub style guard`. Any other
   `FAIL` blocks. Do not rewrite main's history to make check 10 green.
3. Frontend drift: `scripts/check-prod-drift.sh origin/main`. It lists what the
   docroot would receive. Anything marked as present on the server and absent
   in git that is not in its `IGNORE` list is a hand edit: find out before you
   overwrite it.
4. Note the time. The rollback tag in step 2 is named by it.

## Step 1: confirm the layout and the environment (server, read-only)

```bash
ssh -i ~/.ssh/paramant_prod_claude root@116.203.86.81

cd /opt/paramant-relay && git rev-parse --short HEAD        # expect 41501bb
docker compose ls                                            # which compose project, which file
docker compose ps                                            # six containers plus redis, all healthy

# Presence only, never the values. Same shape as the 01-09 measurement.
for v in BILLING_MODE MOLLIE_API_KEY MOLLIE_TEST_API_KEY INTERNAL_AUTH_TOKEN ADMIN_TOKEN PARAMANT_TOTP_MASTER_KEY RELAY_REDIS_URL; do
  printf '%-26s ' "$v"
  docker compose exec -T relay-main sh -c "v=\$(printenv $v); if [ -z \"\$v\" ]; then echo empty; else echo set, prefix \$(echo \$v | cut -c1-5); fi"
done
grep -c '^INTERNAL_AUTH_TOKEN=' .env
```

What has to be true before step 2:

| variable | needed for | required state |
|---|---|---|
| `INTERNAL_AUTH_TOKEN` | `/v2/health/deep` outside `full` mode (#322), and every internal user endpoint that already existed | set, in `.env`, so the compose `x-relay-env` block passes it to all five relays and to admin. Empty keeps `/v2/health/deep` closed, which is the #322 contract, but then step 5 cannot read it. |
| `BILLING_MODE` | the recurring layer | **empty**. Do not set it in this deploy. |
| `MOLLIE_API_KEY` | one-off checkout, as since 08-08 | set, `live_` prefix, unchanged |
| `PARASIGN_CANARY_KEY` | the hourly ParaSign canary in `product-heartbeat.yml` | not a relay variable: a GitHub Actions secret holding a `psk_test_` key with the parasign scope. See step 7. |

If `INTERNAL_AUTH_TOKEN` is empty: generate one (`openssl rand -hex 32`), add
`INTERNAL_AUTH_TOKEN=...` to `/opt/paramant-relay/.env`, and know that the
containers only pick it up when recreated in step 4. Do not restart anything
for it now.

## Step 2: tag the rollback images and back up the state (server)

This is what makes step 8 possible. Same procedure as the 3.0.0 runbook, with
the real compose directory.

```bash
cd /opt/paramant-relay
TS=$(date +%Y%m%d-%H%M)
mkdir -p /home/paramant/backups
MANIFEST=/home/paramant/backups/rollback-images-$TS.txt
: > "$MANIFEST"
for svc in relay-main relay-health relay-finance relay-legal relay-iot admin; do
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  [ -z "$cid" ] && { echo "skip $svc (not running)"; continue; }
  img=$(docker inspect --format '{{.Config.Image}}' "$cid")
  docker tag "$img" "paramant-rollback/$svc:$TS"
  echo "$svc|$img|paramant-rollback/$svc:$TS" >> "$MANIFEST"
done
ln -sfn "$MANIFEST" /home/paramant/backups/rollback-images-latest.txt
cat "$MANIFEST"                                              # six lines, or stop here

cp .env /home/paramant/backups/.env-pre-3.1-$TS && chmod 600 /home/paramant/backups/.env-pre-3.1-$TS
docker compose ps > /home/paramant/backups/state-pre-3.1-$TS.txt
tar czf /home/paramant/backups/docroot-pre-3.1-$TS.tgz -C /home/paramant app
cp /etc/nginx/sites-enabled/paramant-public.conf /etc/nginx/backups/paramant-public.conf.pre-3.1-$TS
```

`deploy/ops/backup-full-state.sh` exists for the data volumes; run it too if
the users file or the CT log matter to you today (they should).

## Step 3: pull main, run the sanity gate, build (server)

```bash
cd /opt/paramant-relay
git status                                                   # clean, or stash and note what it was
git fetch origin && git pull --ff-only origin main
git rev-parse --short HEAD                                   # the commit you tested locally

tests/static-sanity.sh; echo "exit $?"                       # expect exit 1: checks 1 to 9 OK, only check 10 FAIL
docker compose build                                         # relays and admin from source, containers untouched
```

Read the sanity output the way "Before you start" step 2 says: checks 1 to 9
are the gate, check 10 (the commit style guard on the last commit) is known
red on main and does not block. Anything else red blocks. This is also why
this runbook does not call `deploy.sh`: its step 1 runs the same script and
exits on the same check 10, so it would stop before building anything.

`.env` stays as it was, plus the `INTERNAL_AUTH_TOKEN` line from step 1 if it
was missing. **`BILLING_MODE` stays empty.**

## Step 4: recreate, one canary relay first (server)

The 06-24 deploy did `relay-iot` first, then the fleet; that order is kept. The
health wait is the loop from `deploy.sh` step 3 (`docker inspect` on
`.State.Health.Status`, compose healthcheck is `wget http://127.0.0.1:3000/health`).

```bash
cd /opt/paramant-relay
wait_healthy() {  # container name, max seconds
  local w=0; while [ $w -lt ${2:-60} ]; do
    s=$(docker inspect --format='{{.State.Health.Status}}' "$1" 2>/dev/null || echo unknown)
    [ "$s" = healthy ] && { echo "$1 healthy after ${w}s"; return 0; }
    [ "$s" = unhealthy ] && { echo "$1 UNHEALTHY"; docker logs "$1" 2>&1 | tail -20; return 1; }
    sleep 5; w=$((w+5)); done; echo "$1 not healthy after ${2:-60}s"; return 1; }

docker compose up -d --no-deps relay-iot
wait_healthy paramant-relay-iot || exit 1
docker logs paramant-relay-iot 2>&1 | grep -E '"relay_started"|"billing_config"'
```

The `billing_config` line is the first thing to read. Expected, verbatim in
shape:

```
{"level":"warn","msg":"billing_config","mode":"live","mode_source":"inferred","recurring":false,"key_present":true,"key_prefix":"live_","stance":"live: one-off payments only, no customers or subscriptions (BILLING_MODE not set)"}
```

`recurring:false` and `mode_source:inferred` are the brake. If it says
`recurring:true`, `BILLING_MODE` is set somewhere: stop, find it, and do not
continue until the line reads as above. `relay_started` must say
`version:"3.1.0"`.

Then the rest:

```bash
docker compose up -d --no-deps relay-main
wait_healthy paramant-relay-main || exit 1
docker compose up -d --no-deps relay-health relay-finance relay-legal admin
for c in health finance legal admin; do wait_healthy paramant-relay-$c || exit 1; done
```

## Step 5: frontend and nginx (server)

The docroot is a copy, not the checkout. Without `--delete`, on purpose:
`dist/`, `paramant-mark.svg`, `developer.js` and the investor brief live only
on the server (`scripts/check-prod-drift.sh`).

```bash
rsync -rc --no-times /opt/paramant-relay/frontend/ /home/paramant/app/
```

nginx: main changes three things in `deploy/nginx-paramant-live.conf`
(`/sign` no longer behind `auth_request`, the three `/compliance/*` locations
gone, `/dicom` now `return 404`) and removes the `/compliance` lines from
`deploy/nginx-paramant-public.conf`. The server files carry the 01-09 ParaID
deny that the repo files do not, so **do not copy the repo files over them**.
Apply the three changes by hand and keep the deny:

```bash
nginx -T 2>/dev/null | grep -n 'paraid/issue\|location = /sign\|/compliance\|location = /dicom'
# edit /etc/nginx/sites-enabled/paramant-public.conf and the live conf accordingly
nginx -t && systemctl reload nginx
```

The ParaID deny may stay: the route is gone from the relay (#319), so the
deny answers 404 for a path that would answer 404 anyway. Remove it in a later
round, not in this one.

## Step 6: smoke tests

In the order `deploy.sh` runs them, plus the two the 3.0.0 runbook used.

```bash
# 6a. deploy.sh step 4, from anywhere: public auth surface, never a 5xx
tests/auth-smoke.sh https://paramant.app

# 6b. the 3.0.0 verify suite, on the server so the local relay is reachable
bash scripts/post-deploy-verify.sh https://paramant.app http://127.0.0.1:3000
```

`post-deploy-verify.sh` still probes `/health/deep`, a path main does not
serve (the route is `/v2/health/deep`). That check is marked non-critical in
the script; expect it red and read the real one by hand:

```bash
# 6c. the deep check from #322: 200 with the token, 401 without
T=$(grep '^INTERNAL_AUTH_TOKEN=' /opt/paramant-relay/.env | cut -d= -f2-)
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/v2/health/deep                       # 401
curl -s -H "X-Internal-Auth: $T" http://127.0.0.1:3000/v2/health/deep | python3 -m json.tool | head  # overall green or yellow
unset T

# 6d. what #319 removed, on the public host and on a sector host
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://paramant.app/v1/paraid/issue-document       # 404
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://iot.paramant.app/v1/paraid/issue-document   # 404

# 6e. what #317 changed: /sign answers itself, no redirect to /auth/login
curl -s -o /dev/null -w '%{http_code}\n' https://paramant.app/sign                                   # 200

# 6f. the version the relay reports
curl -s https://paramant.app/health | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version"))'   # 3.1.0

# 6g. billing stance on every relay, once more, from the logs
for c in main health finance legal iot; do printf '%-8s' $c; docker logs paramant-relay-$c 2>&1 | grep '"billing_config"' | tail -1 | grep -o '"recurring":[a-z]*'; done
```

Stop and roll back (step 8) on: a relay that does not reach `healthy`,
`auth-smoke.sh` exit 1, `post-deploy-verify.sh` exit 2, `/health` without
`3.1.0`, or a `billing_config` line with `recurring:true`.

## Step 7: after the deploy

1. **Watch thirty minutes**: `docker compose logs -f --tail=200 relay-main`.
   5xx spikes are code, 4xx spikes are config, memory growth is a leak.
2. **The ParaSign canary.** On 2026-09-02 `gh api repos/Apolloccrypt/paramant-relay/actions/secrets`
   lists neither `PARASIGN_CANARY_KEY` nor `PARAMANT_CANARY_KEY`, so both keyed
   canary tests skip by name every hour. Mint a `psk_test_` key on the new
   relay, from the server, with the admin token:
   ```bash
   A=$(grep '^ADMIN_TOKEN=' /opt/paramant-relay/.env | cut -d= -f2-)
   curl -s -X POST http://127.0.0.1:3000/v2/admin/keys/mint-parasign \
     -H "X-Admin-Token: $A" -H 'Content-Type: application/json' \
     -d '{"account_id":"<the canary account>","test":true,"label":"parasign-canary"}'
   unset A
   ```
   The key is shown once (`relay.js`, `/v2/admin/keys/mint-parasign`). Then
   `gh secret set PARASIGN_CANARY_KEY` and trigger `product-heartbeat.yml` once
   with `workflow_dispatch`: expected 3 pass, 0 skip on the ParaSign canary.
   Every `/v2/admin` path is behind `X-Admin-Token` (`relay.js`, `isAdminPath`),
   and nginx answers 404 for it on the public host, so this only works on the
   server against `127.0.0.1:3000`.
3. **Drift guard** from the NUC: `scripts/check-prod-drift.sh origin/main` must
   print `OK`.
4. Tag it: `git tag v3.1.0 <commit> && git push origin v3.1.0`, and put the live
   date in `CHANGELOG.md`.
5. Write the deploy down in the vault (`Sessies/2026-09/`), with the
   `billing_config` line as it was logged.

## Deciding on the recurring layer, later, not today

This is a separate change with its own PR-free procedure, because it is one
line in `.env` and a recreate:

1. Get a Mollie test key. Set `MOLLIE_TEST_API_KEY=test_...` and
   `BILLING_MODE=test` in `.env`, `docker compose up -d --no-deps relay-main`,
   read the boot line (`mode:test`, `recurring:true`, `key_prefix:test_`), buy
   a plan on the test account, watch `billing_subscription` in the log, cancel
   it through `/v2/billing/cancel`. While `BILLING_MODE=test` no real customer
   can pay: this is a maintenance window, keep it short.
2. Only then `BILLING_MODE=live`, recreate, read the boot line again.

Never set `BILLING_MODE=live` as the first step: that is exactly the deploy
this brake exists to prevent.

## Step 8: rollback

Trigger: any of the stop conditions in step 6, or clear breakage in the first
thirty minutes.

From the NUC, with the `TS` that step 2 printed:

```bash
bash deploy/deploy-3.1.sh --rollback 20260902-1830
```

That reads the manifest of step 2, retags the saved images, recreates the
containers without rebuilding, restores `.env`, the nginx confs and the
docroot, and re-runs the smoke tests. By hand, on the server, the equivalent
is the 3.0.0 script, which asks before it restores `.env`:

```bash
cd /opt/paramant-relay
COMPOSE_DIR=/opt/paramant-relay BACKUP_DIR=/home/paramant/backups bash scripts/rollback-3.0.0.sh
```

The script reads `rollback-images-latest.txt` from step 2, retags the saved
images onto the compose image names, recreates the containers **without
rebuilding**, waits for `:3000/health`, and offers to restore `.env`. It does
not touch git; the checkout stays on main, which is fine, because the images
are what run. Confirm afterwards:

```bash
docker exec paramant-relay-main grep -c _paraidAuth /app/relay.js     # 0 again on the 08-08 image
curl -s http://127.0.0.1:3000/health | grep -o '"version":"[^"]*"'
```

Frontend and nginx, if step 5 was reached:

```bash
tar xzf /home/paramant/backups/docroot-pre-3.1-$TS.tgz -C /home/paramant
cp /etc/nginx/backups/paramant-public.conf.pre-3.1-$TS /etc/nginx/sites-enabled/paramant-public.conf
nginx -t && systemctl reload nginx
```

Manual fallback for a single service, from the 3.0.0 runbook:

```bash
docker images | grep paramant-rollback
IMG=$(docker inspect --format '{{.Config.Image}}' paramant-relay-main)
docker tag paramant-rollback/relay-main:<TS> "$IMG"
docker compose up -d --no-deps --force-recreate relay-main
```

`deploy.sh` itself prints `git revert HEAD && ./deploy.sh <container>` as its
rollback. That rebuilds from source and is slower; the tagged images are the
fast path.

## What this runbook does not do

- It does not deploy by itself. Every command above is one Mick runs, by hand
  or through `deploy/deploy-3.1.sh`, which runs exactly these steps and
  nothing more.
- It does not automate step 7. Watching the logs, minting the canary key,
  tagging the release and writing the deploy down stay hand work, because each
  needs a judgement the script cannot make.
- It does not set `BILLING_MODE`. The recurring layer stays off until there is
  a test key and a deliberate second change.
- It does not remove the ParaID nginx deny. Harmless while it stays, and its
  removal is a separate, reversible edit.
