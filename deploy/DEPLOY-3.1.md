# Deploy runbook: main (3.1.0) to production

> `deploy/deploy-3.1.sh` executes this runbook. One command from the NUC
> (`bash deploy/deploy-3.1.sh`) runs every step below, prints the command and
> the measurement for each one, and stops at the first result the runbook did
> not predict. `--preflight-only` does the checks and nothing else,
> `--dry-run` prints every remote command instead of running it,
> `--rollback <TS>` is step 8, and `--verify-only` is steps 6 and 7 on a server
> that is already deployed. This file stays the readable source: the script
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

`docker-compose.yml` is **no longer** byte-identical between `41501bb` and
main, and that matters for this deploy. Two changes:

- #340 rewrote the version header comment.
- This PR adds `PARAMANT_INLINE_RECEIPT_HEADER` and the three
  `PARAMANT_RECEIPT_*` variables from #342 to the `x-relay-env` block.

That second one is not cosmetic. There is **no `env_file`** in
`docker-compose.yml`: `.env` only fills in `${VAR}` references inside the
compose file itself, so a variable without its own line in `x-relay-env`
never reaches a container, however carefully it is written into `.env`. The
four receipt variables had no line, so setting the inline-receipt opt-in in
`.env` alone would have done nothing at all.

Nothing has to be done by hand for this: step 3 pulls the new compose file
with the rest of main, and the step 4 recreate is what makes the containers
read it. `deploy/deploy-3.1.sh` proves it before recreating anything, with
`docker compose config` on the server: the flag has to render as
`PARAMANT_INLINE_RECEIPT_HEADER: "1"` on all five relays, or the deploy stops
there rather than at the smoke test with 3.1.0 already live.

Every other environment variable this runbook mentions already had its line.

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

1. CI on main is green, judged per workflow. `gh run list --branch main -L 5`
   is not the check: that window mixes workflows, so one red run of something
   that is red on purpose reads as "main is broken". On 2026-09-02 it stopped
   `--preflight-only` on a red `heartbeat` run, which is the hourly alarm
   reporting that its own two canary secrets are absent, and it waved through
   two runs that were still `in_progress`, because "in progress" is not the
   string "failure".

   ```bash
   for wf in test.yml csp-inline-check.yml sign-e2e.yml product-heartbeat.yml; do
     printf '%-24s ' "$wf"
     gh run list --workflow "$wf" --branch main --status completed -L 1 \
       --json conclusion --jq '.[0].conclusion // "NONE"'
   done
   ```

   Every one must print `success`. `NONE` (no completed run on main) blocks too.
   That list is every workflow in `.github/workflows` that runs on a push to
   `main` without a `paths:` filter. Not on it, on purpose:

   * `heartbeat.yml` does not run on push at all (schedule and
     `workflow_dispatch`, gated on `vars.HEARTBEAT_ENABLED`) and is red by its
     own design while the two canary secrets are missing: it has no skip, a
     missing secret fails and names the secret. Gating the deploy on it would
     mean no deploy until the alarm has its secrets.
   * `security-posture.yml` runs on pull requests, on a schedule and on
     `workflow_dispatch`, never on a push to `main`, and its live job is gated
     on `vars.SECURITY_POSTURE_ENABLED`. Its last completed run on `main` is the
     nightly external scan, and that scan is red on purpose: a missing CAA
     record, an unsigned zone, a duplicated HSTS header set by a layer above
     this repository, and one Rust advisory that carries no severity in any
     database and needs a human ruling. All of those describe the DNS zone or
     the server, not whether `main` is deployable. Its own gate, the selftest
     that drives all 109 measurements green once and red once, does run on every
     pull request, which is how every change reaches `main`.
   * `docker-publish.yml` and `build-image.yml` are path-gated on `relay/**`, so
     a commit that touches only the frontend produces no run at all and a hard
     "must be success" would block every such deploy. Neither is what this
     runbook deploys: step 4 recreates from the server's own checkout.

   A run of a required workflow that is still `in_progress` or `queued` on the
   sha you would deploy is not a pass, it is an answer that has not arrived.
   Wait for it with `gh run watch <id>`, at most 15 minutes, then judge what it
   became. `deploy/deploy-3.1.sh` phase 0a does exactly this and stops when a
   required workflow is still running after the wait.

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

cd /opt/paramant-relay && git rev-parse --short HEAD        # see "Which commit do we expect here" below
docker compose ls                                            # which compose project, which file
docker compose ps                                            # six containers plus redis, all healthy

# Presence only, never the values. Same shape as the 01-09 measurement.
for v in BILLING_MODE MOLLIE_API_KEY MOLLIE_TEST_API_KEY INTERNAL_AUTH_TOKEN ADMIN_TOKEN PARAMANT_TOTP_MASTER_KEY RELAY_REDIS_URL; do
  printf '%-26s ' "$v"
  docker compose exec -T relay-main sh -c "v=\$(printenv $v); if [ -z \"\$v\" ]; then echo empty; else echo set, prefix \$(echo \$v | cut -c1-5); fi"
done
grep -c '^INTERNAL_AUTH_TOKEN=' .env
```

### Which commit do we expect here

`41501bb` is where **this runbook** starts: the stand of 8 August, before any
3.1 deploy ran. It is not where the checkout stands after a deploy. After step
3 the checkout is on main, so a gate that only ever accepts `41501bb` makes the
whole procedure single-use: the second deploy stops on this line, and so does
every resume of a run that died halfway through step 5.

So `deploy/deploy-3.1.sh` treats the expected commit as a parameter with three
sources, most specific first.

| source | when it applies | what it demands |
|---|---|---|
| `PARAMANT_EXPECTED_HEAD=<commit>` | you set it | the checkout equals it, and nothing else is consulted |
| `/home/paramant/backups/deployed-head` | the file exists on the server | the checkout equals what that file names, **and** that commit is an ancestor of the deploy ref (`git merge-base --is-ancestor`, after a `git fetch`) |
| `41501bb` | no marker, so no deploy has ever finished here | the checkout equals `41501bb`, the runbook's own starting point |

The marker is written by step 7, by the script, with the commit the checkout is
actually on. The ancestor test is what keeps the second and later runs honest:
equal to the marker says nothing moved the checkout outside a deploy, and
ancestor of the ref says the fast-forward pull in step 3 can reach the ref from
here. Both have to hold; either alone lets a deploy start from a commit the ref
does not contain.

A short sha and a full sha of the same commit count as equal. Anything shorter
than seven characters is not an identification and never matches.

If the checkout has moved and you know why, say so:
`PARAMANT_EXPECTED_HEAD=<commit> bash deploy/deploy-3.1.sh`. That is the escape
hatch, and it is deliberately explicit: it accepts equality and skips the
ancestor test, so it is the one place where a human overrules the measurement.

The rollback (step 8) does **not** rewrite the marker. It restores images,
`.env`, nginx and the docroot and leaves the checkout where it stands, and the
marker names the checkout. If you move the checkout back by hand afterwards,
either write that commit into the marker or run the next deploy with
`PARAMANT_EXPECTED_HEAD`.

What has to be true before step 2:

| variable | needed for | required state |
|---|---|---|
| `INTERNAL_AUTH_TOKEN` | `/v2/health/deep` outside `full` mode (#322), and every internal user endpoint that already existed | set, in `.env`, so the compose `x-relay-env` block passes it to all five relays and to admin. Empty keeps `/v2/health/deep` closed, which is the #322 contract, but then step 5 cannot read it. |
| `BILLING_MODE` | the recurring layer | **empty**. Do not set it in this deploy. |
| `MOLLIE_API_KEY` | one-off checkout, as since 08-08 | set, `live_` prefix, unchanged |
| `PARASIGN_CANARY_KEY` | the hourly ParaSign canary in `product-heartbeat.yml` | not a relay variable: a GitHub Actions secret holding a `psk_test_` key with the parasign scope. See step 7. |
| `BILLING_SELLER_ADDRESS` | the supplier address on every invoice | set, with `\n` between lines. Empty prints an empty address block, which makes the document invalid under Wet OB art. 35a. |
| `BILLING_SELLER_VAT` | whether a paid customer gets an invoice or a receipt | **not known yet.** Leave empty until the btw-id is on file. See below. |

If `INTERNAL_AUTH_TOKEN` is empty: generate one (`openssl rand -hex 32`), add
`INTERNAL_AUTH_TOKEN=...` to `/opt/paramant-relay/.env`, and know that the
containers only pick it up when recreated in step 4. Do not restart anything
for it now.

### Invoices: the four seller variables

Since this deploy the relay issues one numbered document per paid Mollie
payment. The number comes from a redis counter per calendar year
(`PS-2026-0001`), the record is kept in redis without a TTL because bookkeeping
retention is seven years, and the PDF is mailed to the account address through
the existing Resend key. Nothing about the payment path itself changes.

| variable | default | what it does |
|---|---|---|
| `BILLING_SELLER_NAME` | `Paramantis Solutions B.V.` | the name on the document |
| `BILLING_SELLER_ADDRESS` | empty | the address block; `\n` separates lines |
| `BILLING_SELLER_KVK` | `42115132` | printed in the footer (Handelsregisterwet art. 25) |
| `BILLING_SELLER_VAT` | empty | the btw-id; **decides what the document is** |

`BILLING_SELLER_VAT` is the one that matters. A document without the supplier's
VAT identification number is not an invoice, and a customer who files it cannot
deduct the VAT. So while the variable is empty the relay does not pretend:

- the document is titled **Payment receipt**, not Invoice;
- it carries the line *Invoice with VAT number follows*;
- the relay logs one `billing_invoice_no_vat_number` warning per process, not
  one per payment;
- the customer still gets the PDF, still sees it on `/account`, and the record
  is still kept.

Set the variable and every document issued after the restart is a full VAT
invoice. Documents already issued keep the form they were issued in on purpose:
an invoice is a record of what was sent, not a template that reprints.

Verify after the deploy, on any relay container:

```
docker compose exec relay-main printenv | grep BILLING_SELLER
```

and, once a real payment has come in, that the log line says `result:"issued"`:

```
docker compose logs relay-main --since 1h | grep billing_invoice
```

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

### The nginx conf names are not the same on every server

Step 2b backs up the nginx confs, and it needs their names. Those names differ
per machine. On the run of 03-09 production had
`/etc/nginx/sites-enabled/paramant-public.conf` and no `paramant-live.conf` at
all: `deploy/signup-fix-deploy.sh` edits `paramant.conf` on that same host, so
the backend conf is called `paramant.conf` there.

The script therefore works with conf **slots** instead of fixed names. A slot
is a list of candidate names separated by `|`, slots are separated by
whitespace, and the default is

```
paramant-public.conf paramant-live.conf|paramant.conf
```

On the server the first candidate of each slot that is really in
`sites-enabled` is chosen, and the choice is written to the log as

```
nginxconf paramant-public.conf resolved to paramant-public.conf
nginxconf paramant-live.conf resolved to paramant.conf
```

A slot is always named after its first candidate, so the left half of that line
is the same everywhere and the right half is what this server actually calls
it. Every step that names a conf file uses the resolved name: the backup in 2b,
the edits in 5c, and both rollback steps in 8. The backups are filed under the
resolved name (`paramant.conf.pre-3.1-$TS`), and step 8 resolves the same way,
so a rollback looks for the file that is really there.

Step 6 is not in that list, and does not need to be. It reads `nginx -T`, the
config that is actually loaded, and probes the site over HTTP. Neither knows or
cares what the file on disk is called, so a rename cannot make step 6 measure
the wrong thing. (The commit message of #376 said step 6 used the resolved name
as well; that was wrong, and this is the correction.)

Step 5c also refuses to edit a conf that has no 2b backup under this run's TS.
2b and 5c resolve independently, each asking the server what is there when it
runs, and phases 3 and 4 sit in between. If sites-enabled is rearranged in that
window, 5c would otherwise edit a conf nothing had backed up, and every FATAL
in 5c calls a restore that can only put back what was filed. The check sits
before the first `sed`, so a run that hits it has written nothing:

```
FATAL no phase 2b backup /etc/nginx/backups/paramant.conf.pre-3.1-$TS for paramant.conf, which this phase would edit
before confs without a backup = 1
```

Run step 2 again for that TS, or start the deploy over so 2b backs up the confs
that are there now.

If no candidate of a slot is present the run stops in 2b with

```
nginxconf paramant-live.conf ABSENT, none of these is in /etc/nginx/sites-enabled: paramant-live.conf paramant.conf
```

and the hint to set `PARAMANT_NGINX_CONFS`. That variable still overrides the
whole list, now in the slot syntax:

```bash
PARAMANT_NGINX_CONFS="paramant-public.conf paramant.conf" deploy/deploy-3.1.sh
```

`paramant.conf` as a candidate is an assumption drawn from
`deploy/signup-fix-deploy.sh`, not a confirmed reading of the live server. The
script does not rely on the assumption being right: it checks on the server
each run and says which name it landed on.

`deploy/ops/backup-full-state.sh` exists for the data volumes; run it too if
the users file or the CT log matter to you today (they should).

## Step 3: pull main, run the sanity gate, build (server)

```bash
cd /opt/paramant-relay
git status --porcelain --untracked-files=no                  # empty, or stash and note what it was
git fetch origin && git pull --ff-only origin main
git rev-parse --short HEAD                                   # the commit you tested locally

tests/static-sanity.sh; echo "exit $?"                       # expect exit 1: checks 1 to 9 OK, only check 10 FAIL
docker compose build                                         # relays and admin from source, containers untouched
```

### What counts as a dirty working tree in 3a

Only **tracked** changes. A modified tracked file stops the run, before the
fetch, because a fast-forward pull would tangle it with what is coming in and
the log would then report a merge conflict instead of the hand edit that caused
it. Untracked paths are listed and left alone: `git pull --ff-only` cannot lose
one.

3a prints both counts, so the log says which of the two it judged:

```
before untracked paths = 1
  untracked backups/
before tracked changes = 0
```

Deploy run 5 (TS 20260903-0242) stopped here on `dirty ?? backups/`, an
untracked directory in `/opt/paramant-relay` and nothing else wrong. No script
in this repo writes a relative `backups/` (`deploy/ops/backup-full-state.sh`
defaults to an absolute `/home/paramant/backups/full-state`), so what put it
there is **not established**; a `BACKUP_ROOT` or `BACKUP_DIR` override on the
server is the likely candidate. `backups/` is in the repo `.gitignore` from
this commit on, so once the server has pulled it, 3a stops reporting it at all.

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
`deploy/nginx-paramant-public.conf`. **Step 5c has a fourth edit since the two-product-names round**:
the rules page moved from `/pararules` to `/rules`, so every server block that
answers for the site gains

```nginx
location = /pararules { return 301 https://$host/rules; }
```

That one is an addition, not a rewrite, and it is permanent: `/pararules` is
indexed, so the redirect is not a migration step that gets tidied away in a
later round. It is in both repo confs already, and the script writes it into
the server confs itself, anchored on the ParaID deny (`paramant-live.conf`
carries no `server_name`, so the hostname is not usable as an anchor there).
It is idempotent: a block that already has the line is left alone. If you are
doing step 5c by hand instead of through the script, this is the line to add.

**And a sixth edit, on the `:8090` block that backs `/dicom/`**:

```nginx
server {
    listen 127.0.0.1:8090;
    access_log off;          # <- this line
```

It was the only server block in `paramant-live.conf` still writing a combined
line, and /security claims logging is off on every block that serves the site.
#374 put it in the repo conf and could go no further, because 5c edits the live
confs by anchor and never copies a repo file over them: without an edit of its
own the line does not travel with a deploy. What it was recording is the
request line, the URI, the timing, the status, the referrer and the user-agent
of each `/dicom/` call, **not** the client IP: `set_real_ip_from` and
`real_ip_header` live in the `:8080` block and `location /dicom/` forwards no
`X-Real-IP`, so `$remote_addr` here is `127.0.0.1` on every request.

The anchor is the `listen` line itself, because this block carries neither a
`server_name` nor the ParaID deny that the other five edits key on. In practice
that means slot 2, the live conf: `paramant-public.conf` has no `:8090` block,
so the edit is a no-op there. Two passes, like the buffers and the `/pararules`
301, so a block that already has the line is left untouched.

A `:8090` block that logs to a **file** is refused, not edited. The phase
prints `before 8090 blocks logging to a file` and stops if that is not zero.
`access_log off;` written above an `access_log /var/log/nginx/dicom.log;` would
leave two `access_log` directives on the same level and would undo a log
somebody put there on purpose. Neither is a deploy's call: decide by hand which
of the two the block should have, then run the phase again.

### What the block counters do not see: an indented `server {`

Both block-counting edits, the `/pararules` 301 and this one, walk the conf by
counting `^server[[:space:]]*{`. That anchor is pinned to **column 0**. Every
`server` block in both confs and in the repo files starts there, and nginx
config written by hand or by this repo has always looked like that, so the
count is right for the confs that exist today. It is a convention, not a rule
nginx enforces: nginx would happily read

```nginx
    server {
        listen 127.0.0.1:8090;
    }
```

and both counters would miss it. What that means in practice is that an
indented block is invisible to the walk, not that it gets edited wrongly: an
unseen block is never counted and never written into, and the after-counters
then agree with the before-counters, so the phase passes with the block
untouched. If a conf on some server ever indents its `server` blocks, the
counts are the thing to read: `before 8090 blocks = 0` on a server that does
have the gateway is the symptom, and the anchor is what needs widening.

The server files carry the 01-09 ParaID deny that the repo files do not, so
**do not copy the repo files over them**. Apply the six changes by hand and
keep the deny:

```bash
nginx -T 2>/dev/null | grep -n 'paraid/issue\|location = /sign\|/compliance\|location = /dicom\|/pararules\|127.0.0.1:8090'
# edit /etc/nginx/sites-enabled/paramant-public.conf and the backend conf accordingly
nginx -t && systemctl reload nginx
```

Which files those are is the slot question from step 2: the backend conf is
`paramant-live.conf` on one server and `paramant.conf` on another. 5c resolves
the slots exactly as 2b did and prints the same `nginxconf <slot> resolved to
<name>` lines before it touches anything, followed by a `target <name> -> <path>`
line per conf. Read those two first: they say which files the six edits are
about to land in. A slot with no candidate at all is FATAL here, and a resolved
conf without the ParaID deny is FATAL too, with the resolved names in the
message.

The ParaID deny may stay: the route is gone from the relay (#319), so the
deny answers 404 for a path that would answer 404 anyway. Remove it in a later
round, not in this one.

### Running step 5 twice

All six nginx changes are idempotent, and the script reads the three rewrites
as being in one of three states before it edits anything. The three additions,
the `/v2/outbound` buffers, the `/pararules` 301 and `access_log off` on
`:8090`, are counted per block instead: a block that lacks one is a pending
edit, a block that has one is left untouched.

| state | what the conf carries | what happens |
|---|---|---|
| `todo` | the old shape (`auth_request` on `/sign`, a `/compliance` location, `try_files /dicom.html`) | the edit runs |
| `done` | the old shape is gone and the wanted shape is there (`location = /sign` without `auth_request`, no `/compliance` locations, `location = /dicom { return 404; }`) | reported as **already applied**, no error |
| `unknown` | neither shape | `FATAL`, because this is not the conf the runbook describes and editing it further would be editing blind |

The `/sign` state is read per **block**, not per line. The sed edit removes the
one-line spelling the repo conf uses, and a grep for that line is blind to a
hand edit that put the gate back across several lines:

```nginx
location = /sign {
    auth_request /api/user/check;
    error_page 401 = @login_redirect;
    try_files /sign.html =404;
}
```

A line-based read calls that `done` and reports **already applied** while
`/sign` is behind the login again. An awk walk over the `location = /sign`
block, brace depth and all, sees the `auth_request` wherever it sits, so this
reads as `todo`. The one-line sed still cannot remove it, and that is the
point: the phase then stops with a `FATAL` that names the multi-line spelling
and asks for a hand edit, instead of shipping a gated `/sign` as a success.

Only `unknown` stops the deploy. The older script read "nothing to do" as
`FATAL` outright, which meant the second deploy died on an edit that had simply
already succeeded. The removal of the docroot files main deleted (step 5b)
already worked this way: a file that is already gone is counted as *already
absent*, not as a failure.

What is asserted after the edits is where the weight sits: no `auth_request` on
`/sign`, zero `/compliance` locations, `/dicom` answering `return 404`, the
ParaID deny still present, `proxy_buffer_size 32k` inside **every**
`location ~ ^/v2/outbound` block, the `/pararules` 301 inside **every** site
block, `access_log off` inside **every** `:8090` block, and `nginx -t` clean
before the reload. A run that changed nothing still tests and reloads nginx, so a hand
edit made between deploys cannot hide behind "already applied".

### Step 5d: the limit_req zones, from a tracked file

Both site confs rate limit on named zones (`relay_auth`, `relay_trial`,
`relay_inbound`, `relay_outbound`, `api`) and neither conf defines one, because
`limit_req_zone` is an http-level directive and a `server {}` block is not that
level. On the live server all five were typed into `/etc/nginx/nginx.conf` by
hand, so nothing in the repo said what they were: a conf review could not see
them, and a rebuilt server would have had locations pointing at zones that did
not exist.

`deploy/nginx/snippets/paramant-limit-req.conf` is now that record, and step 5d
places it at `/etc/nginx/conf.d/paramant-limit-req.conf`
(`PARAMANT_LIMIT_REQ_DEST` overrides the path). The rates are the ones the
tracked self-host config already sets for the same jobs; the rates on the live
server were never in the repo and the snippet does not guess at them.

A zone may be bound only **once**. A second `limit_req_zone` with a name that
is already bound is not a warning, it is a config nginx refuses to load. So 5d
does not copy the file blindly:

1. it reads `nginx -T`, the config nginx really loads, minus the destination
   file itself, and collects the zone names that are already bound there
2. it writes the snippet with those lines commented out, each with a line
   saying which zone was left where it was
3. `nginx -t`, and on failure the previous file goes back, byte for byte (or
   is removed again when there was none), then a reload of the old config
4. `nginx -T` again, to prove the file it wrote is in the list of files nginx
   loaded. A file in a directory no `include` reaches passes `nginx -t` and
   defines nothing, and only the dump tells those two apart
5. every zone the resolved site confs reference has to be bound in that dump.
   This is the check that catches `relay_auth` disappearing out of a
   hand-edited `nginx.conf` while `/api/user/` still limits on it

On the server as it stands all five names are already bound in `nginx.conf`, so
the phase writes a file that changes no rate and says so:
`after zone lines written = 0`, `after zone lines left elsewhere = 5`. Move a
zone out of `nginx.conf` and the next deploy supplies it from the snippet
instead. The counters to read are `before duplicate zones`,
`after zone lines written`, `after snippet loaded` and
`after zones referenced and undefined`.

Doing it by hand:

```bash
nginx -T 2>/dev/null | grep -c 'limit_req_zone .* zone=relay_auth'   # must be 1, never 2
```

## Step 6: smoke tests

In the order `deploy.sh` runs them, plus the two the 3.0.0 runbook used.

### Finishing a deploy that died in the checks: `--verify-only`

Steps 3, 4 and 5 do the work; step 6 measures it and step 7 writes the
deployed-head marker the next run gates on. A deploy that lands the work and
then dies in a check leaves the server correct and the marker missing, which
stops the NEXT run in 1a. Deploy run 6 (TS 20260903-0259) is that case: six
containers on 3.1.0, the nginx edits applied, the site live, and then 6h
stopped on a swallowed line, so 6h, 6i and the 7a marker never happened.

```bash
bash deploy/deploy-3.1.sh --verify-only
```

runs phases 6 and 7 and nothing else. No tags, no backups, no pull, no build,
no recreate, no nginx edit, no `.env` write. Redoing the whole script for two
checks and one marker would rebuild and recreate six healthy containers.

It gates first, in the spirit of 1a, and refuses if the server is not already
deployed:

- the deployed commit is **on the mainline**: `git merge-base --is-ancestor
  HEAD $DEPLOY_REF`, asked after a fetch so the ref is real
- `/health` reports the same version as `package.json` in that checkout, which
  is what says the running containers were built from it

Either one off and the mode stops with "Run the full deploy instead".

**Behind the tip is normal, not a fault.** main moves while a deploy runs. Run
6 deployed `4e6de0b` and `origin/main` was already on `05bbd1b` by the time
this mode existed, so a gate demanding equality would have refused exactly the
state it was written for. Being *beside* the mainline is the real problem,
because then nobody can say what is running. So the ancestor test is the gate
and the difference from the tip is a note:

```
  note  checkout is on 4e6de0b, origin/main is 05bbd1b; this mode signs off on the DEPLOYED commit
  note  so the deployed-head marker will name 4e6de0b, which is what the next run gates on
```

The marker phase 7a writes names the commit the checkout is **on**, not the tip
of the ref. That is the commit that is actually deployed, and it is what the
next run's phase 1a gates on; a later full run fast-forwards from there.

`PARAMANT_VERIFY_HEAD=<sha>` names the deployed commit yourself, the way
`PARAMANT_EXPECTED_HEAD` does in 1a, and likewise skips the test it replaces:
the mainline check. The version check still runs.

The ref is `$DEPLOY_REF`, so `DEPLOY_REF=origin/release bash
deploy/deploy-3.1.sh --verify-only` gates against that instead. It does not
combine with `--preflight-only` or `--rollback`; those three are separate runs
and the script exits 2 if you ask for two of them.

```bash
# 6a. deploy.sh step 4, from anywhere: public auth surface, never a 5xx
tests/auth-smoke.sh https://paramant.app

# 6b. the 3.0.0 verify suite, on the server so the local relay is reachable
bash scripts/post-deploy-verify.sh https://paramant.app http://127.0.0.1:3000
```

`post-deploy-verify.sh` used to probe `/health/deep`, a path the relay has
never served (the route is `/v2/health/deep`), so it answered 404 on every run
and the suite could never exit 0. It now asks `/v2/health/deep` and expects the
`401` the #322 gate gives a caller with no token, which is the strongest thing
that script can prove: it reads no `.env` and takes no secret on its command
line. Phase 6g therefore stops the deploy on **any** non-zero exit, not only on
exit 2.

Because 6g is hard, the probes retry. The shared curl carries
`--retry 2 --retry-delay 2 --retry-all-errors`, and `http_code` asks once more,
from scratch, when the answer is still `000`. `000` is not a status the server
sent: it is what curl writes when the transfer never produced a status line at
all. Without that, one CDN hiccup, one 429 or one DNS blip ends a deploy that
is entirely healthy, and it ends it after the work landed and before 6h, 6i and
the phase 7a marker, which is deploy run 6 all over again. A real status is
never retried, so a genuine 503 stays a 503 and does not become a slow one.

The authenticated `200` is step 6c, which does have the token:

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
`3.1.0`, or a `billing_config` line with `recurring:true`. A
`post-deploy-verify.sh` exit 1 stops the script too, but it is a non-critical
failure: read the list, fix it, do not roll back on it.

## A rule for every remote block: `</dev/null`

The script sends each remote step as a heredoc piped into `ssh ... bash -s`.
That means the script text **is** the remote shell's stdin, and bash reads it
lazily, one compound command at a time. Any command in that block that reads
stdin therefore eats the rest of the script.

Run 6 stopped in 6h on "the server never printed 'effective outbound
buffers'". The measurement was fine; the line had been swallowed by

```bash
docker compose exec -T "$svc" sh -c '...'      # no </dev/null: reads stdin
```

The two lines above it came out normally, because the whole `for` loop was
parsed before it ran, which is why the log read like a failed measurement and
not like a truncated script.

So: **every stdin-reading command inside a remote heredoc gets `</dev/null`**.
Two families:

- **always reads, whatever its arguments**: `docker compose exec`,
  `docker compose run`, `docker exec`, `docker run`, a nested `ssh`, and
  `xargs`. `xargs rm -f` is not xargs-with-an-operand, it is xargs reading
  stdin.
- **reads only when given no file**: `cat`, `sort`, `wc`, `python -`,
  `node -`, and any `read`. `cat "$f"` and `wc -l < "$f"` are fine; `cat` and
  `wc -l` on their own are not.

A command to the **right of a pipe** reads the pipe, not the script, so
`... | wc -l` is fine and `wc -l` alone is not. A `read` in a loop that is
already redirected (`done < "$file"`, `done < <(...)`) or fed by a here-string
is fine as it is.

`tests/deploy-3.1-dryrun.test.sh` scans every remote block in the script for
this and fails on a command that lacks it. It also pins the number of blocks it
walked, so an extraction that silently loses half the script fails instead of
passing on an empty search.

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

`deploy/deploy-3.1.sh` does one write of its own here, before the summary: it
records the commit the checkout ended on in
`/home/paramant/backups/deployed-head`. That file is the whole reason a second
deploy can start (see "Which commit do we expect here" under step 1). Doing it
by hand comes down to:

```bash
cd /opt/paramant-relay && git rev-parse HEAD > /home/paramant/backups/deployed-head
```

Without it the next run has no marker, falls back to `41501bb`, and stops.

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

The backups in `/etc/nginx/backups/` carry the name step 2b resolved, so on a
server whose backend conf is `paramant.conf` the second file is
`paramant.conf.pre-3.1-$TS` and it goes back to
`/etc/nginx/sites-enabled/paramant.conf`. `ls /etc/nginx/backups/` says which
names were filed. The script does this resolution itself in step 8, and stops
before it writes anything if a backup under the resolved name is missing.

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

### Deploying again after a rollback

A rollback leaves the server in a state that reads like a finished deploy but
is not one, and step 5b is where that bites.

The tar restore puts the **whole** pre-3.1 docroot back, including all 26 pages
main deleted. The checkout is untouched, so it stays on main, and so does the
deployed-head marker. A step 5b that diffed `marker..HEAD` would find that main
deleted nothing since the commit the marker names, prune nothing, and leave the
26 pages served. Step 6e then dies on `/compliance/nis2` answering `200`, with
the containers, `.env` and nginx already live. That is the worst place to find
out.

So 5b never diffs against the marker alone. It takes the **older** of the
deployed commit and `41501bb`, which in practice means it diffs `41501bb..HEAD`
on every run. The server decides which is older, with
`git merge-base --is-ancestor`, because only the server has both commits. The
choice is printed as `before base choice` and the answer as `before prune base`.

Pruning something that is already gone costs nothing, so the normal answer on a
healthy second deploy is:

```
after removed = 0
after already absent = 26
```

and after a rollback it is `after removed = 26` instead. Both are fine. What is
not fine is a delete list of zero on a docroot that still serves the pages, and
that is the case the floor removes.

The same applies if you move the checkout back by hand during a rollback: put
that commit in the marker, or run the next deploy with
`PARAMANT_EXPECTED_HEAD`. The prune base is unaffected either way, because the
floor is older than both.

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
