# The hourly heartbeat

The alarm that goes off when a product stops working, before a customer finds
out. It runs every hour at :17 from `.github/workflows/heartbeat.yml` and the
checks themselves live in `scripts/heartbeat/`.

## Why it was rebuilt

Run 33624449015, on 2026-09-02, reported all four steps green. Two of them
proved nothing.

`node --test` prints a skipped test as `ok N - name # SKIP reason` and counts it
in `# pass`. Both canaries used `{ skip: KEY ? false : 'reason' }`, so a missing
secret meant a skip, a skip meant `ok`, and `ok` meant a green tick. The log
shows it plainly:

```
ok 1 - parasign: an envelope is created, signed and notarised # SKIP PARASIGN_CANARY_KEY not set
  duration_ms: 1.284603
ok 2 - parasign: the signed document comes back stamped # SKIP PARASIGN_CANARY_KEY not set
  duration_ms: 0.115257
# pass 1
# fail 0
# skipped 2
```

The duration is the part that cannot be argued with. Creating an envelope,
signing it and verifying an ML-DSA-65 signature does not take 1.28 milliseconds.
Nothing left the runner.

The failure filter had the same blind spot from the other side: it scanned the
log for `^(✖|not ok|  AssertionError|ℹ fail)`, and a skipped test begins with
`ok`. Invisible in both directions.

The one rule this rewrite is built on:

> A monitoring step may never have an escape hatch. If what it needs is missing,
> that is red, with the name of what is missing. A reason belongs in the error
> message, not in the verdict.

## What each step proves

Run them all with `node scripts/heartbeat/run.mjs`, or one at a time by name.

### `surface` - the public surface

| check | what a failure means |
| --- | --- |
| `GET /health` answers as the relay | not just a 200: the body must be JSON, must say it is healthy, and must carry a mode or a version. A status code alone is not a liveness check, because nginx, a cache, a maintenance page or a parked domain will all return 200 with a body that has nothing to do with the relay |
| `GET /v2/health/deep` unauthenticated | either the readiness check is still dropped by the mode allowlist (405, recorded and not fatal), or it is public because the relay runs in `full` mode, or its `X-Internal-Auth` gate answers 401. A 200 outside full mode would be an information leak: that endpoint publishes version, loaded keys, free disk and certificate age |
| `GET /v2/health/deep` with the token | the eight component checks (relay, crypto, storage, memory, disk, tls, users, audit) and their `overall` verdict. The handler answers HTTP 200 even when `overall` is red, so the body is what gets asserted, never the status code |
| six entrances x two ParaID issuance paths | the deny that closed the open credential-signing route on 2026-09-01 is still in place on all six hosts. 404 is green. 401, 403, 405 and 410 mean the route is refused but still present, which is recorded as a warning. A 400 means the handler parsed the body and rejected it on content, which is the exact signature of the hole being back |

The deny check is the one worth understanding. It was closed by hand, with
`location ~ ^/v1/paraid/issue- { return 404; }` inserted into all six server
blocks of `paramant-public.conf`. A hand-inserted nginx rule is what a config
restore, a deploy or a certbot reload quietly reverts, and four of the six hosts
log nothing at all, so nobody would ever see it come back. This checks it hourly
from outside.

### `parasend` - the file actually moves

Both routes, because only one of them was ever checked.

- anonymous (`POST /v2/anon-inbound`): upload, fetch, compare the bytes against
  the sha256 that went in, then fetch again and require 410. Burn-on-read is a
  promise on the front page, so "it is gone" is asserted like anything else.
- integrity: a payload that does not match its declared hash must be refused
  with `hash_mismatch` before storage.
- keyed (`POST /v2/inbound`, `GET /v2/outbound/:hash`): the same round trip a
  paying customer gets, plus `X-Paramant-Burned: true` and a second fetch that
  must not return 200.

Nothing is left behind: both blobs are destroyed by the reads that prove they
could be read.

### `parasign-receipt` - the evidence the product sells

The `/v1` developer API with a `psk_test_` key, where the sandbox auto-signer
completes the envelope inside the create call and produces a full `.psign`.

1. the envelope reaches `completed` with every slot filled
2. the receipt is a real `parasign-envelope-receipt` committing to the same
   document hash as the envelope
3. the notary counter-signature verifies **offline**, against the key published
   at `/v2/pubkey` and not the key printed inside the receipt. A receipt that
   only verifies against its own key proves nothing
4. every party's own signature verifies, with the sign message rebuilt by the
   relay's own `signMessageBytes`
5. a sandbox receipt says `mode: test` and `sandbox: true` inside the signed
   evidence, so a test receipt can never be passed off as a real one
6. the signed document comes back as a PDF with `X-ParaSign-Stamped: true`

Point 3 is the one that matters. A route can answer 200 with a receipt nobody
can verify, and that is exactly the failure a status page cannot see.

### `parasign-public-sign` - the ceremony a person walks

The `/v2` multi-party flow. Its sign route is public: no API key, no header,
exactly what a recipient's browser sends. The sandbox auto-signer never touches
it, so this is the only way to prove that the route a real person clicks still
works.

1. create the envelope and store the document capsule, and require the relay to
   agree on its hash
2. read the party view over the public route and check it carries the sign
   recipe and does not leak `invite_token`
3. **submit a signature that does not verify and require a 400 `bad_signature`.**
   This is the load-bearing negative: a relay that rubber-stamps would sail
   through every positive check ever written
4. sign for real over the public route, with the message built by the repo's own
   `signMessageBytes` at recipe v4 (open-mode slots are signer-bound)
5. verify that same signature offline against ML-DSA-65, independently of what
   the relay says
6. read the envelope back and require the signature to be recorded
7. check the CT log grew, carries a new `envelope_sign` leaf, and that leaf's
   Merkle inclusion proof folds to the published tree head, recomputed here with
   the repo's own `ctNodeHash`

The public CT projection carries no envelope id (deliberately, for privacy), so
step 7 identifies the entry by type and index window rather than by id. If the
CT log is not reachable at all that is recorded rather than asserted, because
not every relay mode has one and inventing a promise production never made is
its own kind of false alarm.

## Switching it on

**The hourly run is off until it is switched on, deliberately.** The job carries

```yaml
if: github.event_name == 'workflow_dispatch' || vars.HEARTBEAT_ENABLED == 'true'
```

so a scheduled run does nothing until the repository variable exists.

This is an order-of-operations problem, not caution. The alarm fails loudly when
a secret is missing, which is the whole point of it, and neither canary secret
exists yet. Merged without the gate it would go red at :17 every hour and
comment on the same issue twenty-four times a day, for a reason everybody
already knows. An alarm that cries every hour for a known reason is one people
learn to ignore, and that is how a monitor dies a second time.

Three commands, in this order:

```bash
# 1. the two required secrets, from the machine that holds the keys
gh secret set PARAMANT_CANARY_KEY    # a relay API key (pgp_)
gh secret set PARASIGN_CANARY_KEY    # a ParaSign bearer key (psk_test_)

# 2. try it by hand first. workflow_dispatch ignores the gate, so this runs
#    whether or not the variable exists, and tells you exactly what is missing
gh workflow run heartbeat.yml
gh run watch "$(gh run list --workflow=heartbeat.yml --limit 1 --json databaseId --jq '.[0].databaseId')"

# 3. only once that run is green, turn on the schedule
gh variable set HEARTBEAT_ENABLED --body true
```

Optional, and worth setting at the same time:

```bash
gh secret set PARAMANT_INTERNAL_AUTH_TOKEN   # matches INTERNAL_AUTH_TOKEN on the relay
gh label create heartbeat --description "the hourly production alarm" --color B60205
```

To switch it off again, without touching the workflow:

```bash
gh variable set HEARTBEAT_ENABLED --body false   # or: gh variable delete HEARTBEAT_ENABLED
```

Step 2 is not a formality. The first real run is the first time anything has
checked ParaSign against production, so it is also the first chance to find that
ParaSign has been broken for the eleven days nobody signed anything. Do it
watching the log, not on a schedule at three in the morning.

`scripts/directie/signalen.py` reads this switch before anything else. While it
is off, the directie report carries one orange `heartbeat` signal naming the
variable and whichever canary secret is still missing, rather than three canary
signals reporting nothing. Once it is on, that becomes three signals, one per
proof step, read out of the run's evidence artifact. See
[docs/directie.md](directie.md).

One thing follows the switch: `/sla` currently says the check "runs hourly once
enabled" and is "switched off until its credentials are in place". That stops
being true the moment `HEARTBEAT_ENABLED` is set, and `site-claims.test.mjs`
fails on it deliberately, in that direction, so the page cannot be forgotten.

## Secrets

| secret | required | why |
| --- | --- | --- |
| `PARAMANT_CANARY_KEY` | yes | a relay API key (`pgp_`). Used for the keyed ParaSend route and to create the `/v2` envelope. Without it, the paid transfer route and the whole public signing ceremony are untested |
| `PARASIGN_CANARY_KEY` | yes | a ParaSign bearer key, `psk_test_` so the sandbox signer drives it and the receipt is flagged as a test inside its own signed evidence. Without it there is no `.psign` and no notary signature to verify |
| `PARAMANT_INTERNAL_AUTH_TOKEN` | no | matches `INTERNAL_AUTH_TOKEN` on the relay. Without it the run still proves the deep-readiness gate is shut to the internet; with it, it also reads the eight component checks behind that gate. It is the only optional input, and it is optional only because something real is proven either way |

A missing required secret is a red run whose first line names the secret. It is
never a skip.

`psk_test_` matters for a second reason: the sandbox signer needs no human, no
mailbox and no real document, so an hourly check stays compatible with the
privacy promise the product is sold on. Nothing about a customer is read, sent
or stored, and every object the run creates is prefixed `canary-`.

The signing key needs headroom of roughly 1500 signatures a month. An hourly run
that hits its quota reports 402 and goes red, correctly but uselessly.

## Evidence

Every step writes `heartbeat-evidence/<step>.json` with the ids, hashes, request
statuses and timings it observed, plus `summary.json` for the run as a whole.
The directory is uploaded as an artifact on every run, green or red, and kept
for 30 days.

This is what makes the green tick mean something. `runStep` fails a step that
recorded no proof, even when nothing threw, so a step cannot pass by doing
nothing ever again.

A dry run is held to the same rule from the other side: it contacted nothing, so
`summary.ok` is false and the process exits 2 whatever its steps did. `steps_ok`
records separately that the wiring is sound. Exiting 0 after printing "nothing
is proven about production" would be the same species of lie this directory
exists to remove.

`scripts/heartbeat/` is itself covered by `tests/heartbeat-lib.test.mjs`, which
runs on every push. It pins the ML-DSA-65 argument order (including that the
wrong order throws rather than returning false, which is how the old canary's
bug stayed invisible), the recipe-v4 sign message, that a step recording no
proof fails, that a missing secret is a named failure and never a skip, and that
a dry run cannot exit 0. Nothing watched this directory before that file
existed, and a swapped verify order lived in it for a while as a result.

Response times are recorded for every request, pass or fail. A threshold that
only speaks when it trips gives no series to look at, and the first question
after an incident is always whether it had been creeping up. Budgets are 2500 ms
for ordinary requests and 15000 ms for signing, both overridable with
`HEARTBEAT_SLOW_MS` and `HEARTBEAT_SLOW_SIGN_MS`. The numbers come from
measurement: median round trip from the Netherlands on 2026-09-01 was 85 to 124
ms, worst sample 205 ms, and a GitHub runner adds roughly 150 ms of transit.

## When it goes red

- one line at the head of the run page, as a `::error::` annotation, naming the
  step and the cause
- the same line at the top of the job summary, with a table of every step
- one GitHub issue titled `Heartbeat rood`, labelled `heartbeat`. The lookup is
  over `state: all` and matches on the title: searching only open issues would
  find nothing after a green run had closed the last one, and would file a fresh
  issue for every red episode. A closed one is reopened and commented on; a
  green run comments and closes it again
- the workflow holds `issues: write` and `contents: read`, and nothing else

## Running it by hand

```
# every step, against production. Needs the secrets in your environment.
PARAMANT_CANARY_KEY=pgp_... PARASIGN_CANARY_KEY=psk_test_... \
  node scripts/heartbeat/run.mjs

# one step
node scripts/heartbeat/run.mjs surface

# the wiring only: no network, nothing contacted. It exits 2, never 0, and
# summary.ok is false however many steps passed, so a dry run can never be
# read as a green production run
HEARTBEAT_DRY_RUN=1 node scripts/heartbeat/run.mjs

# the failure path: no secrets set, expect red naming each one
HEARTBEAT_DRY_RUN=1 node scripts/heartbeat/run.mjs parasend
```

Or from the Actions tab: **heartbeat** has `workflow_dispatch`, which ignores the
`HEARTBEAT_ENABLED` gate, so a run can always be started by hand.

## Wie merkt het als deze zelftest zelf stilvalt

Deze workflow niet. Het alarm hierboven is een stap *in* de job die
`HEARTBEAT_ENABLED` uitzet, dus zolang die schakelaar uit staat wordt de job
overgeslagen, vuurt `if: failure()` nooit, en meldt niets dat er niets gemeten
wordt. Zo bleef het van 2 tot 5 september stil: negentien geplande runs op rij
overgeslagen, en een overgeslagen run is bij GitHub grijs, niet rood.

Dat is nu van buiten belegd bij [`guards.yml`](../.github/workflows/guards.yml),
die dagelijks kijkt of deze job werkelijk een geslaagde run heeft opgeleverd en
er anders één issue voor open zet. Zie [guards.md](guards.md).

Environment: `PARAMANT_RELAY_URL` (default `https://relay.paramant.app`),
`PARAMANT_BASE_URL` (default `https://paramant.app`), `HEARTBEAT_EVIDENCE_DIR`
(default `heartbeat-evidence`).

## What this does not cover

`product-heartbeat.yml` still runs the browser suite as the pull-request gate,
and the hourly job runs it too: the July 2026 breaks (a relative import 404, a
module loaded as a classic script, a CSP-blocked signup) failed only in a
browser console and were invisible to every HTTP check. External link
destinations are checked hourly for the same reason: a third party can delete a
page without telling anyone.

Nothing here measures usability. There is no error counter on the forms, no
drop-off measurement, no session length that means anything. That gap is real
and this does not close it.
