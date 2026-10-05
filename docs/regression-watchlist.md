# Auth Stack Regression Watchlist

Three bugs reached production silently in the week of 2026-04-20. In each case,
shallow healthchecks returned 200 while the actual signup → TOTP setup → login
sequence was broken for every new user. This document captures the bug classes
so they don't repeat.

---

## Bug #1 — Response shape change: email field dropped from GET /v2/admin/keys

**Commit fixed:** c7dd74b

**What happened:**  
A refactor of the admin keys endpoint (`relay.js` → `GET /v2/admin/keys`) removed
the `email` field from the per-key object in the response. The admin UI, the
key-management pages, and any downstream consumer expecting `key.email` silently
received `null` or a JS `undefined`, breaking email-based lookups without any
explicit error.

**Why it regresses:**  
Response shape changes are invisible to callers unless the shape is tested.
The relay returns `200 OK` regardless of whether optional fields are present.
No existing test checked the returned object's schema — only that the endpoint
was reachable.

**How `e2e-auth-flow.sh` catches it (Test A):**  
`GET /v2/admin/keys` is called with the admin token and the response is parsed with
`python3`. The test asserts that *every* entry in the `keys` array contains the
`email` key (even if its value is `null`). If the field disappears from the object,
the test fails immediately.

**Code location:** `relay/relay.js` — search for `GET /v2/admin/keys`

---

## Bug #2 — Orphan code: admin container crashed on startup with ReferenceError

**Commit fixed:** c7dd74b

**What happened:**  
Dead code from the retired `/request-key` trial flow in `admin/server.js`
referenced a function that no longer existed in scope. The admin container started,
passed its HTTP healthcheck (`/admin/`), but then crashed with a `ReferenceError`
the first time a code path triggered the stale reference. Because the crash happened
inside a request handler rather than at startup, the container remained "healthy"
in docker's view while silently dropping requests.

**Why it regresses:**  
Post-deploy healthchecks that only ping an HTTP endpoint cannot distinguish a
fully-functional container from one that crashes on specific code paths. Orphan
code accumulates during refactors and is easy to miss in review.

**How `e2e-auth-flow.sh` catches it (Test B):**  
`docker logs paramant-relay-admin --since 1h` is scanned for `ReferenceError`.
Any occurrence fails the test. This is a blunt check but sufficient: a
ReferenceError in the admin process means a code path is broken.

**What to do when refactoring:**  
Search for all references to a function before removing it. Use
`grep -rn 'functionName' admin/` before deleting.

---

## Bug #3 — Uninitialized client: redisClient was `null`, verifyTotpGeneric missing

**Commit fixed:** afb80c7

**What happened:**  
Two related issues in `relay/relay.js`:
1. `redisClient` was declared but never initialized — the `createClient()` call
   and `connect()` were missing, leaving it as `null`. Any call to
   `redisClient.get(...)` or `redisClient.set(...)` threw `TypeError: Cannot
   read properties of null`.
2. `verifyTotpGeneric()` was referenced in the TOTP verification path but was
   not defined in the file. Any verify-totp call threw `ReferenceError:
   verifyTotpGeneric is not defined`.

Both bugs affected every user attempting TOTP setup or login. The relay returned
500, but since the admin UI caught the error and displayed a generic message, the
failure was not immediately obvious.

**Why it regresses:**  
Redis clients, database connections, and external service clients initialized at
module load time can be silently left as `null` during a refactor or merge conflict
resolution. Missing function definitions produce `ReferenceError` only at call time,
not at startup.

**How `e2e-auth-flow.sh` catches it (Tests C and D):**  
- **Test C** (`POST /v2/user/setup-totp`): Calls the endpoint with `provisional:true`
  for the test user. A live response of `{secret: ...}` or `{error: "totp_already_configured"}`
  proves redis is connected and the function exists. A 500 proves one of them is broken.
- **Test D** (`POST /v2/user/verify-totp`): Calls the endpoint with a deliberately wrong
  TOTP code. Any non-500 response (e.g. `{valid: false}`) proves `verifyTotpGeneric`
  is defined and redis is reachable.

**Code location:** `relay/relay.js` — `RELAY_REDIS_URL` block (line ~47) and
`async function verifyTotpGeneric` (line ~802).

---

## Bug #4 - A store that is gone, and a route that never answers

**Found:** review of #368, 2026-09-03. **Fixed on:** `fix/auth-hardening-2`.

**What happened:**
node-redis does not time a command out, and it holds commands on an offline
queue while it reconnects. Against a redis that had gone away, a request did not
fail: it waited, and went on waiting. Every redis-backed route in both services
had this shape, which is roughly 300 call sites. #368 bounded exactly one of
them, on the TOTP verify path, and recorded the rest in SECURITY.md as open.

**Why it belongs in this document:**
it is the same failure class as bugs 1 to 3. `/health` on the relay answered 200
throughout, because it touches no redis; `/v2/health/deep` answered green,
because it did not check the store either; and the admin's container probe was
`GET /api/auth/check`, which answers 401 when nobody is signed in, so it was
already "healthy" when nothing worked. A monitor watching any of those saw a
healthy stack while no user could sign in. Nothing was returning an error,
because nothing was returning at all, which is the one thing a 5xx counter
cannot see.

**The second half nobody expects:**
a per-command deadline makes the CALLER safe, not the client. After a command is
lost to a connection that stays open and goes silent, node-redis keeps waiting
for its reply and holds every later command behind it, so the client never
recovers even once the network does. Measured on 5.12.1 and 6.2.1: it reports
itself ready and answers nothing, until the process is restarted.

**What catches it now:**
`relay/test/route-redis-outage.test.js` and `admin/test/redis-outage.test.js`
boot both processes against a real redis behind a proxy, cut it, black-hole it,
and assert that every redis-backed route answers 503 inside
`PARAMANT_REDIS_DEADLINE_MS`, that the health routes tell the truth, and that
both processes heal on their own when the store comes back.

**Code location:** `relay/lib/redis-deadline.js` and its copy in `admin/lib/`;
the two `createClient` calls in `relay/relay.js` and `admin/lib/redis.js`.

---

## Bug #5 - The limiter that locked the door and threw away the key

**Found:** review of the fix for bug #4, 2026-09-03. **Fixed on:**
`fix/auth-hardening-2`.

**What happened:**
every rate limiter in both services was INCR followed by
`if (count === 1) await expire(key, WINDOW)`. Correct only while those two
commands always happen together. The redis deadline added for bug #4 makes the
gap reachable in a single request: the INCR outlives the deadline while the
server still executes it, the caller gets an outage, the expiry is never sent,
and the next INCR returns 2 so no later call sets it either. TTL -1 is for ever.

**Why it belongs in this document:**
it is a fix that created a new failure of the same class it was fixing. Nothing
errors, nothing is logged, and the only symptom is that one source address, or
one e-mail address, or one paying account, is refused from then on. Twenty-three
call sites had the shape, including the per-IP login limiter, the failure
counter behind the proof-of-work threshold, and every monthly quota counter.

**What catches it now:**
`admin/test/ratelimit-ttl.test.js` boots a real admin behind a proxy that
delivers commands to redis and drops the replies, which is the only sabotage
that reproduces it. `tests/redis-deadline-parity.test.mjs` fails if any of the
five files goes back to calling INCR directly.

**Code location:** `relay/lib/redis-counter.js` and its copy in `admin/lib/`.

---

## Severity Classification

| Bug class               | Silent? | Healthcheck catches? | e2e-auth-flow catches? |
|-------------------------|---------|----------------------|------------------------|
| Response shape change   | Yes     | No                   | Yes (Test A)           |
| Orphan code / ReferenceError | Partial (crashes in-handler) | No | Yes (Test B) |
| Uninitialized client    | Yes     | No                   | Yes (Tests C, D)       |

---

## Running the tests

```bash
# Full suite (requires docker group membership):
./tests/e2e-auth-flow.sh

# Without docker (tests E, F always run; A, B, C, D skip):
./tests/e2e-auth-flow.sh

# With tokens exported (runs A, C, D but not B):
ADMIN_TOKEN=xxx INTERNAL_AUTH_TOKEN=yyy ./tests/e2e-auth-flow.sh
```

Run `scripts/post-deploy.sh` after a deploy to catch auth-stack regressions
(it exits non-zero on failure). The canonical deploy is `docker compose` — see
`docs/RUNBOOK-DEPLOY-3.0.0.md`.
