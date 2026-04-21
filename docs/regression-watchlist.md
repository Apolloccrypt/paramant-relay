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

The post-deploy hook at `scripts/post-deploy.sh` runs this automatically after
`deploy/deploy.sh` restarts services.
