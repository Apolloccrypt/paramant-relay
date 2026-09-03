# Security Policy

## Reporting a vulnerability

Email: privacy@paramant.app
Subject: Security vulnerability — paramant-relay

We aim to respond within 48 hours and patch within 7 days for critical issues.
All reports are treated with responsible disclosure.

### PGP key

We do not currently publish a PGP key. If your report is sensitive, email
privacy@paramant.app and we will arrange an encrypted channel.

When a key is published it will be served at
<https://paramant.app/.well-known/openpgp-key.asc> and its fingerprint listed
here. Until then, treat any PGP key that claims to be ours as unverified and
confirm through a separate channel before sending anything sensitive.

---

## Security audits

### 2026-04-15 — RAPTOR security review (R. Zwarts)

10 findings, all resolved.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | DOM XSS in `ct-log.html` — CT log entry fields and verify result rendered via `innerHTML` without escaping (CWE-79) | Fixed: `esc()` applied to all API-sourced values in log entry renderer, verify result, and proof hash list |
| 2 | High | AES-256 key embedded in Thunderbird FileLink upload blob (CWE-320) | Fixed: key excluded from blob (packet v0x02), travels via URL fragment only — relay never holds decryption material |
| 3 | High | `X-Forwarded-For: $proxy_add_x_forwarded_for` in nginx — client-controlled header passed to backend (CWE-290) | Fixed: both `nginx-paramant-live.conf` and `nginx-selfhost.conf` changed to `$remote_addr`; relay uses `CF-Connecting-IP` → `X-Real-IP` → socket via `getClientIp()` helper |
| 4 | Medium | `decodeURIComponent()` without try/catch crashes relay process on malformed `%` sequences (CWE-248) | Fixed: all 4 routes (`/v2/did`, `/v2/pubkey`, `/v2/fingerprint`, `/v2/attest`) wrapped in try/catch → HTTP 400 |
| 5 | Medium | `users.json` read-modify-write race condition under concurrent key operations (CWE-362) | Fixed: `_mutateUsersJson()` serialises all read-modify-write cycles inside a promise queue |
| 6 | Medium | `/v2/sign-dpa` unauthenticated and unthrottled (CWE-770) | Fixed: per-IP (3/24 h) and per-email (1/24 h) in-process limits + nginx `limit_req zone=api` |
| 7 | Low | HTML injection in trial key email templates — `name`, `email`, `useCase` interpolated raw (CWE-116) | Fixed: `escHtml()` helper applied to all user-supplied fields in `welcomeHtml` and `notifyHtml` |
| 8 | Low | `drop.html` QR fallback uses `innerHTML` with relay-returned URL (CWE-79) | Fixed: replaced with `document.createElement` + `textContent` |
| 9 | Low | SDK `pyproject.toml` allows vulnerable `requests` and `cryptography` versions | Fixed: floors raised to `requests>=2.33`, `cryptography>=43.0.1`, `pytest>=9`; `requires-python` bumped to `>=3.10`; `requirements.txt` lockfile generated |
| 10 | Low | Duplicate IP-derivation logic at 4 call sites in `relay.js` | Fixed: consolidated into `getClientIp()` helper |

### 2026-04-13 — CIS Ubuntu 24.04 benchmark (production server)

114 checks applied across 13 categories on paramant.app:

| Category | Result |
|----------|--------|
| Kernel module blacklist (33 modules) | Enforced |
| /tmp as tmpfs (nodev, nosuid, noexec) | Configured |
| AppArmor | 119/121 profiles enforcing |
| SSH hardening (MACs, LoginGraceTime, MaxStartups) | Applied |
| Kernel network hardening | Applied |
| PAM hardening (pwquality, faillock, pwhistory) | Applied |
| auditd | 49 CIS L2 rules loaded |
| AIDE | Installed, daily integrity check |
| Cron permissions | Restricted to root |
| Password policy | MAX_DAYS=365, SHA512 |
| sudo logging | Enabled with full I/O logging |
| Firewall | UFW/nftables, default deny |
| Login banners | Configured |

### 2026-04-11 — R. Zwarts (verification review)

14 findings, all resolved in commit `e6f216d`.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | Admin login plain === + no rate limiting | Fixed: timingSafeEqual + per-IP rate limiter |
| 2 | Medium | safeEqual() bypassed on 3 relay paths | Fixed: all paths use safeEqual() |
| 3 | Medium | pgp_ enterprise admin path broken | Fixed: removed pgp_ admin support |
| 4 | Medium | Blob burned before transfer complete | Fixed: deferred deletion on res.finish() |
| 5 | Medium | TOTP timing-sensitive + code reuse | Fixed: full window scan + _usedTotpCodes |
| 6 | Medium | Sync file I/O on key create/revoke | Fixed: serialized async write queue |
| 7 | Medium | Relay registry unbounded + unpaginated | Fixed: cap + limit/offset pagination |
| 8 | Medium | CT log appendFileSync + no rotation | Fixed: async write stream + size rotation |
| 9 | Medium | Webhook SSRF port not restricted | Fixed: allowlist 443 + 80 only |
| 10 | Low | DID lookup O(n) scan | Fixed: O(1) via didRegistry.get(did) |
| 11 | Low | Admin login leaks internal address | Fixed: generic error, server-side log only |
| 12 | Low | Revoked keys keep WebSocket open | Fixed: ws.close(4401) on revoke |
| 13 | Low | Arbitrary plan strings accepted | Fixed: VALID_PLANS allowlist |
| 14 | Low | Invalid Base32 in TOTP_SECRET silent | Fixed: startup validation + clear error |

### 2026-04-10 — R. Zwarts (independent security researcher)

6 findings, all resolved in commit `0db3ef0`.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | WebSocket proxy uses plain TCP to HTTPS upstream | Fixed: tls.connect() |
| 2 | High | stream-next returns synthetic hash not real blob hash | Fixed: per-device queue with real sha256 |
| 3 | High | Webhook SSRF — DNS not resolved before connecting | Fixed: dns.resolve + private range reject |
| 4 | Medium | SDK uses ?k= query param rejected by relay | Fixed: X-Api-Key header |
| 5 | Medium | pgp_ enterprise admin path broken end-to-end | Fixed: removed pgp_ support |
| 6 | Medium | Blob burned before transfer complete | Fixed: deferred deletion on res.finish() |

### 2026-04 — Ryan Williams, Smart Cyber Solutions (independent)

20 findings across 4 critical / 5 high / 6 medium / 5 low.
Full report: [docs/security-audit-2026-04.md](docs/security-audit-2026-04.md)

| # | Severity | Status |
|---|----------|--------|
| 1–3 | Critical | Fixed |
| 4 | Critical | In progress: plaintext filename in relay RAM |
| 5–9 | High | Fixed |
| 10–15 | Medium | Fixed (13: accepted — documented) |
| 16–20 | Low | Fixed |

---

## Open findings

| # | Severity | Finding | ETA |
|---|----------|---------|-----|
| 4 | Critical | Plaintext filename stored in relay RAM | v2.4.6 |
| 14 | Medium | CT Merkle tree non-RFC-6962 compliant | v2.5.0 |

---

### 2026-09-03: the ParaSend account key leaves the browser

The security review of #397 accepted that /parashare had stopped keeping a key
in `localStorage` and then said the harder thing: the key should not be in the
browser at all. This records what was done about it and, more usefully, what is
still true afterwards.

#### The old ceiling

`/parashare` fetched the account's API key from `GET /api/user/account/key` and
held it in a variable for the life of the tab. That key is a full data-plane
credential with no expiry and no scope. Anything that got to run script on
paramant.app could read it out of the page and keep it: upload and download on
the account, list and revoke its transfers, enrol a signing key, create ParaSign
envelopes, read the audit chain. Not for fifteen minutes. Until the owner
noticed and rotated the key, which is a thing an owner does when something has
already gone wrong.

The page's own hardening did not touch this. The key was never persisted and
never logged; it was simply present, in a variable, which is all an injected
script needs.

#### What replaced it

A `pst_` session token, minted by the admin panel on behalf of a logged-in user
and handed to the browser instead of the key. Three properties, and the second
is the one that matters:

- **Fifteen minutes.** Held in the relay's shared Redis, so all five sectors
  honour the same token; not an operator knob, because a deployment that could
  set this to a week would have rebuilt the credential this removes.
- **Five routes.** An allowlist in `relay/lib/session-token.js`, checked above
  every route comparison in `relay.js`: `/v2/check-key`, `POST /v2/ws-ticket`,
  `POST /v2/pubkey`, `GET /v2/pubkey/:device`, `POST /v2/inbound`. Everything
  else is `403`, including `/v2/user/*`, `/v2/outbound`, `/v2/audit`,
  `/v2/admin/*`, the ParaSign envelope routes, and a second mint: a token cannot
  extend its own fifteen minutes.
- **The same account.** Inside that scope the token authenticates as the api-key
  it was minted for, so quota, the audit chain and the tier ceilings resolve
  against the owner. A token is a narrower way to present an account, never a
  second account.

`POST /v2/session-token` needs `X-Internal-Auth` and a live `X-Api-Key`, so the
admin plane is the only caller and a browser can never name another account.
Revoking the key sweeps its tokens out of the store, and a token whose owner key
is inactive grants no principal even when that sweep did not run: the sweep is
the fast path, not the guarantee.

#### Three things the review of this change tightened

- **The stored record names its owner by hash.** It used to carry the api-key in
  the clear. The key NAMES were already hashed, because SCAN output, keyspace
  listings and the slowlog all show names, but the VALUE was not: an RDB
  snapshot, a replica, a backup on a laptop or a `MONITOR` session carried live
  `pgp_` credentials for every account that had sent a file in the last fifteen
  minutes. The record is now `{kh, exp}`, and the relay turns the hash back into
  a key by looking it up in the api-key table it already has in memory. Nothing
  derives a key from a hash; a read-only copy of the store is a copy of hashes.
  It also means key revocation and deletion arrive for free, because the lookup
  is against the live table.
- **The expiry is required, not optional.** A record with no `exp`, or one whose
  `exp` is not a number, is refused. It used to fall through a `typeof` guard to
  whatever TTL redis happened to have on the key, which meant a credential whose
  lifetime was a property of the store alone, and no lifetime at all when the
  store was wrong.
- **A transfer made with a token is marked in the audit chain**, with one field,
  `"via": "pst"`. Not a second identity: the chain is the owner's, keyed on the
  owner's api-key exactly as for a request that carried the key. Without the
  field an owner reading their own log cannot tell a transfer made from a
  browser session apart from one made with the key itself, which is the
  distinction that matters when they are working out what happened.

There is also a ceiling of 20 live tokens per account, answered with `429` and a
`Retry-After`. It is not a rate limit: the page mints one per load and one per
refresh, so twenty is far above honest use, and what it stops is a signed-in
session being run as a credential factory. Tokens already issued keep working,
and room returns as they expire; the sweep index is pruned of names redis has
already expired before a refusal is made, so nobody is refused on the strength
of tokens that are gone.

#### The new ceiling, stated plainly

**A script that runs on paramant.app can still act as the signed-in user for
fifteen minutes.** It can start a transfer, publish a handshake key and upload a
blob against the account's monthly quota. What it can no longer do is take the
key with it: it cannot read the account's downloads or audit log, cannot enrol a
signing identity, cannot create or sign an envelope, and cannot do any of it
after the token expires, because minting a new one requires the session cookie
to still be there and the mint route to be reached through the admin panel.

That is a real reduction and it is not a fix for cross-site scripting. The CSP
on the site and the escaping in the pages remain the thing that stops a script
running in the first place; this only bounds what one gets if it does.

#### What was still open, and what closed it

The `GET /api/user/account/key` reveal route existed and ParaSend was not its
only caller: `/account`, `/pricing` and `/dashboard` each fetched the raw key
into the browser and used it as a relay credential. The honest statement of the
ceiling at the time was that on `/parashare` the key was gone, and on a browser
that had loaded any of those three pages it was not.

That is now closed, and closing it needed a second purpose rather than a wider
scope.

**A token is minted FOR a purpose, and the purpose picks the allowlist.**
`relay/lib/session-token.js` holds two lists. `SCOPE` is the ParaSend one and is
unchanged: the five transfer routes above. `APP_SCOPE` is the new one and holds
three routes, each because one page needed exactly it:

| Route | Page | Why |
|-------|------|-----|
| `POST /v2/billing/checkout` | `/pricing` | pressing a price button creates the Mollie payment |
| `GET /v2/user/history` | `/dashboard` | the account's own send/envelope history, read-only |
| `GET /v2/parasign/audit-export` | `/dashboard` | the account's own signing audit, read-only, Business+ |

The two lists are **disjoint**. A token minted on `/parashare` is `403` on all
three app routes, and a token minted on `/pricing` is `403` on all five transfer
routes. Merging them into one flat allowlist would have widened the ParaSend
token by three routes to give three other pages a credential they needed, which
is how a narrow credential quietly becomes an api-key again. `/v2/user/history`
is named on its own path, never as a prefix, so the rest of `/v2/user/*` (the
signing-key and TOTP surface) stays shut under both purposes, as do `/v2/keys`,
`/v2/outbound`, `/v2/audit`, `/v2/admin/*` and a second mint.

The purpose is chosen by the ADMIN ROUTE, never by the caller:
`POST /api/user/parasend/token` asks for `parasend` and
`POST /api/user/app/token` asks for `app`, both ignore their request body, and a
purpose the relay does not recognise is refused at the mint with `400
unknown_purpose` rather than folded onto a default. A stored record with no
purpose field predates this change and is a ParaSend token; a record carrying a
purpose the running build does not know authenticates nobody at all.

**What each page does now.**

| Page | File | Credential |
|------|------|------------|
| `/account` | `frontend/js/account.inline1.js` | the reveal route, and only when the "Advanced account key" fold is opened. Nothing is fetched or rendered on load |
| `/pricing` | `frontend/js/pricing-billing.js` | `Authorization: Bearer pst_...`, purpose `app`, minted on the first click |
| `/dashboard` | `frontend/js/dashboard-history.js` | the same, minted on the click that needs it. `/dashboard` no longer prints a key in any form, masked included |

`tests/app-pages-no-api-key.test.mjs` drives real Chromium over the three pages
and fails if any of them asks for the key on load, or renders anything shaped
like one.

**What is left, stated plainly.** The reveal route still exists and still
answers any signed-in browser with the raw key, because `/account` is the page
whose job is to show it to you and a self-hoster genuinely needs it. So a script
that runs on paramant.app with a session cookie can still ask for the key
directly. What changed is that it no longer finds one lying in a variable on a
page nobody opened for that reason, and that the two pages which used to put it
there now run on a credential that expires and opens three routes.

---

### 2026-09-03: login lockout and TOTP replay (internal review of #367)

Two decisions came out of reviewing the site-claims work in #367, both about
authentication, and both recorded here because the reasoning matters more than
the diff.

#### 1. A rate limit keyed on an email address is a lockout, not a limit

`/api/user/login` incremented `paramant:user:ratelimit:email:<email>` before it
called `findUserByEmail`, refused at eleven inside fifteen minutes, and never
deleted the key on a successful sign-in. The address is request input. Eleven
posts spread over three IP addresses (the per-IP cap is five) put the owner of
that address on `429` for the full window, from any browser, with no way to
clear it. The relay carried the same shape one layer down: `userMfaAttemptOk`
counted attempts against a caller-supplied `user_id` and refused at ten.

**The rule now:** a counter keyed on an identity the attacker gets to name may
impose cost on that identity, never denial.

| Layer | Keyed on | Counts | Over the threshold |
|-------|----------|--------|--------------------|
| `admin/lib/login-ratelimit.js` | IP address | attempts | refused, 429, 5 per 15 min |
| `admin/lib/login-ratelimit.js` | email (hashed) | failures only | proof-of-work, 428, after 10 |
| `relay/lib/auth-throttle.js` | `user_id` | failures only | delay, 250 ms per failure, capped at 2 s |

A successful sign-in clears the per-account counters at both layers. The
proof-of-work is the 2^18 challenge already used by signup and password reset;
the relay layer has no client to run one, so it throttles instead. The request
that asks for the proof is refunded to the per-IP counter, because it was never
evaluated: charging for the quote as well as the answer would leave an honest
user two real attempts out of five.

What the proof-of-work is worth, measured rather than assumed: a native solver
on this repository finds a nonce in roughly 150 to 250 ms; a browser doing the
same work through WebCrypto takes one to two seconds. So it prices automated
guessing per attempt and it keeps a stranger from switching an account off. It
is NOT the thing that stops guessing. That is the per-IP refusal, which is why
that one stayed a refusal.

**What was given up.** There is no longer any per-account ceiling that refuses.
A distributed attacker with many IP addresses can keep guessing one address
indefinitely, at a couple of hundred milliseconds of CPU per attempt plus five
attempts per IP per fifteen minutes. The per-IP limit is what makes that
expensive; the proof-of-work only prices each attempt. Against a six-digit TOTP
with a one-slot window under two algorithms (roughly six in a million per guess)
it is a botnet-scale cost for a poor return, and it is the price of not handing
every passer-by a way to switch off somebody else's account. If the trade needs
revisiting, raise the difficulty for a hot address; do not reintroduce the
refusal.

**Both deadlines are configurable**, `PARAMANT_REDIS_DEADLINE_MS` (relay.js) and
`PARAMANT_TOTP_REPLAY_TIMEOUT_MS` (lib/totp.js), default 1000 ms each, both
documented in `deploy/.env.example`. A value of zero or a non-number is ignored
and the default applies: an unbounded guard does not fail closed, it hangs.

The e-mail counter is hashed (`paramant:user:loginfail:<sha256>`), so the
rate-limit namespace no longer stores addresses in plaintext, and the namespace
is new, so no counter written under the old shape survives a deploy still
holding somebody out.

#### 2. TOTP single-use now fails closed

`relay/lib/totp.js` guarded replay with a per-slot `SET NX`, and swallowed a
store error with `.catch(() => 'OK')`. The comment above it called that a
deliberate choice: availability over replay protection, so a Redis blip could
not block a legitimate first use.

It is not defensible on this endpoint. The NX key is the only thing between an
observed six-digit code and its replay inside the same 30-second slot, on the
path that mints admin-panel sessions. And the availability it bought was
imaginary: the session store is the same Redis, so a login that skips the replay
check still cannot be issued a session.

A store failure now yields `{ valid: false, error: 'replay_store_unavailable' }`.
`/v2/user/verify-totp` and both `/v2/user/signing-key` routes answer `503` and
log `totp_replay_store_unavailable`; the admin login passes the 503 through as
`totp_unavailable` rather than dressing it up as a wrong code, and does not
count it as a failed attempt. A refused replay is `error: 'replay'`, a wrong code
carries no error at all, so the three cases stay distinguishable.

**A store that never answers is an outage too.** Fail-closed only means
something if a decision arrives. node-redis queues commands while it
reconnects, so against an unreachable server a call neither resolves nor
rejects. Measured on a booted relay with the server killed underneath it, the
verify path did not fail open OR closed: it hung, with no answer at all after
twelve seconds. Two bounded waits fix that on this path: the replay `set`
inside `verifyTotpGeneric` (`storeTimeoutMs`, 1s) and the secret read in front
of it (`redisDeadline` in relay.js, 1s). A timeout is reported exactly like a
thrown error, so the route answers 503 in about a second.

**Closed by the 2026-09-03 change below.** This was left open here as "a
property of the relay's redis client, not of this path", with every other
redis-backed route still inheriting it. It is now bounded on the client, in both
services. See *No redis call in either service can hang*.

Pinned by `relay/test/verify-totp.test.js` (a throwing store, a synchronously
throwing store and a store that never answers, none of which may validate a
code), `relay/test/route-user-mfa-lockout.test.js` (a real relay, a real redis,
and the connection cut underneath it mid-suite), `relay/test/auth-throttle.test.js`
and `admin/test/login-ratelimit.test.js`.

---

### 2026-09-03: redis outages, a login timing oracle, and a test that tested itself

Three findings from the review of #368.

#### 1. No redis call in either service can hang

This closes the finding #368 left open above, and it turned out to be two
problems rather than one.

**The offline queue.** node-redis holds commands in memory while it reconnects,
and its default reconnect strategy retries for as long as the process lives.
Measured against redis 5.12.1 (relay) and 6.2.1 (admin), with a live connection
cut underneath the client: the first command after the cut rejects in about a
millisecond, and every command after that neither resolves nor rejects. Still
pending after four seconds, after twelve, after any bound worth measuring.
`disableOfflineQueue` turns that into an immediate refusal.

**A connection that goes silent.** If the bytes stop but the socket stays open
(a dropped firewall rule, a wedged proxy, a frozen container) nothing fails at
all. `isReady` stays `true`, the command goes out, the reply never comes.
`disableOfflineQueue` cannot see this case, because from the client's point of
view nothing is wrong. Only a per-command deadline catches it. Both, therefore,
and neither is redundant.

**A bound makes the caller safe, not the client.** A third measurement: after a
command is lost to a silent connection, node-redis goes on waiting for its reply
and holds every later command behind it, so the client never recovers even once
the network does. On both major versions, a connection that was holed and then
healed answered nothing again, ever, while continuing to report itself ready.
`destroy()` followed by `connect()` rebuilds it in about three milliseconds. The
guard does that after two unanswered commands in a row; not after one, because a
single slow command is a big `SCAN` or a loaded server, and tearing the socket
down for that would turn a slow minute into a broken one.

The bound lives on the CLIENT, in `lib/redis-deadline.js`, not on the call
sites: `guardRedisClient` returns a proxy that puts the deadline on every
command, every `MULTI` chain and every `scanIterator` step. There are roughly
300 redis call sites across `relay.js`, `relay/lib/*`, `relay/envelope.js`,
`admin/server.js` and `admin/lib/*`, including the `sMembers`/`sRem` pair in
`consumeBackupCode` that #368 bounded on the verify path and not on the
backup-code path next to it. A per-call-site list would have been wrong the
first time somebody added a route.

An exceeded bound, a closed socket and an offline client all arrive as one
`RedisUnavailableError`, so a route does not have to know which happened to know
that the honest answer is 503. Three places turn it into one:
`relay.js redisOutage503` for the 31 route-level catches that used to answer 400
`bad_request` or 500 `internal` for an outage, a new top-level catch on the
relay's request handler for everything that does not catch (an async throw there
was previously an unhandled rejection: no answer at all, and on Node 22 a process
exit), and the admin's express error middleware.

`PARAMANT_REDIS_DEADLINE_MS` keeps its name from #368 and is now the single
configuration source for both services. Default 1000 ms; zero or a non-number
falls back to the default, because "wait forever" is the failure it exists to
prevent.

**What was given up.** During an outage every request pays the deadline once
before it is refused, where before it paid nothing and answered nothing. A
deployment whose redis routinely takes longer than a second to answer will see
503s it did not see before, and must raise the knob rather than remove it. There
is no retry and no open circuit: throughput during an outage is not what this
buys, a bounded answer is.

**Honesty about the store.** `GET /health` on the relay touches no redis and
still answers 200, which is correct: the process is up. `GET /v2/health/deep`
now carries a `redis` check and goes red when the store is unreachable, where it
previously reported the same green as a healthy relay. The admin had no health
route at all -- its container probe was `GET /api/auth/check`, which answers 401
when nobody is signed in, so "healthy" meant "the process still refuses me". It
now has `GET /health`, always 200, with `status: "degraded"` when redis cannot be
reached.

Pinned by `relay/test/route-redis-outage.test.js` and
`admin/test/redis-outage.test.js` (a booted relay and a booted admin, a real
redis behind a proxy the suite cuts and then black-holes mid-run, every
redis-backed route asserted to answer 503 inside the deadline, and both
processes asserted to heal by themselves when the store comes back),
`relay/test/redis-deadline.test.js` (the classifier, the deadline, the proxy and
the rebuild, without a redis) and `tests/redis-deadline-parity.test.mjs` (the
relay and admin copies of the module are one file, and both services actually
wrap their client with it).

#### 2. The login page told you which addresses were customers

`POST /api/user/login` did strictly more work for an address that exists, in two
separate ways, and the first round of this fix only closed the smaller one.

**The cheap half: the work itself.** An address with an account reached a second
relay call (`/v2/user/verify-totp`) and one more redis read, where one without
returned two steps earlier. About 4 ms with a realistic relay, with the two
distributions not overlapping. The status codes were already identical on
purpose (#368 folded three 403s into one 401 for exactly this reason); the clock
was not.

**The expensive half: the throttle.** `relay/lib/auth-throttle.js` delays a wrong
code by 250 ms per failure past ten, capped at two seconds, and `relay.js`
charges it on `/v2/user/verify-totp` before it checks anything. Only a request
naming an account that EXISTS ever reaches that sleep. So the anti-guessing
delay was itself the oracle, and it is three orders of magnitude louder than the
work difference. Twelve wrong codes from rotating source addresses put an
address there, and nothing refuses them, because the per-address counter
deliberately imposes cost rather than denial.

Measured on a booted admin with a stub relay charging the same throttle,
100 requests per case, interleaved, one source address each:

| prior failures | exists (p50) | absent (p50) | ranges |
|---|---|---|---|
| 0 | 251.87 ms | 251.90 ms | overlap |
| 12 | 509.91 ms | 251.61 ms | **do not overlap** |
| 20 | 2010.23 ms | 251.82 ms | **do not overlap** |

A third path leaked as well: `503 totp_unavailable`, the answer the admin passes
through when the relay's replay store is down, was not floored and is only
reachable for an address that has an account. Nine milliseconds against two
hundred and fifty.

**What replaces it.** The delay has to be charged by something that does not
know whether the account exists. That is the admin, which owns a failure counter
keyed on the hashed ADDRESS and increments it for a miss exactly as for a hit.
`loginRate.mirrorThrottleMs()` reproduces the relay's curve on that counter, the
result is added to the floor under every credential answer on both login routes,
and the admin tells the relay it has already paid (`throttled_upstream`) so the
account-keyed delay is not charged a second time. The relay still counts the
failure, still reports what it would have charged as `throttle_ms`, and still
charges any caller that does not set the flag; the route is `X-Internal-Auth`
only, so the callers who can set it are callers who could already name any
account they like.

The 503 branch is floored like the rest. Same instrument, same 100 requests:

| prior failures | exists (p50) | absent (p50) | delta | ranges |
|---|---|---|---|---|
| 0 | 251.86 ms | 251.87 ms | -0.01 ms | overlap |
| 12 | 751.84 ms | 751.76 ms | 0.08 ms | overlap |
| 20 | 2251.90 ms | 2252.11 ms | -0.21 ms | overlap |

**What was not padded, and why.** 429 (per-IP refusal) and 428 (proof-of-work
required) are not credential answers: their status codes tell them apart
whatever the clock says, and holding the 428 back only delays the login page
that is waiting to start hashing.

**What this still does not fix.** An address over the failure threshold answers
428 where one under it answers 401, so an attacker willing to burn ten failures
per address can tell them apart by status code. That is the cost of pricing an
attempt instead of refusing it, and it is a far more expensive oracle than a
timing difference: ten failures and a 2^18 proof-of-work per address, against
one unauthenticated request. It is a deliberate trade, not an oversight.

`PARAMANT_LOGIN_MIN_ANSWER_MS` (default 250 ms) is only the BASE of the floor;
the throttle is added on top, so a clean address is answered at 250 ms and one
with twenty failures at 2250 ms, either way regardless of whether it exists. The
base has to cover the work, which is about 10 ms against a healthy relay. An
answer that overruns its floor is logged as such, because at that point the
floor has stopped being one.

Pinned by `admin/test/login-timing.test.js`, which measures both cases at 0, 12
and 20 prior failures with the shipped default floor and the real throttle
values, asserts the medians do not separate and the ranges overlap, and pins the
`throttled_upstream` flag itself so a change that drops it cannot pass on a
quiet machine. Against the previous revision of this branch it fails on the
twelve-failure level. The instrument that produced the tables above is
`admin/test/login-timing.bench.js`; `ADMIN_SERVER_JS=` points it at any checkout.

#### 3. A test that reimplemented the handler it was testing

`admin/test/login-ratelimit.test.js` drove `lib/login-ratelimit.js` directly
through an `attemptLogin()` helper written inside the test file, and then read
`server.js` as a string to assert the order of three calls. The module is
correct and the order assertion is worth keeping, but between them they never
ran the handler: the decision under test was one the test file made up, so it
could pass while the route was wrong.

`admin/test/_admin-server.js` is the admin counterpart of
`relay/test/_relay-server.js`: it spawns the real `admin/server.js`, points it
at a stub relay that answers the two routes a login touches, and speaks HTTP to
it. `admin/test/login-http.test.js` runs the reviewer's scenario on it -- ten
wrong codes on one address from three source addresses, then the owner solving
a real 2^18 proof-of-work and getting a session -- plus the per-IP refusal, the
IP refund on a priced attempt, and the relay 503 being passed through instead of
reported as a wrong code.

Checked against the code it is meant to catch: run against the pre-#368 admin,
three of its five tests fail, on the 429 where a 428 belongs and on the outage
reported as `invalid_credentials`. `login-timing.test.js` fails there too.


#### 4. A rate-limit counter that lost its expiry refused for ever

Found while reviewing the deadline in finding 1, and caused by it. Every limiter
in both services was written as an INCR followed by a CONDITIONAL expiry:

```js
const count = await redis.incr(k);
if (count === 1) await redis.expire(k, WINDOW_S);   // only on the first hit
```

That is correct only while the two commands always happen together. The deadline
makes the gap reachable in one request: if the INCR exceeds the deadline while
the server still executes it, the caller gets an outage and the EXPIRE is never
sent. The key then holds a count with TTL -1, and because the next INCR returns
2 rather than 1, no later call sets the expiry either. TTL -1 means for ever.

Measured on a booted admin with the replies from redis dropped for the duration
of one login: `paramant:user:ratelimit:ip:<ip>` stood at 9 with TTL -1, and that
source address kept getting 429 until the key was deleted by hand.

Three kinds of permanent damage, all of them denial of service produced by a
redis hiccup in the code that exists to prevent denial of service:

- `paramant:user:ratelimit:ip:<ip>` -- a permanent 429 for that source address;
- `paramant:user:loginfail:<hash>` -- a proof-of-work obligation that never
  lifts, on an address anybody may name;
- the monthly counters in `relay/lib/quota.js` -- an account permanently over
  its transfer or signing quota.

`lib/redis-counter.js` (`incrInWindow`) sets the expiry UNCONDITIONALLY after
every INCR, with `NX` so it can only ever create a window and never slide one.
The healthy case behaves exactly as before; the broken case is repaired by the
first request that lands after it, so a missing TTL survives one request instead
of for ever. All 18 INCR call sites in both services go through it:
`admin/lib/login-ratelimit.js` (2), `admin/lib/webauthn.js` (1),
`admin/server.js` (8), `relay/lib/quota.js` (6), `relay/relay.js` (1). (An
earlier revision of this note said 23, which counted the two copies of the
helper itself and miscounted `admin/server.js`.) `EXPIRE ... NX` needs Redis 7.0;
`docker-compose.yml` pins 7.4.8 by digest, and a server that refuses the option
makes the helper fall back to a TTL read for the life of the process, because an
error on every rate-limited route would be a worse regression than the bug.

Pinned by `admin/test/ratelimit-ttl.test.js`, which boots a real admin behind a
proxy that delivers commands and drops replies -- the shape that makes the
server execute the INCR while the client gives up on it -- and then reads the
TTL on its own connection. Against the previous revision of this branch both
counters come back TTL -1. A third test pins the `NX`: a later hit must not
extend a window that already exists, or the repair becomes the same denial of
service from the other end. `tests/redis-deadline-parity.test.mjs` fails if any
of the five files goes back to calling INCR directly.

#### 5. The backup-code route answered the same question with argon2

The fixed floor from finding 2 was applied to `/api/user/login-with-backup` in
the same change, and it was not enough, because on that route the work is not
4 ms of redis reads. `consumeBackupCode` verifies the provided code against
EVERY stored hash until one matches, and a wrong code matches none, so a miss
costs ten full argon2id verifications at 64 MiB and timeCost 3. An address with
no account pays none of it.

Measured on the machine this was written on, with ten codes really stored:

| | p50 | min | max |
|---|---|---|---|
| one argon2 verification | 49.7 ms | 44.7 ms | 95.9 ms |
| ten of them (one wrong code) | 494.2 ms | 462.3 ms | 870.9 ms |

Through the route, with the 250 ms floor it had inherited: 472.7 ms for an
address that exists against 251.6 ms for one that does not, ranges not
overlapping. The admin logged `answer overran its floor` on 40 requests out of
40, which is the code saying out loud that the number it was given was not a
floor at all. That log line existed and nobody had run the route past it.

Two changes. The floor on this route is its own,
`PARAMANT_LOGIN_BACKUP_MIN_ANSWER_MS`, 1500 ms by default: 1.7x the slowest
ten-hash miss measured here and 3x the median. And the per-address throttle is
mirrored onto this route as well, on the counter it already keeps
(`bk:email:<sha256>`, incremented before the account lookup so it is the same
number for a hit and a miss). It needs its own curve rather than
`mirrorThrottleMs`: the route refuses at five attempts per address per window,
so the relay's threshold of ten is unreachable through it and a mirror using
that threshold would be zero for every attempt the route allows. It starts after
the first attempt instead, with the same 250 ms step and the same 2 s ceiling.

The route is the emergency path a user takes once, when their authenticator is
gone, so a second and a half is a cost worth paying to stop it answering the
question "is this address a customer". A slower machine needs a higher floor and
will say so on every request that overruns it.

Pinned by `admin/test/login-timing.test.js`, which for this route boots a REAL
relay rather than the stub, enrols an account, checks that ten argon2 hashes are
really stored, and then measures a wrong code against an address that exists and
one that does not, at zero and four prior attempts (five prior attempts is a 429
for both, which is not a credential answer). Against the previous revision of
this branch it reads 491.99 ms against 253.16 ms with no overlap. The suite also
fails if the admin logged a single floor overrun.

#### 6. Two smaller things from the same review

**A body that was not what it said it was answered 500 in a millisecond.**
`{"email": {}}` is truthy, so `if (!email)` waved it through into
`String(email).trim().toLowerCase()`, which threw. Both login routes now check
the type and answer 400, which is the same answer for every caller and carries
no information about the address. It was also an unhandled throw on an
unauthenticated route.

**The health routes repeated the deadline in their error text.** The redis
deadline error carries the configured bound in its message ("no answer within
1000ms"), and both `/health` on the admin and the `redis` check in
`/v2/health/deep` passed it straight through, unauthenticated. They report a
fixed word now; the real message goes to the log.

#### A residual: 503 against 401, when the two services have separate stores

Worth writing down because it is a property of the deployment rather than of the
code. If the RELAY's redis is unreachable while the ADMIN's is not, an address
with an account answers `503 totp_unavailable` (the relay's replay guard failing
closed, passed through) while an address without one answers 401, because the
second never reaches the relay at all. The floor makes them take the same time;
the status codes still differ.

In the shipped topology this is not reachable: `docker-compose.yml` gives both
services the same redis, so the admin cannot serve a login at all while the
relay's store is down. It becomes reachable the moment somebody splits them, or
points the two at different instances of a cluster. Anyone doing that should
know that the split turns an outage into an enumeration oracle, which is why it
is recorded here rather than left as a surprise.

#### Follow-ups, recorded rather than fixed here

**`consumeBackupCode` can spend a code while the caller sees 503.** It is
SMEMBERS, then an argon2 verification per stored hash, then SREM. Each of those
is bounded separately now, so a deadline breach on the SREM leaves the code
consumed on the server while the admin answers 503 and the user is told the
service is down. The failure direction is safe (a code is burned, not accepted
twice) but it costs a legitimate user one of their backup codes for an outage
they did not cause. Fixing it properly means making the read-verify-remove
atomic, which is a Lua script or a WATCH/MULTI, and it belongs in its own change.

**`regenerateBackupCodes` is a DEL followed by a SADD with nothing between
them.** If the process dies, or the SADD exceeds its deadline, the account is
left with no backup codes at all and no error the user can act on. The same
transaction work covers both.

Both are reachable only through `X-Internal-Auth` routes and neither accepts a
code that should have been refused.

---

### 2026-04-20 — Admin panel hardening + email security

**Scope:** TOTP reset flow abuse protection, error response hardening,
rate limit verification, email template security review.

| Area | Finding | Status |
|------|---------|--------|
| TOTP reset | Two-stage confirmation prevents enumeration + abuse | Implemented |
| Error responses | JSON-only on all endpoints; no HTML stack traces | Verified |
| Rate limits | All mutating endpoints rate-limited and audited | Verified |
| Email security | From-address, reply-to, List-Unsubscribe, masked IPs | Implemented |
| Integration tests | 24/24 passing after enterprise sprint | Passing |

---

### 2026-04-19 — Automated internal audit (6 layers + load test)

**Scope:** Static code analysis, authentication flows, network and infrastructure, active penetration testing, cryptographic implementation review, business logic, load testing.

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | Fixed in-session |
| Low | 1 | Fixed in-session |
| Informational | 11 | All passing |

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| A-01 | Medium | Setup token consumed by email scanner before user interaction | Fixed: `setup.html` gates `init()` behind explicit button click |
| A-02 | Medium | `POST /v2/user/setup-totp` returned 409 for provisional (unactivated) TOTP | Fixed: endpoint is now idempotent; returns existing secret until activation |
| A-03 | Low | `INTERNAL_AUTH_TOKEN` absent from admin container environment | Fixed: env var injected in `docker-compose.yml` |
| A-04 through A-15 | Info | Argon2id params, TOTP timing safety, AES-GCM nonces, PQ layer, setup token entropy, billing auth, email canonicalization, rate limits, container hardening, secrets hygiene | All passing |

**Load test results** (tool: `hey`, target: `https://paramant.app/`):

| Load | Requests | p95 latency | Errors | Container state |
|------|----------|-------------|--------|----------------|
| 10 rps | 100 | 10 ms | 0 | All healthy |
| 50 rps | 500 | 18 ms | 0 | All healthy |
| 100 rps | 1000 | 43 ms | 0 | All healthy |
| 500 rps | 5000 | 135 ms | 0 | All healthy |

**Next audit:** External third-party penetration test planned before public general availability.

---

### 2026-04-15 — TOTP algorithm mismatch (internal)

| Severity | Finding | Status |
|----------|---------|--------|
| High | Installer scripts emitted `algorithm=SHA1` in `otpauth://` URIs while relay.js verifies TOTP with HMAC-SHA256 (`relay.js:746`). TOTP codes generated by authenticator apps would fail silently on every login attempt. | Fixed: `install.sh` and `install-pi.sh` updated to `algorithm=SHA256` in both the URI and the manual-entry display string. |

---

## CT Log gossip protocol & external anchoring

### Trust model

Before Mission 4, tamper-evidence depended on trusting Paramant's own servers:
> "Trust Paramant's servers"

After Mission 4, the trust model is:
> "Trust that **at least one relay operator is honest**"

This is the same trust model as RFC 6962 Certificate Transparency. Any relay operator running `paramant-verify-peers` becomes an independent auditor.

### Signed Tree Heads (STH)

Every change to the CT log produces a Signed Tree Head (STH) — an ML-DSA-65 signed commitment to the current Merkle root:

```json
{
  "version": 1,
  "relay_id": "https://health.paramant.app",
  "tree_size": 59,
  "sha3_root": "deed04dd...",
  "timestamp": 1713000000000,
  "signature": "<base64 ML-DSA-65 over canonical JSON>"
}
```

Signature is over the canonical JSON of `{relay_id, sha3_root, timestamp, tree_size, version}` (keys sorted). Signed with the relay's ML-DSA-65 identity key (NIST FIPS 204).

### Gossip protocol (push STH)

After every STH is produced, the relay broadcasts it to all registered peers:

```
POST /v2/sth/ingest
Body: { relay_id, sha3_root, timestamp, tree_size, version, signature, public_key, relay_pk_hash }
```

- Receiver verifies ML-DSA-65 signature before storing
- Invalid signatures are logged and rejected (HTTP 400)
- Valid STHs are stored in `data/peer-sths/{relay_pk_hash}.jsonl`
- Non-blocking, best-effort — peer failures do not affect the local relay

### Cross-relay verification endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /v2/sth/peers` | List all peer relays + their latest mirrored root |
| `GET /v2/sth/peers/:pk_hash` | Full STH history mirrored from a specific peer |
| `GET /v2/sth/consistency?from=N&to=M` | RFC 6962 consistency proof between two tree sizes |
| `GET /ct/feed.xml` | RSS feed of signed tree heads for external archiving |

### Consistency proof (append-only guarantee)

`GET /v2/sth/consistency?from=<old_size>&to=<new_size>` returns an RFC 6962-style proof that the new tree contains the old tree as a prefix. This is the key property that prevents a relay from "rewinding" its log.

```bash
# Verify no entries were removed or reordered between size 10 and current
curl "https://health.paramant.app/v2/sth/consistency?from=10" | jq .
```

### RSS feed anchoring

Subscribe to `/ct/feed.xml` with any RSS reader to independently archive STH roots:

```
https://health.paramant.app/ct/feed.xml
```

If a relay later claims a different root for a published timestamp, any subscriber has cryptographic proof of the original commitment.

### paramant-verify-peers CLI

```bash
# Install
npm install -g @noble/post-quantum  # required for ML-DSA-65

# Verify all peer STHs are consistent
paramant-verify-peers --relay https://health.paramant.app

# Exit 0 = all consistent (or 0 peers)
# Exit 1 = inconsistency detected
```

The tool:
1. Fetches the peer STH mirror from the local relay
2. Verifies ML-DSA-65 signatures on each peer's latest STH
3. Cross-checks by fetching the STH directly from the peer relay
4. Checks for tree_size rollbacks (append-only violation)
5. Reports inconsistencies with full details

---

## Server hardening (paramant.app)

Additional fixes applied 2026-04-13:

| Fix | Detail |
|-----|--------|
| .env permissions | chmod 600 |
| Stale debug process | Killed (API key was visible in ps aux) |
| SSH | PermitRootLogin prohibit-password, MaxAuthTries 3 |
| Spurious arm64 arch | Removed from apt |
| HSTS | `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on all 7 HTTPS server blocks (paramant.app + 5 relay subdomains). Applied directly in `/etc/nginx/sites-enabled/paramant-public` — the deploy-time nginx config (`deploy/nginx-paramant-live.conf`) also carries this header but the Cloudflare-facing config is gitignored. |
| TLS | `ssl_protocols TLSv1.2 TLSv1.3` + forward-secret cipher suite (`ECDHE-*-GCM` + `CHACHA20-POLY1305`) explicit on all 443 vhosts; `ssl_prefer_server_ciphers off` (client chooses) |
| Google Fonts | Removed from CSP |
| atd | Stopped and disabled |
| NATS | Dedicated system user, systemd hardening |
| Docker | admin + relay containers non-root (since e6f216d) |

---

## Dependency audit (2026-04-13)

> Historical record, kept as measured on that date. The base image has moved
> since: it is `node:24-alpine3.24`, pinned by digest, as of 3.1.0. `node:22`
> and `node:25` are both past their support window; see CHANGELOG.md.

- 0 npm vulnerabilities across all 4 packages
- Base image: node:22-alpine (node:20 was EOL)
- express 4.x → 5.x
- 0 GPL/AGPL/LGPL licenses
- 0 hardcoded secrets

---

## Security incidents

### 2026-04-15 — Credential exposure in git history

**What:** gitleaks scan revealed historical credential exposure.

| Credential | Committed | Status |
|------------|-----------|--------|
| `RESEND_API_KEY` (`re_K1YQ…XvA`) | 2026-04-01 in `deploy/systemd/*.service` (files since removed) | Verified invalid via Resend API on 2026-04-15 |
| 3× demo API keys (`pgp_…`) | 2026-04-01 – 2026-04-07 in `frontend/index.html`, `poc/README.md` | Revoked via `/admin/` on 2026-04-15 |

**Remediation:** Server `.env` permissions hardened to 600; gitleaks pre-commit hook installed.

**Note on git history:** Historical commits still contain the now-invalid credentials. Rewriting history would break existing clones with no security benefit since the credentials are revoked. Documented here for transparency.

---

## Threat model

### What Paramant protects against

| Threat | Mitigation |
|--------|------------|
| Third-party storage provider reading file contents | Zero-knowledge relay: content encrypted client-side before transmission; relay never holds decryption keys |
| Network-level interception (MITM) | TLS 1.2/1.3 with forward-secret cipher suites; HSTS enforced on all subdomains |
| Harvest-now-decrypt-later (post-quantum adversary) | ML-KEM-768 key encapsulation inside TLS; classical TLS layer provides defense in depth |
| Credential stuffing | User accounts require TOTP; no stored passwords |
| Email link preview scanners consuming one-time tokens | Setup tokens are click-gated; endpoint is idempotent for provisional state |
| Log tampering (CT log) | SHA3-256 Merkle tree with ML-DSA-65 signed tree heads; gossip protocol between peer relays |

### What Paramant does not protect against

| Threat | Note |
|--------|------|
| Endpoint compromise | If your device runs malware, client-side encryption offers no protection |
| Coerced disclosure | Legal orders directed at the operator can compel log disclosure; content remains encrypted |
| Social engineering of operators | Administrative access is protected by TOTP but not immune to targeted attacks |
| Quantum cryptanalysis of prior TLS sessions | Mitigated by the PQ encryption layer inside TLS, which is not retroactively breakable |

---

## Compliance posture

Paramant maps technical controls to NIS2 (EU 2022/2555), IEC 62443 (industrial control systems), and NEN 7510 (Dutch healthcare). Mapping documents are part of the standard delivery package for Enterprise customers.

**What this means:**

- Architecture aligns with the technical requirements of these frameworks (RAM-only storage, post-quantum key exchange, signed CT log, EU-only jurisdiction, no US CLOUD Act exposure).
- Compliance documentation is generated from operational evidence — CT log, deployment artefacts, configuration — and updated per release.
- A signed Data Processing Agreement under GDPR Art. 28 is available to all paid tiers.

**What this does NOT mean:**

- No external penetration test has been conducted as of the date of this document. The internal automated audit (2026-04-19) and the independent reviews by R. Zwarts and Ryan Williams listed above are not third-party certification.
- No certification body has audited Paramant against ISO 27001, SOC 2, or any of the frameworks mentioned. The mapping documents are operator-generated.
- "Compliant by design" describes architectural alignment, not formal attestation. Customers requiring independent attestation should treat Paramant as a component within their broader ISMS and contract their own auditor.

If you need formal certification or third-party attestation as part of your procurement process, talk to us early — we will work with your auditor and provide the evidence we have, but we will not represent the platform as pre-certified.

---

## Known limitations (beta)

- Beta access only; hardening for general public availability is in progress.
- Billing in the bundled admin tool uses optional Stripe device-sync hooks (operator-configured); the hosted paramant.app service uses Mollie.
- Some accounts created before TOTP rollout operate on API-key-only authentication.
- Rate limits have not been validated under sustained adversarial load; no WAF is deployed.
- External third-party penetration test has not yet been conducted.

---

## Hall of fame

| Researcher | Contribution | Date |
|------------|-------------|------|
| Ryan Williams ([@scs-labrat](https://github.com/scs-labrat)) | Independent security review — 20 findings | April 2026 |
| R. Zwarts ([@raymond-itsec](https://github.com/raymond-itsec)) | Code audit — 20 findings across two reports | April 2026 |
| Hendrik Bruinsma ([@readefries](https://github.com/readefries)) | FileLink extension + bug reports | April 2026 |
