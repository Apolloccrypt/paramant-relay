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

`POST /api/user/login` did strictly more work for an address that exists: it
reached a second relay call (`/v2/user/verify-totp`) and one more redis read,
where a non-existent address returned two steps earlier. The status codes were
already identical on purpose -- three different 403s were folded into one 401 in
#368 for exactly this reason -- but the clock was not.

Measured on a booted admin, 200 requests per case, interleaved, one source
address each, with the relay stub given a realistic 3 ms cost for the verify
call:

| | median | range |
|---|---|---|
| address exists | 6.44 ms | 4.59 - 9.94 ms |
| address absent | 2.20 ms | 0.90 - 3.73 ms |

The ranges do not overlap. One request classifies an address, under the rate
limit, without any credentials. The review measured 5.40 against 2.95 ms on the
production pair; same channel, slower machine.

No credential answer on that route now leaves before `t0` plus
`PARAMANT_LOGIN_MIN_ANSWER_MS` (default 250 ms), so what an attacker times is a
constant this code sets rather than the path the request took. The not-found
branch also makes the same number of redis calls as the found one, so the floor
is a margin rather than the only thing holding the two paths together. After,
same instrument, same 200 requests:

| | median | range |
|---|---|---|
| address exists | 251.37 ms | 249.61 - 253.01 ms |
| address absent | 251.27 ms | 249.70 - 253.00 ms |

**What was not padded, and why.** 429 (per-IP refusal) and 428 (proof-of-work
required) are not credential answers: their status codes tell them apart
whatever the clock says, and holding them back would only slow down the honest
client whose page is waiting to start hashing. **What this does not fix:** an
address that is over the failure threshold answers 428 where one that is not
answers 401, so a determined attacker who is willing to burn ten failures per
address can still tell them apart by status code. That is the cost of pricing an
attempt instead of refusing it, and it is a far more expensive oracle than a
2 ms timing difference.

Pinned by `admin/test/login-timing.test.js`, which measures both cases against a
booted admin and asserts the medians do not separate and the ranges overlap. The
instrument that produced the numbers above is `admin/test/login-timing.bench.js`
and it can be pointed at any checkout with `ADMIN_SERVER_JS=`.

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
