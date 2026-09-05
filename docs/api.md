# API Reference — PARAMANT v3.0.0

## Base URLs

| Sector | URL | Compliance |
|--------|-----|------------|
| General | https://relay.paramant.app | — |
| Healthcare | https://health.paramant.app | NEN 7510, DICOM |
| Legal | https://legal.paramant.app | eIDAS, KNB |
| Finance | https://finance.paramant.app | NIS2, DORA |
| IoT | https://iot.paramant.app | IEC 62443 |

## Authentication

Three credential types are in use across different API surfaces:

| Credential | Header / Mechanism | Used for |
|------------|-------------------|----------|
| API key (`pgp_` prefix) | `X-Api-Key: pgp_your_key` | Data plane — uploads, downloads, CT log (developer clients) |
| Operator key (`plk_` prefix) | `X-Api-Key: plk_your_key` | Data plane — unlimited throughput (operator license) |
| DID signature | `X-DID: did:paramant:…` + `X-DID-Signature: <sig over request URL>` | Data plane — **active fallback** when no `X-Api-Key` is sent (see Device Identity) |
| ParaSend session token (`pst_` prefix) | `Authorization: Bearer pst_…` | Data plane: the five ParaSend transfer routes only, 15 minutes, minted for a browser session (see below) |
| Session cookie | `Cookie: paramant_user_session=<token>` | `/api/user/*` endpoints — set automatically after TOTP login |
| Admin token | `X-Admin-Token: <token>` | `/admin/api/admin/*` endpoints — admin panel only |

> **DID fallback semantics.** When a request carries no API key but a valid
> `X-DID` + `X-DID-Signature` pair, the relay authenticates the device **as the
> API key the DID was enrolled under**: the request runs with that owner's real
> plan and entitlements, and monthly quotas (`transfers_month`, `signs_month`)
> count on the owner's account exactly as if the owner's `X-Api-Key` had been
> sent, including the same `402` responses over quota. A keyless enrollment
> (e.g. an `inv_` receiver session), a revoked enrollment, or an enrollment
> whose owner key is revoked or deleted grants no principal (`401`). An
> enrolled device credential is therefore a full data-plane credential for the
> owner's account, not merely an attribution label: treat device private keys
> with the same care as API keys, and revoke the DID enrollment when a device
> is retired or compromised.

> **Browser session tokens.** A `pst_` token is a narrow, short-lived stand-in
> for an account API key, so a browser never has to hold the key itself. It is
> minted by the admin panel on behalf of a logged-in user, which asks the relay
> for it over the internal channel; the browser is only ever handed the token,
> never the key. Properties, all enforced by the relay:
>
> - **Purpose, and two allowlists.** A token is minted FOR a purpose, and the
>   purpose picks the list it is judged against. `parasend`
>   (`POST /api/user/parasend/token`, used by `/parashare`) opens
>   `/v2/check-key`, `POST /v2/ws-ticket`, `POST /v2/pubkey`,
>   `GET /v2/pubkey/:device` and `POST /v2/inbound`. `app`
>   (`POST /api/user/app/token`, used by `/pricing`, `/dashboard` and the
>   signed-in homepage) opens `POST /v2/billing/checkout`,
>   `POST /v2/billing/redeem`, `GET /v2/user/history`,
>   `GET /v2/parasign/audit-export` and `GET /v2/parasign/inbox`. The two lists are disjoint: neither purpose
>   can do the other's work. The purpose is fixed by the admin route, not by the
>   caller, and an unknown one is refused at the mint with `400 unknown_purpose`.
> - **Scope.** The allowlist is checked above every route handler. Any path not
>   on the list for that purpose answers `403 session_token_out_of_scope`,
>   including the rest of `/v2/user/*`, `/v2/keys`, `/v2/outbound/:hash`,
>   `/v2/audit`, `/v2/admin/*`, the ParaSign envelope routes, and a second
>   `POST /v2/session-token`: no token mints another, whatever it was minted
>   for.
> - **Identity.** Inside that scope the token authenticates **as the API key it
>   was minted for**. Monthly quotas (`transfers_month`), the audit chain,
>   device queues and per-tier limits all resolve against the owner's account,
>   byte-identical to a request that carried the owner's `X-Api-Key`.
> - **Lifetime.** 15 minutes, held in the relay's shared Redis so all five
>   sectors honour the same token. It is not configurable. The stored record
>   carries the owner as a SHA-256 hash, never as an API key, and the relay
>   resolves it against the key table it already holds in memory; a read-only
>   copy of the store therefore contains no usable credential. A record without
>   a numeric expiry is refused outright.
> - **Ceiling.** At most 20 live tokens per account. The 21st mint answers
>   `429 session_token_cap_reached` with `Retry-After`; tokens already issued
>   keep working, and room returns as they expire.
> - **Audit.** A transfer made with a token appears in the owner's audit chain
>   like any other, with one extra field, `"via": "pst"`. It is a note on the
>   credential, not a second identity.
> - **Revocation.** Revoking the API key deletes every live token for it, and a
>   token whose owner key is revoked or deleted grants no principal even if that
>   sweep did not run.
> - **Precedence.** A request that carries `X-Api-Key` is that key's request; the
>   `Authorization` header is only read when no API key was sent.
> - **Outage.** With the store unreachable a token is answered `503
>   redis_unavailable` with `Retry-After`, never `401`.

CT log and STH endpoints are **public** — no credential required.

The `/v2/auth/capabilities` endpoint is public and returns which authentication modes are enabled on this relay instance.

---

## Data plane

### POST /v2/inbound — Upload an encrypted blob

```bash
curl -X POST https://relay.paramant.app/v2/inbound \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"hash":"sha256hex","payload":"base64_5mb_blob","ttl_ms":3600000}'
```

Response:

```json
{
  "ok": true,
  "hash": "a3f2…",
  "ttl_ms": 3600000,
  "size": 5242880,
  "sig_verified": true,
  "download_token": "6b3c…",
  "merkle_proof": {
    "leaf_hash":  "d4e1…",
    "leaf_index": 42,
    "tree_size":  43,
    "audit_path": [
      {"hash": "8a0b…", "position": "left"},
      {"hash": "f391…", "position": "right"}
    ],
    "root":          "c7a9…",
    "sth":           { "relay_id": "relay.paramant.app", "sha3_root": "c7a9…", "tree_size": 43, "timestamp": 1744123456789, "signature": "…" },
    "sth_signature": "ML-DSA-65 base64…"
  }
}
```

`merkle_proof` proves the blob was appended to the CT log. Re-walk `audit_path` from `leaf_hash` to reproduce `root`, then verify `sth.signature` with `/v2/pubkey`.

---

### The share link: `/v2/dl/<token>` end to end

`POST /v2/inbound` hands back a `download_token`. That token is the whole of the
asynchronous route: it lets somebody who was not present when you uploaded come
and fetch the blob later, with no account, no API key and no second browser
awake. This is what the "Send a link" stand on the ParaSend web app is built on,
and what an integration builds on directly.

**1. Upload the sealed bytes.** The file is encrypted on the sender's side. The
relay is handed ciphertext and a SHA-256 of exactly those bytes, and it verifies
the two match before it stores anything, so the hash written into the CT log
leaf is a hash of bytes the relay really held.

```bash
curl -X POST https://relay.paramant.app/v2/inbound \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"hash":"sha256hex","payload":"base64_ciphertext","ttl_ms":3600000}'
```

**2. Take the token out of the response.**

```json
{ "ok": true, "hash": "a3f2…", "ttl_ms": 3600000, "download_token": "6b3c…" }
```

`download_token` is 24 random bytes as 48 hex characters. `ttl_ms` is the value
the relay actually applied, which is **not** always the one you asked for: the
upload clamps your request to the account's ParaSend tier ceiling (`view_ttl_ms`
in `relay/lib/tiers.js`: 1 hour on Community, 24 hours on Firm, 7 days on
Enterprise, and the table under "ParaSend limits per tier" above is
generated from the same rows). Compute the expiry the receiver is told from the
`ttl_ms` that came back, never from the one you sent.

**3. Build the link, and put the key after the `#`.** A URL fragment is never
put on the wire by a browser, so a key that lives there is a key the relay
cannot see even while it is holding the ciphertext. Everything before the `#`
is fair game for the relay, a proxy, a mail server and a log; everything after
it is not.

```
https://paramant.app/get?t=<download_token>&r=<sector>#<base64url(key||iv)>
```

| Part | What it is |
|---|---|
| `t` | the `download_token` from step 2 |
| `r` | which relay sector holds the blob: `health`, `legal`, `finance` or `iot`. An account is valid on exactly one. Omitted, `/get` asks `health`. |
| fragment | `base64url(key32 then iv12)`, unpadded: the AES-256-GCM key and nonce, 44 bytes before encoding |

The plaintext `/get` expects inside the ciphertext is
`[uint32-LE nameLen][name UTF-8][file bytes]`, so the file name travels sealed
and the relay never learns it. The same wire is produced by the "Send a link"
stand in the web app (`frontend/js/parashare.page.js`) and read by
`frontend/js/get.page.js`.

**4. The receiver opens it.** Three routes serve the link, and only one of them
burns anything:

| Route | What it does |
|---|---|
| `GET /v2/dl/:token` | An HTML confirmation page. Safe for link preloaders and mail scanners: known preload user-agents get a static placeholder, and nothing is spent. |
| `GET /v2/dl/:token/get` | The download itself, and the only route that burns. Answers `410` to a known preload user-agent's twin, `409` while another download of the same token is in flight, and `410` once the token is spent or expired. |
| `GET /v2/dl/:token/info` | `{ ok, enc_meta, file_size, ttl_left_s, used }` while the link is live, `404` once it is not. No credential. |

**5. It works exactly once.** The blob is deleted and its buffer zeroed on the
`finish` event of the download response, not when the response starts: a
transfer that dies mid-flight leaves the token spendable, so a dropped
connection is a retry and not a lost file. Once a download does finish, the
token is marked used and the bytes are gone. The TTL is enforced separately by a
timer, so a link nobody opens is destroyed when it expires whether or not
anybody asks.

**No delivery receipt on this route.** The relay signs a delivery receipt for
`GET /v2/outbound/:hash`, the API's own download path, and you fetch it back
from `GET /v2/transfers/:receipt_id/receipt`. The `/v2/dl` family signs nothing.
If you need proof that a specific person took the file, use `/v2/outbound` and
its receipt; `/v2/dl/:token/info` gives you a status and not a proof, and it
cannot tell "downloaded" apart from "expired" on its own: both answer `404`.
A caller that recorded the expiry at upload time can separate the two by its own
clock, which is what the web app's "sent links" list does, and that inference is
the caller's, not the relay's.

---

### GET /v2/outbound/:hash — Download (burn-on-read)

```bash
curl https://relay.paramant.app/v2/outbound/a3f2… \
  -H "X-Api-Key: pgp_your_key" \
  --output received.bin
```

Response headers:

| Header | Value |
|--------|-------|
| `X-Paramant-Burned` | `true` if blob was destroyed |
| `X-Paramant-Hash` | SHA-256 hex of the blob |
| `X-Paramant-Receipt-Id` | 32 hex characters. Fetch the receipt with it |
| `X-Paramant-Receipt-Hash` | `sha3-256:<hex>` over the receipt bytes you will get back |
| `X-Paramant-Receipt-Url` | `/v2/transfers/<receipt_id>/receipt` |

The receipt is handed over by reference, not by value. It carries a full
ML-DSA-65 signature and an inclusion proof, so the payload is around 18 KB:
too large for a response header. Node's default `maxHeaderSize` is 16 KB and
nginx's default `proxy_buffer_size` is 4k/8k, so a receipt in the header meant
`UND_ERR_HEADERS_OVERFLOW` on the client and 502 at the proxy.

**Deprecated:** `X-Paramant-Receipt`, which carried that payload inline. It is
off by default from 2026-09 and will be removed after **2026-12-01**. An
operator can put it back for the transition with
`PARAMANT_INLINE_RECEIPT_HEADER=1`, and must then also raise
`proxy_buffer_size` on any proxy in front of the relay.

While the old header is off, every download also carries
`X-Paramant-Receipt-Deprecated: removed 2026-12-01; GET /v2/transfers/<id>/receipt`.
It exists because a client that reads `X-Paramant-Receipt` and finds nothing
cannot tell "this transfer had no receipt" from "the receipt moved", and a
delivery proof must never go missing quietly. The header is not sent when the
opt-in is on, because then there is nothing to announce.

---

### GET /v2/transfers/:receipt_id/receipt (fetch a delivery receipt)

Requires the same API key that made the download. An unknown, expired, or
foreign id all answer with the same 404, so the route cannot be used to probe
whether a transfer existed.

**How long you have, exactly.** Fetch the receipt right after the download.
Three things can take it away, and all three answer with the same 404:

| | |
|---|---|
| **Time** | 15 minutes from the download. |
| **Your own volume** | The relay keeps your account's most recent receipts, up to twice your ParaSend tier's hourly download ceiling: Community 100, Firm 1000, legacy business 4000, Enterprise 10000. Past that your oldest receipts drop. Another account's downloads can never take yours. |
| **A relay without redis** | A relay configured with `REDIS_URL` keeps receipts in redis, so they survive a restart of the relay process. A relay without one keeps them in memory, and then a restart or a deploy loses every outstanding receipt. |

If none of that is acceptable for your use, the receipt can still be delivered
inline on the download itself: ask the operator to run the relay with
`PARAMANT_INLINE_RECEIPT_HEADER=1`, which restores the `X-Paramant-Receipt`
header alongside the reference. That header is around 18 KB, so it needs
`proxy_buffer_size` raised on any proxy in front of the relay, and it is
removed after 2026-12-01.

```bash
curl https://relay.paramant.app/v2/transfers/$RECEIPT_ID/receipt \
  -H "X-Api-Key: pgp_your_key"
```

```json
{
  "ok": true,
  "receipt": "<base64url>",
  "receipt_hash": "sha3-256:9c1f…"
}
```

`receipt_hash` is identical to the `X-Paramant-Receipt-Hash` the download
carried, over the exact `receipt` string returned here, so the handover is
verifiable end to end.

`receipt` decodes to:

```json
{
  "blob_hash":               "a3f2…",
  "sector":                  "health",
  "retrieved_at":            "2026-04-15T09:00:00.000Z",
  "relay_id":                "health.paramant.app",
  "tree_size_at_retrieval":  43,
  "inclusion_proof":         { "leaf_hash": "d4e1…", "audit_path": […], "root": "c7a9…" },
  "burn_confirmed":          true,
  "signature":               "ML-DSA-65 base64…"
}
```

Pass this to `POST /v2/verify-receipt` to cryptographically confirm delivery.

---

### POST /v2/verify-receipt — Verify a delivery receipt

Public. No API key required.

This endpoint asks the relay to check its own signature. To check a receipt
without the relay, and without a network connection at all, open
[https://paramant.app/verify#receipt](https://paramant.app/verify#receipt) and
drop the receipt in. That page carries the relay identity key and repeats the
same four checks in the browser.

```bash
curl -X POST https://relay.paramant.app/v2/verify-receipt \
  -H "Content-Type: application/json" \
  -d '{"receipt":"<base64url from GET /v2/transfers/:receipt_id/receipt>"}'
```

Success:

```json
{
  "valid": true,
  "blob_hash": "a3f2…",
  "burn_confirmed": true,
  "tree_size_at_retrieval": 43,
  "retrieved_at": "2026-04-15T09:00:00.000Z"
}
```

Failure (signature invalid, proof mismatch, missing fields):

```json
{ "valid": false, "reason": "signature_invalid" }
{ "valid": false, "reason": "inclusion_proof_invalid", "detail": "recomputed root 8a0b… ≠ claimed root c7a9…" }
```

Verification performs two independent checks: ML-DSA-65 signature over the canonical receipt JSON, then re-walks the Merkle audit path to recompute the root.

---

### GET /v2/stream-next — Poll for next pending blob

```bash
curl https://relay.paramant.app/v2/stream-next \
  -H "X-Api-Key: pgp_your_key" \
  -H "X-Device-Id: receiver-001"
# 200: {"blob_hash":"a3f2…","queued_at":"2026-04-15T…"}
# 204: no pending blobs
```

---

### GET /v2/status/:hash — Check blob availability

```bash
curl https://relay.paramant.app/v2/status/a3f2… \
  -H "X-Api-Key: pgp_your_key"
# {"available":true,"bytes":5242880,"ttl_remaining_ms":3598012,"sig_valid":true}
```

---

## Certificate Transparency log

All CT endpoints are **public** — no API key required.

### GET /v2/sth — Latest Signed Tree Head

```bash
curl https://relay.paramant.app/v2/sth
```

```json
{
  "ok": true,
  "sth": {
    "relay_id":   "relay.paramant.app",
    "sha3_root":  "c7a9ef34…",
    "tree_size":  43,
    "timestamp":  1744123456789,
    "version":    1,
    "signature":  "ML-DSA-65 base64…",
    "pk_hash":    "sha3-256 of relay public key"
  }
}
```

The relay signs `{relay_id, sha3_root, timestamp, tree_size, version}` (keys sorted, JSON-serialised) using ML-DSA-65. Verify the signature against the key returned by `GET /v2/pubkey`.

`timestamp` is rounded down to the top of the hour **before it is signed**, so a head says
when it was signed no more precisely than the log says when anything happened. A head is
produced on every append, so a millisecond timestamp here would have given away the exact
time of the leaf at `tree_size - 1`, and the leaf commits to that time. `tree_size` still
orders the heads one per append. Heads signed before this changed keep the precise
timestamp they were signed with and still verify: verification rebuilds the canonical
payload from the fields a head carries and pins no resolution.

The response may also carry a `forked` object. It appears only when the relay has REFUSED
to sign a head that would contradict one it already signed, which is what happens when a
relay comes back from a restart with its signing key and its head history but without its
tree. The relay then stops issuing heads rather than publishing a second history, and this
field is how an outside monitor tells that apart from a quiet week.

---

### GET /v2/sth/history — STH history

```bash
curl "https://relay.paramant.app/v2/sth/history?limit=10"
# {"ok":true,"count":10,"total":48,"sths":[…]}
```

`limit` max 100.

---

### GET /v2/sth/:unixms — STH at or after a timestamp

```bash
curl https://relay.paramant.app/v2/sth/1744100000000
# {"ok":true,"sth":{…}}   — first STH at or after that Unix millisecond timestamp
# 404 if none exists
```

---

### GET /v2/pubkey — Relay identity public key

```bash
curl https://relay.paramant.app/v2/pubkey
```

```json
{
  "ok": true,
  "alg": "ML-DSA-65",
  "public_key": "base64…",
  "pk_hash": "sha3-256 hex of the key"
}
```

Use this key to independently verify any STH signature or delivery receipt signature. The key is generated once at first boot and persisted; `pk_hash` is its SHA3-256 fingerprint.

---

### GET /v2/ct/log — CT log entries

```bash
curl "https://relay.paramant.app/v2/ct/log?limit=20"
# {"ok":true,"entries":[{…}],"tree_size":43,"root":"c7a9…"}
```

`index` is the entry's position in the log, counted from the start. It is
derived at request time, so it always matches the index `/v2/ct/proof` resolves
and the leaf position the Merkle tree commits to.

---

### GET /v2/ct/proof — Inclusion proof for a specific index

```bash
curl "https://relay.paramant.app/v2/ct/proof?index=7"
# {"ok":true,"leaf_hash":"d4e1…","audit_path":[…],"root":"c7a9…","tree_size":43}
```

---

### GET /v2/sth/consistency — RFC 6962 consistency proof

Prove that tree at size `from` is a prefix of tree at size `to`:

```bash
curl "https://relay.paramant.app/v2/sth/consistency?from=20&to=43"
# {"ok":true,"from":20,"to":43,"proof":["hash1","hash2",…]}
```

`to` defaults to current tree size if omitted.

---

## Cross-relay gossip

These endpoints power the peer-to-peer STH exchange. They allow any relay (or auditor) to independently archive and verify each other's tree heads.

### POST /v2/sth/ingest — Submit a peer STH

```bash
curl -X POST https://relay.paramant.app/v2/sth/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "relay_id":  "health.paramant.app",
    "sha3_root": "c7a9…",
    "timestamp": 1744123456789,
    "tree_size": 43,
    "version":   1,
    "signature": "base64…",
    "public_key":"base64…"
  }'
# {"ok":true,"relay_pk_hash":"sha3-256 hex"}
```

The relay verifies the ML-DSA-65 signature before storing. Replay attacks are blocked by a 5-minute timestamp window.

---

### GET /v2/sth/peers — List mirrored peer relays

```bash
curl https://relay.paramant.app/v2/sth/peers
```

```json
{
  "ok": true,
  "count": 3,
  "peers": [
    {
      "relay_pk_hash":     "a1b2…",
      "relay_id":          "health.paramant.app",
      "sth_count":         12,
      "latest_root":       "c7a9…",
      "latest_tree_size":  43,
      "latest_ts":         "2026-04-15T09:00:00.000Z"
    }
  ]
}
```

---

### GET /v2/sth/peers/:pk_hash — Full STH history for a specific peer

```bash
curl "https://relay.paramant.app/v2/sth/peers/a1b2…?limit=50&offset=0"
# {"ok":true,"relay_pk_hash":"a1b2…","sths":[…],"total":12,"limit":50,"offset":0}
```

---

## CT log web UI and feeds

| Path | Description |
|------|-------------|
| `GET /ct/` | Public web UI — live tree view, verify button, no auth |
| `GET /ct/feed` | JSON feed for the UI (auto-refresh every 10s). `t` is rounded to the hour, as in `/v2/ct/log` |
| `GET /ct/feed.xml` | RSS feed — last 20 STHs. Subscribe to independently archive roots. |

The RSS feed is designed for external archiving: any subscriber retains an independent copy of each signed tree head, making log tampering detectable even if the relay is compromised later.

---

## Other endpoints

### GET /health — Relay status (public)

```bash
curl https://relay.paramant.app/health
# {"ok":true,"version":"3.0.0","sector":"relay","edition":"community"}
```

### GET /v2/relays — Relay registry (public)

```bash
curl https://relay.paramant.app/v2/relays
# {"total":5,"relays":[{"url":"…","version":"3.0.0","sector":"relay",…}]}
```

### POST /v2/pubkey — Register device public keys

```bash
curl -X POST https://relay.paramant.app/v2/pubkey \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"phone-001","ecdh_pub":"base64…","kyber_pub":"base64…"}'
# {"ok":true}
```

### GET /v2/pubkey/:device — Fetch a device's public keys

```bash
curl https://relay.paramant.app/v2/pubkey/phone-001 \
  -H "X-Api-Key: pgp_your_key"
# {"device_id":"phone-001","ecdh_pub":"…","kyber_pub":"…","registered_at":"…"}
```

### POST /v2/session-token: mint a ParaSend session token (internal)

Not reachable from a browser or from the public internet. It requires the
internal channel header **and** the account's API key, and the admin panel is
the only caller: it sends the key of the session that asked, so a browser can
never name an account other than the one it is signed in as. See the
Authentication section above for what the resulting token can and cannot do.

```bash
curl -X POST https://health.paramant.app/v2/session-token \
  -H "X-Internal-Auth: $INTERNAL_AUTH_TOKEN" \
  -H "X-Api-Key: pgp_your_key"
# {"ok":true,"token":"pst_…","expires_ms":1767225600000,"expires_in_s":900}
```

| Status | Meaning |
|--------|---------|
| 200 | Token minted. The response never contains the API key. |
| 401 | Missing or wrong `X-Internal-Auth`, or no live account key. The two are not distinguishable. |
| 403 | The caller presented a session token; a token cannot mint another one. |
| 429 | The account already holds 20 live tokens. `Retry-After: 60`. |
| 503 | The relay store is unreachable, so no checkable token can be issued. |

The browser-facing half of this is two routes on the admin panel, both session
cookie, both ignoring their request body, both returning only `token` and
`expires_in_s`: `POST /api/user/parasend/token` mints purpose `parasend` and
`POST /api/user/app/token` mints purpose `app`. The purpose is a property of the
route, so a page cannot ask for the other one's authority.

`POST /v2/session-token` itself takes an optional body `{"purpose": "parasend" |
"app"}`. An absent purpose means `parasend`, so a caller written before purposes
existed is unchanged; an unrecognised one is `400 unknown_purpose`.

---

## Device Identity

Ghost Pipe supports W3C-compatible decentralised identifiers (`did:paramant:`) for field devices. Registering a device identity enrolls it in the CT log and allows transfers to be attributed to a specific device without exposing the API key.

Note that an enrolled DID is also an **authentication fallback**: a request
without an API key but with a valid `X-DID` + `X-DID-Signature` is accepted
and runs under the plan and quotas of the API key the DID was enrolled under
(see Authentication).

### POST /v2/did/register — Enroll a device

```bash
curl -X POST https://iot.paramant.app/v2/did/register \
  -H "X-Api-Key: plk_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "plc-factory-01",
    "ecdh_pub":  "<base64 ECDH P-256 uncompressed public key, 65 bytes>",
    "dsa_pub":   "<base64 ML-DSA-65 public key — optional>"
  }'
```

Response:

```json
{
  "ok": true,
  "did": "did:paramant:a3f2b7c1…",
  "document": {
    "id": "did:paramant:a3f2b7c1…",
    "verificationMethod": [
      {
        "id": "did:paramant:a3f2b7c1…#keys-1",
        "type": "JsonWebKey2020",
        "controller": "did:paramant:a3f2b7c1…",
        "publicKeyHex": "<ecdh_pub>"
      }
    ]
  },
  "ct_index": 42
}
```

`ct_index` is the CT log position of this registration — auditors can verify the enrollment timestamp via `/v2/ct/proof?index=42`.

Limits: max 500 DIDs per API key. Receiver sessions (`device_id` starting with `inv_`) do not require an API key.

---

### GET /v2/did/:did — Resolve a DID document

Public endpoint — no API key required.

```bash
curl https://iot.paramant.app/v2/did/did:paramant:a3f2b7c1…
```

Returns the W3C DID document including the device's public key and CT registration index.

---

### GET /v2/did — List enrolled devices

```bash
curl https://iot.paramant.app/v2/did \
  -H "X-Api-Key: plk_your_key"
```

```json
{
  "ok": true,
  "count": 3,
  "dids": [
    { "did": "did:paramant:a3f2…", "device": "plc-factory-01", "ts": "2026-04-01T…" },
    { "did": "did:paramant:b8e1…", "device": "plc-factory-02", "ts": "2026-04-01T…" }
  ]
}
```

---

### POST /v2/attest — Attest a device

Verify that a device holds the private key corresponding to its registered public key:

```bash
curl -X POST https://iot.paramant.app/v2/attest \
  -H "X-Api-Key: plk_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id":   "plc-factory-01",
    "attestation": {
      "method":    "ecdh-challenge",
      "challenge": "<base64 challenge bytes>",
      "response":  "<base64 signed response>"
    }
  }'
```

```json
{ "ok": true, "valid": true, "device": "plc-factory-01" }
```

---

## ParaSend limits per tier

Every ceiling below is enforced from one source, the account's **ParaSend**
tier. That tier is its own axis: it is carried by `plan_parasend` on the account
and is independent of the ParaSign tier, so buying one product does not move the
other. A ParaSend purchase raises `plan_parasend` alone, and every gate reads
that, so the limits a customer is held to are the limits the pricing page sold
him. An account with no tier on file is held to Community.

| | Community | Firm | Enterprise |
|---|---|---|---|
| Transfers per month | 10 | 500 | 1,000,000 |
| Link lifetime (max TTL) | 1 hour | 24 hours | 7 days |
| Reads per link (max views) | 1 | 10 | 100 |
| Registered devices | 5 | 50 | unlimited |
| Max blob size | 5 MB | 5 MB | 5 MB (relay `MAX_BLOB`) |
| Downloads per hour | 50 | 500 | unlimited |

Notes:

- **Downloads per hour** is a sliding one-hour window per API key on
  `GET /v2/outbound/:hash`; over it the relay answers `429`. It also sets how
  many delivery receipts your account keeps (twice this number, see above).
- **Max blob size** is the lower of the tier's ceiling and the operator's
  `MAX_BLOB`, which is 5 MB on the hosted relay and bounds relay memory. The
  operator's value is always the last word, which is why an Enterprise account
  is held to 5 MB as well and why `GET /v2/admin/usage` reports 5 rather than
  "uncapped" for it.
- **Reads per link** and **link lifetime** are ceilings, not defaults: a request
  asking for more gets the ceiling back in the upload response, so the clamp is
  visible to the caller. Asking for less is honoured as asked.
- **Registered devices** is a ceiling on how many device public keys an account
  may hold, not a limit on requests. A device the account already holds may
  always re-register, so an account that is over the ceiling keeps its existing
  devices working and is refused only a new one.
- A legacy `business` plan is a ParaSign tier name. On ParaSend it keeps its own
  row (2000 transfers a month, 100 devices, a 7 day link, 25 reads, 2000
  downloads an hour) rather than being raised to Enterprise or cut to Firm. It is
  resolved, never sold: ParaSend cannot be bought or granted at that tier.

---

## Error codes

| Code | Meaning |
|------|---------|
| 400 | Bad request — missing or invalid fields |
| 401 | Invalid API key or signature |
| 403 | Forbidden: wrong API key for this blob, or `session_token_out_of_scope` |
| 404 | No blob / no STH at that timestamp |
| 429 | Rate limit exceeded |
| 503 | ML-DSA-65 not available on this relay |
| 500 | Relay error |

---

## Python SDK

```bash
pip install paramant-sdk
```

```python
from paramant_sdk import GhostPipe

gp = GhostPipe(api_key="pgp_xxx", device="device-001", sector="health")

# Send — returns (hash, inclusion_proof)
hash_, proof = gp.send(open("scan.dcm", "rb").read(), ttl=3600)
print(proof["root"])          # Merkle root at time of upload
print(proof["leaf_index"])    # Position in the tree

# Receive — returns (data, receipt)
data, receipt = gp.receive(hash_)
print(receipt["burn_confirmed"])   # True if blob was destroyed
print(receipt["tree_size_at_retrieval"])

# Verify receipt (calls POST /v2/verify-receipt)
result = gp.verify_receipt(receipt)
print(result["valid"])        # True if ML-DSA-65 sig + Merkle proof both check out

# Anonymous drop (BIP39 mnemonic)
mnemonic = gp.drop(b"sensitive data", ttl=3600)
data, _   = gp.receive(mnemonic)  # pickup by mnemonic
```

---

## CLI tools

Install via:

```bash
curl -fsSL https://paramant.app/install-client.sh | bash
```

Or included in [paramantOS](https://github.com/Apolloccrypt/ParamantOS). Full list and source: [`scripts/`](../scripts/).

### CT log verification

```bash
# Fetch the latest STH and verify the ML-DSA-65 signature
paramant-verify-sth --relay https://relay.paramant.app

# Verify against a specific relay and print the tree state
paramant-verify-sth --relay https://health.paramant.app --verbose

# Cross-check STH consistency across all peer relays
paramant-verify-peers
paramant-verify-peers --relay https://relay.paramant.app
```

`paramant-verify-sth` fetches `/v2/sth` and `/v2/pubkey`, verifies the ML-DSA-65 signature, and exits non-zero if invalid.

`paramant-verify-peers` fetches `/v2/sth/peers` and verifies that each mirrored STH is internally consistent and that tree sizes only grow.

### Delivery receipts

```bash
# View the receipt returned after a receive operation
paramant-receipt --hash a3f2…

# Save receipt to file
paramant-receipt --hash a3f2… --save receipt.json

# Verify a saved receipt
paramant-receipt --verify receipt.json
paramant-receipt --verify <base64url>
```

`paramant-receipt --verify` calls `POST /v2/verify-receipt` and prints the result. Exit code 0 = valid, 1 = invalid.

---

## Trust model

The CT log follows the same trust model as [Certificate Transparency (RFC 6962)](https://tools.ietf.org/html/rfc6962): you need at least one honest participant in the ecosystem to detect misbehaviour.

- **Monitors** call `GET /v2/sth` on a schedule and archive each root. A root that changes without a corresponding tree extension is a fork — proof of log manipulation.
- **Auditors** call `GET /v2/ct/proof?index=N` to check inclusion of any known blob hash.
- **Gossip** (`/v2/sth/ingest`, `/v2/sth/peers`) lets relays cross-check each other's trees. A relay cannot silently show different trees to different parties if peers are exchanging STHs.
- **RSS archiving** (`/ct/feed.xml`) lets anyone subscribe to the STH feed. Once published, a root cannot be un-published without leaving evidence.

You do not need to trust the relay operator to detect log tampering — you only need to trust that at least one monitor, auditor, or RSS subscriber is honest and retains their copy.

---

## User account API

All `/api/user/` endpoints are served by the **admin panel** (`https://paramant.app`), not the sector relays. They require either an active session cookie or are part of the unauthenticated signup and login flows.

### POST /api/user/signup

```bash
curl -X POST https://paramant.app/api/user/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com"}'
# {"ok":true}
```

Sends a TOTP setup link to the given email address. Rate-limited per IP and per email.

### POST /api/user/auth/setup/:token

```bash
curl -X POST https://paramant.app/api/user/auth/setup/abc123... \
  -H "Content-Type: application/json"
# {"secret":"BASE32SECRET","backup_codes":["code1","code2",…]}
```

Returns the TOTP secret (as a Base32 string) and one-time backup codes. Idempotent: if the enrollment is provisional (QR scanned but not yet confirmed), the same secret is returned on repeat calls. Returns 409 only if TOTP is already fully activated.

### POST /api/user/auth/setup/:token/confirm

```bash
curl -X POST https://paramant.app/api/user/auth/setup/abc123.../confirm \
  -H "Content-Type: application/json" \
  -d '{"totp_code":"123456"}'
# {"ok":true}
```

Verifies the first TOTP code and activates the account. After this call the setup token is consumed and cannot be reused.

### POST /api/user/auth/login

```bash
curl -X POST https://paramant.app/api/user/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","totp_code":"123456"}'
# Sets: Set-Cookie: paramant_user_session=<token>; HttpOnly; Secure; SameSite=Strict
# {"ok":true}
```

**Rate limits on this endpoint.** Two counters, and they are deliberately not
the same kind of thing:

| Keyed on | Counts | Window | Over the limit |
|----------|--------|--------|----------------|
| IP address | every attempt | 15 min | `429 rate_limited` after 5 |
| Email address | failed sign-ins only | 15 min | `428 pow_required` after 10, never a refusal |

The per-IP counter is a hard refusal, because the IP address is the caller's own
resource. The per-email counter is not, because the address is request input:
anyone can name yours. It counts only attempts that actually failed, a
successful sign-in deletes it, and once it is over the threshold the next
attempt has to carry a solved proof-of-work (`challenge_id` + `nonce` from
`GET /api/captcha/challenge`, the same 2^18 challenge signup uses) instead of
being turned away. The request that asks for the proof is not charged to the
per-IP counter, so the five attempts stay five real attempts.

Be clear about what that proof buys. It is a fixed 2^18 challenge: measured on
this repository a native solver finds a nonce in roughly 150 to 250 ms, and a
browser doing the same work through WebCrypto takes one to two seconds. It makes
each automated guess measurably more expensive and it stops a stranger from
switching your account off, but it is not the brake on guessing. The brake is
the per-IP limit above: five attempts per IP per fifteen minutes.

```bash
# after ten failed attempts on this address
curl -X POST https://paramant.app/api/user/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","totp_code":"123456","challenge_id":"...","nonce":12345}'
```

A `503 totp_unavailable` means the single-use guard behind TOTP verification
could not reach Redis. The code was not rejected and nothing is wrong with the
account; verification fails closed rather than accepting a code it cannot mark
as spent. See SECURITY.md.

**Every credential answer on this route is held to a floor**, so a 401 for an
address that has an account takes exactly as long as one for an address that
does not. The floor is `PARAMANT_LOGIN_MIN_ANSWER_MS` (default 250 ms) plus what
the address owes for its own recorded failures: 250 ms per failure past ten,
capped at 2000 ms. So a clean address is answered at 250 ms and one with twenty
failures at 2250 ms, either way whether or not it exists.

That second part used to be charged by the relay against the ACCOUNT, and only
an address with an account could reach it, so the anti-guessing delay was itself
an existence oracle: 509.91 ms against 251.61 ms at twelve prior failures, with
no overlap. The `503 totp_unavailable` answer was unfloored for the same reason
and is floored now too. The 428 and the 429 are not held back: their status
codes tell them apart whatever the clock says, and the login page is waiting on
the 428 to start hashing.

An address over the failure threshold still answers 428 where one under it
answers 401, so the status code remains a distinguisher for an attacker willing
to burn ten failures and a proof-of-work per address. That is the deliberate
price of pricing an attempt rather than refusing it.

### POST /api/user/auth/login-with-backup

```bash
curl -X POST https://paramant.app/api/user/auth/login-with-backup \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","backup_code":"abc-def-ghi"}'
# {"ok":true}
```

Backup codes are single-use. The account is re-locked after use; a new TOTP enrollment is required.

**This route is floored too, and higher.** A wrong backup code is verified
against every stored hash, so a miss costs ten argon2id verifications at 64 MiB:
about half a second, and an address with no account pays none of it. Every
credential answer is held to `PARAMANT_LOGIN_BACKUP_MIN_ANSWER_MS` (default
1500 ms) plus 250 ms per prior attempt on that address past the first, capped at
2000 ms. Five attempts per address and ten per source address per fifteen
minutes are refused outright with a 429.

A body whose `email` or `backup_code` is not a string is a `400 missing_fields`,
the same answer for every caller.

### POST /api/user/auth/logout

```bash
curl -X POST https://paramant.app/api/user/auth/logout \
  -H "Cookie: paramant_user_session=<token>"
# {"ok":true}
```

### GET /api/user/session/verify

```bash
curl https://paramant.app/api/user/session/verify \
  -H "Cookie: paramant_user_session=<token>"
# {"ok":true,"user_id":"…","email":"jane@example.com"}
```

### GET /api/user/account

Returns the account profile, active sessions, and billing status.

```bash
curl https://paramant.app/api/user/account \
  -H "Cookie: paramant_user_session=<token>"
# {"ok":true,"email":"jane@example.com","plan":"free","sessions":[…]}
```

### DELETE /api/user/account

Permanently deletes the account and all associated Redis state.

```bash
curl -X DELETE https://paramant.app/api/user/account \
  -H "Cookie: paramant_user_session=<token>"
# {"ok":true}
```

### POST /api/user/account/totp/reset

Sends a new TOTP setup link, invalidating the current TOTP secret. Requires an active session.

### POST /api/user/account/sessions/revoke-others

Revokes all sessions except the current one.

### POST /api/user/account/backup-codes/regenerate

Generates a new set of backup codes and invalidates all previous ones.

### POST /api/user/billing/checkout (410 Gone)

Removed on 20 July 2026 and kept as a 410 so a stale client gets a clean answer: it granted a plan without a payment. `GET /api/user/billing/checkout/:token` and `POST /api/user/billing/checkout/:token/confirm` answer the same.

```bash
curl -X POST https://paramant.app/api/user/billing/checkout \
  -H "Cookie: paramant_user_session=<token>"
# 410
# {"error":"billing_stub_removed","message":"Checkout moved to Mollie; this endpoint no longer grants plans."}
```

The one path to a paid plan is the Mollie checkout on the relay, `POST /v2/billing/checkout`, see [Billing (Mollie)](#billing-mollie) below. The tier is granted by `/v2/billing/webhook` only after Mollie confirms the payment as paid for the amount the catalog names, and that same webhook issues the invoice or payment receipt. The `stub_notice` field this section used to point at is gone from `GET /api/user/billing/status` too.

### POST /api/user/billing/cancel

Schedules a downgrade at the end of the current billing period. Returns `{"scheduled_downgrade_at":"…"}`.

### GET /api/user/billing/status

Returns current plan and subscription state: `current_plan`, `period`, `amount_eur`, `next_billing_date`, `cancellation_scheduled_at`.

### GET /api/user/billing/history

Returns one chronological list, newest first: the payments and credit notes the
relay has documents for, the plan terms that ended, and the admin plan changes
from the audit log (plan changes, scheduled cancellations, downgrades). Rows
carry `ts`, `type`, `label`, `detail`, `amount`, `currency` and `document`; a row
with a `document` is downloadable at
`/api/user/billing/invoices/<number>.pdf`.

### GET /api/user/billing/invoices

Returns this account's invoices and credit notes, proxied from the relay.

---

## Billing (Mollie)

Paid ParaSend and ParaSign plans are billed through [Mollie](https://www.mollie.com). The relay creates the payment and grants the entitlement from the webhook. Prices come from the server-side catalog (`relay/lib/billing-catalog.js`); the caller can never set an amount.

### POST /v2/billing/checkout — Start a Mollie payment

Requires an API key. The body names a product, plan, and interval; the price is looked up server-side.

```bash
curl -X POST https://relay.paramant.app/v2/billing/checkout \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"product":"firm","plan":"firm","interval":"monthly"}'
# {"ok":true,"payment_id":"tr_…","checkout_url":"https://www.mollie.com/checkout/…","mode":"live"}
```

| Field | Values |
|-------|--------|
| `product` | `firm`, `parasign`, `parasend` |
| `plan` | `firm` (firm); `business` (parasign); legacy `pro` (parasign, parasend) |
| `interval` | `monthly`, `yearly` |

`firm`/`firm` is the bundle, and the only paid plan sold alongside
`parasign`/`business`. One payment grants **both** product entitlements,
ParaSign `pro` and ParaSend `pro`, from one catalog amount and with **one**
`paid_until` written to both, so a Firm term ends on one day. The single
exception is upward: a product that already carries a LATER `paid_until`, bought
before the change, keeps it. Buying Firm never shortens a term somebody paid
for, so it can only ever leave one product ahead of the other, never behind.

`parasign`/`pro` and `parasend`/`pro` are no longer sold. They stay resolvable
in the catalog on purpose: an outstanding renewal of a term bought before the
change still checks out at its own price, and an existing Mollie subscription
created against one of them keeps charging and keeps being granted. Nothing on
the site links to them.

Redirect the buyer to `checkout_url` to complete the payment; Mollie then redirects back to `/dashboard?billing=return`. `mode` is `live` or `test`, controlled by `BILLING_MODE` and which Mollie key (`MOLLIE_API_KEY` / `MOLLIE_TEST_API_KEY`) is configured. The recurring layer (a Mollie customer, a `sequenceType: first` payment and a subscription created after the grant) runs only when `BILLING_MODE` is set explicitly to `live` or `test`; with `BILLING_MODE` empty the relay creates plain one-off payments, and the `billing_config` log line at boot says which stance is active.

Errors: `401 unauthorized` (missing or invalid API key), `400 bad_json` / `unknown_product` / `unknown_plan` / `unknown_interval`, `502 checkout_failed` (Mollie unreachable or rejected the payment).

### POST /v2/billing/webhook — Mollie status callback

Called by Mollie with `id=tr_…` (form-encoded). The relay ignores everything else in the webhook body, re-fetches the payment from the Mollie API as the only source of truth, verifies the amount actually paid against the catalog, and grants the product tier idempotently. Responds `200` on every handled event, `400 bad_payment_id` for a malformed id, and `503` on a transient Mollie fetch failure (so Mollie retries).

A `firm` payment is a bundle: one handled event sets **two** entitlements,
ParaSign to `pro` and ParaSend to `pro`, both with the same `paid_until`. A
single-product payment (the legacy `pro` plans, or `parasign`/`business`) sets
one. Idempotency is per payment id, so a Mollie retry of a bundle grants both
again without extending either term.

Not intended to be called by clients.

A refund or a chargeback arrives on the same `tr_` id as the payment. A
**chargeback** also takes the entitlement back: a charged-back `firm` payment
returns **both** products to their floor, ParaSign to `free` and ParaSend to
`community`, because the one payment is what held both up, and it clears the
paid period with them. A charged-back single-product payment returns only that
product. A **refund** moves no entitlement; the credit note is the record. The
relay issues a **credit note** for either: its own sequential number in its own series
(`CN-2026-0001`, per calendar year), referring to the invoice it credits by
number and date, with negative net, VAT and total. One per reversal, idempotent
against a Mollie retry. A partial refund is credited for the amount that went
back, with VAT pro rata in whole cents; the invoice itself is only marked
reversed once the whole of it has been credited.

### GET /v2/billing/invoices: this account's documents

Requires `X-Api-Key`. Returns every document issued to the account, newest
first: invoices (`PS-…`), payment receipts, and credit notes (`CN-…`, `kind`
`credit_note`, with `credit_for` naming the invoice and `partial` saying whether
the rest of it still stands). Each row carries `pdf_url`.

### GET /v2/billing/invoices/:number.pdf: one document

Requires `X-Api-Key`. Serves the PDF for one `PS-` or `CN-` number, rendered on
demand from the stored record. `400 bad_invoice_number` for a malformed number,
`404` for a number that does not belong to this account.

### GET /v2/billing/history: one chronological list

Requires `X-Api-Key`. Derived, never stored: the invoice and credit-note records
for the money, and the paid periods on those same records for the terms that
ended. Rows carry `ts`, `type` (`invoice`, `credit_note`, `term_ended`), `label`,
`detail`, `amount`, `currency`, `document` and `pdf_url`. A period end that a
renewal extended is not an ending and is not listed.

### GET /v2/admin/billing/export: the books for one period

Requires `X-Admin-Token` (`ADMIN_TOKEN`), like every other `/v2/admin/*` path.
This is the whole customer base's billing in one answer, so it is never reachable
with a customer key.

```
GET /v2/admin/billing/export?from=2026-09-01&to=2026-09-30&format=csv
GET /v2/admin/billing/export?from=2026-09-01&to=2026-09-30&format=json
GET /v2/admin/billing/export?from=2026-09-01&to=2026-09-30&pdfs=1
```

Every document issued in the period, both ends inclusive, both series, filtered
on the date the document itself states. One row per document, with the columns
`number`, `date`, `type`, `customer_name`, `customer_email`, `customer_vat`,
`description`, `amount_net`, `vat_rate`, `amount_vat`, `amount_gross`,
`currency`, `payment_id` (the Mollie `tr_` id), `credit_for` (the invoice a
credit note reverses) and `moneybird_id`. A credit note carries negative
amounts; nothing is netted off.

`format=csv` (the default) answers with a downloadable file for a Dutch Excel:
semicolon separated, a UTF-8 BOM, CRLF line endings and a comma as the decimal
mark. `format=json` answers with the same rows using dots, plus `totals` over
the period and `missing`, the numbers in the series whose record could not be
read. `pdfs=1` answers with a `application/zip` holding the ledger file and one
PDF per document, stored without compression.

`400 bad_period` for a date that is not `YYYY-MM-DD` or a `from` after the `to`;
`400 bad_format` for anything but `csv` or `json`; `503 export_unavailable` when
redis is not reachable, because the documents live there.

## Gift codes

A code gives an account a term without any money moving. It is **not** a
checkout with a 100% discount: nothing reaches Mollie, no invoice number is
drawn, and nothing lands in the books as revenue, because nothing was sold. What
a redemption does share with a payment is the half the customer cares about, and
it shares it by calling the same `setProductPlan` the webhook calls, so
`plan_<product>` and `paid_until_<product>` are written the ordinary way and the
entitlement layer, the expiry index and the reminder mails need no special case.

Rules the store enforces (`relay/lib/coupon.js`):

- codes are case-insensitive, `A-Z`, `0-9` and `-`, 3 to 32 characters;
- one redemption per **account** per code;
- the cap is real: the claim is a single Lua script, so the redemption after the
  last seat is refused rather than racing past it;
- a term is **added**, never substituted. An account with a paid term still
  running gets the gift days after that term, not instead of it.

### POST /v2/admin/coupons: create a code

Requires `X-Admin-Token` (`ADMIN_TOKEN`), like every other `/v2/admin/*` path.

The example below is the live campaign: the code handed to the Buy Me a Coffee
supporters, three months of both products, a hundred places, redeemable up to
and including 30 September 2026.

```bash
curl -X POST https://health.paramant.app/v2/admin/coupons \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"COFFEE","max_redemptions":100,"valid_until":"2026-09-30T23:59:59Z",
       "created_by":"mick","note":"Buy Me a Coffee supporters",
       "grants":[{"product":"parasign","tier":"pro","days":90},
                 {"product":"parasend","tier":"pro","days":90}]}'
# 201 {"ok":true,"coupon":{"code":"COFFEE","used":0,"remaining":100,
#      "describes":"3 months of ParaSign Pro and ParaSend Pro", ...}}
```

| Field | Meaning |
|-------|---------|
| `code` | The code itself. Upper-cased; `A-Z0-9-`, 3 to 32 characters |
| `grants` | One entry per product: `{product, tier, days}`. Optional; the default is ParaSign Pro and ParaSend Pro for 90 days. Every entry must carry the same `days` |
| `max_redemptions` | The cap. Default 100, ceiling 100000 |
| `valid_until` | Optional end date. Absent means no end date |
| `created_by`, `note` | Free text, for the admin's own trail |

Errors: `400 bad_code`, `400 invalid_product` / `invalid_tier` / `floor_tier` /
`bad_days` / `mixed_days` / `bad_max_redemptions` / `bad_valid_until`,
`409 code_exists` (a code is created once; withdraw it and make another rather
than changing a cap people are already redeeming against), `503
coupons_unavailable` when redis is not reachable.

### GET /v2/admin/coupons: every code with its counter

Requires `X-Admin-Token`. Returns each code with `grants`, `max_redemptions`,
`used`, `remaining`, `valid_until`, `revoked_at` and `describes` (the one-line
English summary of what it gives).

### DELETE /v2/admin/coupons/:code: withdraw a code

Requires `X-Admin-Token`. The code is in the path and the request carries no
body, deliberately: a DELETE body that the admin gate refuses before reading
leaves those bytes on the wire and desynchronises a kept-alive connection.

Stamps `revoked_at`; the code stops being redeemable immediately. Nothing is
deleted and no term already given is taken back: the redemptions are the record
of what was given away. `404 unknown_code` for a code that was never created.

### GET /v2/admin/coupons/:code/redemptions: who took a seat

Requires `X-Admin-Token`. The coupon plus one row per redemption
(`account`, `at`).

### POST /v2/billing/redeem: spend a code

Authenticated as the account, either with `X-Api-Key` or with a `pst_` session
token minted with purpose `app` (it is one of the five routes in that
allowlist). Body `{"code":"COFFEE"}`. **The account is the one the relay
resolved from the credential, never one the body names.**

```bash
curl -X POST https://relay.paramant.app/v2/billing/redeem \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"code":"COFFEE"}'
# {"ok":true,"code":"COFFEE",
#  "granted":[{"product":"parasign","tier":"pro","days":90,"ends":"2026-12-03T…"},
#             {"product":"parasend","tier":"pro","days":90,"ends":"2026-12-03T…"}],
#  "message":"Your code is redeemed. You now have ParaSign Pro until 3 December
#             2026 and ParaSend Pro until 3 December 2026. Nothing was charged."}
```

Every answer carries `message`, one plain English sentence meant to be printed
to the person who typed the code. The machine-readable `error` is for logs and
tests:

| Status | `error` | What the reader is told |
|---|---|---|
| 404 | `unknown` | We do not know that code. Check the spelling and try again. |
| 409 | `expired` | That code has expired. |
| 409 | `already_used` | You have already used this code on this account. |
| 409 | `exhausted` | That code has been fully claimed. It has run out. |
| 409 | `revoked` | That code is no longer valid. |
| 500 | `grant_failed` | Nothing was changed; the seat is given back. |
| 503 | `redeem_unavailable` | The coupon store did not answer. |

A redemption writes **one line in the billing history** (`GET
/v2/billing/history`, type `gift`, e.g. `Gift: 3 months of ParaSign Pro and
ParaSend Pro, code COFFEE`, with no amount and no document) and sends **one
confirmation mail**. It writes no invoice and no credit note. The seven-day
expiry warning and the "your plan has ended" mail follow on their own, because
`paid_until_<product>` was written the ordinary way.

### Moneybird

With `MONEYBIRD_TOKEN` and `MONEYBIRD_ADMINISTRATION_ID` set, every invoice and
credit note is also pushed to Moneybird as an **external sales invoice**: our own
number goes in `reference`, Moneybird draws no number of its own and sends
nothing to the customer, and the PDF is attached. The Moneybird id is written
back onto the record as `moneybird_id`, so a document is never pushed twice; a
failed push is queued and retried by a six-hour sweep. The push is aftercare and
can never fail a payment or an invoice. Without both variables nothing is sent at
all. See `deploy/DEPLOY-3.1.md` for how to make the token.

---

## Relay internal endpoints (operators only)

These endpoints are served by the sector relays and are intended for internal calls from the admin panel. They require the `X-Internal-Auth` header set to the value of `INTERNAL_AUTH_TOKEN` in the relay environment.

They are not accessible from the public internet.

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/v2/auth/capabilities` | Public — returns `{user_totp_available: bool}` |
| `POST` | `/v2/user/setup-totp` | Provision a TOTP secret; idempotent for provisional state |
| `POST` | `/v2/user/verify-totp` | Verify a TOTP code against the stored secret |
| `POST` | `/v2/user/activate-totp` | Mark TOTP as fully activated |
| `POST` | `/v2/user/consume-backup` | Consume and invalidate a single backup code |
| `POST` | `/v2/user/regenerate-backup` | Generate a new backup code set |
| `POST` | `/v2/user/delete-totp` | Remove all TOTP state for a user |
| `POST` | `/v2/user/get-totp-provisional` | Return the existing secret if enrollment is provisional |
| `POST` | `/v2/user/get-backup-codes-plaintext` | Return plaintext backup codes (used during setup display) |

**Idempotency note for `/v2/user/setup-totp`:** If a TOTP secret already exists but `totp_active` is `false` (provisional), the endpoint returns the existing secret and backup codes rather than 409. A 409 is returned only when `totp_active` is `true`.

---

## Error codes

| HTTP | Code | Meaning |
|------|------|---------|
| 400 | `bad_request` | Malformed request body or missing required field |
| 401 | `unauthorized` | Missing or invalid API key, session cookie, or admin token |
| 401 | `invalid_or_expired_token` | Setup token not found or past TTL |
| 401 | `invalid_totp_code` | TOTP code incorrect or outside allowed window |
| 401 | `invalid_backup_code` | Backup code not found or already consumed |
| 403 | `totp_not_activated` | Account exists but TOTP setup was not completed |
| 404 | `not_found` | Resource does not exist |
| 409 | `totp_already_configured` | TOTP is fully activated; cannot re-enroll without a reset |
| 409 | `email_already_registered` | Signup attempted for an email that already has an account |
| 428 | `pow_required` | This email address has collected enough failed sign-ins that the next attempt must carry a solved proof-of-work. Not a refusal: solve `GET /api/captcha/challenge` and post again |
| 429 | `rate_limited` | Too many requests from this IP address |
| 503 | `totp_unavailable` | The TOTP single-use guard could not reach Redis. Verification fails closed; retry when the relay reports healthy |
| 503 | `redis_unavailable` | Any other Redis-backed route whose store did not answer inside `PARAMANT_REDIS_DEADLINE_MS` (default 1000 ms). Carries `Retry-After: 5`. Nothing is wrong with the request; the relay refuses rather than waiting for a store that may never answer |
| 503 | `session_store_unavailable` | The admin could not read the session behind an authenticated request, for the same reason |
| 500 | `internal` | Unexpected server error; check relay logs |

### POST /admin/api/admin/force-totp

Require or remove TOTP for a specific user.

**Body:**
```json
{ "key": "pgp_...", "required": true, "reason": "compliance policy" }
```

**Effect when `required: true`:**
- `paramant:user:totp_required:{key}` set in Redis
- All active user sessions revoked
- Setup email sent automatically
- Login blocked until TOTP active

**Rate limit:** 20/admin/24h
**Audit event:** `admin_totp_required_toggled`

---
