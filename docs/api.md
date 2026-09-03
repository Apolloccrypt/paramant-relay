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
| **Your own volume** | The relay keeps your account's most recent receipts, up to twice your ParaSend tier's hourly download ceiling: Community 100, Pro 1000, legacy business 4000, Enterprise 10000. Past that your oldest receipts drop. Another account's downloads can never take yours. |
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
| `GET /ct/feed` | JSON feed for the UI (auto-refresh every 10s) |
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

| | Community | Pro | Enterprise |
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
  downloads an hour) rather than being raised to Enterprise or cut to Pro. It is
  resolved, never sold: ParaSend cannot be bought or granted at that tier.

---

## Error codes

| Code | Meaning |
|------|---------|
| 400 | Bad request — missing or invalid fields |
| 401 | Invalid API key or signature |
| 403 | Forbidden — wrong API key for this blob |
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

### POST /api/user/billing/checkout

Creates a pending plan-change order and returns an internal confirmation URL. This flow does not charge a payment method (see the `stub_notice` field on billing status); paid ParaSend and ParaSign upgrades are billed through the Mollie checkout on the relay, see [Billing (Mollie)](#billing-mollie) below.

```bash
curl -X POST https://paramant.app/api/user/billing/checkout \
  -H "Cookie: paramant_user_session=<token>" \
  -H "Content-Type: application/json" \
  -d '{"plan_id":"pro","period":"monthly"}'
# {"checkout_url":"/billing/checkout/<token>","expires_at":"2026-…"}
```

The order expires after one hour. `GET /api/user/billing/checkout/:token` returns the pending order (`plan_id`, `plan_name`, `period`, `amount_eur`, `email`, `status`). `POST /api/user/billing/checkout/:token/confirm` applies the plan change and returns `{"success":true,"new_plan":"pro","effective_from":"…"}`.

### POST /api/user/billing/cancel

Schedules a downgrade at the end of the current billing period. Returns `{"scheduled_downgrade_at":"…"}`.

### GET /api/user/billing/status

Returns current plan and subscription state: `current_plan`, `period`, `amount_eur`, `next_billing_date`, `cancellation_scheduled_at`.

### GET /api/user/billing/history

Returns the most recent billing events (plan changes, scheduled cancellations, downgrades).

---

## Billing (Mollie)

Paid ParaSend and ParaSign plans are billed through [Mollie](https://www.mollie.com). The relay creates the payment and grants the entitlement from the webhook. Prices come from the server-side catalog (`relay/lib/billing-catalog.js`); the caller can never set an amount.

### POST /v2/billing/checkout — Start a Mollie payment

Requires an API key. The body names a product, plan, and interval; the price is looked up server-side.

```bash
curl -X POST https://relay.paramant.app/v2/billing/checkout \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"product":"parasign","plan":"pro","interval":"monthly"}'
# {"ok":true,"payment_id":"tr_…","checkout_url":"https://www.mollie.com/checkout/…","mode":"live"}
```

| Field | Values |
|-------|--------|
| `product` | `parasend`, `parasign` |
| `plan` | `pro` (parasend); `pro` or `business` (parasign) |
| `interval` | `monthly`, `yearly` |

Redirect the buyer to `checkout_url` to complete the payment; Mollie then redirects back to `/dashboard?billing=return`. `mode` is `live` or `test`, controlled by `BILLING_MODE` and which Mollie key (`MOLLIE_API_KEY` / `MOLLIE_TEST_API_KEY`) is configured. The recurring layer (a Mollie customer, a `sequenceType: first` payment and a subscription created after the grant) runs only when `BILLING_MODE` is set explicitly to `live` or `test`; with `BILLING_MODE` empty the relay creates plain one-off payments, and the `billing_config` log line at boot says which stance is active.

Errors: `401 unauthorized` (missing or invalid API key), `400 bad_json` / `unknown_product` / `unknown_plan` / `unknown_interval`, `502 checkout_failed` (Mollie unreachable or rejected the payment).

### POST /v2/billing/webhook — Mollie status callback

Called by Mollie with `id=tr_…` (form-encoded). The relay ignores everything else in the webhook body, re-fetches the payment from the Mollie API as the only source of truth, verifies the amount actually paid against the catalog, and grants the product tier idempotently. Responds `200` on every handled event, `400 bad_payment_id` for a malformed id, and `503` on a transient Mollie fetch failure (so Mollie retries).

Not intended to be called by clients.

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
