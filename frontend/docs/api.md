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

All data-plane endpoints require: `X-Api-Key: your_key`

- `pgp_` prefix, end user key. Community plan: 50 transfers a month, 500 MB per file.
- `plk_` prefix — operator license key (unlimited, from `.env`)

CT log and STH endpoints are **public** — no API key required.

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
| **Your own volume** | The relay keeps your account's most recent receipts, up to twice your tier's hourly download ceiling: community 100, pro 1000, business 4000, enterprise 10000. Past that your oldest receipts drop. Another account's downloads can never take yours. |
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

### GET /v2/capabilities — Negotiable crypto capabilities (public)

Advertises the algorithm set this relay accepts on the wire. Since v3.0.0 the relay ships in `core` mode by default — a compact, two-algorithm set (ML-KEM-768 + ML-DSA-65) — with extended algorithm sets available opt-in via the `CRYPTO_MODE` environment variable (ADR R006). SDKs negotiate against this endpoint so a client and relay always agree on a shared, byte-compatible set.

```bash
curl https://relay.paramant.app/v2/capabilities
# {"ok":true,"mode":"core","kem":["ML-KEM-768"],"sig":["ML-DSA-65"],"wire":"v1"}
```

### GET /v2/health/deep — Comprehensive health check (public)

A deeper readiness probe than `/health`: in addition to the version and sector it reports on dependent subsystems (storage volume, CT log writability, relay identity key, peer reachability). Used by the setup wizard and by monitoring to distinguish "process up" from "fully operational".

```bash
curl https://relay.paramant.app/v2/health/deep
# {"ok":true,"version":"3.0.0","checks":{"storage":"ok","ct_log":"ok","identity":"ok","peers":"ok"}}
```

### POST /v2/setup/check + /v2/setup/apply — First-run onboarding (M11)

The first-run setup wizard at `/setup` drives these endpoints (ADR R005). They are gated to a relay with no keys yet (or an explicit `SETUP_MODE` flag) and are inert once the relay is provisioned.

- `POST /v2/setup/check` — validate a proposed configuration (domain, DNS, TLS readiness) and run `/v2/health/deep` before any change is written.
- `POST /v2/setup/apply` — generate the admin token, enroll TOTP, mint the first key and persist the configuration, returning an all-systems-go summary.

```bash
# Inspect readiness (safe, read-only)
curl -X POST https://relay.paramant.app/v2/setup/check \
  -H "Content-Type: application/json" \
  -d '{"domain":"relay.example.com"}'
# {"ok":true,"setup_mode":true,"dns":"ok","tls":"pending","health":{…}}
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

### POST /v2/did/register — Enroll a device

```bash
curl -X POST https://iot.paramant.app/v2/did/register \
  -H "X-Api-Key: plk_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "plc-factory-01",
    "ecdh_pub":  "<base64 ECDH P-256 or X25519 public key>",
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
| Max file size | 500 MB | 500 MB | 500 MB (tier `file_mb`) |
| Max blob size | 5 MB | 5 MB | 5 MB (relay `MAX_BLOB`, one padded block) |
| Downloads per hour | 50 | 500 | unlimited |

Notes:

- **Downloads per hour** is a sliding one-hour window per API key on
  `GET /v2/outbound/:hash`; over it the relay answers `429`. It also sets how
  many delivery receipts your account keeps (twice this number, see above).
- **Max blob size** is the lower of the tier's ceiling and the operator's
  `MAX_BLOB`, which is 5 MB on the hosted relay: that is the size every packet
  is padded to, so a blob larger than one block is malformed rather than merely
  big. It is not the file limit. A file is sent as a run of blocks, so the file
  ceiling is the tier's `file_mb` (500 MB), enforced by counting the blocks that
  share a `meta.file_id`. `GET /v2/admin/usage` reports `file_mb`, the number
  you can actually send, and not the block size.

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
