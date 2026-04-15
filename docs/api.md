# API Reference — PARAMANT v2.4.5

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

- `pgp_` prefix — end user key (10 uploads/day free, no account needed)
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
| `X-Paramant-Receipt` | Base64url-encoded signed delivery receipt |

The `X-Paramant-Receipt` value is a base64url-encoded JSON object:

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
  -d '{"receipt":"<base64url from X-Paramant-Receipt>"}'
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
# {"ok":true,"version":"2.4.5","sector":"relay","edition":"community"}
```

### GET /v2/relays — Relay registry (public)

```bash
curl https://relay.paramant.app/v2/relays
# {"total":5,"relays":[{"url":"…","version":"2.4.5","sector":"relay",…}]}
```

### POST /v2/request-trial — Request a free trial API key

```bash
curl -X POST https://relay.paramant.app/v2/request-trial \
  -H "Content-Type: application/json" \
  -d '{"name":"Jane Smith","email":"jane@example.com","use_case":"DICOM transfer for radiology dept"}'
# {"ok":true,"message":"Trial key sent to jane@example.com"}
```

Rate limits: 3 requests per IP per 24 hours, 1 request per email address per 7 days. Key is delivered via Resend. Also available via the web form at `https://paramant.app/request-key`.

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

## Rate limits

| Tier | Uploads/day | Retention |
|------|-------------|-----------|
| Free (pgp_) | 10 | 1 hour |
| Community (plk_) | unlimited | 1 hour |
| Professional | unlimited | 24 hours |
| Enterprise | unlimited | configurable |

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
