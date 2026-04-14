# API Reference — PARAMANT Relay v2.4.5

**Base URLs:**

| Sector | URL | Compliance |
|--------|-----|------------|
| General | `https://relay.paramant.app` | — |
| Healthcare | `https://health.paramant.app` | NEN 7510, DICOM, HL7 FHIR |
| Legal | `https://legal.paramant.app` | eIDAS, KNB |
| Finance | `https://finance.paramant.app` | NIS2, DORA, ISO 20022 |
| IoT | `https://iot.paramant.app` | IEC 62443, EU CRA |

**Authentication:** `X-Api-Key: pgp_your_key` header on all authenticated endpoints.  
**Key format:** `pgp_` + 64 hex chars (256-bit random). Get one at [paramant.app/request-key](https://paramant.app/request-key).

---

## Endpoints overview

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/health` | Node status, version, edition | Public |
| GET | `/v2/relays` | Relay registry | Public |
| POST | `/v2/inbound` | Upload encrypted blob (RAM-only) | Key |
| GET | `/v2/outbound/:hash` | Download + burn (one retrieval only) | Key |
| GET | `/v2/stream-next` | Poll for next queued blob hash | Key |
| GET | `/v2/status/:hash` | Check blob availability (non-destructive) | Key |
| POST | `/v2/ack` | Confirm delivery, log latency to CT | Key |
| GET | `/v2/monitor` | Live relay stats | Key |
| POST | `/v2/ws-ticket` | Get 30s one-time WebSocket ticket | Key |
| POST | `/v2/fingerprint` | Register device public key (TOFU) | Key |
| GET | `/v2/ct` | CT log root + entries | Key |
| POST | `/v2/request-trial` | Self-service trial key request | Public |

---

## GET /health

Node health, version, and edition. No authentication required.

**Request:**
```bash
curl https://health.paramant.app/health
```

**Response 200:**
```json
{
  "ok": true,
  "version": "2.4.5",
  "sector": "health",
  "edition": "community",
  "max_keys": 5,
  "active_keys": 2,
  "uptime_s": 86400
}
```

| Field | Description |
|-------|-------------|
| `edition` | `community` (≤5 keys) or `licensed` (unlimited) |
| `max_keys` | `null` for licensed edition (unlimited) |
| `active_keys` | Number of active API keys currently registered |

---

## POST /v2/inbound — Upload blob

Upload an encrypted blob. The relay stores it in RAM only — nothing written to disk.

**Request:**
```bash
curl -X POST https://health.paramant.app/v2/inbound \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "hash":    "sha256_of_plaintext_payload",
    "payload": "base64_encoded_ciphertext_5mb",
    "ttl_ms":  3600000
  }'
```

| Field | Required | Description |
|-------|----------|-------------|
| `hash` | Yes | SHA-256 of the plaintext content (before encryption). Used as blob identifier in the CT log. |
| `payload` | Yes | Base64-encoded ciphertext. Padded to exactly 5 MB by the SDK. |
| `ttl_ms` | No | Time-to-live in milliseconds. Default: 3 600 000 (1 hour). Max: 604 800 000 (7 days, enterprise only). |
| `device_id` | No | Device identifier. Include for device-to-device routing via `/v2/stream-next`. |

**Response 200:**
```json
{
  "ok": true,
  "blob_hash": "sha256...",
  "ttl_ms": 3600000,
  "ct_index": 42
}
```

**Response 401:** `{"error": "Invalid API key"}`  
**Response 402:** `{"error": "Community Edition limit reached", "upgrade_url": "https://paramant.app/pricing"}`  
**Response 429:** `{"error": "Rate limit exceeded"}`

---

## GET /v2/outbound/:hash — Download and burn

Retrieve an encrypted blob by its hash. **The blob is destroyed immediately after this response.** One download only.

**Request:**
```bash
curl https://health.paramant.app/v2/outbound/abc123def456... \
  -H "X-Api-Key: pgp_your_key" \
  --output received.bin
```

**Response 200:** Raw ciphertext bytes (5 MB, application/octet-stream).

**Response 404:** `{"error": "Blob not found or already burned"}`

> The SDK decrypts the ciphertext using ML-KEM-768 + AES-256-GCM on the client side. The relay never has the decryption key.

---

## GET /v2/stream-next — Poll for incoming blobs

Poll for the next blob queued for your device. Non-destructive — returns the hash without consuming the blob.

**Request:**
```bash
curl https://health.paramant.app/v2/stream-next \
  -H "X-Api-Key: pgp_your_key" \
  -H "X-Device-Id: my-device"
```

**Response 200:** Blob waiting
```json
{
  "blob_hash": "sha256...",
  "queued_at": "2026-04-14T10:00:00Z",
  "sender_device": "sender-001"
}
```

**Response 204:** No content — no pending blobs for this device.

---

## GET /v2/status/:hash — Check blob existence

Non-destructive check — does not consume the blob.

**Request:**
```bash
curl https://health.paramant.app/v2/status/abc123... \
  -H "X-Api-Key: pgp_your_key"
```

**Response 200:** `{"ok": true, "blob_hash": "abc123...", "ttl_remaining_ms": 2891000}`  
**Response 404:** `{"error": "Not found"}`

---

## POST /v2/ack — Confirm delivery

Acknowledge successful receipt. Logs delivery latency to the CT log.

**Request:**
```bash
curl -X POST https://health.paramant.app/v2/ack \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"blob_hash": "abc123...", "latency_ms": 342}'
```

**Response 200:** `{"ok": true}`

---

## POST /v2/ws-ticket — WebSocket ticket

Get a one-time ticket for upgrading to a WebSocket connection. Ticket is valid for 30 seconds.

**Request:**
```bash
curl -X POST https://health.paramant.app/v2/ws-ticket \
  -H "X-Api-Key: pgp_your_key"
```

**Response 200:** `{"ticket": "one-time-token-abc123", "expires_in": 30}`

**Connect via WebSocket:**
```javascript
const ws = new WebSocket(
  'wss://health.paramant.app/v2/ws?ticket=one-time-token-abc123'
);
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  // msg.type: "blob_ready" | "ack" | "ping"
  // msg.blob_hash — retrieve with GET /v2/outbound/:hash
};
```

---

## POST /v2/fingerprint — Register device key (TOFU)

Register a public key for this device (Trust On First Use). Subsequent uploads from this device are signed with the registered key.

**Request:**
```bash
curl -X POST https://health.paramant.app/v2/fingerprint \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id":  "mri-scanner-01",
    "public_key": "base64_ml_dsa_65_pubkey",
    "algorithm":  "ml-dsa-65"
  }'
```

**Response 200:** `{"ok": true, "ct_index": 7, "fingerprint": "sha256..."}`

---

## GET /v2/ct — Certificate Transparency log

Every key registration, relay registration, and delivery acknowledgement is appended to a SHA3-256 Merkle tree. Public and auditable.

**Request:**
```bash
curl https://health.paramant.app/v2/ct \
  -H "X-Api-Key: pgp_your_key"
```

**Response 200:**
```json
{
  "ok": true,
  "size": 58,
  "root": "deed04dd...34418382",
  "entries": [
    {
      "index": 0,
      "type":  "key_reg",
      "hash":  "sha256...",
      "ts":    "2026-04-01T00:00:00Z"
    },
    {
      "index": 1,
      "type":  "relay_reg",
      "url":   "https://health.paramant.app",
      "sector": "health"
    }
  ]
}
```

**Entry types:**

| Type | Description |
|------|-------------|
| `key_reg` | API key or device public key registration |
| `relay_reg` | Relay self-registration with ML-DSA-65 signed identity |
| `delivery_ack` | Confirmed delivery with latency |

---

## GET /v2/relays — Relay registry

Discover all relays registered in the CT log.

**Request:**
```bash
curl https://health.paramant.app/v2/relays
```

**Response 200:**
```json
{
  "ok": true,
  "count": 5,
  "relays": [
    {
      "url":            "https://health.paramant.app",
      "sector":         "health",
      "version":        "2.4.5",
      "edition":        "licensed",
      "pk_hash":        "3d9b960c...",
      "verified_since": "2026-04-01T00:00:00Z",
      "last_seen":      "2026-04-14T09:00:00Z",
      "ct_index":       1
    }
  ]
}
```

---

## POST /v2/request-trial — Self-service trial key

Request a trial API key by email. Rate-limited to 1 per address per 7 days.  
This endpoint is also available via the form at [paramant.app/request-key](https://paramant.app/request-key).

**Request:**
```bash
curl -X POST https://paramant.app/api/request-key \
  -H "Content-Type: application/json" \
  -d '{
    "email":   "you@example.com",
    "name":    "Jane Smith",
    "usecase": "healthcare"
  }'
```

| Field | Required | Values |
|-------|----------|--------|
| `email` | Yes | Valid email address |
| `name` | No | Display name for welcome email |
| `usecase` | No | `healthcare` / `legal` / `iot` / `finance` / `development` / `other` |

**Response 200:**
```json
{
  "ok": true,
  "message": "Key sent to you@example.com"
}
```

The key is provisioned across all 4 sector relays with `plan=trial`, `max_uploads=10`, 30-day expiry.

---

## Rate limits

| Plan | Uploads/day | File size | TTL | Views/blob |
|------|-------------|-----------|-----|------------|
| `trial` | 10 | 5 MB | 1 hour | 1 |
| `community` | 50 | 5 MB | 1 hour | 1 |
| `pro` | Unlimited | 500 MB | 24 hours | 10 |
| `enterprise` | Unlimited | Unlimited | 7 days | 100 |

IP-level rate limits (regardless of key): 60 requests/min per IP (burst 30), 10 uploads/min per IP (burst 5).

---

## Error codes

| HTTP | Error | Meaning |
|------|-------|---------|
| 400 | `Invalid request` | Malformed JSON or missing required fields |
| 401 | `Invalid API key` | Key not found, inactive, or expired |
| 402 | `Community Edition limit reached` | Operator exceeded 5-key limit |
| 404 | `Blob not found` | Burned, expired, or never existed |
| 429 | `Rate limit exceeded` | Too many requests — back off and retry |
| 502 | `Relay unreachable` | Admin→relay communication failure |

---

## SDK — Python

```bash
pip install paramant-sdk
```

```python
from paramant_sdk import GhostPipe

gp = GhostPipe(
    api_key = "pgp_xxx",
    device  = "device-001",
    sector  = "health",   # routes to health.paramant.app
)

hash_ = gp.send(open("scan.dcm", "rb").read(), ttl=3600)
data  = gp.receive(hash_)
```

## SDK — JavaScript / Node.js

```bash
npm install @paramant/sdk
```

```javascript
import { GhostPipe } from '@paramant/sdk';

const gp = new GhostPipe({ apiKey: 'pgp_xxx', device: 'node-01', sector: 'health' });

const hash = await gp.send(fileBuffer, { ttl: 3600 });
const data = await gp.receive(hash);
```

Dual CJS + ESM exports. Works in Node.js and the browser (WASM crypto, no native deps).

---

## Webhook notifications

Pro and Enterprise keys can register a webhook URL to receive delivery notifications:

```bash
curl -X POST https://health.paramant.app/v2/webhook \
  -H "X-Api-Key: pgp_pro_key" \
  -H "Content-Type: application/json" \
  -d '{
    "url":    "https://your-server.com/paramant-webhook",
    "secret": "hmac_signing_secret"
  }'
```

On delivery, PARAMANT sends a POST to your URL signed with HMAC-SHA256:

```json
{
  "event":     "blob.burned",
  "blob_hash": "sha256...",
  "burned_at": "2026-04-14T10:01:23Z",
  "latency_ms": 342
}
```

Verify: `X-Paramant-Signature: sha256=hmac_hex`
