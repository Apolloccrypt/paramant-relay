# PARAMANT Ghost Pipe

Post-quantum encrypted file transfer. Files are encrypted client-side, transit through a RAM-only relay that never sees the key, and are permanently destroyed after one download.

**Live:** [paramant.app/parashare](https://paramant.app/parashare)

---

## Threat model

| Component | Trust level | Rationale |
|-----------|-------------|-----------|
| Sender | Trusted | Controls encryption, holds private key |
| Receiver | Trusted | Holds private key, decrypts locally |
| Relay | **Untrusted** | Sees only encrypted ciphertext |
| Network | Untrusted | TLS in transit, contents already encrypted |
| Infrastructure | Untrusted | RAM-only, no disk persistence |

**What a compromised relay can and cannot do:**

| Action | Possible? | Mitigation |
|--------|-----------|------------|
| Read file contents | No | Never has the decryption key |
| Replace pubkey before registration | No | First-registration-wins policy |
| Replace pubkey after registration | No | Overwrite rejected (409) |
| Return fake pubkey to sender | Yes | Fingerprint OOB verification detects this |
| Deny service | Yes | Acceptable — no data leakage |
| Learn file size | Partial | All blobs padded to fixed block size |

The fingerprint comparison (out-of-band, e.g. via phone or Signal) is the trust anchor for key distribution. A compromised relay returning a fake key will produce a different fingerprint — detectable if the parties compare.

---

## Cryptographic protocol

### ParaShare (browser E2E)

```
Receiver browser:
  ML-KEM-768.keygen() → (pk_kem, sk_kem)
  ECDH P-256.keygen() → (pk_ecdh, sk_ecdh)
  fingerprint = SHA-256(pk_kem ‖ pk_ecdh)[0:10]   ← shown to receiver

Sender browser (after OOB fingerprint verification):
  ct_kem, ss_kem  = ML-KEM-768.encapsulate(pk_kem)
  ss_ecdh         = ECDH(sender_ephemeral_priv, pk_ecdh)
  aes_key         = HKDF-SHA256(ss_kem ‖ ss_ecdh, salt=ct_kem[0:32], info="paramant-v2")
  ciphertext      = AES-256-GCM(aes_key, plaintext)
  blob            = 0x02 ‖ u32be(len(ct_kem)) ‖ ct_kem
                         ‖ u32be(len(sender_pk_ecdh)) ‖ sender_pk_ecdh
                         ‖ nonce(12) ‖ u32be(len(ct)) ‖ ct
  padded_blob     = blob ‖ random_padding → fixed 5MB block

Receiver browser:
  ss_kem  = ML-KEM-768.decapsulate(sk_kem, ct_kem)
  ss_ecdh = ECDH(sk_ecdh, sender_pk_ecdh)
  aes_key = HKDF-SHA256(ss_kem ‖ ss_ecdh, salt=ct_kem[0:32], info="paramant-v2")
  plain   = AES-256-GCM.decrypt(aes_key, ct)
```

### CLI / SDK (Python)

```
HKDF-SHA256(api_key, salt=random(32), info="paramant-v6") → aes_key
AES-256-GCM(aes_key, plaintext)
blob = salt(32) ‖ nonce(12) ‖ ciphertext
padded_blob → configurable block: 4KB / 64KB / 512KB / 5MB
```

> **Note on interoperability:** The browser (v2, asymmetric ML-KEM) and CLI (v6, symmetric API key) use different packet formats and are not directly interoperable. The Python receiver detects v2 blobs and returns a clear error. Unified format is planned.

### Drop (BIP39 anonymous transfer)

```
entropy         = random(16)
mnemonic        = BIP39.encode(entropy)          ← 12 words, given to receiver OOB
aes_key         = HKDF-SHA256(entropy, salt="paramant-drop-v1", info="aes-key")
lookup_hash     = SHA-256(HKDF(entropy, info="lookup-id"))
ciphertext      = AES-256-GCM(aes_key, plaintext)
→ stored at relay under lookup_hash, burn-on-read
```

### Primitives

| Primitive | Standard | Purpose |
|-----------|----------|---------|
| ML-KEM-768 | NIST FIPS 203 | Post-quantum key encapsulation |
| ML-DSA-65 | NIST FIPS 204 | Post-quantum signatures (relay) |
| ECDH P-256 | NIST | Classical hybrid (forward secrecy) |
| AES-256-GCM | NIST SP 800-38D | Authenticated encryption |
| HKDF-SHA256 | RFC 5869 | Key derivation |
| Argon2id | RFC 9106 | Password-protected blobs (19MB, 2 iter) |
| BIP39 | BIP39 | Mnemonic encoding for drop keys |

---

## Relay

### Architecture

```
Client → TLS (Let's Encrypt) → nginx → Node.js relay (127.0.0.1)
                                        │
                                        ├── RAM-only blobStore (Map)
                                        ├── pubkeys (Map, first-write-wins)
                                        ├── downloadTokens (Map, one-time)
                                        └── NATS (optional, cross-relay events)
```

- **No disk writes.** All blobs in RAM. Swap must be disabled on the host.
- **Burn-on-read.** Blob deleted and zeroed from RAM immediately after retrieval.
- **Fixed padding.** Every blob is padded to 5MB regardless of file size (DPI masking).
- **Key zeroization.** All derived keys overwritten with `randomFillSync` + `fill(0)` after use.
- **Graceful shutdown.** SIGTERM, SIGINT, `uncaughtException`, and `unhandledRejection` all trigger blob zeroization before exit.

### Sectors

| Sector | URL | Port |
|--------|-----|------|
| Health | health.paramant.app | 3005 |
| Legal | legal.paramant.app | 3002 |
| Finance | finance.paramant.app | 3003 |
| IoT | iot.paramant.app | 3004 |

### API

All endpoints except `/health`, `/v2/check-key`, `/v2/ct/*`, `/v2/did/*`, and `/v2/dl/:token` require a valid API key via `X-Api-Key` header.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/v2/inbound` | Required | Upload encrypted blob |
| `GET` | `/v2/outbound/:hash` | Required | Burn-on-read download |
| `POST` | `/v2/pubkey` | Required (sender) / session key (receiver) | Register ML-KEM-768 + ECDH pubkeys |
| `GET` | `/v2/pubkey/:device` | Session key | Fetch receiver pubkeys |
| `GET` | `/v2/status/:hash` | Required | Check blob availability |
| `POST` | `/v2/drop/create` | Required | Upload BIP39 drop |
| `POST` | `/v2/drop/pickup` | Required | Retrieve drop via mnemonic |
| `POST` | `/v2/drop/status` | Required | Check drop availability |
| `GET` | `/v2/dl/:token` | None (one-time token) | Download via one-time link |
| `GET` | `/health` | None (limited) | Relay health |
| `GET` | `/v2/ct/log` | None | Certificate transparency log |
| `GET` | `/metrics` | Admin token | Prometheus metrics |

#### Inbound request body

```json
{
  "hash":    "<sha256-hex>",
  "payload": "<base64-encoded-padded-blob>",
  "ttl_ms":  300000,
  "max_views": 1,
  "password": "optional-argon2id-protected",
  "meta": { "file_name": "...", "chunk_index": 0, "total_chunks": 1 }
}
```

#### Pubkey registration

```json
{
  "device_id": "inv_<session-token>",
  "ecdh_pub":  "<hex>",
  "kyber_pub": "<hex>",
  "dsa_pub":   "<hex, optional ML-DSA-65>"
}
```

First registration for a `(device_id, api_key)` pair wins. Subsequent attempts return `409 Conflict`. This prevents key substitution if an attacker intercepts a session link.

---

## ParaShare (browser widget)

**URL:** `paramant.app/parashare` — no install, no account.

### Transfer flow

```
1. Sender   → enter API key, select file → session created
2. Relay    → generates session link (inv_* token + transfer key)
3. Receiver → opens link → ML-KEM-768 + ECDH keypair generated in browser
4. Both     → fingerprint displayed: SHA-256(kyber_pub ‖ ecdh_pub)[0:10]
              formatted as XXXX-XXXX-XXXX-XXXX-XXXX (80 bits)
5. Sender   → calls/messages receiver via separate channel (phone, Signal)
              confirms fingerprint matches → checks mandatory checkbox
6. Sender   → encrypt & send (ML-KEM-768 encapsulate → AES-256-GCM)
7. Relay    → stores padded blob, issues one-time download token
8. Receiver → fetches token → decrypts locally → blob burned from relay RAM
```

### Why the fingerprint step matters

The relay is untrusted for key distribution. Without out-of-band verification, a compromised relay could substitute the receiver's public key with its own, encrypt the file to itself, and MITM the transfer. The fingerprint verification makes this detectable: a substituted key produces a different fingerprint. The sender **must** verify via a channel the relay cannot see.

The relay now enforces first-registration-wins: once the receiver has registered their key, no overwrite is accepted. This closes the race-condition window between receiver registration and sender key fetch.

### Browser requirements

- WebCrypto API (all modern browsers)
- `@noble/ml-kem` bundle served from `/noble-mlkem-bundle.js`
- If the ML-KEM library fails to load, both sender and receiver abort — no fallback to weaker crypto

---

## Python SDK

```bash
pip install paramant-sdk
# or from source:
pip install -e sdk-py/
```

```python
from paramant_sdk import GhostPipe

gp = GhostPipe(api_key="pgp_...", device="my-device")

# Send
hash_ = gp.send(b"secret data", ttl=300, max_views=1)

# Receive
data = gp.receive(hash_)

# Drop — receiver needs only the 12-word mnemonic, no API key
mnemonic = gp.drop(b"sensitive data", ttl=3600)
# → "word1 word2 word3 ... word12"
data = gp.pickup("word1 word2 word3 ... word12")

# Access policies
hash_ = gp.send(data, ttl=7200, max_views=3, pad_block=65536)

# Password protection (Argon2id)
hash_ = gp.send(data, password="hunter2")
data  = gp.receive(hash_, password="hunter2")

# Select relay sector
gp = GhostPipe(api_key="pgp_...", device="d1", relay="legal")
```

**Block sizes:** `4096` (4KB) · `65536` (64KB) · `524288` (512KB) · `5242880` (5MB, default)

### Key zeroization (Python)

All derived keys are overwritten after use via CPython's internal bytes layout:

```python
def _zero(b: bytes) -> None:
    offset = sys.getsizeof(b) - len(b) - 1
    ctypes.memset(id(b) + offset, 0, len(b))
```

---

## CLI tools

### paramant-sender.py

```bash
python3 paramant-sender.py \
  --key pgp_... \
  --relay health \
  --file contract.pdf \
  --ttl 3600 \
  --max-views 1 \
  --pad-block 5m

# Anonymous drop (receiver needs only the mnemonic)
python3 paramant-sender.py --key pgp_... --drop --file secret.pdf
```

### paramant-receiver.py

```bash
# Fetch by hash
python3 paramant-receiver.py \
  --key pgp_... \
  --relay health \
  --hash <sha256> \
  --output ./received/

# Listen mode (polls for new blobs)
python3 paramant-receiver.py --key pgp_... --listen --output ./received/

# Pickup anonymous drop
python3 paramant-receiver.py \
  --key pgp_... \
  --pickup "word1 word2 ... word12" \
  --output ./received/
```

> The Python receiver detects browser v2 blobs (`0x02` magic + 1088-byte ML-KEM ciphertext) and returns a clear error. Browser-encrypted files cannot be decrypted by the CLI receiver — they require the receiver's ML-KEM private key, which never leaves the browser.

---

## Relay: running your own

PARAMANT relays are self-hostable. You can run a single relay or all four sector relays behind nginx using Docker Compose.

### Docker Compose (recommended)

```bash
git clone https://github.com/Apolloccrypt/paramant-relay
cd paramant-relay

# Step 1 — interactive preflight: detects port conflicts, generates ADMIN_TOKEN
bash scripts/preflight.sh

# Step 2 — start the stack
docker compose up -d

# Step 3 — verify all sectors are live + get next-steps guide
bash scripts/post-install.sh
```

The preflight handles port conflicts automatically (e.g. if 80/443 are taken by Caddy
or nginx, it picks alternate ports and saves them to `.env`). `post-install.sh` reads
the actual running ports, tests all four sectors, and shows how to create your first API key.

Self-signed TLS is generated automatically on first start. For Let's Encrypt, see
[`docs/self-hosting.md`](docs/self-hosting.md).

Add API keys without restarting:

```bash
# On the host, edit the users.json inside the named volume, then:
ADMIN_TOKEN=your-token python3 scripts/paramant-admin.py sync
# ✓ health: 3 keys geladen
# ✓ legal: 3 keys geladen
```

### Single relay (Node.js, no Docker)

```bash
cd relay/
npm install
cp ../.env.example .env
# Edit .env: set ADMIN_TOKEN at minimum

node relay.js
# or with sector:
SECTOR=legal PORT=3002 node relay.js
```

### Requirements

- Node.js 20+ (or Docker)
- 1 GB+ RAM per relay (512 MB reserved, remainder for blobs)
- Swap **disabled** (`swapoff -a`) — relay uses RAM-only blob storage
- TLS termination via nginx (included in Compose stack)
- Optional: NATS server for multi-relay federation

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_TOKEN` | — | **Required.** Admin API token for `/v2/reload-users` and admin endpoints |
| `PORT` | `3001` | Listen port |
| `SECTOR` | `health` | Relay sector (`health` / `legal` / `finance` / `iot`) |
| `RELAY_MODE` | `ghost_pipe` | Enabled endpoint set (`ghost_pipe` or `iot`) |
| `USERS_FILE` | `./users.json` | Path to API key store |
| `USERS_JSON` | — | Inline JSON users (overrides `USERS_FILE`; useful for secret managers) |
| `RAM_LIMIT_MB` | `512` | Max RAM for in-flight blob storage |
| `RAM_RESERVE_MB` | `256` | Reserve before rejecting new inbound blobs |
| `TOTP_SECRET` | — | TOTP MFA seed (base32) for admin UI |
| `RESEND_API_KEY` | — | Email delivery for welcome mails |

### Zero-downtime key reload

After editing `users.json`, reload all relays without a restart:

```bash
POST /v2/reload-users
X-Api-Key: <ADMIN_TOKEN>

→ {"ok":true,"loaded":11}
```

Or via the admin CLI:

```bash
ADMIN_TOKEN=xxx python3 scripts/paramant-admin.py sync
```

### users.json schema

```json
{
  "api_keys": [
    {
      "key":    "pgp_<hex32>",
      "plan":   "pro",
      "limit":  null,
      "active": true,
      "label":  "customer-name",
      "email":  "user@example.com"
    }
  ]
}
```

---

## Repository layout

```
paramant-master/
├── relay/
│   └── relay.js              Ghost Pipe relay (Node.js, v2.2.0)
├── frontend/
│   ├── parashare.html        Browser sender (ML-KEM-768 E2E)
│   ├── ontvang.html          Browser receiver
│   ├── index.html            Landing page
│   └── noble-mlkem-bundle.js @noble/ml-kem (ML-KEM-768, client-side)
├── scripts/
│   ├── paramant_sdk.py       Python SDK (GhostPipe class)
│   ├── paramant-sender.py    CLI sender (v6.0)
│   └── paramant-receiver.py  CLI receiver (v6.0)
├── sdk-js/                   JavaScript SDK
├── sdk-py/                   Python package (pip-installable)
├── deploy/
│   ├── .env.example          Environment template
│   ├── deploy.sh             Deploy script
│   ├── nginx-paramant.conf   nginx config
│   └── systemd/              systemd unit files
└── outlook-addin/            Microsoft Outlook integration
```

---

## Security changelog

| Date | Change |
|------|--------|
| 2026-04-08 | `genFingerprint` → SHA-256(kyber_pub ‖ ecdh_pub)[0:10], 80-bit, 5×4 hex groups |
| 2026-04-08 | Fingerprint verification mandatory: checkbox + OOB warning in UI |
| 2026-04-08 | ML-KEM guard: abort if library fails to load, no silent fallback |
| 2026-04-08 | `POST /v2/pubkey`: requires valid API key (receiver sessions exempt via `inv_` prefix) |
| 2026-04-08 | First-registration-wins on pubkey: overwrites rejected with 409 |
| 2026-04-08 | SIGINT, `uncaughtException`, `unhandledRejection` → blob zeroization before exit |
| 2026-04-08 | Python receiver detects browser v2 packet format, clear error instead of garbled output |
| 2026-04-07 | Argon2id password protection for blobs (19MB memory, OWASP compliant) |
| 2026-04-07 | BIP39 drop feature: 12-word mnemonic, client-side key derivation |
| 2026-04-07 | Key zeroization: ctypes.memset (Python), randomFillSync+fill(0) (Node.js) |
| 2026-04-07 | Content-Disposition sanitization: RFC 5987 + ASCII fallback, prevents relay crash on unicode filenames |
| 2026-04-06 | Cloudflare removed: direct TLS via Let's Encrypt, no US intermediary |

---

## Known limitations

- **Browser ↔ CLI not interoperable.** Browser uses ML-KEM-768 asymmetric encryption (v2 packet format); CLI uses symmetric HKDF from API key (v6 format). Unified format planned.
- **Relay is trust point for uptime.** A relay that drops connections causes transfer failure (no data leakage, but denial of service is possible).
- **No persistent key storage.** Browser private keys exist only for the session tab lifetime. If the receiver closes their tab before downloading, the transfer cannot be completed.
- **RAM limit.** A relay with 512MB RAM holds at most ~100 concurrent 5MB blobs. Inbound is rejected with `503` when capacity is reached.
- **API keys in users.json.** No key rotation API yet. Admin must edit users.json and send SIGHUP or restart.

---

## License

BUSL-1.1 — see [LICENSE](LICENSE). Change Date: 2029-01-01 → Apache 2.0.

Free for non-production use. Contact for commercial licensing.
