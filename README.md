# PARAMANT Ghost Pipe

**Post-quantum encrypted file relay. RAM-only. Burn-on-read. Self-hostable in minutes.**

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.2.1-brightgreen.svg)](CHANGELOG.md)
[![Docker](https://img.shields.io/badge/Docker-mtty001%2Frelay-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/mtty001/relay)
[![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-lightgrey.svg)](https://hub.docker.com/r/mtty001/relay)
[![Node](https://img.shields.io/badge/Node.js-20%2B-339933?logo=node.js&logoColor=white)](relay/package.json)

Files are encrypted in the browser with ML-KEM-768 + AES-256-GCM before they reach the relay.
The relay stores only ciphertext — in RAM, never on disk — and destroys it after one download.
No account needed to send. No file touches your cloud provider.

**[Try it now →](https://paramant.app/parashare)**  · 
**[Self-host in 60 seconds ↓](#quick-start)**  · 
**[Docs →](docs/self-hosting.md)**  · 
**[Free API key →](mailto:privacy@paramant.app?subject=Free+API+key+request)**

---

## How it works

```
  Sender browser                  Relay (your server)              Receiver browser
  ─────────────────               ────────────────────             ─────────────────
  ML-KEM-768 encapsulate    ──►  RAM-only ciphertext store   ──►  ML-KEM-768 decapsulate
  AES-256-GCM encrypt             Never sees plaintext             AES-256-GCM decrypt
  Fixed 5 MB padding              Burn-on-read (zeroed)            File saved locally
  Fingerprint OOB verify ◄──────── First-registration-wins ──────► Fingerprint OOB verify
```

| Property | Detail |
|----------|--------|
| **Encryption** | ML-KEM-768 (NIST FIPS 203) + ECDH P-256 hybrid + AES-256-GCM |
| **Signatures** | ML-DSA-65 (NIST FIPS 204) |
| **Key derivation** | HKDF-SHA256 (RFC 5869) |
| **Storage** | RAM only — swap must be disabled |
| **Padding** | Fixed 5 MB blocks (DPI masking) |
| **After download** | Blob zeroed with `randomFillSync` + `fill(0)`, deleted from map |
| **Jurisdiction** | EU/DE · Hetzner · GDPR · no US CLOUD Act |

---

## Quick Start

### Raspberry Pi (3B+ / 4 / 5)

```bash
curl -fsSL https://paramant.app/install-pi.sh | bash
```

Detects your Pi, installs Docker, disables swap, starts all 4 relay sectors, prints a QR code.

### Linux VPS / Docker

```bash
git clone https://github.com/Apolloccrypt/paramant-relay
cd paramant-relay
cp .env.example .env          # set ADMIN_TOKEN (openssl rand -hex 32)
docker compose up -d
bash scripts/post-install.sh  # verify + print next steps
```

Or pull directly from Docker Hub (no build needed):

```bash
docker pull mtty001/relay:latest
```

### Try the managed relay — no install

Email [privacy@paramant.app](mailto:privacy@paramant.app?subject=Free+API+key+request) with subject **"Free API key request"** → receive a `pgp_` API key by return mail. No account, no credit card.

Then use it at [paramant.app/parashare](https://paramant.app/parashare) or via the Python SDK.

---

## Architecture

```
  Internet
      │ TLS (Let's Encrypt or self-signed)
  ┌───▼──────────────────────────────────┐
  │  nginx                                │  ports 80 / 443
  │  rate-limit · TLS termination         │
  └───┬──────────────────────────────────┘
      │ relay-internal (Docker network, not reachable from outside)
  ┌───┴──────────────────────────────────────────────────────┐
  │  relay-health :3005   relay-legal :3002                  │
  │  relay-finance :3003  relay-iot   :3004                  │
  │                                                          │
  │  Per relay:                                              │
  │  ■ RAM-only blobStore (Map)    ■ pubkeys (first-write)   │
  │  ■ Burn-on-read + zeroize      ■ CT log (Merkle chain)   │
  │  ■ NATS optional (cross-relay) ■ Prometheus /metrics     │
  └──────────────────────────────────────────────────────────┘
```

All relay containers run as non-root user `relay`. Files in `/app` are owned by root and not writable by the relay process.

---

## License & Pricing

```
  ┌─ RELAY OPERATOR ──────────────────────────┐   ┌─ END USER ──────────────────────────────┐
  │  You self-host a relay for your team       │   │  You use a relay to send/receive files  │
  │                                            │   │                                          │
  │  Key type:  plk_<64 hex>  (license key)    │   │  Key type:  pgp_<64 hex>  (API key)     │
  │  Goes in:   PARAMANT_LICENSE= in .env      │   │  Goes in:   X-Api-Key: header           │
  │  Unlocks:   > 5 users on your relay        │   │  Grants:    upload / download access    │
  │                                            │   │                                          │
  │  Community  free · up to 5 users · BUSL    │   │  Free   10 uploads/day · 1-hour TTL     │
  │  Licensed   plk_ key → unlimited users     │   │  Pro    unlimited · 24h TTL · webhooks  │
  └────────────────────────────────────────────┘   └──────────────────────────────────────────┘
         plk_ keys are for relay operators  ·  pgp_ keys are for end users  ·  never the same person
```

### For relay operators

| Edition | Users per relay | Price |
|---------|----------------|-------|
| **Community** | Up to 5 | Free |
| **Licensed** | Unlimited | [paramant.app/pricing](https://paramant.app/pricing) |
| **Enterprise** | Unlimited + SLA | [Contact us](mailto:privacy@paramant.app) |

Community Edition is free forever. Add `PARAMANT_LICENSE=plk_...` to `.env` to unlock unlimited users.

### For end users (managed relay)

| Plan | Uploads | TTL | File size | Price |
|------|---------|-----|-----------|-------|
| **Free** | 10/day | 1 hour | 20 MB | Free |
| **Pro** | Unlimited | 24 hours | 500 MB | [pricing](https://paramant.app/pricing) |
| **Enterprise** | Unlimited | 7 days | Unlimited | [Contact us](mailto:privacy@paramant.app) |

**License:** BUSL-1.1 — source available, free for ≤ 5 users in production.
Change Date: 2029-01-01 → Apache 2.0. See [LICENSE](LICENSE) and [docs/licensing.md](docs/licensing.md).

---

## Add users (zero downtime)

```bash
export $(grep -v '^#' .env | xargs)

# Create an API key
python3 scripts/paramant-admin.py add --label alice --plan pro --email alice@example.com

# Reload all relays — no restart, no dropped connections
python3 scripts/paramant-admin.py sync
```

Keys 6+ are blocked with HTTP 402 on Community Edition until a `plk_` license key is added.

---

## Python SDK

```bash
pip install paramant-sdk
```

```python
from paramant_sdk import GhostPipe

gp = GhostPipe(api_key="pgp_...", device="my-device")

hash_ = gp.send(b"secret data", ttl=3600, max_views=1)   # encrypt + upload
data  = gp.receive(hash_)                                  # download + decrypt + burn

# Anonymous drop — receiver needs only a 12-word mnemonic, no API key
mnemonic = gp.drop(b"sensitive data", ttl=3600)
data     = gp.pickup(mnemonic)

# Password protection (Argon2id, 19 MB memory)
hash_ = gp.send(data, password="hunter2")
data  = gp.receive(hash_, password="hunter2")
```

Full SDK reference → [scripts/README.md](scripts/README.md)

---

## Threat model (short version)

| Component | Trust | Why |
|-----------|-------|-----|
| Sender / Receiver | Trusted | Hold private keys, decrypt locally |
| Relay | **Untrusted** | Sees only ciphertext |
| Network | Untrusted | Contents already encrypted, TLS in transit |

A compromised relay **cannot** read file contents or substitute public keys after first registration. It **can** deny service. Fingerprint verification (out-of-band, e.g. via phone) is the trust anchor — a substituted key produces a different fingerprint.

Full threat model → [docs/threat-model.md](docs/self-hosting.md#security-notes)

---

## Docs

| Document | Contents |
|----------|----------|
| [docs/self-hosting.md](docs/self-hosting.md) | Full deployment guide · env vars · nginx · TLS · upgrade |
| [docs/licensing.md](docs/licensing.md) | Two key types · edition enforcement · known limitations |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy |
| [pentest-report-2026-04-08.txt](pentest-report-2026-04-08.txt) | Independent security assessment + remediation status |

---

## Requirements

| Resource | Minimum | Notes |
|----------|---------|-------|
| OS | Ubuntu 22.04 / Debian 12 | Any Linux with Docker 24+ |
| RAM | 1 GB | 512 MB reserved per relay for blob storage |
| Disk | 10 GB | Logs + Docker images |
| Swap | **Disabled** | `swapoff -a` — RAM storage cannot page to disk |

Tested on Hetzner CX22 (2 vCPU / 4 GB / €4/mo), DigitalOcean, Raspberry Pi 4/5.

---

## Support

- **Docs:** [paramant.app/docs](https://paramant.app/docs)
- **GitHub Issues:** [Apolloccrypt/paramant-relay/issues](https://github.com/Apolloccrypt/paramant-relay/issues)
- **Email:** [privacy@paramant.app](mailto:privacy@paramant.app)
- **Security:** see [SECURITY.md](SECURITY.md)

Community Edition support is community-only (GitHub Issues).
Licensed / Enterprise includes email support and SLA.
