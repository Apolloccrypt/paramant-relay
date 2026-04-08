# PARAMANT Ghost Pipe

**Post-quantum encrypted file relay. Encrypted before it leaves your device. Destroyed after one download.**

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.2.1-brightgreen.svg)](CHANGELOG.md)
[![Docker](https://img.shields.io/badge/Docker-mtty001%2Frelay-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/mtty001/relay)
[![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-lightgrey.svg)](https://hub.docker.com/r/mtty001/relay)
[![Pentest](https://img.shields.io/badge/pentest-2026--04--08-success.svg)](pentest-report-2026-04-08.txt)

- **Zero plaintext** — ML-KEM-768 + AES-256-GCM encryption happens in the browser, before upload
- **Burn-on-read** — blob is zeroed from RAM immediately after the first download
- **RAM only** — no disk writes, no logs, no traces — swap disabled by design
- **Self-hostable** — Community Edition is free forever for up to 5 users, `docker compose up -d`

**[Try ParaShare →](https://paramant.app/parashare)** &nbsp;·&nbsp;
**[Free API key →](mailto:privacy@paramant.app?subject=Free+API+key+request)** &nbsp;·&nbsp;
**[Self-host ↓](#quick-start)** &nbsp;·&nbsp;
**[Docs →](docs/self-hosting.md)**

---

## Quick Start

**Raspberry Pi** (3B+ / 4 / 5, one command):
```bash
curl -fsSL https://paramant.app/install-pi.sh | bash
```

**Linux VPS / Docker** (~2 minutes):
```bash
git clone https://github.com/Apolloccrypt/paramant-relay
cd paramant-relay
cp .env.example .env && echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env
docker compose up -d
bash scripts/post-install.sh   # verify all 4 sectors + print next steps
```

**Managed relay — no install:**
Email [privacy@paramant.app](mailto:privacy@paramant.app?subject=Free+API+key+request) → **"Free API key request"** → get a `pgp_` key by return mail. No account, no credit card. Use it at [paramant.app/parashare](https://paramant.app/parashare) or via the Python SDK.

---

## Architecture

```
  Client
    │ HTTPS + E2E encrypted (relay never sees plaintext)
  ┌─▼──────────────────────────────────────────────────┐
  │  nginx  ·  TLS termination  ·  rate limiting        │
  └─┬──────────────────────────────────────────────────┘
    │  relay-internal network  (isolated, not internet-facing)
  ┌─┴──────────────────────────────────────────────────────┐
  │  relay-health :3005   relay-legal  :3002               │
  │  relay-finance :3003  relay-iot    :3004               │
  │                                                        │
  │  · RAM-only blobStore        · Burn-on-read + zeroize  │
  │  · First-registration-wins   · Merkle CT log           │
  │  · Prometheus /metrics       · Non-root containers     │
  └────────────────────────────────────────────────────────┘
```

| Stack | Standard |
|-------|----------|
| Key encapsulation | ML-KEM-768 · NIST FIPS 203 |
| Signatures | ML-DSA-65 · NIST FIPS 204 |
| Symmetric | AES-256-GCM · NIST SP 800-38D |
| Key derivation | HKDF-SHA256 · RFC 5869 |
| Password blobs | Argon2id · RFC 9106 · 19 MB memory |
| Jurisdiction | Hetzner DE · EU/GDPR · no US CLOUD Act |

---

## Who are you?

```
  ┌─ RELAY OPERATOR ──────────────────────────┐   ┌─ END USER ──────────────────────────────┐
  │  You self-host a relay for your team       │   │  You use a relay to send/receive files  │
  │                                            │   │                                          │
  │  Key type:  plk_<64 hex>  (license key)    │   │  Key type:  pgp_<64 hex>  (API key)     │
  │  Goes in:   PARAMANT_LICENSE= in .env      │   │  Goes in:   X-Api-Key: header           │
  │  Unlocks:   > 5 users on your relay        │   │  Grants:    upload / download access    │
  │                                            │   │                                          │
  │  Community  free · up to 5 users           │   │  Free   10 uploads/day · 1-hour TTL     │
  │  Licensed   plk_ key → unlimited users     │   │  Pro    unlimited · 24h TTL · webhooks  │
  └────────────────────────────────────────────┘   └──────────────────────────────────────────┘
         plk_ keys are for operators  ·  pgp_ keys are for end users  ·  never the same person
```

### For relay operators

| Edition | Users | Price |
|---------|-------|-------|
| **Community** | Up to 5 | Free · no license key needed |
| **Licensed** | Unlimited | [paramant.app/pricing](https://paramant.app/pricing) |
| **Enterprise** | Unlimited + SLA | [Contact us](mailto:privacy@paramant.app) |

### For end users (managed relay)

| Plan | Uploads/day | TTL | Price |
|------|------------|-----|-------|
| **Free** | 10 | 1 hour | Free — [request key](mailto:privacy@paramant.app?subject=Free+API+key+request) |
| **Pro** | Unlimited | 24 hours | [pricing](https://paramant.app/pricing) |
| **Enterprise** | Unlimited | 7 days | [Contact us](mailto:privacy@paramant.app) |

---

## Add users (zero downtime)

```bash
export $(grep -v '^#' .env | xargs)
python3 scripts/paramant-admin.py add --label alice --plan pro --email alice@example.com
python3 scripts/paramant-admin.py sync   # reload all relays — no restart, no dropped connections
```

Keys 6+ are blocked with HTTP 402 on Community Edition until a `plk_` license is added to `.env`.

---

## Python SDK

```bash
pip install paramant-sdk
```

```python
from paramant_sdk import GhostPipe

gp    = GhostPipe(api_key="pgp_...", device="my-device")
hash_ = gp.send(b"secret data", ttl=3600, max_views=1)  # encrypt + upload
data  = gp.receive(hash_)                                # download + decrypt + burn

mnemonic = gp.drop(b"sensitive data", ttl=3600)          # 12-word anonymous drop
data     = gp.pickup(mnemonic)                           # receiver needs only the words
```

---

## Security

The relay is **untrusted by design** — it never holds a decryption key.

| What a compromised relay can do | What it cannot do |
|---------------------------------|-------------------|
| Deny service | Read file contents |
| Learn transfer timing | Substitute a public key after registration |
| See blob sizes (mitigated by fixed 5 MB padding) | Decrypt any stored ciphertext |

**Independent assessment:** [pentest-report-2026-04-08.txt](pentest-report-2026-04-08.txt) — no CRITICAL or HIGH findings. All MEDIUM findings addressed. Full remediation log included.

---

## Docs

| | |
|--|--|
| [docs/self-hosting.md](docs/self-hosting.md) | Deploy guide · env vars · nginx · TLS · upgrade |
| [docs/licensing.md](docs/licensing.md) | Key types · edition enforcement · known limitations |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

---

## Requirements

1 GB RAM · Ubuntu 22.04+ / Debian 12+ · Docker 24+ · **swap disabled** (`swapoff -a`)

Tested: Hetzner CX22 (€4/mo), DigitalOcean Basic, Raspberry Pi 4 / 5.

---

## Support

| | |
|--|--|
| Community | [GitHub Issues](https://github.com/Apolloccrypt/paramant-relay/issues) |
| Licensed / Enterprise | [privacy@paramant.app](mailto:privacy@paramant.app) |
| Security disclosure | [SECURITY.md](SECURITY.md) |

**License:** BUSL-1.1 — source available, free for ≤ 5 users in production. Change Date 2029-01-01 → Apache 2.0.
