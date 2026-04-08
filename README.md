# PARAMANT Ghost Pipe

**Post-quantum encrypted file relay. Encrypted before it leaves your device. Destroyed after one download.**

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.2.1-brightgreen.svg)](CHANGELOG.md)
[![Docker](https://img.shields.io/badge/Docker-mtty001%2Frelay-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/mtty001/relay)
[![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-lightgrey.svg)](https://hub.docker.com/r/mtty001/relay)
[![Pentest](https://img.shields.io/badge/pentest-2026--04--08-success.svg)](pentest-report-2026-04-08.txt)

- **Zero plaintext** — ML-KEM-768 + AES-256-GCM encryption happens in the browser, before upload
- **Burn-on-read** — blob is zeroed from RAM after the first download
- **RAM only** — no disk writes, no logs, no database
- **Self-hostable** — Community Edition free forever, up to 5 users, one `docker compose up`

---

## Two ways to use PARAMANT

| | **Managed relay** | **Self-hosted relay** |
|---|---|---|
| **Who** | End users — send/receive files | Teams / operators — run your own relay |
| **Key type** | `pgp_` API key | `plk_` license key (only if > 5 users) |
| **Free tier** | 10 uploads/day, 1-hour TTL | Community Edition — unlimited for ≤ 5 users |
| **Get started** | [Request a free key →](mailto:privacy@paramant.app?subject=Free+API+key+request) | [Self-host ↓](#self-host) |

---

## Managed relay — no install

**[Try ParaShare →](https://paramant.app/parashare)** — browser-based, no account needed.

Or request a `pgp_` API key to use with the SDK:

```
Email: privacy@paramant.app
Subject: Free API key request
→ Returns: pgp_<key>  — no account, no credit card
```

| Plan | Uploads/day | TTL | |
|------|-------------|-----|---|
| Free | 10 | 1 hour | [Request key](mailto:privacy@paramant.app?subject=Free+API+key+request) |
| Pro | Unlimited | 24 hours | [paramant.app/pricing](https://paramant.app/pricing) |
| Enterprise | Unlimited | 7 days | [Contact us](mailto:privacy@paramant.app) |

---

## Self-host

**Raspberry Pi / Linux VPS / Docker** (~2 minutes):

```bash
git clone https://github.com/Apolloccrypt/paramant-relay
cd paramant-relay
cp .env.example .env && echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env
docker compose up -d
```

Community Edition is **free forever** for up to 5 users. No license key required.
For unlimited users, add a `plk_` relay license to `.env`. → [docs/licensing.md](docs/licensing.md)

| Edition | Users | Price |
|---------|-------|-------|
| Community | Up to 5 | Free |
| Licensed | Unlimited | [paramant.app/pricing](https://paramant.app/pricing) |
| Enterprise | Unlimited + SLA | [Contact us](mailto:privacy@paramant.app) |

Full deploy guide: [docs/self-hosting.md](docs/self-hosting.md)

---

## Python SDK

```bash
pip install paramant-sdk
```

```python
from paramant_sdk import GhostPipe

gp    = GhostPipe(api_key="pgp_...", device="my-device")
hash_ = gp.send(b"secret data", ttl=3600, max_views=1)
data  = gp.receive(hash_)

mnemonic = gp.drop(b"sensitive data", ttl=3600)   # 12-word anonymous drop
data     = gp.pickup(mnemonic)
```

---

## Security

The relay is **untrusted by design** — it never holds a decryption key.

| What a compromised relay can do | What it cannot do |
|---------------------------------|-------------------|
| Deny service | Read file contents |
| Learn transfer timing | Substitute a registered public key |
| See blob sizes (fixed 5 MB padding) | Decrypt any stored ciphertext |

| Stack | Standard |
|-------|----------|
| Key encapsulation | ML-KEM-768 · NIST FIPS 203 |
| Symmetric | AES-256-GCM · NIST SP 800-38D |
| Signatures | ML-DSA-65 · NIST FIPS 204 |
| Key derivation | HKDF-SHA256 · RFC 5869 |
| Password blobs | Argon2id · RFC 9106 |
| Jurisdiction | Hetzner DE · EU/GDPR · no US CLOUD Act |

**Independent pentest:** [pentest-report-2026-04-08.txt](pentest-report-2026-04-08.txt) — no CRITICAL or HIGH findings.

---

## Docs

| | |
|--|--|
| [docs/self-hosting.md](docs/self-hosting.md) | Deploy, env vars, nginx, TLS, upgrade |
| [docs/licensing.md](docs/licensing.md) | Key types, edition limits, known limitations |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

---

**Requirements:** 1 GB RAM · Ubuntu 22.04+ / Debian 12+ · Docker 24+ · swap disabled

**License:** BUSL-1.1 — source available, free for ≤ 5 users. Change Date 2029-01-01 → Apache 2.0.
