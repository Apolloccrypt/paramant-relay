# PARAMANT Ghost Pipe

**Post-quantum encrypted file relay. Encrypted before it leaves your device. Destroyed after one download.**

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.4.0-brightgreen.svg)](CHANGELOG.md)
[![Docker](https://img.shields.io/badge/Docker-mtty001%2Frelay-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/mtty001/relay)
[![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-lightgrey.svg)](https://hub.docker.com/r/mtty001/relay)
[![Security Audit](https://img.shields.io/badge/security%20audit-apr%202026-blue.svg)](docs/security-audit-2026-04.md)

- **Zero plaintext** — ML-KEM-768 + AES-256-GCM encryption happens in the browser, before upload
- **Burn-on-read** — blob is zeroed from RAM after the first download
- **RAM-only blobs** — encrypted payload data is never written to disk; only cryptographic hashes (CT log) and API key config are persisted
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

Starts 6 containers: 5 sector relays (main / health / legal / finance / iot), an admin panel. System nginx handles TLS termination.

| Container | Internal port | Host port | Domain |
|-----------|--------------|-----------|--------|
| relay-main | 3000 | 127.0.0.1:3000 | relay.paramant.app |
| relay-health | 3000 | 127.0.0.1:3001 | health.paramant.app |
| relay-finance | 3000 | 127.0.0.1:3002 | finance.paramant.app |
| relay-legal | 3000 | 127.0.0.1:3003 | legal.paramant.app |
| relay-iot | 3000 | 127.0.0.1:3004 | iot.paramant.app |
| admin | 4200 | 127.0.0.1:4200 | /admin/ |

**First user (after deploy):**

```bash
export $(grep -v '^#' .env | xargs)

# Create your admin key
python3 scripts/paramant-admin.py add --label "admin" --plan enterprise --email you@example.com
python3 scripts/paramant-admin.py sync

# Admin panel → https://your-domain/admin/
# Login: ADMIN_TOKEN + 6-digit TOTP code
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
| Crypto runtime | Rust/WASM (wasm-pack) — browser-side encrypt runs in native code, not JS |
| Jurisdiction | Hetzner DE · EU/GDPR · no US CLOUD Act |

**Independent security audit (April 2026):** [Ryan Williams](https://github.com/scs-labrat) · Smart Cyber Solutions Pty Ltd (AU) · uncompensated, voluntary review
Findings: **4 critical · 5 high** · 6 medium · 5 low · [Full report](pentest-report-2026-04-08.txt) · [Patch status →](docs/security-audit-2026-04.md)

**v2.4.0 (April 2026):**
- **Docker architecture**: one shared relay codebase → 5 sector containers (compartmentalisation)
- All browser crypto (parashare, drop, ontvang) migrated to **Rust/WASM** via `crypto-bridge.js`
- WASM self-integrity: SHA-256 of `paramant_crypto_bg.wasm` verified at runtime before first use
- WASM binary committed to git (`frontend/pkg/`) — no Rust toolchain needed to self-host
- `noble-mlkem-loader.js` retained only for keypair generation (keygen not in WASM)
- `scripts/deploy.sh` added for one-command server deploy

**v2.3.6 hardening (April 2026):**
- CSP: `unsafe-inline` removed from `script-src`/`style-src`; `wasm-unsafe-eval` added for WASM
- SRI `sha384` integrity hashes on all local `<script>` tags
- `Strict-Transport-Security`, `Referrer-Policy: no-referrer`, `Permissions-Policy` on all responses
- Encrypt path in browser migrated from JS to **Rust/WASM** (`crypto-wasm/`, 112 KB `.wasm`)
- JS build pipeline: terser + javascript-obfuscator → `frontend/dist/`

![PARAMANT Ghost Pipe — Crypto Stack](docs/assets/crypto-stack.jpg)

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
