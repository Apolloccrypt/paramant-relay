# PARAMANT — Post-Quantum Encrypted File Relay

[![Version](https://img.shields.io/badge/version-v0.9.0--beta-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![Security Audit](https://img.shields.io/badge/security_audit-passed%202026--04--19%20%E2%80%94%20low%20risk-brightgreen.svg)](SECURITY.md)
[![Relays](https://img.shields.io/badge/relays-5%20live-brightgreen.svg)](https://paramant.app/status)
[![Jurisdiction](https://img.shields.io/badge/jurisdiction-EU%2FDE%20only-blue.svg)](https://paramant.app/compliance/nis2)
[![Docker](https://img.shields.io/badge/Docker-mtty001%2Frelay-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/mtty001/relay)

**Post-quantum encrypted file relay. Burn-on-read. EU jurisdiction. Self-hostable in 2 minutes.**

Data is encrypted client-side with ML-KEM-768 + AES-256-GCM, relayed through RAM only, and destroyed after one download. Nothing is ever written to disk. Every transfer is recorded in a public Merkle tree — proving delivery without storing content.

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/Apolloccrypt/paramant-relay && cd paramant-relay

# 2. Configure
cp .env.example .env
echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env

# 3. Launch (6 containers: 5 sector relays + admin panel)
docker compose up -d

# 4. Verify
curl http://localhost:3001/health
# {"ok":true,"version":"2.5.0","sector":"health","edition":"licensed"}
```

Or on a Raspberry Pi / fresh VPS:

```bash
curl -fsSL https://paramant.app/install-pi.sh | bash
```

Or via the browser — no install:
**[Try ParaShare →](https://paramant.app/parashare)** (no account, no key needed)

**[Create a free account →](https://paramant.app/signup)** (TOTP, no password)

**[Get a free API key →](https://paramant.app/request-key)** (email delivery, 30-second form)

---

## What is included

| Feature | Status |
|---------|--------|
| Post-quantum file relay (ML-KEM-768 + AES-256-GCM) | Live — all 5 sector relays |
| Anonymous drop (no account, 12-word mnemonic) | Live — [paramant.app/drop](https://paramant.app/drop) |
| User accounts with TOTP (no password required) | Live — [paramant.app/signup](https://paramant.app/signup) |
| Admin dashboard (Overview, Users, Audit, Billing, Relay) | Live — `/admin/` |
| Resend TOTP setup link | Live — admin panel |
| Developer API keys | Live — [paramant.app/request-key](https://paramant.app/request-key) |
| Billing (Stripe integration) | Scaffold — Stripe connect pending |
| Chromium browser extension | Source in repo — server-side encryption path during client-side PQ migration ([architecture §08](https://paramant.app/architecture#components)) |
| Outlook Add-in | Source in repo — server-side encryption path during client-side PQ migration ([architecture §08](https://paramant.app/architecture#components)) |
| Thunderbird FileLink extension | Source in repo |

**Zero-knowledge scope:** the relay-cannot-read guarantee applies to transfers from the official SDKs (`paramant-sdk` for Python and JavaScript), the WebApp tools (ParaShare, ParaDrop), and the anonymous `/send` flow. The Chromium and Outlook extensions currently take a server-side encryption path while their client-side hybrid crypto is being finished — until that lands, treat extension uploads as relay-side, not zero-knowledge.

---

## How it works

```
Sender                     Ghost Pipe Relay               Receiver
------                     ----------------               --------
file.pdf                   RAM only — no disk writes      file.pdf
  │                        burn-on-read                     ▲
  ▼                        5 MB fixed padding               │
encrypt(ML-KEM-768)  ───►  hash → Merkle CT log  ────►  decrypt(ML-KEM-768)
X-Api-Key header           blob destroyed on read          X-Api-Key header
```

**What the relay never sees:** plaintext, encryption keys, filenames, or recipient identity.  
**What it does see:** fixed-size (5 MB) ciphertext blobs, blob hashes, API key identifiers.

Every transfer is hashed into a SHA3-256 Merkle tree. The relay signs each tree head with ML-DSA-65 and publishes it publicly — anyone can verify that a specific blob was delivered, and that the log has not been tampered with, without reading its contents.

---

## Use cases

### Healthcare — DICOM / HL7 FHIR (NEN 7510)

```bash
# Send MRI scan to specialist — burned after one download
python3 paramant-sender.py \
  --key pgp_xxx --device mri-001 --sector health scan.dcm

# Receive and forward to PACS system
python3 paramant-receiver.py \
  --key pgp_xxx --stream --forward https://pacs.hospital.nl/api

# Structured referral (HL7 FHIR R4)
paramant-referral referral.json --type fhir --from gp-001 --to cardiology-umcg
```

→ [NEN 7510 compliance](https://paramant.app/compliance/nen7510) · [DICOM setup guide](docs/dicom-guide.md)

---

### Legal & Notary — eIDAS compatible

```bash
# Send signed deed — cryptographically gone after receipt, CT log proof preserved
paramant-notary deed.pdf --sign --receipt

# Court documents with case reference
paramant-legal summons.pdf --case ROT-2026-1234 --proof
```

→ [Legal compliance](https://paramant.app/compliance/nis2)

---

### Industrial IoT — IEC 62443

```bash
# PLC telemetry — no VPN, no direct OT exposure to internet
python3 paramant-sender.py \
  --heartbeat 15 --device plc-factory-01 --sector iot data.bin

# Firmware update to body cams / IoT device fleet
paramant-firmware update-v2.1.bin \
  --sign --device-group bodycams.txt --version 2.1
```

→ [IEC 62443 compliance](https://paramant.app/compliance/iec62443)

---

### Finance — NIS2 / DORA

```bash
# ISO 20022 payment file relay with Merkle audit trail
python3 paramant-sender.py \
  --watch /export/iso20022/ --device bank-nl-01 --sector finance

# Every transfer produces a CT log entry for DORA audit
curl https://finance.paramant.app/v2/ct -H "X-Api-Key: pgp_xxx"
```

---

### HR — GDPR-compliant payslip distribution

```bash
# Bulk payslip delivery — no email, no storage, no GDPR risk
paramant-payslip \
  --bulk employees.csv --dir ./payslips/april/
```

---

### Software supply chain — EU CRA 2027

```bash
# CI/CD: sign + relay build artifacts with SBOM
paramant-cra dist/app-v1.2.tar.gz \
  --sbom sbom.json --sign --registry https://registry.company.nl/api
```

---

## Sector relays

Five live relays — each tuned for its compliance domain:

| Subdomain | Sector | Port | Compliance |
|-----------|--------|------|------------|
| relay.paramant.app | General | 3000 | — |
| health.paramant.app | Healthcare | 3001 | NEN 7510, DICOM, HL7 FHIR |
| legal.paramant.app | Legal/Notary | 3003 | eIDAS, KNB |
| finance.paramant.app | Finance | 3002 | NIS2, DORA, ISO 20022 |
| iot.paramant.app | Industrial IoT | 3004 | IEC 62443, EU CRA |

All five run the same codebase — the `SECTOR` env var determines which compliance mode activates.

---

## Self-hosting

### Linux VPS (Ubuntu 22.04+ / Debian 12+)

```bash
git clone https://github.com/Apolloccrypt/paramant-relay
cd paramant-relay
cp .env.example .env
echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env
docker compose up -d
```

This starts 6 containers: 5 sector relays + admin panel. System nginx handles TLS.

| Container | Host port | Public URL |
|-----------|-----------|------------|
| relay-main | 127.0.0.1:3000 | relay.your-domain |
| relay-health | 127.0.0.1:3001 | health.your-domain |
| relay-finance | 127.0.0.1:3002 | finance.your-domain |
| relay-legal | 127.0.0.1:3003 | legal.your-domain |
| relay-iot | 127.0.0.1:3004 | iot.your-domain |
| admin | 127.0.0.1:4200 | your-domain/admin/ |

### Raspberry Pi (arm64)

```bash
curl -fsSL https://paramant.app/install-pi.sh | bash
# Detects Pi model, installs Docker, disables swap, prints relay URL
```

### Automated full setup (domain + TLS + sectors)

```bash
curl -fsSL https://paramant.app/install.sh | bash
# Prompts: domain, email (Let's Encrypt), admin token, sectors, license key
```

### Bootable OS (no Docker needed)

Flash [paramantOS](https://github.com/Apolloccrypt/ParamantOS) to USB — relay starts on boot.

---

## API

### Send a file

```bash
curl -X POST https://health.paramant.app/v2/inbound \
  -H "X-Api-Key: pgp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"hash":"sha256_of_payload","payload":"base64_5mb_blob","ttl_ms":3600000}'
# Returns: {"blob_hash":"sha256...","ttl":3600}
```

### Receive a file (burn-on-read)

```bash
curl https://health.paramant.app/v2/outbound/abc123... \
  -H "X-Api-Key: pgp_your_key" --output received-file.bin
# Blob is destroyed immediately after this response
```

### Health check (public)

```bash
curl https://health.paramant.app/health
# {"ok":true,"version":"2.5.0","sector":"health","edition":"licensed"}
```

### CT log (public)

```bash
# Latest Signed Tree Head — ML-DSA-65 signed, public
curl https://relay.paramant.app/v2/sth
# {"ok":true,"sth":{"relay_id":"relay.paramant.app","sha3_root":"c7a9…","tree_size":43,"timestamp":1744123456789,"signature":"…"}}

# Verify the signature
paramant-verify-sth --relay https://relay.paramant.app

# Relay identity public key (for independent signature verification)
curl https://relay.paramant.app/v2/pubkey
# {"ok":true,"alg":"ML-DSA-65","public_key":"base64…","pk_hash":"sha3-256…"}

# Verify a delivery receipt
curl -X POST https://relay.paramant.app/v2/verify-receipt \
  -d '{"receipt":"<base64url from X-Paramant-Receipt header>"}'
# {"valid":true,"blob_hash":"a3f2…","burn_confirmed":true}
```

Full API reference: [docs/api.md](docs/api.md)

---

## CLI tools

All 44 `paramant-*` tools are included in [paramantOS](https://github.com/Apolloccrypt/ParamantOS) and installable via `.deb`:

```bash
curl -fsSL https://paramant.app/install-client.sh | bash
```

### Setup & diagnostics

```
paramant-help              # full command reference
paramant-setup             # first-time wizard (key + relay URL)
paramant-status            # relay health across all sectors
paramant-doctor            # automated health check
paramant-relay-setup       # clone + configure + start relay
```

### Sector tools (use-case specific)

```
paramant-referral          # healthcare referral (NEN 7510, HL7 FHIR, DICOM)
paramant-notary            # legal document transport (eIDAS, KNB)
paramant-legal             # court document relay (replaces Zivver)
paramant-payslip           # HR payslip distribution (GDPR)
paramant-firmware          # IoT/body cam firmware updates (IEC 62443)
paramant-cra               # software supply chain relay (EU CRA 2027)
paramant-ticket            # one-time transit ticket issuer/verifier
```

### Key management

```
paramant-keys              # list all API keys
paramant-key-add           # add new API key
paramant-key-revoke        # revoke an API key
```

### CT log verification

```
paramant-verify-sth        # fetch /v2/sth + /v2/pubkey, verify ML-DSA-65 signature
paramant-receipt           # view, save, or verify a delivery receipt
paramant-verify-peers      # cross-check STH consistency across all peer relays
```

### Security & network

```
security-status            # all security layers at a glance
paramant-ports             # firewall rules + listening ports
paramant-scan              # LAN relay discovery + registry
paramant-verify            # TOFU fingerprint verification
paramant-crypto-audit      # scan for quantum-vulnerable algorithms
paramant-hybrid-check      # verify PQC hybrid mode is active
```

### Data management

```
paramant-backup            # backup keys + CT log
paramant-restore           # restore from backup
paramant-export            # export audit log to USB
paramant-logs              # live log stream
paramant-update            # check for updates
paramant-migrate           # migrate relay data between versions
paramant-roadmap           # PQC migration roadmap generator
paramant-supply-chain      # software supply chain audit
```

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
# proof contains leaf_hash, leaf_index, tree_size, audit_path, root, sth

# Receive — returns (data, receipt)
data, receipt = gp.receive(hash_)
# receipt contains blob_hash, burn_confirmed, tree_size_at_retrieval, ML-DSA-65 signature

# Verify receipt (calls POST /v2/verify-receipt)
result = gp.verify_receipt(receipt)
assert result["valid"]

# Anonymous drop with 12-word mnemonic
mnemonic = gp.drop(b"sensitive data", ttl=3600)
data, _  = gp.receive(mnemonic)
```

---

## Security

The relay is **untrusted by design** — it never holds a decryption key.

| What a compromised relay can do | What it cannot do |
|---------------------------------|-------------------|
| Deny service | Read file contents |
| Learn transfer timing | Substitute a registered public key |
| See blob sizes (fixed 5 MB) | Decrypt any stored ciphertext |

**Crypto stack:**

| Layer | Standard |
|-------|----------|
| Key encapsulation | ML-KEM-768 · NIST FIPS 203 |
| Symmetric | AES-256-GCM · NIST SP 800-38D |
| Signatures | ML-DSA-65 · NIST FIPS 204 |
| Key derivation | HKDF-SHA256 · RFC 5869 |
| Password blobs | Argon2id · RFC 9106 |
| Crypto runtime | Rust/WASM — browser-side encryption runs in native code |
| Storage | RAM only — never written to disk |
| Padding | 5 MB fixed — all transfers look identical (DPI masking) |
| Audit log | SHA3-256 Merkle tree — tamper-evident, public |
| Infrastructure | Hetzner Frankfurt DE — EU jurisdiction only, no US CLOUD Act |
| Docker | cap_drop ALL, no-new-privileges, read-only rootfs |

**Security audits (April 2026):**

- **2026-04-19 — internal automated audit (6-layer + load test):** 0 critical · 0 high · 2 medium (fixed) · 1 low (fixed) · 11 passing checks. Load tested to 500 req/s, p95 latency 135 ms, zero errors. [Full report](SECURITY.md)
- **2026-04-15 — R. Zwarts RAPTOR review:** 10 findings (3 high · 3 medium · 4 low), all resolved. Commit [769f163](https://github.com/Apolloccrypt/paramant-relay/commit/769f163)
- **2026-04-13 — R. Zwarts dependency review:** 0 npm vulnerabilities. Node 20 EOL → node:22-alpine. express 4.x → 5.x. Commit [e6f216d](https://github.com/Apolloccrypt/paramant-relay/commit/e6f216d)
- **2026-04-11 — R. Zwarts verification review:** 14 findings (1 high · 8 medium · 5 low), all resolved. Commit [e6f216d](https://github.com/Apolloccrypt/paramant-relay/commit/e6f216d)
- **2026-04-10 — R. Zwarts independent audit:** 6 findings (3 high · 3 medium), all resolved. Commit [0db3ef0](https://github.com/Apolloccrypt/paramant-relay/commit/0db3ef0)
- **2026-04-08 — Ryan Williams, Smart Cyber Solutions (AU):** 4 critical · 5 high · 6 medium · 5 low. [Full report](docs/security-audit-2026-04.md)

All findings publicly documented in [SECURITY.md](SECURITY.md).

---

## Certificate Transparency log

Every transfer is appended to a public SHA3-256 Merkle tree. The trust model mirrors [RFC 6962](https://tools.ietf.org/html/rfc6962): you don't trust the relay operator, you verify the math.

| What you can prove | How |
|-------------------|-----|
| A specific blob was uploaded | `merkle_proof` in `POST /v2/inbound` response |
| A specific blob was delivered and burned | `X-Paramant-Receipt` header on `GET /v2/outbound` |
| Receipt is genuine and unmodified | `POST /v2/verify-receipt` |
| Log has not been forked | `GET /v2/sth/consistency?from=N&to=M` |
| Peer relays agree on the tree | `GET /v2/sth/peers` |

```bash
# Independent verification — no trust required
curl https://relay.paramant.app/v2/sth       # latest tree root
curl https://relay.paramant.app/v2/pubkey    # relay signing key
paramant-verify-sth --relay https://relay.paramant.app
paramant-verify-peers

# RSS archiving (subscribe to independently retain signed tree heads)
curl https://relay.paramant.app/ct/feed.xml

# Public web UI
open https://relay.paramant.app/ct/
```

---

## Compliance

| Regulation | Status | Details |
|------------|--------|---------|
| NIS2 (EU 2022/2555) | Ready | [Compliance page](https://paramant.app/compliance/nis2) |
| NEN 7510 (Healthcare NL) | Ready* | [Compliance page](https://paramant.app/compliance/nen7510) |
| IEC 62443 (Industrial IoT) | Ready | [Compliance page](https://paramant.app/compliance/iec62443) |
| DORA (Finance EU) | Ready | NIS2 compliance covers DORA Art. 6 |
| EU CRA 2027 | Designed for | paramant-cra tool + CT log |
| GDPR Art. 28 | Ready | [DPA](https://paramant.app/dpa) |

*NEN 7510: finding #4 (filename in transit RAM) patched in v2.4.5 — filename encrypted in relay RAM and never written to disk.

---

## Pricing

Tiers, limits, and current prices are maintained on the website:

**https://paramant.app/pricing**

API key signup: https://paramant.app/signup

---

## Docs

| | |
|--|--|
| [docs/api.md](docs/api.md) | Full API reference — all endpoints, request/response formats |
| [docs/self-hosting.md](docs/self-hosting.md) | Docker deploy, nginx, TLS, env vars, upgrade |
| [docs/dicom-guide.md](docs/dicom-guide.md) | Healthcare sector — DICOM gateway, HL7 FHIR, NEN 7510 |
| [docs/licensing.md](docs/licensing.md) | Key types, edition limits, Ed25519 enforcement |
| [docs/security.md](docs/security.md) | Threat model, crypto stack, audit reports |
| [Apolloccrypt/ParamantOS](https://github.com/Apolloccrypt/ParamantOS) | Bootable NixOS ISO — plug in, boot, relay is live |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

---

**Requirements:** 1 GB RAM · Ubuntu 22.04+ / Debian 12+ · Docker 24+ · swap disabled

**License:** BUSL-1.1 — source available, free for ≤ 5 active API keys per relay.

Licensor: PARAMANT | Jurisdiction: EU/DE | Contact: privacy@paramant.app
