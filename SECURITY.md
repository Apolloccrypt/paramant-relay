# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| **2.3.x** | ✓ **Active** |
| 2.2.x   | ✓ Active (security fixes backported) |
| 2.1.x   | ✗ End of life |
| < 2.1   | ✗ End of life |

---

## Reporting a Vulnerability

**Email:** privacy@paramant.app  
**Response time:** 48 hours for initial acknowledgement  
**Resolution target:** 14 days for critical, 30 days for high, 90 days for medium/low

Please include:
- A clear description of the vulnerability
- Steps to reproduce (curl commands, PoC code, screenshots)
- Affected component (relay, frontend, SDK, nginx config)
- Your assessment of severity and impact

We do **not** have a bug bounty program at this time. We will credit researchers in the Hall of Fame below (with your consent).

---

## Scope

### In scope

- `relay.paramant.app` and sector relays (`health`, `legal`, `finance`, `iot`)
- `paramant.app` frontend (ParaDrop, ParaShare, ParaVault)
- Relay source code at `github.com/Apolloccrypt/paramant-relay`
- SDK packages: `paramant` (PyPI), `@paramant/sdk` (npm)
- Authentication, authorisation, and key management logic
- Cryptographic protocol implementation (ML-KEM-768, ECDH P-256, AES-256-GCM)
- Burn-on-read and first-registration-wins enforcement
- Rate limiting and abuse controls

### Out of scope

- Denial of service against production infrastructure
- Social engineering of staff
- Physical attacks
- Issues in third-party dependencies with no exploit path in this codebase
- Theoretical attacks without a practical reproduction
- Self-hosted instances not operated by Paramant
- Reports generated solely by automated scanners without manual validation

---

## Disclosure Policy

We follow **coordinated (responsible) disclosure**:

1. Report the vulnerability privately to privacy@paramant.app
2. We acknowledge within 48 hours
3. We work with you to validate and fix the issue
4. We aim to release a patch within 14–90 days depending on severity
5. After the patch is released (or 90 days from your report, whichever comes first), you are free to publish

We will not take legal action against researchers who follow this policy.

---

## What We Ask

- Do not access, modify, or delete data belonging to other users
- Do not perform automated scanning at rates that degrade service for others
- Do not disclose findings publicly before the 90-day window expires or a patch is released

---

## Recent Security Patches

### v2.3.2 — 2026-04-09 (security release)

Three vulnerabilities reported by Raymond Zwarts, independent security researcher. All patched and deployed same day.

#### P1 — RAM admission TOCTOU · Severity: High · Affected: paid accounts only

**What:** `ramOk()` checked relay capacity _before_ reading the request body. Under concurrent uploads, multiple requests could simultaneously pass the RAM gate, then each allocate a full blob-sized buffer — bypassing the limit entirely.

**Where:** `POST /v2/inbound` and `POST /v2/drop/create` in all relay files.

**Fix (v2.3.2):** `inFlightInbound` counter incremented atomically after `ramOk()` passes, before `await readBody()`, protected with `try/finally`. `ramOk()` now projects RSS including all in-flight allocations: `rssMB + BLOB_SIZE_MB * (inFlightInbound + 1)`.

#### P2 — Download handlers duplicate blobs in RAM · Severity: Medium

**What:** All download, outbound, and drop/pickup handlers called `Buffer.from(entry.blob)` — creating a full copy of the blob in RAM before sending. During download, every blob occupied 2× its size in memory.

**Where:** `/v2/dl/:token/get`, `/v2/outbound/:hash`, `/v2/drop/pickup` in all six relay files (10 call sites total).

**Fix (v2.3.2):** All handlers now use the buffer reference directly (`const blob = entry.blob`) and zero it in the `res.end()` flush callback (`res.end(blob, () => { blob.fill(0) })`). No copy created; zeroing deferred until TCP stack confirms delivery.

#### P3 — Pubkeys Map unbounded — no TTL, no device cap · Severity: Medium

**What:** `POST /v2/pubkey` stored entries without expiry or per-key limits. A free user could register an unlimited number of device IDs, growing the in-process Map indefinitely — a slow RAM exhaustion vector.

**Where:** `/v2/pubkey` POST handler in all relay files.

**Fix (v2.3.2):**
- Per-plan device limits enforced at registration time: **free = 5 devices, pro = 50, enterprise = unlimited**
- TTL on every entry: **free = 7 days, pro = 30 days, enterprise = 1 year**
- Invite-session pubkeys expire after **1 hour**
- `GET /v2/pubkey` evicts expired entries on access
- Hourly cleanup sweep removes remaining expired entries

---

## Hall of Fame

We thank the following researchers for responsible disclosure:

| Date       | Researcher           | Findings                                      |
|------------|----------------------|-----------------------------------------------|
| 2026-04-09 | **Raymond Zwarts** · Independent security researcher | RAM admission TOCTOU on `/v2/inbound` + `/v2/drop/create` (P1) · Download handlers double blob RAM via `Buffer.from()` copy (P2) · Both patched same day · Pubkeys Map TTL absent — free users could register unlimited deviceIDs (P3, patched 2026-04-09) |
| 2026-04-09 | Ryan Williams ([@scs-labrat](https://github.com/scs-labrat)) · Smart Cyber Solutions Pty Ltd (AU) | Independent, uncompensated review · 20 findings (4 critical, 5 high, 6 medium, 5 low) · [Full report](pentest-report-2026-04-08.txt) · [Patch status](docs/security-audit-2026-04.md) |
| 2026-04-08 | Hendrik Bruinsma ([@readefries](https://github.com/readefries)) | Security review (5 findings: Argon2 race condition, `/health` info leak, `X-Paramant-Views-Left` header leak, `/v2/ct/proof` routing, stale CSP domain) + 4 bug reports (QR bug, fingerprint mismatch on refresh, receiver stuck at fingerprint, preload burn bug) + Thunderbird FileLink add-on · All patched in v2.2.1 / v2.3.0 |

---

## Security Contacts

| Purpose             | Contact                  |
|---------------------|--------------------------|
| Vulnerability report | privacy@paramant.app     |
| General security     | privacy@paramant.app     |
| Legal / compliance   | privacy@paramant.app     |
