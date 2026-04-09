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

### v2.3.3 — 2026-04-09 (security hardening release)

Deep security review and self-hosting hardening. No external researcher report; internal findings.

#### DNS Rebinding bypass on webhook fire · Severity: Medium

**What:** `isSsrfSafeUrl()` was only checked at webhook registration time. An attacker registers a webhook URL pointing to a legitimate public IP (passes the check), lets the DNS TTL expire, then switches their DNS record to a private address (RFC1918, `169.254.169.254`, `::1`). On the next blob upload the relay fires the webhook to the now-private IP — bypassing the SSRF guard.

**Fix (v2.3.3):** `pushWebhooks()` now resolves the webhook hostname via `dns.promises.lookup()` immediately before every outbound request and re-verifies the resolved IP through `isSsrfSafeUrl()`. Redirected-to-private requests are blocked and logged as `webhook_dns_rebinding_blocked`. Applied to all 7 relay files.

#### Version disclosure via `X-Paramant-Version` response header · Severity: Low

**What:** Every relay response included `X-Paramant-Version: 2.x.x`, giving attackers an exact version string to cross-reference against CVE databases or known weaknesses without probing.

**Fix (v2.3.3):** Header removed from all `setHeaders()` calls. Version remains in `/health` JSON response body (needed by SDKs) and admin-only Prometheus metrics.

#### Google Fonts CDN in ParaDrop · Severity: Low

**What:** `drop.html` fetched fonts from `fonts.googleapis.com` and `fonts.gstatic.com` on every page load, leaking user IP addresses and timing to Google — contrary to the product's privacy promises.

**Fix (v2.3.3):** External font import removed. System font stack used instead.

#### Docker container runs with full Linux capabilities · Severity: Medium

**What:** Relay containers ran without capability restrictions. A container escape would give an attacker all Linux capabilities inside the container, including `CAP_NET_RAW`, `CAP_SYS_PTRACE`, etc.

**Fix (v2.3.3):** All relay containers now use `no-new-privileges: true` and `cap_drop: ALL`. Root filesystem set to read-only with a 64 MB tmpfs for `/tmp`. Memory limits enforced (1500m per relay).

#### Docker image uses floating `:latest` tag · Severity: Medium

**What:** `mtty001/relay:latest` is resolved at pull time. A supply-chain compromise of the Docker Hub account would silently deliver malicious code.

**Fix (v2.3.3):** Image pinned to `mtty001/relay:2.3.3`.

#### Build tools present in production Docker image · Severity: Medium

**What:** `python3`, `make`, `g++` (needed to compile argon2 native bindings) were present in the final runtime image, expanding the attack surface after a container escape.

**Fix (v2.3.3):** Multi-stage Dockerfile: build stage compiles with tools; runtime stage is lean — only compiled `node_modules` + `relay.js`.

#### nginx missing rate limits, security headers, session hardening · Severity: Medium

**What:** `nginx-selfhost.conf` (self-hosting stack) lacked: per-endpoint rate limiting for key registration and admin paths, HSTS `preload` + `includeSubDomains`, OCSP stapling, `ssl_session_tickets off`, `proxy_hide_header Server`, slowloris timeouts, `client_max_body_size`, upstream health fail tracking.

**Fix (v2.3.3):** Comprehensive hardening — see CHANGELOG v2.3.3 for full list.

---

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

#### P4 — SSRF via webhook URL registration · Severity: High · Affected: pro/enterprise accounts

**What:** `POST /v2/webhook` accepted any URL and stored it. When a blob was uploaded, the relay fired an outbound HTTP POST to the stored URL — including private RFC1918 addresses, loopback (`127.x.x.x`, `::1`), link-local (`169.254.x.x`), cloud metadata endpoints (`169.254.169.254`), and `.internal` hostnames. A paid user could use this to probe internal network services from the relay's network perspective.

**Where:** `pushWebhooks()` and `POST /v2/webhook` in all relay files.

**Fix (v2.3.2):** `isSsrfSafeUrl()` guard added. Enforced at two layers:
1. **Registration** (`POST /v2/webhook`): URL must be `https:` and hostname must not match any private/loopback/link-local range. Returns HTTP 400 with clear error if rejected.
2. **Fire** (`pushWebhooks()`): Guard re-checked before every outbound request. Any stored URL that fails the check is skipped and logged as `webhook_ssrf_blocked`. Blocked ranges: loopback (`127.x.x.x`, `::1`), link-local (`169.254.x.x`, `fe80::/10`), RFC1918 (`10.x`, `172.16-31.x`, `192.168.x`), IPv6 ULA (`fc00::/7`), `.local`/`.internal`/`.localhost` TLDs.

---

## Hall of Fame

We thank the following researchers for responsible disclosure:

| Date       | Researcher           | Findings                                      |
|------------|----------------------|-----------------------------------------------|
| 2026-04-09 | **Raymond Zwarts** ([@rzwarts74](https://github.com/rzwarts74)) · Independent security researcher | RAM admission TOCTOU `/v2/inbound` + `/v2/drop/create` (P1 · High) · Download handlers duplicate blobs in RAM (P2 · Medium) · pubkeys Map unbounded — no TTL, no device cap (P3 · Medium) · SSRF via webhook URL registration (P4 · High) · All 4 patched in v2.3.2 |
| 2026-04-09 | Ryan Williams ([@scs-labrat](https://github.com/scs-labrat)) · Smart Cyber Solutions Pty Ltd (AU) | Independent, uncompensated review · 20 findings (4 critical, 5 high, 6 medium, 5 low) · [Full report](pentest-report-2026-04-08.txt) · [Patch status](docs/security-audit-2026-04.md) |
| 2026-04-08 | Hendrik Bruinsma ([@readefries](https://github.com/readefries)) | Security review (5 findings: Argon2 race condition, `/health` info leak, `X-Paramant-Views-Left` header leak, `/v2/ct/proof` routing, stale CSP domain) + 4 bug reports (QR bug, fingerprint mismatch on refresh, receiver stuck at fingerprint, preload burn bug) + Thunderbird FileLink add-on · All patched in v2.2.1 / v2.3.0 |

---

## Security Contacts

| Purpose             | Contact                  |
|---------------------|--------------------------|
| Vulnerability report | privacy@paramant.app     |
| General security     | privacy@paramant.app     |
| Legal / compliance   | privacy@paramant.app     |
