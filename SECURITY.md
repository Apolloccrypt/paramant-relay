# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.2.x   | ✓ Active  |
| 2.1.x   | ✓ Active  |
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

## Hall of Fame

We thank the following researchers for responsible disclosure:

| Date       | Researcher           | Findings                                      |
|------------|----------------------|-----------------------------------------------|
| 2026-04-09 | Ryan Williams ([@scs-labrat](https://github.com/scs-labrat)) · Smart Cyber Solutions Pty Ltd (AU) | Independent, uncompensated review · 20 findings (4 critical, 5 high, 6 medium, 5 low) · [Full report](pentest-report-2026-04-08.txt) · [Patch status](docs/security-audit-2026-04.md) |
| 2026-04-08 | Hendrik Bruinsma ([@readefries](https://github.com/readefries)) | Security review (5 findings: Argon2 race condition, `/health` info leak, `X-Paramant-Views-Left` header leak, `/v2/ct/proof` routing, stale CSP domain) + 4 bug reports (QR bug, fingerprint mismatch on refresh, receiver stuck at fingerprint, preload burn bug) + Thunderbird FileLink add-on · All patched in v2.2.1 / v2.3.0 |

---

## Security Contacts

| Purpose             | Contact                  |
|---------------------|--------------------------|
| Vulnerability report | privacy@paramant.app     |
| General security     | privacy@paramant.app     |
| Legal / compliance   | privacy@paramant.app     |
