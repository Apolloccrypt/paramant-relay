# Security Policy

## Reporting a vulnerability

Email: privacy@paramant.app
Subject: Security vulnerability — paramant-relay

We aim to respond within 48 hours and patch within 7 days for critical issues.
All reports are treated with responsible disclosure.

---

## Security audits

### 2026-04-13 — CIS Ubuntu 24.04 benchmark (production server)

114 checks applied across 13 categories on paramant.app:

| Category | Result |
|----------|--------|
| Kernel module blacklist (33 modules) | Enforced |
| /tmp as tmpfs (nodev, nosuid, noexec) | Configured |
| AppArmor | 119/121 profiles enforcing |
| SSH hardening (MACs, LoginGraceTime, MaxStartups) | Applied |
| Kernel network hardening | Applied |
| PAM hardening (pwquality, faillock, pwhistory) | Applied |
| auditd | 49 CIS L2 rules loaded |
| AIDE | Installed, daily integrity check |
| Cron permissions | Restricted to root |
| Password policy | MAX_DAYS=365, SHA512 |
| sudo logging | Enabled with full I/O logging |
| Firewall | UFW/nftables, default deny |
| Login banners | Configured |

### 2026-04-11 — R. Zwarts (verification review)

14 findings, all resolved in commit `e6f216d`.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | Admin login plain === + no rate limiting | Fixed: timingSafeEqual + per-IP rate limiter |
| 2 | Medium | safeEqual() bypassed on 3 relay paths | Fixed: all paths use safeEqual() |
| 3 | Medium | pgp_ enterprise admin path broken | Fixed: removed pgp_ admin support |
| 4 | Medium | Blob burned before transfer complete | Fixed: deferred deletion on res.finish() |
| 5 | Medium | TOTP timing-sensitive + code reuse | Fixed: full window scan + _usedTotpCodes |
| 6 | Medium | Sync file I/O on key create/revoke | Fixed: serialized async write queue |
| 7 | Medium | Relay registry unbounded + unpaginated | Fixed: cap + limit/offset pagination |
| 8 | Medium | CT log appendFileSync + no rotation | Fixed: async write stream + size rotation |
| 9 | Medium | Webhook SSRF port not restricted | Fixed: allowlist 443 + 80 only |
| 10 | Low | DID lookup O(n) scan | Fixed: O(1) via didRegistry.get(did) |
| 11 | Low | Admin login leaks internal address | Fixed: generic error, server-side log only |
| 12 | Low | Revoked keys keep WebSocket open | Fixed: ws.close(4401) on revoke |
| 13 | Low | Arbitrary plan strings accepted | Fixed: VALID_PLANS allowlist |
| 14 | Low | Invalid Base32 in TOTP_SECRET silent | Fixed: startup validation + clear error |

### 2026-04-10 — R. Zwarts (independent security researcher)

6 findings, all resolved in commit `0db3ef0`.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | WebSocket proxy uses plain TCP to HTTPS upstream | Fixed: tls.connect() |
| 2 | High | stream-next returns synthetic hash not real blob hash | Fixed: per-device queue with real sha256 |
| 3 | High | Webhook SSRF — DNS not resolved before connecting | Fixed: dns.resolve + private range reject |
| 4 | Medium | SDK uses ?k= query param rejected by relay | Fixed: X-Api-Key header |
| 5 | Medium | pgp_ enterprise admin path broken end-to-end | Fixed: removed pgp_ support |
| 6 | Medium | Blob burned before transfer complete | Fixed: deferred deletion on res.finish() |

### 2026-04 — Ryan Williams, Smart Cyber Solutions (independent)

20 findings across 4 critical / 5 high / 6 medium / 5 low.
Full report: [docs/security-audit-2026-04.md](docs/security-audit-2026-04.md)

| # | Severity | Status |
|---|----------|--------|
| 1–3 | Critical | Fixed |
| 4 | Critical | In progress: plaintext filename in relay RAM |
| 5–9 | High | Fixed |
| 10–15 | Medium | Fixed (13: accepted — documented) |
| 16–20 | Low | Fixed |

---

## Open findings

| # | Severity | Finding | ETA |
|---|----------|---------|-----|
| 4 | Critical | Plaintext filename stored in relay RAM | v2.4.6 |
| 14 | Medium | CT Merkle tree non-RFC-6962 compliant | v2.5.0 |

---

## Server hardening (paramant.app)

Additional fixes applied 2026-04-13:

| Fix | Detail |
|-----|--------|
| .env permissions | chmod 600 |
| Stale debug process | Killed (API key was visible in ps aux) |
| SSH | PermitRootLogin prohibit-password, MaxAuthTries 3 |
| Spurious arm64 arch | Removed from apt |
| HSTS | max-age=63072000 on all HTTPS blocks |
| Google Fonts | Removed from CSP |
| atd | Stopped and disabled |
| NATS | Dedicated system user, systemd hardening |
| Docker | admin + relay containers non-root (since e6f216d) |

---

## Dependency audit (2026-04-13)

- 0 npm vulnerabilities across all 4 packages
- Base image: node:22-alpine (node:20 was EOL)
- express 4.x → 5.x
- 0 GPL/AGPL/LGPL licenses
- 0 hardcoded secrets

---

## Hall of fame

| Researcher | Contribution | Date |
|------------|-------------|------|
| Ryan Williams ([@scs-labrat](https://github.com/scs-labrat)) | Independent security review — 20 findings | April 2026 |
| R. Zwarts ([@rzwarts74](https://github.com/rzwarts74)) | Code audit — 20 findings across two reports | April 2026 |
| Hendrik Bruinsma ([@readefries](https://github.com/readefries)) | FileLink extension + bug reports | April 2026 |
