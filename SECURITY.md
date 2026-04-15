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

### 2026-04-15 — Internal security review

7 findings, all resolved in commit `8e6d4d2`.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | DOM XSS in relay registry viewer — relay fields unescaped in `innerHTML` | Fixed: `esc()` helper applied to all API-sourced values incl. `title=""` attributes |
| 2 | High | AES-256 key stored alongside ciphertext in Thunderbird FileLink blobs | Fixed: key excluded from blob (packet v0x02), travels via URL fragment only |
| 3 | High | Malformed percent-encoding crashes relay process (public DoS, destroys in-flight blobs) | Fixed: `try/catch` on `decodeURIComponent()` at all 4 affected routes → HTTP 400 |
| 4 | High | X-Forwarded-For spoofing bypasses admin brute-force rate limiter | Fixed: `X-Real-IP` (`nginx $remote_addr`) used instead of XFF first-entry |
| 5 | Medium | `users.json` read-modify-write race condition | Fixed: `_mutateUsersJson()` serialises full read-modify-write cycle inside write queue |
| 6 | Medium | Relay rate limits collapse to proxy loopback IP | Fixed: proxy-aware IP chain (`CF-Connecting-IP` → `X-Real-IP` → socket) |
| 7 | Medium | `/v2/sign-dpa` unauthenticated, unlimited, email-abusable | Fixed: per-IP (3/24 h) and per-email (1/24 h) in-process limits + nginx `limit_req` |

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

## CT Log gossip protocol & external anchoring

### Trust model

Before Mission 4, tamper-evidence depended on trusting Paramant's own servers:
> "Trust Paramant's servers"

After Mission 4, the trust model is:
> "Trust that **at least one relay operator is honest**"

This is the same trust model as RFC 6962 Certificate Transparency. Any relay operator running `paramant-verify-peers` becomes an independent auditor.

### Signed Tree Heads (STH)

Every change to the CT log produces a Signed Tree Head (STH) — an ML-DSA-65 signed commitment to the current Merkle root:

```json
{
  "version": 1,
  "relay_id": "https://health.paramant.app",
  "tree_size": 59,
  "sha3_root": "deed04dd...",
  "timestamp": 1713000000000,
  "signature": "<base64 ML-DSA-65 over canonical JSON>"
}
```

Signature is over the canonical JSON of `{relay_id, sha3_root, timestamp, tree_size, version}` (keys sorted). Signed with the relay's ML-DSA-65 identity key (NIST FIPS 204).

### Gossip protocol (push STH)

After every STH is produced, the relay broadcasts it to all registered peers:

```
POST /v2/sth/ingest
Body: { relay_id, sha3_root, timestamp, tree_size, version, signature, public_key, relay_pk_hash }
```

- Receiver verifies ML-DSA-65 signature before storing
- Invalid signatures are logged and rejected (HTTP 400)
- Valid STHs are stored in `data/peer-sths/{relay_pk_hash}.jsonl`
- Non-blocking, best-effort — peer failures do not affect the local relay

### Cross-relay verification endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /v2/sth/peers` | List all peer relays + their latest mirrored root |
| `GET /v2/sth/peers/:pk_hash` | Full STH history mirrored from a specific peer |
| `GET /v2/sth/consistency?from=N&to=M` | RFC 6962 consistency proof between two tree sizes |
| `GET /ct/feed.xml` | RSS feed of signed tree heads for external archiving |

### Consistency proof (append-only guarantee)

`GET /v2/sth/consistency?from=<old_size>&to=<new_size>` returns an RFC 6962-style proof that the new tree contains the old tree as a prefix. This is the key property that prevents a relay from "rewinding" its log.

```bash
# Verify no entries were removed or reordered between size 10 and current
curl "https://health.paramant.app/v2/sth/consistency?from=10" | jq .
```

### RSS feed anchoring

Subscribe to `/ct/feed.xml` with any RSS reader to independently archive STH roots:

```
https://health.paramant.app/ct/feed.xml
```

If a relay later claims a different root for a published timestamp, any subscriber has cryptographic proof of the original commitment.

### paramant-verify-peers CLI

```bash
# Install
npm install -g @noble/post-quantum  # required for ML-DSA-65

# Verify all peer STHs are consistent
paramant-verify-peers --relay https://health.paramant.app

# Exit 0 = all consistent (or 0 peers)
# Exit 1 = inconsistency detected
```

The tool:
1. Fetches the peer STH mirror from the local relay
2. Verifies ML-DSA-65 signatures on each peer's latest STH
3. Cross-checks by fetching the STH directly from the peer relay
4. Checks for tree_size rollbacks (append-only violation)
5. Reports inconsistencies with full details

---

## Server hardening (paramant.app)

Additional fixes applied 2026-04-13:

| Fix | Detail |
|-----|--------|
| .env permissions | chmod 600 |
| Stale debug process | Killed (API key was visible in ps aux) |
| SSH | PermitRootLogin prohibit-password, MaxAuthTries 3 |
| Spurious arm64 arch | Removed from apt |
| HSTS | `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on all 7 HTTPS server blocks (paramant.app + 5 relay subdomains). Applied directly in `/etc/nginx/sites-enabled/paramant-public` — the deploy-time nginx config (`deploy/nginx-paramant-live.conf`) also carries this header but the Cloudflare-facing config is gitignored. |
| TLS | `ssl_protocols TLSv1.2 TLSv1.3` + forward-secret cipher suite (`ECDHE-*-GCM` + `CHACHA20-POLY1305`) explicit on all 443 vhosts; `ssl_prefer_server_ciphers off` (client chooses) |
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

## Security incidents

### 2026-04-15 — Credential exposure in git history

**What:** gitleaks scan revealed historical credential exposure.

| Credential | Committed | Status |
|------------|-----------|--------|
| `RESEND_API_KEY` (`re_K1YQ…XvA`) | 2026-04-01 in `deploy/systemd/*.service` | Verified invalid via Resend API on 2026-04-15 |
| 3× demo API keys (`pgp_…`) | 2026-04-01 – 2026-04-07 in `frontend/index.html`, `poc/README.md` | Revoked via `/admin/` on 2026-04-15 |

**Remediation:** Server `.env` permissions hardened to 600; gitleaks pre-commit hook installed.

**Note on git history:** Historical commits still contain the now-invalid credentials. Rewriting history would break existing clones with no security benefit since the credentials are revoked. Documented here for transparency.

---

## Hall of fame

| Researcher | Contribution | Date |
|------------|-------------|------|
| Ryan Williams ([@scs-labrat](https://github.com/scs-labrat)) | Independent security review — 20 findings | April 2026 |
| R. Zwarts ([@rzwarts74](https://github.com/rzwarts74)) | Code audit — 20 findings across two reports | April 2026 |
| Hendrik Bruinsma ([@readefries](https://github.com/readefries)) | FileLink extension + bug reports | April 2026 |
