# Security Policy

## Reporting a vulnerability

Email: privacy@paramant.app
Subject: Security vulnerability — paramant-relay

We aim to respond within 48 hours and patch within 7 days for critical issues.
All reports are treated with responsible disclosure.

### PGP key

For sensitive reports, encrypt to the Paramant Security key.

| | |
|--|--|
| User ID | `Paramant Security <privacy@paramant.app>` |
| Fingerprint | `09AA 452A 69DE F4A4 EB4B  72DC 5A34 D82F DAF3 54CD` |
| Algorithm | RSA-4096 |
| Created | 2026-04-25 |
| Expires | 2028-04-24 |
| Public key | <https://paramant.app/.well-known/openpgp-key.asc> |

Verify the fingerprint independently before encrypting — the link above is hosted on the same domain you are reporting against. If the fingerprint we publish in this README ever differs from the key served at the URL, treat it as a compromise of one of those channels and contact us via a separate channel before sending anything sensitive.

---

## Security audits

### 2026-04-15 — RAPTOR security review (R. Zwarts)

10 findings, all resolved.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | DOM XSS in `ct-log.html` — CT log entry fields and verify result rendered via `innerHTML` without escaping (CWE-79) | Fixed: `esc()` applied to all API-sourced values in log entry renderer, verify result, and proof hash list |
| 2 | High | AES-256 key embedded in Thunderbird FileLink upload blob (CWE-320) | Fixed: key excluded from blob (packet v0x02), travels via URL fragment only — relay never holds decryption material |
| 3 | High | `X-Forwarded-For: $proxy_add_x_forwarded_for` in nginx — client-controlled header passed to backend (CWE-290) | Fixed: both `nginx-paramant-live.conf` and `nginx-selfhost.conf` changed to `$remote_addr`; relay uses `CF-Connecting-IP` → `X-Real-IP` → socket via `getClientIp()` helper |
| 4 | Medium | `decodeURIComponent()` without try/catch crashes relay process on malformed `%` sequences (CWE-248) | Fixed: all 4 routes (`/v2/did`, `/v2/pubkey`, `/v2/fingerprint`, `/v2/attest`) wrapped in try/catch → HTTP 400 |
| 5 | Medium | `users.json` read-modify-write race condition under concurrent key operations (CWE-362) | Fixed: `_mutateUsersJson()` serialises all read-modify-write cycles inside a promise queue |
| 6 | Medium | `/v2/sign-dpa` unauthenticated and unthrottled (CWE-770) | Fixed: per-IP (3/24 h) and per-email (1/24 h) in-process limits + nginx `limit_req zone=api` |
| 7 | Low | HTML injection in trial key email templates — `name`, `email`, `useCase` interpolated raw (CWE-116) | Fixed: `escHtml()` helper applied to all user-supplied fields in `welcomeHtml` and `notifyHtml` |
| 8 | Low | `drop.html` QR fallback uses `innerHTML` with relay-returned URL (CWE-79) | Fixed: replaced with `document.createElement` + `textContent` |
| 9 | Low | SDK `pyproject.toml` allows vulnerable `requests` and `cryptography` versions | Fixed: floors raised to `requests>=2.33`, `cryptography>=43.0.1`, `pytest>=9`; `requires-python` bumped to `>=3.10`; `requirements.txt` lockfile generated |
| 10 | Low | Duplicate IP-derivation logic at 4 call sites in `relay.js` | Fixed: consolidated into `getClientIp()` helper |

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

### 2026-04-20 — Admin panel hardening + email security

**Scope:** TOTP reset flow abuse protection, error response hardening,
rate limit verification, email template security review.

| Area | Finding | Status |
|------|---------|--------|
| TOTP reset | Two-stage confirmation prevents enumeration + abuse | Implemented |
| Error responses | JSON-only on all endpoints; no HTML stack traces | Verified |
| Rate limits | All mutating endpoints rate-limited and audited | Verified |
| Email security | From-address, reply-to, List-Unsubscribe, masked IPs | Implemented |
| Integration tests | 24/24 passing after enterprise sprint | Passing |

---

### 2026-04-19 — Automated internal audit (6 layers + load test)

**Scope:** Static code analysis, authentication flows, network and infrastructure, active penetration testing, cryptographic implementation review, business logic, load testing.

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | Fixed in-session |
| Low | 1 | Fixed in-session |
| Informational | 11 | All passing |

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| A-01 | Medium | Setup token consumed by email scanner before user interaction | Fixed: `setup.html` gates `init()` behind explicit button click |
| A-02 | Medium | `POST /v2/user/setup-totp` returned 409 for provisional (unactivated) TOTP | Fixed: endpoint is now idempotent; returns existing secret until activation |
| A-03 | Low | `INTERNAL_AUTH_TOKEN` absent from admin container environment | Fixed: env var injected in `docker-compose.yml` |
| A-04 through A-15 | Info | Argon2id params, TOTP timing safety, AES-GCM nonces, PQ layer, setup token entropy, billing auth, email canonicalization, rate limits, container hardening, secrets hygiene | All passing |

**Load test results** (tool: `hey`, target: `https://paramant.app/`):

| Load | Requests | p95 latency | Errors | Container state |
|------|----------|-------------|--------|----------------|
| 10 rps | 100 | 10 ms | 0 | All healthy |
| 50 rps | 500 | 18 ms | 0 | All healthy |
| 100 rps | 1000 | 43 ms | 0 | All healthy |
| 500 rps | 5000 | 135 ms | 0 | All healthy |

**Next audit:** External third-party penetration test planned before public general availability.

---

### 2026-04-15 — TOTP algorithm mismatch (internal)

| Severity | Finding | Status |
|----------|---------|--------|
| High | Installer scripts emitted `algorithm=SHA1` in `otpauth://` URIs while relay.js verifies TOTP with HMAC-SHA256 (`relay.js:746`). TOTP codes generated by authenticator apps would fail silently on every login attempt. | Fixed: `install.sh` and `install-pi.sh` updated to `algorithm=SHA256` in both the URI and the manual-entry display string. |

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

## Threat model

### What Paramant protects against

| Threat | Mitigation |
|--------|------------|
| Third-party storage provider reading file contents | Zero-knowledge relay: content encrypted client-side before transmission; relay never holds decryption keys |
| Network-level interception (MITM) | TLS 1.2/1.3 with forward-secret cipher suites; HSTS enforced on all subdomains |
| Harvest-now-decrypt-later (post-quantum adversary) | ML-KEM-768 key encapsulation inside TLS; classical TLS layer provides defense in depth |
| Credential stuffing | User accounts require TOTP; no stored passwords |
| Email link preview scanners consuming one-time tokens | Setup tokens are click-gated; endpoint is idempotent for provisional state |
| Log tampering (CT log) | SHA3-256 Merkle tree with ML-DSA-65 signed tree heads; gossip protocol between peer relays |

### What Paramant does not protect against

| Threat | Note |
|--------|------|
| Endpoint compromise | If your device runs malware, client-side encryption offers no protection |
| Coerced disclosure | Legal orders directed at the operator can compel log disclosure; content remains encrypted |
| Social engineering of operators | Administrative access is protected by TOTP but not immune to targeted attacks |
| Quantum cryptanalysis of prior TLS sessions | Mitigated by the PQ encryption layer inside TLS, which is not retroactively breakable |

---

## Compliance posture

Paramant maps technical controls to NIS2 (EU 2022/2555), IEC 62443 (industrial control systems), and NEN 7510 (Dutch healthcare). Mapping documents are part of the standard delivery package for Enterprise customers.

**What this means:**

- Architecture aligns with the technical requirements of these frameworks (RAM-only storage, post-quantum key exchange, signed CT log, EU-only jurisdiction, no US CLOUD Act exposure).
- Compliance documentation is generated from operational evidence — CT log, deployment artefacts, configuration — and updated per release.
- A signed Data Processing Agreement under GDPR Art. 28 is available to all paid tiers.

**What this does NOT mean:**

- No external penetration test has been conducted as of the date of this document. The internal automated audit (2026-04-19) and the independent reviews by R. Zwarts and Ryan Williams listed above are not third-party certification.
- No certification body has audited Paramant against ISO 27001, SOC 2, or any of the frameworks mentioned. The mapping documents are operator-generated.
- "Compliant by design" describes architectural alignment, not formal attestation. Customers requiring independent attestation should treat Paramant as a component within their broader ISMS and contract their own auditor.

If you need formal certification or third-party attestation as part of your procurement process, talk to us early — we will work with your auditor and provide the evidence we have, but we will not represent the platform as pre-certified.

---

## Known limitations (beta)

- Beta access only; hardening for general public availability is in progress.
- Stripe billing integration is a scaffold; production payments are not yet active.
- Some accounts created before TOTP rollout operate on API-key-only authentication.
- Rate limits have not been validated under sustained adversarial load; no WAF is deployed.
- External third-party penetration test has not yet been conducted.

---

## Hall of fame

| Researcher | Contribution | Date |
|------------|-------------|------|
| Ryan Williams ([@scs-labrat](https://github.com/scs-labrat)) | Independent security review — 20 findings | April 2026 |
| R. Zwarts ([@raymond-itsec](https://github.com/raymond-itsec)) | Code audit — 20 findings across two reports | April 2026 |
| Hendrik Bruinsma ([@readefries](https://github.com/readefries)) | FileLink extension + bug reports | April 2026 |
