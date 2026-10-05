# Paramant ASVS Compliance Checklist

Run this checklist per release. Status values: PASS / FAIL / PARTIAL /
NA / TODO. Evidence is a file:line reference, an HTTP probe result, or
a config location. Update on every change.

Last run: (see scripts/security/audit.sh output)

| ID | Control | Level | Status | Evidence |
|----|---------|-------|--------|----------|
| ARCH-01 | Threat model documented + reviewed | L2 | TODO | |
| ARCH-02 | Admin separated at process + network level | L3 | TODO | |
| ARCH-03 | Relay zero-knowledge (no plaintext/keys) | L2 | TODO | |
| ARCH-04 | Open-core boundary enforced | L3 | TODO | |
| AUTH-01 | User API key, header-only, over TLS | L2 | TODO | |
| AUTH-02 | Admin requires token AND enforced TOTP | L3 | TODO | |
| AUTH-03 | No shared user/admin credential | L2 | TODO | |
| AUTH-04 | Auth rate-limit + lockout | L2 | TODO | |
| AUTH-05 | TOTP secret encrypted, never logged/returned | L3 | TODO | |
| AUTH-06 | Generic auth failure messages | L2 | TODO | |
| SESS-01 | Cookies HttpOnly+Secure+SameSite | L2 | TODO | |
| SESS-02 | Server-side logout invalidation | L2 | TODO | |
| SESS-03 | High-entropy session IDs, rotated | L2 | TODO | |
| AC-01 | Deny by default on undeclared routes | L2 | TODO | |
| AC-02 | Admin authz server-side per request | L3 | TODO | |
| AC-03 | No IDOR on transfers | L2 | TODO | |
| AC-04 | Restrictive CORS | L2 | TODO | |
| VAL-01 | Allowlist input schema at boundary | L2 | TODO | |
| VAL-02 | Context-aware output encoding | L2 | TODO | |
| VAL-03 | No injection vectors | L2 | TODO | |
| VAL-04 | Admin CLI command whitelist | L3 | TODO | |
| CRYPTO-01 | PQ via @paramant/core | L3 | TODO | |
| CRYPTO-02 | No silent classical downgrade | L3 | TODO | |
| CRYPTO-03 | Private keys client-side only | L3 | TODO | |
| CRYPTO-04 | CSPRNG for all key material | L3 | TODO | |
| CRYPTO-05 | Crypto vendored + pinned | L2 | TODO | |
| LOG-01 | No PII in logs | L2 | TODO | |
| LOG-02 | No stack traces to client | L2 | TODO | |
| LOG-03 | Admin actions to CT log | L3 | TODO | |
| LOG-04 | Security events logged (minus PII) | L2 | TODO | |
| DATA-01 | File + sign plaintext RAM-only, burned | L3 | TODO | |
| DATA-02 | users.json age-encrypted, key offline | L2 | TODO | |
| DATA-03 | Data minimization | L2 | TODO | |
| DATA-04 | Sensitive files never web-reachable | L2 | TODO | |
| COMM-01 | TLS 1.2+, HSTS preload | L2 | TODO | |
| COMM-02 | Strict CSP, no unsafe-eval | L2 | TODO | |
| COMM-03 | Admin network-isolated (+mTLS L3) | L3 | TODO | |
| COMM-04 | Full security header set | L2 | TODO | |
| SUP-01 | Dependencies pinned | L2 | TODO | |
| SUP-02 | Docker images cosign-signed | L3 | TODO | |
| SUP-03 | SBOM per release | L2 | TODO | |
| SUP-04 | Browser deps vendored, no CDN | L2 | TODO | |
| BL-01 | Rate limits on state-changing endpoints | L2 | TODO | |
| BL-02 | Anti-automation on signup/sign | L2 | TODO | |
| FILE-01 | Server-side upload size limits | L2 | TODO | |
| FILE-02 | No path traversal | L2 | TODO | |
| API-01 | Request schema validation | L2 | TODO | |
| API-02 | Admin API rejects without token+TOTP | L3 | TODO | |
| API-03 | Explicit Content-Type, no MIME sniff | L2 | TODO | |
| CFG-01 | /setup gated/disabled after first-run | L3 | TODO | |
| CFG-02 | Secrets via env/mount, never committed | L2 | TODO | |
| CFG-03 | No default credentials | L2 | TODO | |
| CFG-04 | Debug/listing disabled in prod | L2 | TODO | |
| PQ-01 | No silent removal of PQ protection | L3 | TODO | |
| SOV-01 | EU jurisdiction, no US CLOUD Act path | L2 | TODO | |
| TRANS-01 | Paramant actions visible in customer CT log | L3 | TODO | |
