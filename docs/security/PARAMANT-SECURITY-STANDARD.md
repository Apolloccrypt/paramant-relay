# Paramant Security & Privacy Standard

Status: binding for all code in paramant-relay and paramant-management.
Framework: OWASP ASVS 4.0.3.
Baseline: L2 across the whole application.
Elevated: L3 for cryptographic paths and the entire admin surface.

This document is the permanent bar. Every PR is checked against the
compliance checklist (COMPLIANCE-CHECKLIST.md). Nothing ships that
regresses a control already marked PASS.

## Why this bar

Paramant is a post-quantum product. The cryptography (ML-KEM-768,
ML-DSA-65 via @paramant/core) protects data in transit and at rest.
But strong crypto is meaningless if the application layer leaks: an
open admin panel, an XSS in a tool view, or an unauthenticated config
endpoint defeats the entire promise. The application layer is the real
attack surface. It must match the strength of the crypto.

## The four non-negotiable rules (apply to EVERY PR)

1. Server-side authorization on every non-public endpoint. Never a
   client-side-only gate. A client redirect is UX, not security.
2. All user-supplied data is output-encoded at render. No innerHTML
   with untrusted data. No string-built SQL/shell/HTML.
3. Secrets never enter the repository and never reach the browser.
   Private signing keys stay client-side. Server secrets live in
   /etc with 0600, outside git.
4. No external script imports in production. Browser dependencies are
   vendored (esbuild bundle, same-origin). CDN imports break under CSP
   and widen the supply-chain surface.

## V1 - Architecture, design, threat modeling (L2/L3)

- ARCH-01 (L2): A documented threat model exists and is reviewed each
  release. Covers: malicious sender, malicious recipient, network MITM,
  compromised relay operator, stolen API key, stolen admin token,
  harvest-now-decrypt-later.
- ARCH-02 (L3): Admin and user planes are separated at the process
  level (separate container) and the network level (admin not reachable
  from public internet).
- ARCH-03 (L2): Trust boundaries are explicit. The relay is treated as
  untrusted for plaintext (zero-knowledge): it never holds decryption
  keys or document plaintext.
- ARCH-04 (L3): Open-core boundary is enforced. Public protocol code
  carries no management-plane secrets or private license logic.

## V2 - Authentication (L2/L3)

- AUTH-01 (L2): User authentication is an API key (pgp_ prefix), high
  entropy, transmitted only via X-Api-Key header over TLS.
- AUTH-02 (L3): Admin authentication requires ADMIN_TOKEN AND a valid
  TOTP code. TOTP is enforced, never optional or bypassable.
- AUTH-03 (L2): No shared session or credential between user and admin
  planes. A user API key can never satisfy an admin check.
- AUTH-04 (L2): Authentication endpoints are rate-limited with
  exponential backoff and account/source lockout after repeated
  failures. Brute force is infeasible.
- AUTH-05 (L3): TOTP secrets are stored encrypted at rest, never logged,
  never returned to any client after enrollment.
- AUTH-06 (L2): Generic failure messages. Auth errors never reveal
  whether the token, the TOTP, or the account was the failing factor.

## V3 - Session management (L2)

- SESS-01 (L2): If a session cookie is used, it is HttpOnly, Secure,
  SameSite=Strict, with a short idle timeout and absolute lifetime.
- SESS-02 (L2): Sessions are invalidated server-side on logout. Logout
  is always available.
- SESS-03 (L2): Session identifiers are high-entropy, rotated on
  privilege change.

## V4 - Access control (L2/L3)

- AC-01 (L2): Deny by default. Every endpoint explicitly declares its
  required authorization; the default for an undeclared route is deny.
- AC-02 (L3): Admin endpoints enforce authorization server-side on
  every request, not once at login. No reliance on hidden UI.
- AC-03 (L2): No insecure direct object references. A user cannot read
  or burn another user's transfer by guessing an ID.
- AC-04 (L2): CORS is restrictive. Only known origins; no wildcard with
  credentials.

## V5 - Validation, sanitization, encoding (L2)

- VAL-01 (L2): All input validated against a positive (allowlist)
  schema at the trust boundary. Reject, do not sanitize-and-continue,
  on schema violation.
- VAL-02 (L2): Output encoding is context-aware (HTML, attribute, JS,
  URL). No untrusted data in innerHTML.
- VAL-03 (L2): No injection vectors: no string-built shell, SQL, or
  template execution with user data.
- VAL-04 (L3): The admin CLI executes only whitelisted commands. No
  arbitrary command passthrough; arguments are validated.

## V6 - Cryptography (L3)

- CRYPTO-01 (L3): All PQ primitives via @paramant/core. ML-KEM-768
  (FIPS 203) for KEM, ML-DSA-65 (FIPS 204) for signatures.
- CRYPTO-02 (L3): No silent downgrade to classical-only crypto. Hybrid
  (PQ + ECDH) is permitted; classical-alone is never a fallback that
  weakens the PQ guarantee.
- CRYPTO-03 (L3): Private signing keys are generated and held
  client-side. Only document hash + signature + public key cross the
  wire for signing.
- CRYPTO-04 (L3): CSPRNG only for all key/nonce/salt generation.
- CRYPTO-05 (L2): Crypto library is vendored and version-pinned. No
  runtime fetch of crypto code.

## V7 - Error handling and logging (L2)

- LOG-01 (L2): No PII in logs. Never log API keys, filenames,
  recipient identifiers, document content, or TOTP codes.
- LOG-02 (L2): No stack traces or internal detail returned to clients.
- LOG-03 (L3): Every admin action is recorded to the CT log with a
  descriptor (what + when), per the transparency commitment.
- LOG-04 (L2): Security events (auth failure, lockout, admin action)
  are logged with enough context for incident response, minus PII.

## V8 - Data protection and privacy (L2/L3)

- DATA-01 (L3): Transferred file content and ParaSign document
  plaintext are RAM-only, never written to disk, burned on read.
- DATA-02 (L2): The only persistent state (users.json) is backed up
  age-encrypted; the backup private key lives offline, off-server.
- DATA-03 (L2): Data minimization. Collect and retain the minimum;
  no metadata retention beyond operational necessity.
- DATA-04 (L2): Sensitive files (users.json, .env, keys) are never
  web-reachable. Confirmed 403/404, never 200.

## V9 - Communications (L2/L3)

- COMM-01 (L2): TLS 1.2+ only (prefer 1.3). HSTS with includeSubDomains
  and preload.
- COMM-02 (L2): Strict CSP: no unsafe-eval; script-src self plus
  vendored bundles only; explicit connect-src allowlist.
- COMM-03 (L3): Admin transport additionally protected by network
  isolation (VPN / IP allowlist) and optionally mTLS client certs.
- COMM-04 (L2): Security headers present: HSTS, CSP, X-Content-Type-
  Options, X-Frame-Options (or frame-ancestors), Referrer-Policy.

## V10 - Malicious code and supply chain (L2/L3)

- SUP-01 (L2): All dependencies version-pinned. No floating ranges in
  production builds.
- SUP-02 (L3): Release artifacts (Docker images) are cosign-signed;
  consumers verify signatures.
- SUP-03 (L2): An SBOM is produced per release.
- SUP-04 (L2): Browser-shipped third-party code is vendored and
  reviewed, not pulled from a CDN at runtime.

## V11 - Business logic (L2)

- BL-01 (L2): Rate limits on all state-changing and resource-intensive
  endpoints (send, sign, auth).
- BL-02 (L2): Anti-automation on account creation and signing to
  prevent abuse.

## V12 - Files and resources (L2)

- FILE-01 (L2): Upload size limits enforced server-side. ParaShare
  fixed 5 MB padding maintained.
- FILE-02 (L2): No path traversal in any file or static handler.

## V13 - API security (L2/L3)

- API-01 (L2): Every API endpoint validates its request schema.
- API-02 (L3): Admin API endpoints reject any request lacking valid
  ADMIN_TOKEN + TOTP, returning 401/403, never the resource.
- API-03 (L2): API responses set Content-Type explicitly; no MIME
  sniffing exposure.

## V14 - Configuration (L2/L3)

- CFG-01 (L3): The setup wizard (/setup) is not publicly usable after
  first-run. Gated by a one-time setup token or disabled once the relay
  is provisioned.
- CFG-02 (L2): Secrets are injected via environment / mounted files,
  never committed, never in client-delivered code.
- CFG-03 (L2): Default credentials do not exist. First-run forces
  unique ADMIN_TOKEN + TOTP enrollment.
- CFG-04 (L2): Verbose errors, debug modes, and directory listing are
  disabled in production.

## Paramant-specific controls

- PQ-01 (L3): The product never serves a configuration that silently
  removes post-quantum protection. Capability negotiation is explicit
  and logged.
- SOV-01 (L2): Infrastructure remains EU-jurisdiction. No data path
  through US-CLOUD-Act-subject entities.
- TRANS-01 (L3): Every Paramant-side action against a customer relay is
  visible in that customer's CT log (what + when), per open-core trust.

## Verification cadence

- Per PR: the four non-negotiable rules + any controls the PR touches.
- Per release: full COMPLIANCE-CHECKLIST.md run, threat model review.
- Annually or on major change: external pentest (e.g. Cure53).
