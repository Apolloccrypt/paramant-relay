# Changelog

All notable changes to PARAMANT Ghost Pipe are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.2.1] — 2026-04-08

Security patch release. All findings from internal penetration test (2026-04-08).

### Security

- **[MEDIUM — Fix #1]** Argon2 async race condition on `/v2/outbound/:hash`  
  Added `_verifying` in-flight guard before `await argon2Lib.verify()`. Two concurrent requests on a password-protected blob with `max_views ≥ 2` could both receive the blob during the ~200–800ms KDF window. Guard returns 429 to the second request.

- **[MEDIUM — Fix #2]** `/health` endpoint leaked operational intelligence  
  Public response now returns only `{ok, version, sector}`. Fields `blobs`, `uptime_s`, `available_slots`, `edition` are now only visible to requests authenticated with `X-Admin-Token`.

- **[MEDIUM — Fix #3]** `X-Paramant-Views-Left` response header leaked view count  
  Header removed from all `/v2/outbound` responses. `X-Paramant-Burned` is retained (receiver needs it).

- **[MEDIUM — Fix #4]** Free-tier rate limit already enforced per-key (confirmed)  
  `checkFreeRateLimit()` tracks per-API-key upload counts server-side. IP rotation does not bypass the limit. No code change required; confirmed during audit.

- **[MEDIUM — Fix #5]** `/v2/ct/proof?index=N` returned 401 instead of Merkle proof  
  Route handler now accepts both `/v2/ct/proof/:N` (path param) and `/v2/ct/proof?index=N` (query string) without authentication. Both forms return the same public Merkle proof.

- **[LOW — Fix #6]** Stale `paramant-ghost-pipe.fly.dev` removed from CSP `connect-src`  
  Domain was not present in the active CSP; confirmed clean. `unsafe-inline` in `script-src` documented as known limitation of the static-site deployment model.

### Fixed

- **ParaDrop receiver stuck at "waiting for sender to verify fingerprint"**  
  `pollTransfer` callback passed local variables `kyberSec` / `ecdhPair.privateKey` to `receiveFile`. These variables are undefined in the sessionStorage-restore code path, causing a silent ReferenceError. Fixed to use module-level `myPrivateKey_MLKEM` / `myPrivateKey_ECDH` which are set in both fresh-generate and restore paths.

- **ParaDrop fingerprint mismatch on receiver page refresh**  
  Receiver now persists ML-KEM-768 + ECDH P-256 keypair in `sessionStorage` keyed by session token (`paramant_kp_<token>`). Survives refresh; first-registration-wins no longer blocks re-registration with a different keypair.

---

## [2.2.0] — 2026-04-08

### Added

- **Self-hosted relay** — single-binary Node.js relay with systemd unit, zero external dependencies
- **Zero-downtime config reload** — `POST /v2/reload-users` with `X-Admin-Token` hot-reloads `users.json` without restart
- **ParaDrop PWA** — installable on iOS/Android/desktop via `manifest.json` and service worker
- **Sector relay architecture** — separate relay instances per sector (`health`, `legal`, `finance`, `iot`) with independent `users.json`
- **`install.sh`** — one-command self-hosted setup for Debian/Ubuntu
- **ParaShare** — persistent session links for recurring secure transfers
- **CT log persistence** — Merkle hash chain persisted to `ct-log.json` across restarts

### Changed

- **`X-Paramant-Views-Left` header** — now removed in v2.2.1 (see Security above)
- Relay now enforces per-key upload limits server-side (`checkFreeRateLimit`)

---

## [2.1.0] — 2026-04-07

### Security

- **Argon2id password protection** — optional password on blobs, KDF with 19MB memory cost
- **Key zeroization** — `zeroBuffer()` called on blob memory after burn-on-read
- **BIP39 mnemonic drop** — session mnemonics removed; replaced with cryptographically random `inv_` tokens (128-bit entropy)
- **Cloudflare removed** — relay now served directly from Hetzner DE; no third-party TLS termination

### Added

- **ML-DSA-65 (NIST FIPS 204)** — post-quantum signatures for blob attestation (optional, falls back to ECDSA P-256)
- **DID registry** — `POST /v2/did` for decentralised identity document anchoring
- **Attestation endpoint** — `POST /v2/attest` for device attestation verification
- **Vault mode** — multi-file encrypted transfers in a single session
- **Admin key management** — `POST /v2/admin/keys`, `POST /v2/admin/keys/revoke`
- **Stripe webhook** — `POST /admin/stripe-webhook` for plan provisioning

### Fixed

- Admin endpoints now correctly reject unauthenticated requests with 401/403 (no information leak in error body)

---

## [2.0.0] — 2026-04-06

### Added

- **ML-KEM-768 (NIST FIPS 203)** — post-quantum key encapsulation replaces RSA/classic-only KEM
- **PQHB v1 wire format** — `MAGIC + VER + salt + iv + tag + eph_pub + ciphertext`; 20MB fixed-size padding for DPI masking
- **Burn-on-read** — blobs deleted from RAM immediately after first download (or after `max_views` exhausted)
- **First-registration-wins pubkey policy** — relay rejects pubkey overwrites for active sessions
- **Ghost Pipe protocol v2** — two-party encrypted transfer: receiver registers pubkey, sender fetches it, encrypts, uploads; receiver polls and decrypts
- **ParaDrop** — browser-based drag-and-drop encrypted transfer UI

### Security

- All payloads encrypted with hybrid ML-KEM-768 + ECDH P-256 + AES-256-GCM
- Zero plaintext stored on relay — only ciphertext, never decrypted server-side
- Session tokens: 128-bit random (`crypto.getRandomValues`), not enumerable

---

[2.2.1]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Apolloccrypt/paramant-relay/releases/tag/v2.0.0
