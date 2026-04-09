# Changelog

All notable changes to PARAMANT Ghost Pipe are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.3.3] — 2026-04-09

### Security

- **DNS rebinding defense in webhook fire** — `pushWebhooks()` only checked the webhook URL at registration time (`isSsrfSafeUrl()`). An attacker could register a domain pointing to a public IP (passes the SSRF check), wait for the DNS TTL to expire, then switch DNS to a private/RFC1918/cloud-metadata address. On the next blob upload the relay would fire a webhook to the now-private IP — bypassing the SSRF guard entirely. Fixed: `pushWebhooks()` is now `async` and resolves the hostname via `dns.lookup()` immediately before each outbound request, then re-verifies the resolved IP with `isSsrfSafeUrl()`. Requests that resolve to private addresses are blocked and logged as `webhook_dns_rebinding_blocked`. Applied to all 7 relay files.

- **Version disclosure via response header removed** — Every relay response included `X-Paramant-Version: 2.x.x`. This gives attackers an exact version fingerprint to target known vulnerabilities without needing to probe. Header removed from all relay responses (`setHeaders()`). Version is still returned in the `/health` endpoint JSON body (required by SDK) and in Prometheus metrics (admin-only). Applied to all 7 relay files.

- **Google Fonts CDN removed from ParaDrop** — `drop.html` loaded `fonts.googleapis.com` and `fonts.gstatic.com` on page load, leaking user IP addresses and timing to Google. Removed. Replaced with system font stack (`system-ui, -apple-system, 'Segoe UI', sans-serif` for sans; `'Courier New', 'Menlo', monospace` for mono).

- **Docker container hardening** — All relay containers now run with `no-new-privileges: true` and `cap_drop: ALL`. No Linux capabilities are required by the relay process (ports are > 1024; no raw sockets; no filesystem privilege). Nginx retains only `NET_BIND_SERVICE`, `CHOWN`, `DAC_OVERRIDE`, `SETUID`, `SETGID`. Containers run with a `read_only: true` root filesystem with a 64 MB `tmpfs` mount for `/tmp`. Memory limits applied: 1500m per relay, 256m for admin, 128m for nginx.

- **Docker image pinned from floating `:latest`** — `docker-compose.yml` used `mtty001/relay:latest`. A supply-chain compromise of the Docker Hub account would silently deliver malicious code on next `docker compose pull`. Image pinned to `mtty001/relay:2.3.3`.

- **Multi-stage Dockerfile — build tools removed from production image** — `python3`, `make`, `g++` (required to compile `argon2` native bindings) were present in the final runtime image. A container escape could leverage these to compile and execute arbitrary native code. Fixed with a two-stage build: stage 1 compiles with build tools, stage 2 is the lean runtime image with only compiled `node_modules` and `relay.js` — no compilers.

- **nginx hardening (self-hosting)** — `nginx-selfhost.conf` updated:
  - `server_tokens off` — hides nginx version from error pages and `Server:` header
  - `ssl_session_tickets off` — forward secrecy: disables TLS session ticket resumption
  - `ssl_stapling on` + `ssl_stapling_verify on` — OCSP stapling reduces revocation check latency
  - HSTS upgraded: `max-age=63072000; includeSubDomains; preload` (was 1-year, no subdomains, no preload)
  - `ssl_ciphers` tightened to ECDHE + AES-GCM + ChaCha20 only; removed weak `HIGH:!aNULL:!MD5`
  - `proxy_hide_header Server; proxy_hide_header X-Powered-By` — removes upstream version strings
  - `X-Permitted-Cross-Domain-Policies: none` added
  - `Referrer-Policy: no-referrer` + `Permissions-Policy` added
  - `client_max_body_size 35M` — prevents nginx from accepting oversized requests upstream
  - `client_header_timeout 10s` / `client_body_timeout 60s` / `send_timeout 30s` — slowloris mitigation
  - Rate limiting added to: `/v2/pubkey` (20/min), `/v2/did` (20/min), `/v2/admin` (10/min), `/v2/mfa` (10/min, brute-force guard)
  - Dedicated `pubkey` and `auth` rate limit zones added
  - Access logging re-enabled with minimal format (IP, timestamp, method+host+path, status, size, response time — **no query string to prevent API key logging**)
  - `max_fails=3 fail_timeout=10s` on upstream servers — relay is marked unhealthy after 3 failures

- **package.json version mismatch fixed** — `relay/package.json` reported `"version": "5.0.0"` while the actual release is v2.3.3. Fixed.

### Changed

- **Relay version** — all relay files updated from `2.3.2` → `2.3.3`.

---

## [2.3.2] — 2026-04-09

### Security

- **P1 — RAM admission TOCTOU on `/v2/inbound` and `/v2/drop/create`** (reported by Raymond Zwarts)  
  `ramOk()` was evaluated before `readBody()`. Under concurrent load, all requests could pass the RAM gate simultaneously, then all allocate large buffers — bypassing the capacity guard. Fixed by incrementing `inFlightInbound` atomically (Node.js single-threaded guarantee) immediately after `ramOk()` passes and before `await readBody()`, with `finally { inFlightInbound-- }`. `ramOk()` and `ramStatus()` now account for in-flight allocations in both blob count and RSS projection.

- **P2 — Download handlers duplicated blobs in RAM** (reported by Raymond Zwarts)  
  All download, outbound, and drop/pickup handlers called `Buffer.from(entry.blob)`, creating a full copy of the blob before sending — doubling peak RAM per download. Fixed across all relay files: handlers now use the buffer reference directly and zero it in the `res.end()` callback after the TCP stack has flushed the data. No second allocation, zero-on-flush guaranteed.  
  Affected paths: `/v2/dl/:token/get`, `/v2/outbound/:hash`, `/v2/drop/pickup` in `relay-health.js`, `relay-legal.js`, `relay-finance.js`, `relay-iot.js`, `ghost-pipe-relay.js`, `relay.js`.

- **P3 — Pubkeys Map unbounded — no TTL, no per-key device cap** (reported by Raymond Zwarts)  
  `POST /v2/pubkey` stored entries without expiry. A free user could register unlimited device IDs, growing the in-memory Map indefinitely. Fixed with per-plan device limits (free: 5, pro: 50, enterprise: unlimited) and TTL-based expiry (free: 7 days, pro: 30 days, enterprise: 1 year). Invite-session pubkeys expire after 1 hour. Expired entries are evicted lazily on `GET /v2/pubkey` and swept hourly by the TTL flush interval.

- **P4 — SSRF via webhook URL registration** (reported by Raymond Zwarts)  
  `POST /v2/webhook` accepted any URL without validation. The relay fires outbound HTTP POSTs to stored webhook URLs when blobs are uploaded — a paid user could register an internal URL (e.g. `http://169.254.169.254/`, `http://10.x.x.x/`) to probe internal services from the relay's network. Fixed with `isSsrfSafeUrl()` guard applied at both registration (HTTP 400 on private URLs) and fire time (skip + log). Only public `https:` URLs are accepted. Blocked: loopback, link-local, RFC1918, IPv6 ULA, cloud metadata, `.local`/`.internal`/`.localhost` TLDs.

---

## [2.3.1] — 2026-04-09

### Fixed

- **CT log persistence** — `ctLog` was RAM-only; survives relay restarts now. Loaded from `CT_LOG_FILE` (default `/data/ct-log.json`) on startup, written on every registration. For systemd deployments set `CT_LOG_FILE` in the service env file.
- **Key revoke persistence on health relay** — `relay-health.js` revoke only set `active = false` in memory; did not write to `users.json`. After restart, revoked keys would come back active. Now persisted identically to other sector relays.
- **Admin auth on sector relays** — `relay-legal`, `relay-finance`, `relay-iot` only accepted API keys from the `apiKeys` map on admin endpoints (keys, revoke, create, send-welcome). `ADMIN_TOKEN` was rejected with 401. Fixed to accept `ADMIN_TOKEN` or enterprise key, matching `relay-health` behaviour.
- **`/keys/all/revoke` silent success** — always returned `ok: true` even when all sector revokes failed. Now returns `ok: false` (HTTP 502) if no sector successfully revoked the key.
- **Duplicate CT log route** — dead `/v2/ct/log` and `/v2/ct/proof/:index` handlers in authenticated section of `relay-health.js` removed (unreachable; public handlers above returned early).
- **CT log persistence in `ghost-pipe-relay.js` and `relay-sector.js`** — `ctAppend()` was RAM-only in both files. Now uses NDJSON append + startup load, identical to canonical `relay.js`.
- **Admin auth in `relay-sector.js`** — same `!apiKeys.has(tok)` bug as legal/finance/iot; fixed to accept `ADMIN_TOKEN` or enterprise key.
- **Systemd service templates missing env vars** — `paramant-relay-{health,legal,finance,iot}.service` lacked `PORT`, `SECTOR`, `ADMIN_TOKEN`, `USERS_FILE`. Without these, relays all started on port 4000, admin auth was broken, and CT log was not persisted. Fixed with correct values per sector.
- **Admin panel absent from Docker self-hosting stack** — `docker-compose.yml` had no `admin` service; nginx proxied `/admin/` to an unresolvable hostname (`admin:4200`), causing nginx to fail. Admin service added with Docker-native relay URLs.
- **Relay ports not accessible to `paramant` CLI** — relay containers were in an `internal: true` network with no host port binding. `paramant status` and `paramant reload` silently returned empty responses. Added `127.0.0.1:PORT:PORT` bindings (localhost only, not publicly exposed).
- **`paramant-admin.py` used `revoked` key instead of `revoked_at`** — inconsistent with relay schema; fixed to `revoked_at`.
- **`install.sh` cloned `v2.2.0`** — pinned version updated to `v2.3.1`.
- **Self-hosting docs** — version updated to v2.3.1; container count corrected (5→6); admin login docs updated (enterprise key → ADMIN_TOKEN or enterprise key); IP restriction moved to inline nginx example.

---

## [2.3.0] — 2026-04-09

### Added

- **Admin panel** (`/admin/`) — Express-based SPA replacing static r34ct0r admin. Docker container on port 4200, accessible via nginx proxy. Full English UI.
- **Cross-sector key management** — `GET/POST /api/keys/all` and `POST /api/keys/all/revoke` to manage keys across all 4 sectors simultaneously. Partial-failure response (HTTP 207) clearly lists which sectors failed.
- **`LOG_LEVEL` env var** — relay accepts `debug | info | warn | error` (default: `info`). Reduces stdout noise on high-traffic deployments.
- **Thunderbird FileLink add-on** — `thunderbird-filelink/` added to repo under AGPL-3.0; automated release workflow via GitHub Actions.

### Security

- **CSP + security headers on admin** — `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options: DENY` added to all admin responses.
- **`/keys/all` partial-failure visibility** — endpoint now returns HTTP 207 with a `failed[]` array if any sector rejects key creation. Previously returned `ok: true` even when 3/4 sectors failed silently.

### Fixed

- **SHA3-256 correctly labelled** — CT log section on website and docs crypto table now show `SHA3-256` (Merkle chain, DID hashes, PSS commitments). Was incorrectly listed as SHA-256.
- **Healthchecks** — added to `relay-legal`, `relay-finance`, `relay-iot` containers in `docker-compose.yml`. Only `relay-health` had one.
- **Node image pinned** — `relay/Dockerfile` and `admin/Dockerfile` now use `node:20-alpine3.21` instead of floating `node:20-alpine`.
- **Let's Encrypt renewal hook** — hook script now uses `$INSTALL_DIR` baked in at install time instead of hardcoded `/opt/paramant`. Fixes renewal for non-default install paths.
- **nginx certs volume** — `paramant-certs` mounted as `:ro` on nginx container; was writable.
- **JSON body limit** — admin server increased from `32kb` to `1mb`; previously silently dropped bulk key operation payloads.
- **GitHub Actions** — `actions/checkout@v6` (non-existent) → `@v4`; Node.js 20 → 22 in filelink workflow; Docker `latest` tag now only published on `main` branch and version tags, not on every push.
- **Duplicate relay stack cleanup** — Docker relay containers stopped and removed. Single relay stack now runs under systemd; admin container in Docker only.
- **All `r34ct0r` references** — replaced with `/admin/` across nginx configs, docs, and frontend.
- **Admin UI fully in English** — all Dutch strings translated (modals, error messages, status labels, placeholders).

### Changed

- **Icons in self-hosting section** — generic emoji (🍎 📥 📄) replaced with mono symbols: `π` (Raspberry Pi), `⬡` (Docker), `>_` (Linux/VPS).
- **Relay cleanup logging** — download token GC now logs removed count at `debug` level instead of being silent.

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
