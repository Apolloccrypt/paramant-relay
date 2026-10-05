# Live production + documentation audit -- paramant.app

Generated: 2026-05-27T21:15:34+02:00
Target: paramant.app (edge) + sector relays (health/finance/legal/iot.paramant.app), origin 116.203.86.81
Codebase HEAD: ca70d17 (origin/main, branch docs/site-audit)
Method: read-only unauthenticated HTTP, >=1.2s between requests, no auth endpoints, no probes/scans.

---

## Executive summary

Production is healthy and well-hardened on the basics (TLS, HSTS preload, X-Frame-Options,
X-Content-Type-Options, a real per-page CSP, signed STH, RFC 9116 security.txt). No CRITICAL
issues found. The dominant theme is **deploy drift**: production runs build `2.5.0` while
`main` is `3.0.0`, so several "current" features (R006 crypto-mode opt-in, the `@paramant/core`
attribution in docs) are simply not live yet -- expected during the M5b soak, but it means
the public surface does not match the repo. On top of that sit a handful of genuine,
fixable issues, the sharpest being a **placeholder PGP key** advertised in security.txt and
a few **external US-origin asset loads** (Google Fonts, jsDelivr) that contradict the
EU-sovereignty / no-external-calls positioning.

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 7 |
| LOW | 8 |
| INFO / passed | see section 9 |

### Top findings
- M-03  security.txt advertises an Encryption key that is a literal PLACEHOLDER -- sensitive reports cannot be encrypted.
- M-01  Production build 2.5.0 lags main 3.0.0; R006 + @paramant/core docs not deployed.
- M-02  /v2/capabilities advertises all 21 algorithms loaded (pre-R006); accepted ADR R006 default is core-only.
- M-04  /v2/relays registry is empty (total:0) despite 5 sector relays running.
- M-05  admin.html (public) hotlinks Google Fonts (fonts.googleapis.com / gstatic.com).
- M-06  /parashare loads 3 earth-texture images from cdn.jsdelivr.net (US CDN).
- M-07  Live /docs does not document paramant-core / @paramant/core (M5b's core change).

---

## 1. Public endpoint reachability

All probed read-only, unauthenticated, against https://paramant.app.

| Endpoint | Status | Size | Note |
|---|---|---|---|
| /health | 200 | 163B | version 2.5.0 (see M-01) |
| /v2/capabilities | 200 | 1252B | 3 KEM + 18 SIG, all loaded (see M-02) |
| /v2/relays | 200 | 55B | empty registry (see M-04) |
| /v2/sth | 200 | 4618B | signed STH, ML-DSA-65, tree_size 66 (OK) |
| /v2/pubkey | 200 | 2726B | OK |
| /v2/ct/log | 200 | 14903B | OK |
| /v2/status | 401 | 55B | correctly rejects without auth (OK) |
| /ct-log | 200 | 36953B | HTML viewer OK |
| /robots.txt | 200 | 141B | OK, sitemap ref valid |
| /sitemap.xml | 200 | 7438B | present (OK) |
| /.well-known/security.txt | 200 | 788B | RFC 9116 (see M-03, L-07) |
| /.well-known/openpgp-key.asc | 200 | 344B | PLACEHOLDER (see M-03) |

Cross-check against `health.paramant.app`: identical /health and /v2/capabilities payloads
(same build deployed across sectors). Edge is Caddy (`via: 1.1 Caddy`) in front of nginx.

---

## 2. Findings (MEDIUM)

### M-01  Production (2.5.0) lags main (3.0.0) -- "current" features not live
- Evidence: prod `/health` -> `"version":"2.5.0"`; codebase `relay/relay.js` `const VERSION = '3.0.0'`, root `package.json` 3.0.0. `/health` sources `version: VERSION`, so prod is running pre-3.0.0 code.
- Impact: R006 crypto-mode, `@paramant/core` server-side ML-DSA-65 attribution, and other main-only changes are not on the live site. The repo is not a faithful description of production.
- Severity: MEDIUM (expected during the M5b soak, but undocumented to a reader comparing site to repo).
- Suggested fix: add a short "deployed build vs main" note to the status page / docs, or finish the M5b deploy. Track the soak exit explicitly.

### M-02  /v2/capabilities advertises all 21 algorithms as loaded (pre-R006)
- Evidence: live `/v2/capabilities` -> kem: ML-KEM-512/768/1024 (3), sig: none, ML-DSA-44/65/87, Falcon-512/1024, 12x SLH-DSA (18) -- every entry `"loaded":true`.
- Codebase reality: ADR R006 (Status: Accepted) + `relay/crypto/bootstrap.js` default `CRYPTO_MODE=core` registers ML-KEM-768 + ML-DSA-65 only; extended mode (all 18) is opt-in.
- Impact: production still loads/advertises the full algorithm set -- larger advertised surface than the accepted design; consistent with M-01 (R006 not deployed).
- Severity: MEDIUM. Suggested fix: ships with the 3.0.0 deploy; confirm core mode is the production default afterwards.

### M-03  security.txt Encryption key is a placeholder
- Evidence: `/.well-known/security.txt` has `Encryption: https://paramant.app/.well-known/openpgp-key.asc`. That file (200, 344B) contains: `[PLACEHOLDER -- GENERATE REAL KEY AND REPLACE]` and `Comment: real key will be published before 2026-06-01`.
- Impact: a researcher who follows the advertised channel cannot encrypt a sensitive vulnerability report. For a product whose entire value proposition is post-quantum crypto, publishing a placeholder PGP key in a signed RFC 9116 file is a credibility and confidentiality gap. Plaintext email fallback (privacy@paramant.app) still works.
- Severity: MEDIUM (treat as high-priority given the product domain; self-imposed deadline is 2026-06-01, 5 days out).
- Suggested fix: generate and publish the real Security Team key (or drop the Encryption line until it exists). Do NOT edit SECURITY.md disclosure policy -- only the key asset.

### M-04  /v2/relays public registry is empty despite 5 live relays
- Evidence: live `/v2/relays` -> `{"ok":true,"relays":[],"total":0,...}`. Yet health/finance/legal/iot.paramant.app + main all answer /health.
- Codebase: relays self-register on boot by signing a payload and POSTing to `RELAY_PRIMARY_URL` (see docs/self-hosting relay-registry section). The CT-log viewer has a "Registered Relays" tab driven by this.
- Impact: the public relay-transparency feature shows zero relays; "Registered Relays" tab is empty. Either self-registration is disabled/unset in prod env, or the registration is not persisting.
- Severity: MEDIUM (transparency feature non-functional, no security impact).
- Suggested fix: verify `RELAY_SELF_URL` / `RELAY_PRIMARY_URL` env on each container; confirm registration POST succeeds and persists.

### M-05  admin.html (publicly reachable) hotlinks Google Fonts
- Evidence: `/admin.html` -> 200. `frontend/admin.html` lines 8-10: `preconnect` to fonts.googleapis.com + fonts.gstatic.com and `<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono...&family=Inter...">`.
- Impact: loading the admin panel sends the operator's IP / request to Google (US). This contradicts the EU-data-sovereignty / no-external-calls positioning and is a known GDPR exposure (German case law on Google Fonts hotlinking). The rest of the site uses self-hosted / system fonts.
- Severity: MEDIUM. Suggested fix: self-host Inter + IBM Plex Mono (already the site's typefaces) and remove the three Google links; tighten CSP afterwards (see L-02).

### M-06  /parashare loads earth textures from cdn.jsdelivr.net (US CDN)
- Evidence: live `/parashare` references `https://cdn.jsdelivr.net/npm/three-globe/example/img/{earth-night.jpg,earth-topology.png,night-sky.png}` (globe.gl visualization).
- Impact: a visitor's browser fetches three image assets from a US/Cloudflare-fronted CDN -- external runtime dependency and a privacy/sovereignty inconsistency for an EU-positioned product. If jsDelivr is unreachable the globe degrades.
- Severity: MEDIUM. Suggested fix: vendor the three textures under /assets and point three-globe at the local copies.

### M-07  Live /docs does not document paramant-core / @paramant/core
- Evidence: live `/docs` grep -- present: ML-KEM-768, ML-DSA-65, AES-256-GCM, Ghost Pipe, ParaShare, ParaDrop *(ParaDrop has since been removed as a feature, PRs #150-152)*. MISSING: `paramant-core`, `@paramant/core`, `CRYPTO_MODE`.
- Impact: the M5b architectural change (server-side ML-DSA-65 provided by the paramant-core Rust NAPI binding) is invisible to users/auditors on the live docs. Partly an artefact of M-01 (prod 2.5.0) and the docs PR not being deployed.
- Severity: MEDIUM. Suggested fix: deploy the docs update (a prior branch already adds the crypto-stack attribution); add a short CRYPTO_MODE note once R006 is live.

---

## 3. Findings (LOW)

### L-01  HSTS header sent three times
- Evidence: `/` and `/docs` responses include `strict-transport-security: max-age=63072000; includeSubDomains; preload` repeated 3x.
- Impact: harmless to browsers (first wins) but sloppy; some scanners flag duplicate security headers. Likely Caddy + nginx + relay each add it.
- Fix: set HSTS at exactly one layer (the Caddy edge).

### L-02  CSP is broader than actual usage
- Evidence: site-wide CSP allows `style-src ... https://fonts.googleapis.com`, `font-src https://fonts.gstatic.com`, `img-src ... https://cdn.jsdelivr.net https://server.arcgisonline.com`. Only admin.html uses Google Fonts and only /parashare uses jsDelivr; `server.arcgisonline.com` is used by no frontend file (dead whitelist entry).
- Impact: least-privilege violation; whitelisted US origins enlarge the trusted set unnecessarily.
- Fix: after M-05/M-06 self-hosting, drop googleapis/gstatic/jsdelivr/arcgisonline from CSP.

### L-03  Version sprawl across manifests
- Evidence: root `package.json` 3.0.0, `relay/package.json` 2.5.0, `sdk-js/package.json` 3.1.0; `/health` reports relay.js const 3.0.0; npm `paramant-sdk` 3.0.0, PyPI `paramant-sdk` 3.0.0.
- Impact: `relay/package.json` (2.5.0) is stale next to the 3.0.0 VERSION const it ships with; sdk-js local (3.1.0) is ahead of the published 3.0.0. Confusing provenance.
- Fix: reconcile manifest versions to a single source of truth per package.

### L-04  R009 (deprecate ParamantOS) not reflected in the repo
- Evidence: ADR R009 Status: Accepted. `Apolloccrypt/ParamantOS` is `isArchived:false`, last push 2026-04-19, description still "hardened NixOS for relay operators" with no deprecation notice.
- Impact: an accepted deprecation decision is not visible to anyone landing on the repo.
- Fix: add a deprecation banner to the ParamantOS README and/or archive it; link R009.

### L-05  security.txt Hiring link is 404
- Evidence: security.txt `Hiring: https://paramant.app/careers` -> 404. (`/security` and `/security/acknowledgements` both 200.)
- Fix: create /careers or remove the Hiring line.

### L-06  @paramant/core not published to npm
- Evidence: `npm view @paramant/core` -> 404. Relay consumes it via `file:../../paramant-core/crates/paramant-core-node`. No doc instructs `npm install @paramant/core`, so nothing breaks.
- Impact: the "standalone, audit-ready library" framing is weakened -- the binding is not independently installable/auditable from npm; auditors must clone paramant-core.
- Fix (optional): publish the node binding, or state explicitly it is built from source in the relay image.

### L-07  robots.txt disallows /.well-known/
- Evidence: robots.txt `Disallow: /.well-known/`. security.txt lives there.
- Impact: cosmetic -- direct access works and security.txt is found by tooling, but blocking crawlers from the well-known path is unusual.
- Fix: allow /.well-known/ (or at least security.txt).

### L-08  CSP script-src allows 'unsafe-inline'
- Evidence: CSP `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'`.
- Impact: weakens XSS defense-in-depth; required today because pages (dashboard, etc.) use inline scripts.
- Fix (longer term): move inline scripts to /js/ files and drop 'unsafe-inline' (mirrors the mickbeer.com hardening).

---

## 9. Passed / positive (evidence of good hygiene)

- TLS HTTP/2, `strict-transport-security: max-age=63072000; includeSubDomains; preload`.
- `x-frame-options: DENY`, `x-content-type-options: nosniff`, `referrer-policy: no-referrer`, `permissions-policy` present.
- Real per-page CSP with `default-src 'self'` and explicit relay connect-src (wss + https).
- `/v2/status` correctly returns 401 unauthenticated.
- `/v2/sth` returns a properly signed STH (keys: relay_id, sha3_root, signature, timestamp, tree_size, version; tree_size 66).
- security.txt is valid RFC 9116 (Contact, Expires 2027-04-19, Canonical, Policy, Preferred-Languages), /security and acknowledgements pages resolve.
- sitemap.xml present and correctly referenced from robots.txt.
- paramant-sdk published on both npm (3.0.0) and PyPI (3.0.0), versions agree with each other.
- No false marketing claims found on the landing page (no "2 minutes", "5 relays", "100 users" claims to contradict).

---

## Notes on method and scope

- All HTTP was read-only GET/HEAD, unauthenticated, >=1.2s apart; no auth endpoints, no fuzzing/probing.
- Severity reflects honest impact, not the brief's pre-filled guesses; the brief's "self-hostable in 2 minutes" and "5 relays" claim-checks were dropped because the landing page makes no such claims.
- Within the audit safety boundaries: this report observes the security disclosure channel (M-03) but proposes only replacing the key asset, not editing SECURITY.md policy.
