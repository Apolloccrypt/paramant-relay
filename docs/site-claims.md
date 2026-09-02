# Site claims: what the pages say, and which test fails when it stops being true

Inventory taken on 2 September 2026 on `origin/main` after PR #323 (the seventeen
norm and sector pages are gone). Every factual claim on the 38 public pages under
`frontend/`, with the test that pins it or the word UNCOVERED.

The rule from the pruning plan: a page may only exist if a test fails when the
page lies. The ten heaviest claims are pinned in `tests/site-claims.test.mjs`
(the numbered tests below). The rest of this table is the follow-up work.

Pages not in scope: everything behind a login or in a one-shot flow
(`account`, `admin`, `dashboard`, `developer`, `co-sign`, `claim`, `get`,
`ontvang`, `request-key`, `setup`, `parashare`, `auth/*`, `billing/*`,
`signup/verified`, `404`, `all-systems-go`, `iot` redirect).

## Pinned in this PR

| # | Claim | Pages | Source in the code | Test |
|---|---|---|---|---|
| 1 | ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) are the parameter sets | index, about, security, pricing, press, sign, verify, privacy, dpa, architecture, audit-log-export, vs, crypto-agility | `relay/crypto/bootstrap.js` registers exactly these two in core mode; `impls/mlkem768.js`, `impls/mldsa65.js` carry the names | `site-claims.test.mjs` 1 |
| 2 | "The relay loads 3 KEMs and 18 signatures" | security, crypto-agility | `bootstrap.js` registers 3 KEMs and **17** signatures, only in `CRYPTO_MODE=extended`; `.env.example` documents `core` as the default. Text corrected to 17 and the mode caveat added. | `site-claims.test.mjs` 2 |
| 3 | AES-256-GCM, HKDF-SHA256, SHA3-256, PBKDF2-SHA256 | security, privacy, vault, sign, verify | `relay/lib/encryption.js` (`aes-256-gcm`), `crypto-wasm/src/lib.rs` (`Aes256Gcm`, `Hkdf::<Sha256>`), `relay/lib/ct-hash.js` (`sha3-256`), `frontend/sign-flow.js` (`sha3_256`), `frontend/vault.js` (PBKDF2 + AES-GCM 256) | `site-claims.test.mjs` 3 |
| 4 | 5 MB blocks / chunks / padding | privacy, security, vs | `relay/relay.js` `MAX_BLOB` default 5242880; `relay/lib/tiers.js` `file_mb: 5` | `site-claims.test.mjs` 4 |
| 5 | Link expiry 1 hour (Free), 24 hours (Pro), 7 days (Enterprise) | pricing, privacy | `relay/lib/tiers.js` `view_ttl_ms` | `site-claims.test.mjs` 5 |
| 6 | Sessions last one hour; TOTP codes expire after 30 s; login limited to 5 per IP and 10 per email per 15 minutes | security | `admin/server.js` cookie `Max-Age=3600`, `checkLoginRateLimit` (5 / 15 min), `/api/user/login` Redis counters (900 s, >5 IP, >10 email); `relay/lib/totp.js` step 30. The sentence "after ten consecutive failures an account locks for thirty minutes" had no code behind it and is removed. | `site-claims.test.mjs` 6 |
| 7 | Three external audits in April 2026, 40 findings, 4 critical | press, trust, dpa, docs | `/docs#audits` table (Zwarts 14 + 6, Williams 4C 5H 6M 5L); `docs/security-audit-2026-04.md` summary line. Press said "twenty findings across two audits, fully resolved before public release"; corrected to forty across three, and "fully resolved" dropped while the audit document still lists findings 4, 6 and 14 as in progress or open. Links from trust and dpa now point at the table that exists (`/security#audits` did not). | `site-claims.test.mjs` 7 |
| 8 | Uptime commitment 99.5 % / 99.95 %; how it is measured | sla, pricing | `sla.html` is the commitment; pricing quoted 99.9 % for Enterprise and now quotes 99.95 %. The measurement paragraph claimed a 60-second probe from multiple EU locations and uptime history in the CT log; neither exists. It now describes exactly what runs, which as of 2026-09-02 is `/status` and nothing else. The hourly end-to-end check is built (`.github/workflows/heartbeat.yml`, cron `17 * * * *`, `scripts/heartbeat/`) but its job is gated on the repository variable `HEARTBEAT_ENABLED` until `PARAMANT_CANARY_KEY` and `PARASIGN_CANARY_KEY` exist, so the page says it runs hourly *once enabled* and is switched off until then. **Before the rebuild the transfer and signature clauses were aspirational**: both canary suites skipped for want of a secret and reported green, and this row's test only checked that the workflow named them. Each clause is now pinned to the route that makes it true, and the gate is pinned in both directions, so setting `HEARTBEAT_ENABLED` fails this test until the paragraph is rewritten. The sector-relay sentence is pinned to `surface.mjs`: it must reach all four hosts for the ParaID deny check, and the page must say both that and that their uptime is not measured. `/status` (`frontend/js/status.inline1.js`) is the only thing that fetches `GET /health` on all five relays, from the visitor's browser. The test also ties "a run that fails opens an issue" to the `if: failure()` step that calls `issues.create`. | `site-claims.test.mjs` 8 |
| 9 | "IP logging: Nginx access logs, retention 7 days" | security | No log-rotation config in `deploy/`; `nginx-paramant-live.conf` has `access_log off` on every server block that serves the site or a relay (the last block, `127.0.0.1:8090`, only fronts the Outlook add-in). The row now says access logging is off in that configuration, and the retention number and "logs follow the server's log rotation" are gone. The test fails on any `access_log` that is not `off`. What the repository cannot show: whether the nginx on the server matches this file. SECURITY.md (server hardening) says the edge-facing config in `/etc/nginx/sites-enabled/` is not in git, and `deploy/nginx-paramant-public.conf` (older, Cloudflare-era) carries no `access_log` directive at all, which would mean nginx's default log. Settle on the machine (`scripts/check-prod-drift.sh` territory). | `site-claims.test.mjs` 9 |
| 10 | "10 encrypted CLI tools" | index | `admin/lib/developer-tools.js` catalogue has 10 entries | `site-claims.test.mjs` 10 |

## Already covered by an earlier test

| Claim | Pages | Test |
|---|---|---|
| Prices excl. VAT, checkout charges incl. 21 %, yearly discounts, all six checkout buttons resolve in the billing catalog, per-tier signature copy (2 / 100 then EUR 0.40 / 1,000) | pricing | `relay/test/pricing-page.test.js` |
| "No cap, no block" must not appear; no 5 MB file limit claim on pricing | pricing | `relay/test/pricing-page.test.js` |
| Open-mode signature is not a verified signer; not eIDAS-qualified; account requirement stated up front | sign | `tests/ui-truthfulness.test.mjs` |
| Account deactivation wording (what is and is not deleted) | account, admin, email templates | `tests/ui-truthfulness.test.mjs` |
| Title, description, canonical, Open Graph, one h1, JSON-LD on every public page; private pages noindex; sitemap matches disk; no sitemap URL behind a login redirect | all | `tests/seo-contract.test.mjs` |
| Every internal link resolves | all | `tests/links.test.mjs` |
| Site still functions in a browser (send, sign, verify) | index, sign, verify | `tests/product-heartbeat.test.mjs` (hourly, against production) |

## UNCOVERED: provable from the code, test still to write

| Claim | Pages | Where the truth lives |
|---|---|---|
| Signup / setup link works for 14 days | signup | `admin/server.js` `setup_token` `EX: 14 * 86400` |
| Signature image max 1 MB | sign | `frontend/sign-flow.js` line ~1864 |
| Up to 100 reads per link (Enterprise), unlimited devices | pricing | `relay/lib/tiers.js` `max_views`, `devices` |
| Signature quotas 2 / 100 / 1,000 per month match the code, not just the copy | pricing | `relay/lib/tiers.js` `signs_month` (pricing-page.test.js pins the copy only) |
| A TOTP code can be used exactly once, enforced atomically in Redis | security | `relay/lib/totp.js` `SET NX` replay guard; `relay/test/verify-totp.test.js` |
| CT log persists to `/data/ct-log.json` and survives restarts | ct-log | `docker-compose.yml` sets `CT_FILE`; `relay.js` treats it as opt-in (default RAM-only) |
| `verified_since` proves continuous relay identity | security | `relay/relay.js` ~481 to 495, ~3593 |
| Device IDs hashed with SHA3-256 in the CT log; filenames only as `enc_meta` ciphertext | dpa, privacy | `relay/lib/ct-hash.js`; relay `enc_meta` handling |
| Encrypted blobs live in process memory only, a restart destroys them | security, privacy, press, terms | `relay/relay.js` in-memory blob map; no disk write path |
| No tracking cookies, no fingerprinting, only a session cookie after login | privacy, pricing ("No tracking") | `frontend/*.html` carry no third-party script; `admin/server.js` sets one cookie |
| Status page: auto-refresh 30 s, last 24 h kept in the browser | status | `frontend/status.html` script |
| Sub-processors: Hetzner (DE), Resend (US, SCCs), Mollie | dpa, privacy | `admin/lib/email-templates.js`, `admin/lib/config-schema.js` (Resend); `relay/lib/mollie.js` |
| Five sector relays (main, health, legal, finance, iot) | sla, press, index | `admin/server.js` `SECTORS` |
| BUSL-1.1 converts to MIT on a fixed date | license, terms, footer | **Contradiction**: `LICENSE` and `deploy/LICENSE` say Change Date 2029-01-01, `frontend/license.html` and `terms.html` say 1 January 2030. One of them is wrong; decide, then pin. |
| "All resolved" in the `/docs#audits` table | docs | **Contradiction**: `docs/security-audit-2026-04.md` (last touched 15 April) still marks findings 4, 6 and 14 as in progress or open; the table (1 June) says all resolved with commits `e6f216d` / `0db3ef0`. Update whichever is stale, then pin. |
| Audit totals: 40 on the site, 50 in SECURITY.md | press, trust, dpa, docs | **Contradiction**: press, trust and the DPA are pinned to the `/docs#audits` table (three audits, 14 + 6 + 20 = 40 findings), and that table says "all findings are publicly documented in SECURITY.md". SECURITY.md lists four review sections: RAPTOR review 15 April (10), Zwarts verification 11 April (14), Zwarts independent 10 April (6), Williams (20), so 50 findings across four. Either the RAPTOR review belongs in the table (then press reads fifty across four) or SECURITY.md should say why it is left out. Decide, then pin the table to SECURITY.md. |
| sdk-py 3.0.0 / sdk-js 3.0.0 are the versions that encrypt client-side | security, architecture | SDK repos are outside this repository; pin via the published package version if wanted |

## UNCOVERED: not provable from the code; weaken or accept as policy

| Claim | Pages | Note |
|---|---|---|
| "ML-KEM-768 Level 3 in production since 2024" | vs | Repository history starts 1 April 2026 (`master sync: relay v2.0.0`); press kit says founded 2025. Weaken to "in production today". |
| Servers in Germany, Hetzner Nuremberg (NBG1), EU-only, no US CLOUD Act exposure, no CDN in front | index, press, privacy, dpa, sla, docs, security/acknowledgements | Infrastructure, not code. Provable only against the machine (`scripts/check-prod-drift.sh` territory). |
| "ParaShare transfers look identical (fixed 5 MB padding); an observer cannot infer file size" | security | Audit finding 5 (accepted trade-off) says chunk count leaks order of magnitude. Overclaim; weaken to "block size is fixed, chunk count is visible". |
| "Burned on read" as a universal property | index, press, pararules | `tiers.js` gives Pro 10 reads and Enterprise 100 per link; pricing says so. True for Free, not universal. |
| "All tiers meet NIS2 and GDPR requirements by design"; NEN 7510 / eIDAS / IEC 62443 mappings "ship with Pro and Enterprise"; "IEC 62443 / NIS2 / NEN 7510 documentation" | pricing | After PR #323 the norm pages are gone. The only artefact left is `docs/security/COMPLIANCE-CHECKLIST.md`. This is the largest remaining norm claim on the site. |
| Named support within one business day (Business); "published response targets" (Pro); press replies within 24 hours; complaints answered within fourteen days | pricing, press, terms, sla | Service commitments, not code. Keep only if someone will honour them. |
| Breach notification within 48 hours; 14 days notice for sub-processor changes; deletion within 30 days after termination | dpa | Contractual commitments. |
| Disclosure: acknowledgement within 48 hours, updates every 7 days, 90-day coordinated disclosure | security | Policy. |
| auditd (49 CIS L2 rules), AIDE daily, AppArmor enforcing, CIS Ubuntu 24.04 L2 (114 checks) | dpa | Host hardening; `docs/docker-hardening-2026-04-24.md` describes the container side only. |
| Binary sizes and SHA256 sums of the desktop builds; "March 2026 build" | download | `/dl/` is not in this repository. |
| "Load tested to 500 req/s: p95 135 ms"; "6-layer audit, 0 critical, 0 high" | changelog | Historical release notes; leave as history, do not repeat elsewhere. |
| Competitor facts (Zivver / Kiteworks, Tresorit / Swiss Post, WeTransfer / Bending Spoons, certifications) | vs | External sources cited on the page; verify on a schedule or date-stamp the page. |
| "Full NIST suite (FIPS 203, 204, 205, 206) loaded"; "runs the full NIST post-quantum suite today" | architecture, crypto-agility | Same fact as pinned claim 2 in other words; the default mode loads two algorithms. Reword to match security.html. |
| Chromium and Outlook extensions use a server-side encryption path; migration in progress | security, architecture, crypto-agility | Honest caveat about a weaker path. Keep, and pin when the migration lands. |
| "Everything below is running now, no roadmap promises" (pillars list) | index | Partly covered by the hourly heartbeat (send, sign, verify). Dedicated sector relays and the CLI tools are not exercised. |
