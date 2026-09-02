# Site claims: what the pages say, and which test fails when it stops being true

Inventory retaken on 2 September 2026 on `origin/main` at #366. The first
version of this file was taken after #323, before the site was rewritten: #328
to #366 renamed the free tier, gave ParaSend its own product page, rewrote the
homepage, /pricing, /about, /security, /trust, /docs, /help and /download, and
retired the sector and norm pages. Rows that described text which no longer
exists are gone; the pages that replaced them are read here.

40 public pages under `frontend/`. Every factual claim on them, with the test
that pins it or the word UNCOVERED.

The rule from the pruning plan: a page may only exist if a test fails when the
page lies. `tests/site-claims.test.mjs` is that test for the heaviest claims
(the numbered rows below). The rest of this table is the follow-up work.

Pages not in scope: everything behind a login or in a one-shot flow
(`account`, `admin`, `dashboard`, `developer`, `co-sign`, `claim`, `get`,
`ontvang`, `request-key`, `setup`, `parashare`, `auth/*`, `billing/*`,
`signup/verified`, `404`, `all-systems-go`, `iot` redirect).

## Pinned in tests/site-claims.test.mjs

| # | Claim | Pages | Source in the code | Landed in |
|---|---|---|---|---|
| 1 | ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) are the parameter sets | index, about, security, pricing, press, sign, verify, privacy, dpa, architecture, audit-log-export, vs, crypto-agility | `relay/crypto/bootstrap.js` registers exactly these two in core mode; `impls/mlkem768.js`, `impls/mldsa65.js` carry the names | #327 |
| 2 | "The relay loads 3 KEMs and 17 signatures", and the default mode loads two | security, crypto-agility | `bootstrap.js` registration counts, gated on `CRYPTO_MODE=extended`; `.env.example` documents `core` as the default | #327 |
| 3 | AES-256-GCM, HKDF-SHA256, SHA3-256, PBKDF2-SHA256 | security, privacy, vault, sign, verify | `relay/lib/encryption.js`, `crypto-wasm/src/lib.rs`, `relay/lib/ct-hash.js`, `frontend/sign-flow.js`, `frontend/vault.js` | #327 |
| 4 | 5 MB blocks / chunks / padding | privacy, security, vs | `relay/relay.js` `MAX_BLOB` default 5242880; `relay/lib/tiers.js` `file_mb: 5` | #327 |
| 5 | Link expiry 1 hour (Community), 24 hours (Pro), 7 days (Enterprise) | pricing, privacy | `relay/lib/tiers.js` `view_ttl_ms` | #327 |
| 6 | Sessions last one hour; TOTP codes expire after 30 s; login limited to 5 per IP and 10 per email per 15 minutes | security | `admin/server.js` cookie `Max-Age=3600`, `checkLoginRateLimit`, `/api/user/login` Redis counters; `relay/lib/totp.js` step 30. No account lockout exists, so no page may promise one | #327 |
| 7 | Three external audits in April 2026, 40 findings, 4 critical | press, trust, dpa, docs, security | `/docs#audits` table cross-checked against `docs/security-audit-2026-04.md` | #327 |
| 8 | Uptime commitment 99.5 % / 99.95 %, and how it is measured | sla, pricing, status | `.github/workflows/heartbeat.yml` and `scripts/heartbeat/*`, gated on `HEARTBEAT_ENABLED`; `frontend/js/status.inline1.js` | #327 |
| 9 | "IP logging: Nginx access logs" | security | `deploy/nginx-paramant-live.conf` has `access_log off` on every block that serves the site or a relay; no logrotate config in `deploy/`, so no retention is promised | #327 |
| 10 | Any CLI tool count the site states | index (claim since removed) | `admin/lib/developer-tools.js` catalogue size | #327 |
| 11 | Community is 10 transfers a month and 5 MB per file, not "10 uploads an hour" | index, docs, docs/api.md, sweep over every page | `relay/lib/tiers.js` `transfers_month` / `file_mb`, enforced by the 402 and 413 in `relay.js` | #354 |
| 12 | The tier block on /about repeats the numbers /pricing charges for | about, pricing, security, trust | `frontend/pricing.html` tier cards, themselves bound to `tiers.js` by `relay/test/pricing-page.test.js` | #335 |
| 13 | The file size the site promises a buyer | help/gmail-extension, help/iot-integration, sweep over every page | `relay/lib/tiers.js` `file_mb` and `relay.js` `MAX_BLOB`. Both help pages said **"Files up to 5 GB are supported"**, a thousand times the ceiling. Corrected to 5 MB, and no page may state a Paramant file size in gigabytes (`/vs` quotes competitors and is excluded) | this PR |
| 14 | "The API accepts up to 60 uploads per minute per API key" | help/iot-integration | `deploy/nginx-selfhost.conf`: the 60 r/m zone is keyed on `$binary_remote_addr`, so it is per IP and not per key, and it is the general API zone (uploads sit in a stricter one). The per-key ceiling is `outbound_per_hour` in `tiers.js` and it counts retrievals. Sentence rewritten to say both | this PR |
| 15 | The account lockout | help/session-issues, help/lost-authenticator, dpa, sweep over every page | Nothing in `admin/server.js` or `relay/relay.js` locks an account. #327 struck the sentence from /security; it survived verbatim on /help/session-issues with an email address for an "early unlock" nobody can grant, and /dpa quoted the limiter as "5 attempts/min" when the window is 15 minutes. Both corrected, and the sweep is now sitewide. The replacement text is pinned as well: the per-address counter is keyed on the address, incremented before the code is checked and never cleared on success, so another person's attempts spend your budget. No page may deny that while those three properties hold | this PR |
| 16 | "a 256-bit session token ... httpOnly Secure SameSite=Strict cookie" | security | `admin/server.js` `setUserCookie` sets **SameSite=Lax**, deliberately: the comment above it (lines 642-649) explains that a Strict cookie is not sent on the top-level navigation from an emailed invite. That comment cites ADR R018, but `docs/adrs/R018-parasign-invite-webauthn.md` says nothing about SameSite, so the comment is the source and the ADR is not. Corrected, with the reason; the sliding expiry is pinned to the `expire()` refresh | this PR |
| 17 | "TOTP verification uses SHA-256 HMAC" | security, help/authenticator-apps | `relay/lib/totp.js` dual-verifies: the default algorithm list is `['sha256', 'sha1']`, because RFC 6238 defaults to SHA-1 and several common apps offer nothing else. /security named one of the two; corrected to both | this PR |
| 18 | "Each code can be used exactly once across the system, enforced atomically in Redis" | security | `relay/lib/totp.js` sets a per-slot `NX` key, which is atomic, but ends the call with `.catch(() => 'OK')`: on a Redis error the replay check is skipped and the code is accepted again. Weakened to state the fail-open; the test flips if the `.catch` ever goes | this PR |
| 19 | Argon2id, "Password-based blob encryption" (/security) and "Password-protected blob derive" (/docs) | security, docs | `relay/relay.js` hashes the transfer password with Argon2id into `pw_hash` and verifies it on retrieval. No blob key is derived from it, and the module is an optional `try`/`require` that answers 501 when absent. Both rows now say gate, hash and optional | this PR |
| 20 | "An observer on the network cannot infer/determine file size, type, or content" | security, docs | Finding 5 of `docs/security-audit-2026-04.md` (pinned byte-identical to the served copy under `frontend/docs/`, which /security and /trust link), an accepted trade-off, says the opposite: `total_chunks` travels in the clear (`frontend/js/parashare.page.js`), so the block count of a multi-block transfer is visible and the size follows to an order of magnitude. The site was contradicting the report it publishes. Weakened on both pages | this PR |
| 21 | "no IP rate limit" as a paid-plan benefit | index, sweep over every page | No per-IP rate reads a plan: the only one is `ANON_RATE_PER_HOUR` on the deprecated `/v2/anon-inbound`, the same fossil row 11 hunts. What a paid plan raises is `outbound_per_hour` per API key. Replaced with the 50 to 500 figures out of `tiers.js` | this PR |
| 22 | "No third-party requests ... No fonts, CDNs, analytics or pixels" (/parasend), "No tracking." (/pricing) | every public page | The page tree itself: no tag, no `@import` (with or without `url()`), and no runtime call in an inline script (`fetch`, `XMLHttpRequest.open`, `WebSocket`, `EventSource`, `Worker`, `importScripts`) may point off `paramant.app`. The page set is the public list plus `/ontvang` and `/parashare`, which `PRIVATE` keeps out of the sitemap but a share link opens without an account: audit finding 17 was a font stylesheet on exactly that kind of page. True today and nothing held it there | this PR |

## Already covered by an earlier test

| Claim | Pages | Test |
|---|---|---|
| Every price, discount and checkout button resolves in the billing catalog, and every amount inside a tier card belongs to that card's plan | pricing, parasign, parasend, billing/checkout | `relay/test/pricing-page.test.js` |
| Every ParaSend tier line (transfers, link expiry, reads per link, registered devices, retrievals an hour, burn-on-read) is read out of `tiers.js`; Enterprise says "No hourly cap" only while `outbound_per_hour` is unlimited | pricing, parasend | `relay/test/pricing-page.test.js` |
| The ParaSign signature quotas 2 / 100 / 1,000 and the EUR 0.40 overage rate | pricing, parasign | `relay/test/pricing-page.test.js` (rate read from `relay/lib/entitlements.js`) |
| "No limit on receiving": pinned negatively, no receiving dimension exists in any tier row or entitlement | pricing, parasign | `relay/test/pricing-page.test.js` |
| No ParaSign surface states a transfers figure, because a ParaSign grant leaves ParaSend at 10 a month | pricing, parasign, dashboard | `relay/test/pricing-page.test.js`, `tests/ui-truthfulness.test.mjs` |
| The SLA figure on /pricing and /parasend is the one /sla publishes | pricing, parasend, sla | `relay/test/pricing-page.test.js` |
| "Unlimited" may not appear against transfers anywhere in the frontend | all | `tests/ui-truthfulness.test.mjs` |
| The free plan is called Community, never Free, in eleven forbidden shapes | all | `tests/ui-truthfulness.test.mjs` |
| Open-mode signature is not a verified signer; not eIDAS-qualified; account requirement stated up front | sign, parasign | `tests/ui-truthfulness.test.mjs` |
| The three /about signing claims are repeated verbatim on /parasign; the EU data-path sentence carries its Resend exception on index, parasign, parasend and security | about, parasign, parasend, index, security | `tests/ui-truthfulness.test.mjs` |
| Account deactivation wording (what is and is not deleted) | account, admin, email templates | `tests/ui-truthfulness.test.mjs` |
| The reset link lasts 60 minutes and the setup link 14 days, as the server writes them | auth/*, signup | `tests/ui-truthfulness.test.mjs` |
| Founder line, KvK number and company name wherever they appear | about, index, pricing, parasign, dashboard, account | `tests/ui-truthfulness.test.mjs`, `tests/seo-contract.test.mjs` |
| /download: last release v0.2.1 of 28 March 2026, four installers with their measured sha256, three unsigned and one self-signed | download | `tests/ui-truthfulness.test.mjs` |
| Exactly three buyer answers on /help, each a quote of the page that owns it | help/index | `tests/ui-truthfulness.test.mjs` |
| Title, description, canonical, Open Graph, one h1, JSON-LD on every public page; private pages noindex; sitemap matches disk; no sitemap URL behind a login redirect; no certification claim in any title or description | all | `tests/seo-contract.test.mjs` |
| What a buyer must see on a phone without scrolling, on nine pages | index, parasign, parasend, about, security, trust, docs, help, download | `tests/first-screen.test.mjs` |
| The first screen of /pricing, and no tier card wider than its grid | pricing, signup | `tests/pricing-fold.test.mjs` |
| Every internal link resolves; both product pages are linked from the homepage | all | `tests/links.test.mjs` |
| Site still functions in a browser (send, sign, verify) | index, sign, verify | `tests/product-heartbeat.test.mjs` (hourly, against production) |

## UNCOVERED: provable from the code, test still to write

| Claim | Pages | Where the truth lives |
|---|---|---|
| Signature image max 1 MB | sign | `frontend/sign-flow.js` ~1864 (`f.size > 1024 * 1024`) |
| "PARAMANT has five sector relays" and the five hostnames | docs, sla, press, index | `admin/server.js` `SECTORS` (main, health, legal, finance, iot) |
| The per-tier TTL table on /docs (Community 1 h, Pro 24 h, Enterprise 7 d) | docs | `relay/lib/tiers.js` `view_ttl_ms`; row 5 pins only pricing and privacy |
| "Quota: 50 envelope creations per key per hour" | docs | `relay/relay.js` `fixedWindowAllow(envCreateLimits, apiKey, 50, 3600_000)` and the 429 at `/v2/envelopes` |
| "envelope records are held with a 30-day TTL" and the 7-day signing-invite window | docs | `relay/envelope.js` `DEFAULT_TTL_DAYS = 30`, `MAX_TTL_DAYS = 365`, `SIGN_INVITE_TTL_DAYS` |
| Audit-export tiering: "Business or higher, Pro and below 403"; send history "Pro or higher" | docs | `relay/lib/entitlements.js` `features.audit_export`; the 403 in `relay.js` |
| "?limit= default 100, max 1000" and "default 1000, max 10000" | docs | the two export handlers in `relay/relay.js` |
| Community Edition: 5 users, the 6th returns 402, `PLK_KEY` unlocks more | docs, trust | `relay/relay.js` caps **active API keys**, not users, at 5 and flags the rest `over_limit` rather than deactivating them. The word on the page and the thing in the code are not the same unit; settle it, then pin |
| `RAM_LIMIT_MB` default 1024, "503: relay at capacity" | docs | **Mismatch**: `relay/relay.js` line 1262 defaults `RAM_LIMIT_MB` to **512**. The 503 path and `MAX_BLOBS` are real. Correct the page, then pin |
| "Two-step burn: the blob is zeroed in-place, then the Map entry is deleted"; "memory is zeroed immediately" | docs, security, index, parasend | `relay/relay.js` `zeroBuffer(entry.blob)` then `blobStore.delete`, and the `blob.fill(0)` after the response flushes |
| Encrypted blobs live in process memory only, a restart destroys them, no filesystem writes | security, privacy, press, terms, docs, parasend | `relay/relay.js` in-memory blob map; no disk write path for payloads |
| A TOTP code is checked with a +/-1 slot window (so "more than 30 seconds off" is not exactly the tolerance) | help/session-issues | `relay/lib/totp.js` `window = 1` |
| 10 single-use backup codes, hashed with Argon2id, each consumed once | help/backup-codes, help/authenticator-setup, help/lost-authenticator | `relay/lib/user-totp.js` (`argon2id`, `memoryCost: 65536`, `timeCost: 3`) |
| API keys are 64 hex characters and do not expire | help/api-key-vs-totp, help/session-issues, help/iot-integration | `admin/server.js` `'pgp_' + crypto.randomBytes(32).toString('hex')` |
| CT log persists to `/data/ct-log.json` and survives restarts | ct-log | `docker-compose.yml` sets `CT_FILE`; `relay.js` treats it as opt-in (default RAM-only) |
| `verified_since` proves continuous relay identity | security, docs | `relay/relay.js` ~3831 to 3859 |
| Device IDs hashed with SHA3-256 in the CT log; filenames only as `enc_meta` ciphertext | dpa, privacy, docs | `relay/lib/ct-hash.js`; relay `enc_meta` handling |
| Webhooks signed with HMAC-SHA256 of the body, keyed on the API key | docs | the webhook signing path in `relay/relay.js` |
| Status page: auto-refresh 30 s, last 24 h kept in the browser | status | `frontend/js/status.inline1.js` `setInterval(checkAll, 30000)` |
| Sub-processors: Hetzner (DE), Resend (US, SCCs), Mollie | dpa, privacy | `admin/lib/email-templates.js`, `admin/lib/config-schema.js`, `relay/lib/mollie.js` |
| BUSL-1.1 converts to MIT on a fixed date | license, terms, footer | **Contradiction, still open**: `LICENSE` and `deploy/LICENSE` say Change Date 2029-01-01; `frontend/license.html` and `terms.html` say 1 January 2030, including in the head elements that `seo-contract` pins. Decide which is right, then pin; the head change has to go with it |
| Audit totals: 40 on the site, 50 in SECURITY.md | press, trust, dpa, docs, security | **Contradiction, still open**: the `/docs#audits` table is three audits and 40 findings, and says every finding is in SECURITY.md. SECURITY.md carries four review sections totalling 50 (RAPTOR 15 April adds 10). Either the table gains the RAPTOR row or SECURITY.md says why it is left out |
| sdk-py 3.0.0 / sdk-js 3.0.0 are the versions that encrypt client-side | security, architecture, parasend, docs | SDK repos are outside this repository; pin via the published package version if wanted |

## UNCOVERED: not provable from the code; weaken or accept as policy

| Claim | Pages | Note |
|---|---|---|
| Servers in Germany, Hetzner Nuremberg (NBG1), EU-only, no US CLOUD Act exposure, Bunny DNS in Slovenia, no CDN in front | index, parasign, parasend, about, security, help/index, press, privacy, dpa, sla, docs | Infrastructure, not code. Provable only against the machine (`scripts/check-prod-drift.sh` territory). The wording itself (data path plus the Resend exception) is pinned by `ui-truthfulness`; the fact is not |
| "ML-KEM-768 Level 3 in production since 2024" | vs | Repository history starts 1 April 2026; press kit says founded 2025. Weaken to "in production today" |
| "Burned on read" as a universal property | index, parasend, press, pararules | `tiers.js` gives Pro 10 reads and Enterprise 100 per link, and /pricing says so. True for Community, not universal |
| "All tiers meet NIS2 and GDPR requirements by design"; NEN 7510 / eIDAS / IEC 62443 mappings "ship with Pro and Enterprise" | pricing, parasend, security, docs | After #323 the norm pages are gone. The only artefact left is `docs/security/COMPLIANCE-CHECKLIST.md`. The "no third-party certification" disclaimer is pinned by `pricing-page.test.js`; the mapping deliverable itself is not. This is the largest remaining norm claim on the site |
| The sector paragraphs on /docs (NEN 7510, DICOM, HL7 FHIR, eIDAS, KNB, ISO 20022, DORA, IEC 62443) | docs | Positioning for five relays that run identical software. Nothing in the code is sector-specific except the `SECTORS` map and the per-sector env presets in `relay.js` |
| Named support within one business day (Business); "published response targets" (Pro); "We respond within 48 hours" on three help pages; press replies within 24 hours; complaints answered within fourteen days | pricing, parasign, index, help/*, press, terms, sla | Service commitments, not code. Keep only if someone will honour them |
| Breach notification within 48 hours; 14 days notice for sub-processor changes; deletion within 30 days after termination | dpa | Contractual commitments |
| Disclosure: acknowledgement within 48 hours, assessment within 5 working days, updates every 7 days, 90-day coordinated disclosure, no bounty | security | Policy |
| auditd (49 CIS L2 rules), AIDE daily, AppArmor enforcing, CIS Ubuntu 24.04 L2 (114 checks) | dpa | Host hardening; `docs/docker-hardening-2026-04-24.md` describes the container side only |
| The self-host licensing protocol: Ed25519 licence token, a 6-hour licensing call, a 7-day cached capability set, telemetry off by default | trust | Every one of these is labelled planned on the page itself (ADR R013 draft). Pin when it lands, and until then the label is the honest part |
| Docker image provenance: built by the public workflow, verifiable with `cosign` | trust | ADR R015 is in progress; the image tag on the page is not checked against a published digest |
| Binary sizes and SHA256 sums of the desktop builds | download | `/dl/` is not in this repository. The sums are measured and hardcoded in `ui-truthfulness`, which is the closest this can get |
| Gmail and Outlook extension behaviour: 24 hour default TTL, 1 hour to 7 days, key stored locally, Chrome 120+ | help/gmail-extension, help/outlook-extension | The extensions live in `extensions/`, and the copy has never been read against them. Worth a pass of its own |
| Competitor facts (Zivver / Kiteworks, Tresorit / Swiss Post, WeTransfer / Bending Spoons, certifications, gigabyte allowances) | vs | External sources cited on the page; verify on a schedule or date-stamp the page |
| "Full NIST suite (FIPS 203, 204, 205, 206) loaded"; "runs the full NIST post-quantum suite today" | architecture, crypto-agility | Same fact as row 2 in other words; the default mode loads two algorithms. Reword to match security.html |
| Chromium and Outlook extensions use a server-side encryption path; migration in progress | security, architecture, crypto-agility | Honest caveat about a weaker path. Keep, and pin when the migration lands |
| "Everything below is running now, no roadmap promises" (pillars list) | index | Partly covered by the hourly heartbeat (send, sign, verify). Dedicated sector relays are not exercised |
