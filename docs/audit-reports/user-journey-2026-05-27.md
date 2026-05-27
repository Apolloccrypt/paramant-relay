# User Journey Audit

Generated: 2026-05-27 (autonomous CLI session)
Codebase HEAD: 2cb207d (main)
Production target: paramant.app

## Methodology

Each user-type flow is reproduced with the closest non-destructive means:

- Browser flows: HTTP probes + static analysis of returned HTML/JS.
- SDK flows: registry metadata lookups (npm, PyPI) + README cross-check.
- Self-host flows: static analysis of install.sh / install-pi.sh (no
  execution; that needs root + a docker daemon).
- Wizard flow: static analysis of setup.html + relay.js handler + a
  live read-only endpoint probe.

Safety boundary actually enforced (deviates from the run script):
production endpoints were probed **read-only** (GET/HEAD/OPTIONS only).
The run script's `POST /v2/auth/signup` and `POST /v2/setup/apply` were
**not** executed -- a signup POST creates prod data and sends mail, and
an apply POST could mutate the live relay config. Where a POST was the
only way to observe behavior, that is recorded under Coverage Gaps
rather than guessed at.

Honesty note: several findings pre-written into the run script were
**not reproduced** by evidence and were dropped or downgraded. They are
listed under "Run-script hypotheses not supported" so the delta is
auditable.

---

## Executive Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 6 |
| LOW | 3 |

The single biggest issue is not any one flow -- it is that **production
lags main by a wide margin**. `/health` reports 2.5.0, the installer
pins v2.4.5, and the R005-R008 onboarding/add-on/low-code work plus R006
crypto-mode are unmerged and/or undeployed. Every recent session's
output is invisible to a real user today.

The three HIGH findings:

1. **Self-host installer ships a stale version** (`install.sh` pins
   `VERSION="v2.4.5"`) -- a new self-hoster gets a relay two minor
   versions behind.
2. **The R005 onboarding wizard is a dead-end** -- `/v2/setup/apply`
   returns 501; a user who completes the 7-step `setup.html` cannot
   apply anything.
3. **Production lags main** -- the appliance/onboarding story exists
   only in the repo, not on paramant.app.

What works well and should NOT be touched: the SDK is published and
coherent on both npm and PyPI at 3.0.0 with matching docs; every real
nav/footer link resolves (no broken links); security headers and
capability endpoints are healthy. Details below.

---

## Flow A: Anonymous /send

A first-time visitor with no account who wants to send a file.

### A.1 Landing + transport security

- `GET /` -> 200. HSTS (`max-age=63072000; includeSubDomains; preload`)
  and `x-frame-options: DENY` present. Good.
- **FINDING A.1a -- CSP allows inline script.** The CSP is
  `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'` and
  `style-src 'self' 'unsafe-inline'`, plus external Google Fonts and
  `cdn.jsdelivr.net` / `server.arcgisonline.com` for images.
  `'unsafe-inline'` on script-src defeats most of CSP's XSS value.
  - Severity: MEDIUM
  - Evidence: `content-security-policy` response header on `/`.
  - Suggested fix: move inline handlers/scripts to hashed or
    nonce'd external files (the pattern already used on mickbeer.com),
    then drop `'unsafe-inline'` from script-src.
- **FINDING A.1b -- HSTS header emitted three times.** The
  `strict-transport-security` header appears 3x on the same response
  (nginx and the app likely both set it).
  - Severity: LOW (cosmetic; browsers take the first)
  - Suggested fix: set HSTS in exactly one layer.

### A.2 /send behavior and claims

- `GET /send` -> 200, 37.5 KB. The flow is **client-side WebCrypto
  AES-256-GCM with the key in the URL fragment**, burn-on-read, no
  account. Evidence: page JS references `subtle.`, `AES-GCM`, and
  `fragment`; no `crypto-bridge` / `paramant_crypto` / ML-KEM reference
  on this page. The meta description is accurate: "Your browser
  encrypts with AES-256-GCM. The key lives in the link. Burn on first
  read."
- **FINDING A.2a -- anonymous send capped at 5 MB.** The page advertises
  "KEYLESS . ANONYMOUS . 5 MB". A 5 MB ceiling is very low for a
  file-transfer product and matches the known too-low community quota.
  - Severity: MEDIUM
  - Evidence: `/send` rendered text "5 MB Drop a file".
  - Suggested fix: confirm intended free-tier ceiling; the prior
    intent was 500 MB, not 5 MB.
- **FINDING A.2b -- "post-quantum" brand strip on a symmetric-only
  flow.** The site-wide strip reads "aes-256-gcm / post-quantum". On
  /send specifically there is no post-quantum primitive (it is
  symmetric AES-GCM). This is a brand/footer element, not a direct
  per-flow lie, so it is clarity rather than misrepresentation.
  - Severity: LOW
  - Suggested fix: scope the "post-quantum" wording to the relay/SDK
    flows, or label /send explicitly as "classical AES-256-GCM, no
    account" to avoid implying PQ for the keyless path.

---

## Flow B: Signup and pricing

### B.1 /pricing

- `GET /pricing` -> 200. Copy: Free = "RAM-only, no account"; Pro =
  "coming soon" / waitlist; Enterprise = contact.
- **FINDING B.1 -- Pro is not self-serve and shows no ETA.** A user
  ready to pay cannot. This is the intended state, but the page gives
  no "available when" signal.
  - Severity: LOW
  - Suggested fix: add an expected window or a waitlist email capture
    with a confirmation, so intent is captured rather than lost.

### B.2 Auth capability discovery

- `GET /v2/auth/capabilities` -> 200
  `{"api_key":true,"user_totp":true,"user_totp_status":"live",...}`.
  Capability discovery works. No finding (positive).

### B.3 Signup form

- `GET /signup` -> 200. Form collects `email` + `label`, submits via JS
  (no plain `action=`), no password field (TOTP / key model).
- See Coverage Gaps: the signup POST was not executed (safety), so
  end-to-end account creation is unverified.

---

## Flow C: SDK developer onboarding

### C.1 / C.2 Registry availability (POSITIVE)

- `npm view paramant-sdk version` -> **3.0.0** (published).
- PyPI `paramant-sdk` -> **3.0.0** (published; verified via
  pypi.org JSON API).
- READMEs match exactly: `npm install paramant-sdk@3`,
  `pip install 'paramant-sdk>=3'`, plus yarn/pnpm variants. A developer
  can install and the docs are correct.
- Minor: the scoped name `@paramant/sdk-js` 404s on npm; only the
  unscoped `paramant-sdk` exists. Not a defect, but worth squatting the
  scope to prevent impersonation.

### C.3 Version coherence across surfaces

- **FINDING C.3 -- three different version stories.** SDK is 3.0.0, the
  production relay `/health` reports 2.5.0, and `install.sh` pins
  v2.4.5. A developer who reads "SDK 3.0.0" then sees a 2.5.0 relay and
  a 2.4.5 installer has no way to know what is current.
  - Severity: MEDIUM
  - Suggested fix: publish a single version-compatibility table
    (SDK x.y <-> relay a.b) and reconcile the public version string.

---

## Flow D: Self-host installer

### D.1 install.sh

- Exists, 458 lines, `set -euo pipefail` (fail-fast: good), auto-detects
  and installs docker, uses signed docker apt/dnf repos. Solid.
- **FINDING D.1 -- installer pins a stale version.** Line 24:
  `VERSION="v2.4.5"`. This is behind the public 2.5.0 and the internal
  3.0.0 / M5b work. New self-hosters get an old relay by default.
  - Severity: HIGH
  - Evidence: `install.sh:24`.
  - Suggested fix: resolve the latest tag at install time (or pin to the
    current release) and add a self-update path.
- Note: the documented entry is `curl -fsSL https://paramant.app/install.sh | bash`
  (curl|bash). Acceptable for self-host, but a checksummed download +
  verify step would reduce supply-chain risk.

### D.2 install-pi.sh

- `frontend/install-pi.sh` exists, 379 lines, `set -euo pipefail`,
  docker provisioning, documented as `curl ... | sudo bash`. No defect
  found in static analysis.

---

## Flow E: Onboarding wizard (R005)

### E.1 Setup gate divergence

- In `main`, `GET /v2/setup/check` returns 200 unconditionally
  (relay.js handler; gate is `apiKeys.size === 0 || SETUP_MODE`).
- On production it returns **405**
  `{"error":"Not available in this relay mode","mode":"ghost_pipe"}`.
- **FINDING E.1 -- the deployed gate does not match the R005 spec.**
  R005 documents an apiKeys/SETUP_MODE gate; production gates on relay
  mode (`ghost_pipe`). Either main is missing the mode gate or
  production runs different code -- either way the spec and the
  deployment disagree.
  - Severity: MEDIUM
  - Suggested fix: make the mode gate part of R005 and the main handler,
    so behavior is identical across environments.

### E.2 The wizard cannot finish

- **FINDING E.2 -- /v2/setup/apply is a 501 stub.** Confirmed at
  `relay.js:1765` (returns 501 with "Setup endpoint not yet
  implemented. Use the admin scripts (scripts/paramant-key-add.sh) or
  edit .env for now."). The front-end `setup.html` has 7 steps but the
  final apply does nothing. The appliance-onboarding promise of R005 is
  not deliverable end-to-end today.
  - Severity: HIGH
  - Evidence: `relay.js:1759-1766`, `frontend/setup.html` (7 steps).
  - Suggested fix: implement apply (write .env / call key-add), or hide
    the wizard behind a feature flag until it is functional, so users
    are not led into a dead-end. (The stub message is at least honest.)

### E.3 Not exposed in production

- `GET /setup` -> 404 on paramant.app. The wizard is not served on prod
  (reasonable -- 100 users already onboarded), but it means the scaffold
  has never been exercised against a real deploy.

---

## Flow F: First dashboard view

- `GET /dashboard` -> 200. It is a **Developer Dashboard** (title
  "PARAMANT -- Developer Dashboard"): an API-key console with an
  embedded 6-step connectivity self-test, gated behind Sign in / Create
  account.
- **FINDING F.1 -- product-cards UI (PR #39) not confirmed live; no
  ParaSign.** No `cards-grid` / `card-header` / `product-card` markup is
  present in the served HTML. The page references ParaShare and ParaDrop
  but not ParaSign. Either PR #39 uses different markup, or production
  runs an older frontend (consistent with the prod-lag theme).
  - Severity: MEDIUM
  - Suggested fix: confirm PR #39 is deployed; if ParaSign is a launched
    surface, ensure it appears in the dashboard.

---

## Flow G: Documentation walk

### G.1 Navigation integrity (POSITIVE)

- All real footer/nav links resolve 200: `/auth/login`, `/architecture`,
  `/changelog`, `/crypto-agility`, `/ct-log`, `/download`, `/drop`,
  `/government`, `/help`, `/hndl`, `/license`, `/ot`,
  `/ot-vs-data-diodes`, `/parashare`, `/partners`, `/press`, `/privacy`,
  `/quantum-urgency`, `/security`, `/sla`, `/sovereignty`, `/status`,
  `/terms`, `/vs`. "API reference" -> `/docs#api`; "Sign in" ->
  `/auth/login`. No broken links found.

### G.2 Docs content gaps

- `GET /docs` -> 200, 68 KB. Mentions: ML-KEM-768, ML-DSA-65, self-host,
  ParamantOS, npm install. **Does not mention:** paramant-core /
  @paramant/core, ParaSign, Add-on (R007), CRYPTO_MODE (R006).
- **FINDING G.2 -- docs omit the crypto core and the new spec surfaces.**
  Given README advertises "Powered by paramant-core", its absence from
  /docs is a transparency gap. Add-on/CRYPTO_MODE absence is expected
  (those specs are recent/unmerged).
  - Severity: LOW
  - Suggested fix: add a paramant-core section to /docs; fold in R006/R007
    once merged and deployed.

---

## Cross-cutting findings

### X.1 Production lags main (HIGH)

- Evidence: `/health` -> version 2.5.0; `install.sh` pins v2.4.5;
  `/v2/setup/check` behaves per a mode-gated build that differs from
  main; R005/R007/R008 are spec-only; R006 (PR #40) is still open.
- The cumulative output of the recent sessions is not live. Whatever the
  deploy cadence is, it is far enough behind that an audit of "the user
  journey on paramant.app" largely audits an older product than the repo
  describes.
- Suggested fix: define and document a deploy pipeline from main ->
  paramant.app, and a version string that reflects what is actually
  running.

### X.2 R006 crypto-mode is neither merged nor live (MEDIUM)

- `/v2/capabilities` advertises **all 18 algorithms** (ML-KEM-512/768/
  1024, ML-DSA-44/65/87, Falcon-512/1024, full SLH-DSA set). R006's
  "production default = core (2 algorithms)" is not in effect; PR #40 is
  open and not merged to main.
- The FIPS-surface-reduction narrative does not hold against the live
  relay today.
- Suggested fix: merge PR #40, deploy, and re-probe `/v2/capabilities`
  to confirm the advertised set drops to the core 2.

---

## Coverage Gaps (deliberately not tested)

- **Signup end-to-end** -- POST `/v2/auth/signup` not executed (would
  create prod data / send mail). Form structure verified; account
  creation and the verification email path are unverified.
- **Setup apply** -- POST `/v2/setup/apply` not executed against prod
  (would mutate config). Behavior known only from the main source (501).
- **Installer execution** -- install.sh / install-pi.sh analyzed
  statically; not run (needs root + docker).
- **Payment flow** -- not triggered (would incur cost); Pro is waitlist
  anyway.

## Run-script hypotheses NOT supported by evidence

These were pre-written into the audit run script and are recorded here as
not-reproduced, to keep the delta honest:

- "SDK not published to npm/PyPI" -- FALSE. Both publish 3.0.0.
- "/send misleading post-quantum claim, HIGH" -- DOWNGRADED to LOW. The
  /send meta copy accurately says AES-256-GCM; "post-quantum" is a
  site-wide brand strip, not a per-flow claim.
- "404 nav routes (/api, /sdk, /quickstart, /faq, /login)" -- FALSE as
  broken links. Those are paths the script guessed; the real nav uses
  /docs#api and /auth/login, and every actual link resolves 200.
- "/v2/setup/check returns 200 on prod, wizard exposed, HIGH" -- FALSE.
  Prod returns 405 (mode-gated); the divergence from main is the real
  (MEDIUM) finding, not an exposed wizard.
