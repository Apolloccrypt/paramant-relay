# Changelog

All notable changes to PARAMANT Ghost Pipe are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed
- **Every ParaSend limit now reads the product tier, not the unified `plan`.**
  Billing writes a purchase with `setProductPlan` ->
  `entitlements.applyProductTier`, which sets `plan_parasend` (or
  `plan_parasign`) and deliberately leaves the unified `plan` alone. Three
  enforcement points still resolved their ceiling off `plan` and so could not
  see a paid ParaSend upgrade at all: the link TTL and the read count on
  `POST /v2/inbound`, and the device cap on `POST /v2/pubkey`. The moment
  self-serve billing goes live that would hold a ParaSend Pro customer to a
  1 hour link, 1 read and 5 devices while `/pricing` sells him 24 hours, 10
  reads and 50 devices. It is not visible today only because billing still runs
  through the admin route, which sets `plan` as well. All six ParaSend ceilings
  (TTL, max views, devices, transfers per month, blob size, downloads per hour)
  now come from `getEntitlements(record).parasend`, and the ParaSign quotas from
  `.parasign`. `outbound_per_hour` was the one dimension the entitlement layer
  did not carry and has been added, mirroring `lib/tiers.js` like the rest.
- **A key with no plan no longer gets the Pro ceiling.** The device cap
  defaulted to `pro` (50 devices) and the DID-registration pubkey TTL to `pro`
  (30 days) for a record with no plan on file, the mirror image of the default
  already fixed on the inbound ceilings. A missing plan is not evidence of a
  paid one; both now fall to Community, 5 devices and 7 days.
- **The device cap counted nothing.** Registered pubkeys are stored under
  `<device_id>:<account_id>`, but the cap counted entries ending in
  `:<api_key>`, which equals the account id only for a key that has none. For
  every real account the tally stayed 0 and the cap never fired at any tier.
  It now counts the suffix the route writes, so the ceiling is enforced.

  Because the cap never fired, accounts can be over it today, and a tier change
  can put an account over it at any time. The cap governs how many devices an
  account may HAVE, so it applies only to a registration that would ADD one:
  `POST /v2/pubkey` for a device the account already holds skips the cap
  entirely and answers on the device itself (`409` while the entry is live,
  `200` renewing an entry whose TTL has passed but which the hourly sweep has
  not reached). Without that skip an account over its cap got `429` on every
  re-registration, which is the normal path rather than an edge: a Community
  device pubkey lives 7 days, so devices come back to this route routinely, and
  such an account would have lost them one at a time. **The change an operator
  will see: an account over its tier's device count keeps every device it has
  and is refused its next NEW one.**
- **The device-pubkey TTL table had the same hole as `outbound_per_hour`.** It
  held three rows (`free`, `pro`, `enterprise`) behind a `?? free` fallback, so
  `community` and `business` were not in it and reached the free row by
  accident. Every tier name a caller can produce now has its own row.
- **A 402 over quota now names the tier that decided.** The transfer and sign
  quota declines reported the unified `plan`, telling a paying customer he was
  on a tier he was not being held to. Same for `GET /v2/admin/usage`, which
  reported limits derived from `plan` while the gates enforced the product
  tier; it now reports the enforced numbers and carries `parasend_tier` and
  `parasign_tier` alongside `plan`.

- **`GET /v2/admin/usage` reported an uncapped file size for a tier that is
  capped.** The Enterprise row says `file_mb` is unlimited, but `POST /v2/inbound`
  takes the lower of that and the operator's `MAX_BLOB`, so the gate enforces
  5 MB while both usage routes reported `-1`. They now report
  `min(MAX_BLOB, tier file_mb)`, which is what an upload is actually held to.
  Genuinely uncapped dimensions, such as Enterprise devices, still report `-1`.
- **A legacy `business` plan no longer gets the Enterprise ParaSend ceilings.**
  `derivePlanParasend` mapped `business` up to `enterprise` on a "never silently
  downgrade" reading. But `business` is a ParaSign tier name: an account whose
  unified plan says `business` never bought ParaSend, and mapping it up handed
  it the whole enterprise row, uncapped devices and downloads per hour, 100 reads
  per link, a 365 day device-pubkey TTL and the 10000-receipt retention. That is
  a silent upgrade, and the enterprise row is also where the resource ceilings
  come off. Mapping it down to `pro` would have been the opposite error (2000
  transfers a month cut to 500, a 7 day link cut to 24 hours). It now resolves to
  its own row with exactly the numbers it has always had: 2000 transfers, 100
  devices, a 7 day link, 25 reads, 2000 downloads an hour, 4000 receipts. The row
  is resolved but never sold: `POST /v2/admin/keys/set-product-plan` still
  rejects `business` as a ParaSend tier, and `/pricing` sells Community, Pro and
  Enterprise as before.

### Changed
- **The ParaSend delivery receipt moved out of the response header.**
  `GET /v2/outbound/:hash` used to answer with `X-Paramant-Receipt`, the whole
  signed receipt inline: 18551 bytes for that header and 19560 for the block.
  Node's default `maxHeaderSize` is 16384, so a client using `fetch()` could not
  download at all (`UND_ERR_HEADERS_OVERFLOW`), and nginx's default
  `proxy_buffer_size` of 4k/8k answers 502. The download now carries
  `X-Paramant-Receipt-Id`, `X-Paramant-Receipt-Hash` and
  `X-Paramant-Receipt-Url`, and the receipt itself comes from the new
  `GET /v2/transfers/:receipt_id/receipt`, which returns the exact same
  base64url payload. Receipts are held for 15 minutes, per account, and bound to
  the API key that made the download.

### Deprecated
- **`X-Paramant-Receipt`.** Off by default from this release, removed after
  **2026-12-01**. `PARAMANT_INLINE_RECEIPT_HEADER=1` puts it back for the
  transition; a proxy in front of the relay then needs `proxy_buffer_size`
  raised to match. While it is off, every download carries
  `X-Paramant-Receipt-Deprecated` naming the new URL, so a client cannot
  silently turn a missing header into a missing receipt. The Python SDK does
  exactly that today (`sdk-py/paramant_sdk.py:681`), which is why the notice
  exists; `Apolloccrypt/paramant-sdk` PR #5 teaches it both shapes and that
  release must ship before this one reaches production.

---

## [3.1.0] - unreleased

277 commits since the `v3.0.0` tag (2026-06-24), of which 58 arrived through a
numbered pull request and the rest were pushed to `main` directly. Compiled from
`git log v3.0.0..origin/main` on 2026-09-02 and rebased onto `main` the same
day, which brought six more PRs in; PR numbers are given where the commit
carried one. Numbers written as "finding #n" are security findings or issues,
not pull requests.

Not yet tagged. Tagging and publishing are one step, described in
`docs/RELEASE.md`; a tag that is not deployed is worse than no tag.

### Security

- Audit chain hardening: `chain_valid` is a real tamper check that binds every
  field and recomputes rather than trusting a stored flag (finding #19), and the
  SSRF guard now blocks NAT64 and 6to4 IPv4-in-IPv6 embeddings (finding #21).
- AAD verification fails closed, PII is masked in logs, outbound mail is escaped
  and per-user MFA attempts are throttled (#266).
- Monthly tier caps are enforced on active use, not only at issue time, and
  admin logs are masked (#267).
- API keys are delivered through a one-time claim link instead of in plaintext
  in an email (privacy finding H1, #268).
- Audit PII retention is bounded and IP addresses are masked in persistent
  records (privacy finding M2, #271).
- Signing requires a fresh step-up token on `/attested`, and the signer public
  key is pinned (#272).
- `script-src 'unsafe-inline'` is gone from the admin panel (#273) and from the
  public site (#274).
- Batch of low-severity pentest findings #15, #17, #20, #22 and #23 (#206).
- The public transparency log no longer leaks device identifiers (finding H-1,
  #205).
- Single-signer notary signatures are domain-separated (v2); v1 envelopes stay
  verifiable (findings #3 and #4, #208).
- The stub checkout that granted plans without a payment is disabled, and the
  inbound content hash is verified against the payload on `/v2/inbound` and
  `/v2/anon-inbound`.
- DID auth runs against the owner's entitlements and quota, and a revoked
  enrollment is refused.
- The gitleaks allowlist was rebuilt from a verified full-history scan.
- `/v2/health/deep` is reachable on production again, behind internal auth
  rather than open (#322).

### Added

- ParaSign `/v1` signing API with authorization, quota and offline v3 verify
  (#283), documented in the README (#285).
- ParaSign PDF editor: HiDPI preview, placeable text and date fields,
  annotations and page management (#286).
- Recurring billing collects a second period, and `paid_until` survives a
  restart (#315).
- A canary for ParaSign, the product that had no alarm (#316), and a transfer
  canary that runs a real file through the real relay hourly. The transfer
  canary now also checks the clock (#320).
- `/sign` is served to everyone, and says honestly what it needs (#317).
- Visitors are counted by what a client did, not by what it called itself
  (#318).
- A signals script that says what is red without asking a model (#330).
- Product heartbeat and docroot drift guard, running on every pull request, with
  a red heartbeat made visible as a GitHub issue.
- Document-focused user dashboard, a developer dashboard centred on the ParaSign
  API, self-service ParaSign key minting, and encrypted document delivery with
  signing invitations.
- Per-product plan grants: one product's tier can be set without moving the
  unified plan.
- ParaSign sign tiers with Pro overage metering and a hard cap, plus per-tier
  feature gates wired into the relay endpoints.
- Per-account ParaSign envelope index, full per-envelope `.psign` audit export
  and a CLI backfill for the index.
- A one-time usage-purpose question on the dashboard, shown in the admin user
  list.
- `/about` and `/trust` pages, and a ParaSign product page at `/parasign`
  (#325).
- `docs/brand/messaging.md`: who we sell to, what we promise and how each
  promise is proven (#331).

### Changed

- The recurring billing layer stays off until `BILLING_MODE` says otherwise
  (#326).
- Navigation says what we sell: seven items instead of forty (#324), and 17
  standards and sector pages were pruned from paramant.app (#323).
- The installers are served by us, and only the signatures we actually have are
  claimed (#308); the native build's cost is stated alongside what it does well
  (#309).
- The relay is called source-available (BUSL-1.1) rather than open source.
- The billing docs say Mollie, not Stripe, and document `/v2/billing/checkout`
  and its webhook.
- The homepage speaks to a buyer: Community as the gift, the business plans as
  the product (#328).

### Fixed

- The hourly relay crash: a `setInterval` swept a `Map` that no longer existed.
  This is the failure that the `no-undef` gate in `test.yml` now exists to
  catch.
- A comma-operator bug made the create-envelope gate swallow every POST.
- Script readiness is sticky, so `/ontvang` stops hanging on keygen (#303), and
  the heartbeat was extended to the pages that had no progress check (#304).
- Dead destinations fixed, and every button's destination gated (#307).
- The live device-hash feature survived the CSP refactor (#275); auth and
  billing inline scripts were externalized and the real client IP restored
  (#278).
- The installer preserves the pinned release in the frontend scripts (#259), and
  the admin compose volume paths resolve (#260).
- A paid ParaSign upgrade is no longer invisible to the web sign gate; plan
  changes fan out to every relay sector and are verified across all of them; a
  new key plus a restart no longer drops a paid per-product grant.
- Pricing buttons no longer fall back to an unattributable payment link.
- TOTP dual-verifies SHA-256 and SHA-1, with a soft notice on SHA-1.
- Stale entries are lazily pruned from the account envelope index.
- Mobile navigation stays opaque and keeps its scroll position while open.

### Removed

- The Android APK and ParamantOS: nobody used either (#310).
- ParaID (#319).

### Build, CI and dependencies

- The crypto binding builds on `rust:1.98-alpine` again, by adopting a
  paramant-core that uses bindgen 0.72 (#329). This is the real fix for the
  breakage that forced a re-pin to 1.95-alpine twice (#269, #284) and that
  failed the drift gate on both #222 and #313.
- `paramant-core-node` is built with `--locked`, so a transitive bump cannot
  silently drift the crypto build (#270).
- A drift gate that builds the real production Dockerfile on every pull request.
  It is what caught #313 before merge.
- `relay.js` finally has unit tests: the route suites boot a real `relay.js` and
  exercise its critical paths (#341). Point 3 of the toekomstbestendigheid
  report was that 6488 lines and 68 routes were loaded by no unit test at all;
  this is the first bite out of it.
- The heartbeat cannot be green without evidence (#338), and the site's ten
  heaviest claims are pinned to the code that makes them true (#327). Both turn
  a page that merely loads into a page that has to prove something.
- Published relay images are signed with cosign and carry an SBOM and SLSA
  provenance.
- Suites that assert nothing are held to a named list instead of reporting green
  over nothing (#321).
- Browser suites are selected by what they import rather than by a hand-kept
  list of names.
- gitleaks runs on push and on pull request.
- Action bumps: `sigstore/cosign-installer` 3.7.0 to 4.1.2 (#290),
  `anchore/sbom-action` 0.17.9 to 0.24.2 (#291), `gitleaks/gitleaks-action`
  2.3.9 to 3.0.0 (#292), `actions/checkout` 7.0.0 to 7.0.1 (#293),
  `actions/upload-artifact` 4.6.0 to 7.0.1 (#294).
- `redis` in the admin panel: 4.7.1 to 6.0.1 (#254), then 6.0.1 to 6.2.1 (#312).
- #314 landed the 30 August fixes under the name "Release 3.1.0". No tag was cut
  at the time; this section is that release.

### Release hygiene

Landed in this version rather than deferred, because none of it needs a product
decision:

- One version, one place. The root `package.json` is the version;
  `relay/package.json`, `admin/package.json`, both lockfiles and both
  `org.opencontainers.image.version` labels follow it, and `relay.js` reads its
  own `package.json` at runtime instead of restating the number.
  `tests/version-consistency.test.mjs` fails the build if any of them drift.
  Before this, four places gave three answers: root 3.1.0, relay 3.0.0, admin
  0.9.0-beta, image label 3.0.0, and `scripts/post-deploy-verify.sh` asserting
  that `/health` returns 3.0.0 while the relay already answered 3.1.0. The admin
  panel moves from `0.9.0-beta` to the project version.
- One Node line. The image, CI and the devcontainer are on Node 24, the newest
  LTS; `engines` is `>=22 <25`, which is exactly the two LTS lines still getting
  security fixes. The images were on `node:25-alpine3.21` and CI on Node 20, and
  both of those are end-of-life. The relay base moves to
  `node:24-alpine3.24`, which also matches the Alpine of the
  `rust:1.98-alpine` builder stage that compiles the musl binding.
- Every environment variable is written down. `deploy/.env.example` documents all
  77: the 72 the relay or the admin panel reads, plus 5 that docker-compose, the
  deploy scripts or the self-host installers consume. Each with a purpose,
  required-or-optional, its default and the file that reads it. It documented
  three; the code read 57 names, 40 of them written down nowhere.
  `tests/env-documented.test.mjs` fails the build on the next undocumented one,
  on documentation for a variable nothing reads, and on a `read in:` pointer
  naming a file that does not exist or never mentions the variable.
- A release process that exists on paper and in the repo: `docs/RELEASE.md`.
  `docs/PROJECT-STATUS.md`, which declared itself obsolete in its own second
  line, points at the CHANGELOG and that document instead.

### Also in 3.1.0: entries written before the `v3.0.0` tag

The 3.0.0 section below is dated 2026-05-27. The `v3.0.0` tag was cut on
2026-06-24, a month later. Everything written in between sat under
`[Unreleased]` and never got a released section of its own, so as far as any tag
is concerned it is part of 3.1.0. It is folded in here unchanged rather than
rewritten, because rewriting it would be guessing at what it meant.


### Removed
- **Thunderbird FileLink add-on retired.** `thunderbird-filelink/` removed from the
  repo and the add-on unpublished from addons.thunderbird.net (it was status
  `public` at v1.0.0, ~1 daily user). It shipped a base64 bug from 1.0.0 onward:
  `toBase64` encoded in 8192-byte windows, so the relay's base64 decode truncated
  every upload to ~8 KB and recipients could never decrypt. The ParaShare receiver
  mode in `frontend/parashare.html` is kept: it serves the same burn-on-read link
  format the Gmail and Outlook integrations produce.
- **ParaDrop feature removed (relay side).** The anonymous burn-on-read drop
  webapp and its endpoints are gone: `frontend/drop.html`, the `/sw.js`
  ParaDrop service worker, the `/drop` sitemap entry and crypto-agility table
  row, and the relay routes `POST /v2/drop/create|pickup|status` with their
  rate-limit/backoff helpers and allowlist entries. The general receive page
  (`ontvang.html`) and ParaShare are unaffected. The `/drop` navigation links
  and remaining ParaDrop mentions in content pages are scrubbed separately; the
  Rust `para_drop.rs` in paramant-core is removed in its own PR.
- **SDK extracted to its own repository.** `sdk-js/` and `sdk-py/` now live in
  [Apolloccrypt/paramant-sdk](https://github.com/Apolloccrypt/paramant-sdk)
  (Apache-2.0), together with the cross-implementation conformance suite. The
  published packages keep the same names (`paramant-sdk` on PyPI and npm), so
  installs are unaffected. The Python import path is now `from paramant import
  GhostPipe`; the old `from paramant_sdk import ...` still works via a shim that
  is deprecated and will be removed in 4.0. The relay keeps the canonical
  wire-format v1 spec (`docs/wire-format-v1.md`), which the SDK conformance
  suite cites. CI and dependabot entries for the SDK moved with it; the dangling
  `scripts/paramant-receipt` symlink was removed.

### Added
- ParaSign Sg1 step 3 (issue #49): document signing where the relay is a
  NOTARY, not a key holder. `POST /v2/sign` (auth) verifies a client-made
  ML-DSA-65 signature, logs it to the CT tree, and counter-signs a `.psign`
  envelope with the relay identity; `POST /v2/verify` (public, no auth)
  validates an envelope statelessly. The relay never receives a signer private
  key or document content -- only the SHA3-256 hash, the signature, and the
  signer public key.
- `relay/parasign.js`: pure `.psign` envelope build/verify, unit-tested in
  `relay/crypto/parasign.test.js` (valid, hash-mismatch, tampered field,
  tampered signature, wrong notary key, expired).
- `scripts/paramant-sign`: node CLI (`keygen` / `sign` / `verify`) that signs
  locally with `@noble/post-quantum` ML-DSA-65 (byte-equivalent to the relay's
  `@paramant/core` per ADR-0021) and never sends the key to the relay.
- R017 ADR: `.psign` envelope format and notary trust model.
- Deferred to a follow-up: the browser sign/verify UI. It needs in-browser
  SHA3-256, which the vendored WASM and noble bundle do not yet expose; the
  secure client-side signing path (seed-based ML-DSA-65 in `crypto-bridge.js`)
  is already present and waits only on that hash primitive.

### Added (specification only, no implementation)
- R016 Open-core split architecture ADR (Accepted): defines the two-repo
  model -- paramant-relay (public, BUSL-1.1) + paramant-management
  (private, all-rights-reserved). Covers the v1 API contract between the
  repos, CT log discipline for customer-visible remote actions, "Paramant
  Fleet" branding for the management plane, the public /trust page concept,
  and per-repo licensing. Industry-standard open-core model
  (HashiCorp/GitLab/Elastic precedent). Builds on R013/R014/R015.
- R014 Management plane architecture ADR: defines the fleet-overview
  console on Paramant's root server. Customer + relay-instance +
  license-key data model, API endpoints (/api/fleet/*), UI structure,
  audit-trail, remote actions (force-update, support-key, backup, drain),
  and privacy-respecting telemetry opt-in. Builds on R013 license-server
  protocol.
- R007 Add-on architecture ADR: defines manifest format
  (paramant-addon.json), capability-based permission model
  (read:blob-metadata, subscribe:stream, etc), three communication
  channels (webhook, WebSocket, NATS), docker-compose extension
  lifecycle, and registry structure (official + community + local).
- docs/addons/ directory with README + example manifest + example
  compose fragment.
- Zero-knowledge guarantee preserved: no capability grants access
  to plaintext, keys, or signatures. Add-ons work on ciphertext +
  metadata only.
- R008 low-code routing scope ADR: defines what may be expressed
  in visual flow editor (routing, compliance toggles, retention
  policies, notifications) and what may not (crypto switching,
  wire format alternatives, key overrides, plaintext access).
  YAML-based flow-definition format with capability-checked execution.
- docs/low-code/ folder with two example flow YAML files
  (notify-on-health-blob, mirror-to-storage).
- R015 Release-channel model ADR: defines stable/beta/edge channels,
  semver tag scheme, channel-tagged Docker images (mtty001/relay),
  per-main-merge GitHub Actions edge builds, maintainer-triggered
  beta/stable promotion, cosign-signed releases, customer-side
  channel selection + tier-gated auto-update with auto-rollback.
  Replaces "git pull main HEAD" deploys with versioned releases.
- R013 License-server protocol ADR: defines the wire format between a
  customer relay and Paramant's central license-server. ML-DSA-65 signed
  capability-sets, 6h check-in with nonce binding, 7-day offline grace,
  capability-based feature gating, and 402/404/410/503 status semantics.
  Additive to the existing offline Ed25519 PLK_KEY (backward compatible);
  implementation deferred to later phases.

### Changed
- **Recurring billing needs an explicit `BILLING_MODE`.** The customer, mandate
  and subscription layer (`relay/lib/billing-recurring.js`) now runs only when
  `BILLING_MODE` is set by hand to `live` or `test`. With it empty, as production
  has run since billing exists, `billingMode()` still infers the mode from the
  key, but the relay creates plain one-off payments exactly as the 2026-08-08
  code did: no customer, no `sequenceType`, no subscription. The `billing_config`
  line at boot now carries `mode_source`, `recurring` and a one-sentence
  `stance`, at `warn` when the mode is inferred. Pinned by
  `relay/test/billing-stance.test.js` and `billing-stance-boot.test.js`.
  Deploy runbook: `deploy/DEPLOY-3.1.md`.
- `mldsa65.js` migrated to the `@paramant/core` binding (matches the `mlkem768.js`
  M5b pattern). Byte-compatible via paramant-core ADR-0021 cross-impl KAT. Covers
  all ML-DSA-65 use in the relay (STH-signing + receipt/signature verify) through
  `registry.getSig(0x0002)`.
- `bootstrap()` now supports a `CRYPTO_MODE` env var (`core` default, `extended`
  for all 18 algorithms). Production default drops from 18 to 2 algorithms
  advertised via `/v2/capabilities` (ADR R006).

### Migration note for self-hosters
- If you have experimental raw-HTTP clients using ML-KEM-512/1024, ML-DSA-44/87,
  Falcon, or SLH-DSA variants: add `CRYPTO_MODE=extended` to your `.env`. The
  official SDKs (sdk-js, sdk-py) and browser crypto are not affected; they have
  always used ML-KEM-768 + ML-DSA-65.

### CLI
- 12 new operator tools added to `scripts/` and available via `install-client.sh`:
  - **Sector tools:** `paramant-cra`, `paramant-firmware`, `paramant-legal`, `paramant-notary`, `paramant-payslip`, `paramant-referral`, `paramant-ticket`
  - **Security:** `paramant-crypto-audit` (scan for quantum-vulnerable algorithms), `paramant-hybrid-check` (verify PQC hybrid mode)
  - **Maintenance:** `paramant-migrate`, `paramant-roadmap` (PQC migration planner), `paramant-supply-chain`
- Total operator tools: 38 → 44

### Documentation
- Site docs rechtgetrokken voor de M5b-realiteit: crypto-stack op `/docs`
  benoemt nu de split (client-side ML-KEM-768 via WASM, server-side
  ML-DSA-65 via `@paramant/core`) met paramant-core attributie + repo-link;
  self-hosting relay-identity sectie idem. `/send` FAQ verduidelijkt dat de
  anonieme flow AES-256-GCM symmetric-only is en verwijst voor
  post-quantum geverifieerde transfers naar ParaShare/ParaDrop. Stale
  `scripts/paramant-admin.py`-pad rechtgezet naar `deploy/paramant-admin.py`.
  R005 (web onboarding wizard) en R007 (add-on architecture) als
  coming-soon vermeld. Versie-nummers bewust ongemoeid (intern 3.0.0 vs
  marketing build 2.5.0).
- New customer-facing `/trust` page (`frontend/trust.html`): plain-language
  transparency on how license-check works, what Paramant can and cannot see
  of a relay, how to verify a deployment (source / image / planned signed
  releases / CT log), and which remote actions are possible versus
  structurally impossible. Every claim tagged Live or Planned; planned items
  link to the public protocol ADRs (R013 licensing, R014 management plane,
  R015 releases, R016 open-core). Linked from the About nav and footer on all
  pages, plus cross-refs from `/docs` and `/security`.

### Repository
- `scripts/` in `paramant-relay` is now the single source of truth for all CLI tools — previously split between this repo and `ParamantOS/nixos/scripts/`
- Server-side tools moved from `scripts/` to `deploy/`: `fix-nginx-ports.py`, `paramant-admin.py`, `post-install.sh`, `preflight.sh`, `server-fix.sh`, `verify-license.js`
- `ParamantOS` now consumes `paramant-relay` as a Nix flake input — no more script duplication between repos

---

## [3.0.0] - 2026-05-27

Major-version bump for the M5b paramant-core integration. 3.0.0 is now the
SINGLE version across the project: `package.json`, the `/health` endpoint, the
README badge, the site build labels, the installer pin, and the primary docs all
report 3.0.0.

### Changed - Version unification (issue #45)

Reverses the earlier split-version strategy (commit 77bb8d3, "keep marketing
2.5.0"). That split left the surface drifting three ways -- `/health` and
`package.json` at 3.0.0, the README badge and site copy at 2.5.0, and the
installer pinned at 2.4.5 -- which the 2026-05-27 site audit flagged (M-01) and
issue #45 tracked. There is now one version.

- README version badge + `/health` examples: 2.5.0 -> 3.0.0.
- `relay/package.json` (+ lock): 2.5.0 -> 3.0.0 (root `package.json` already 3.0.0).
- `install.sh`, `frontend/install.sh`, `frontend/install-pi.sh` pin: v2.4.5 -> v3.0.0.
- `relay/Dockerfile` OCI image label: 2.4.5 -> 3.0.0.
- `relay/README.md` header + all `frontend/*.html` build labels and version
  stamps + the primary how-to guides (api / self-hosting / licensing / ot /
  dicom): -> 3.0.0.

Deliberately NOT changed: SDK packages (`sdk-js`, `sdk-py` are independently
versioned and already AHEAD at 3.1.0 -- downgrading would be a regression);
historical records (the `[2.4.5]`/`[2.4.4]` release sections, "patched in v2.4.5"
findings, `SECURITY.md`, `docs/security*.md`, the dated 2026-04 and 2026-05-27
audit reports); ParamantOS release-tag links (separate, deprecated product); and
the investor brief's "v2.4.5 live in production" statements (production genuinely
lags main per audit M-01 -- claiming 3.0.0-live would be false until deployed).

ParaSign GA will pick its own version (3.1.0 or 4.0.0) at launch; 3.0.0 is no
longer reserved for it.

### Changed (M5b architecture)
- ML-KEM-768 keygen now runs on the Rust `@paramant/core` NAPI binding instead of
  the JavaScript `@noble/post-quantum` library (M5b, PR #33). Wire format and
  client behavior unchanged; this is an internal crypto-implementation swap.
- Multi-stage Dockerfile builds the `@paramant/core` binding for musl in-image,
  pinned by `PARAMANT_CORE_COMMIT` (currently `dc454d4`, `@paramant/core`
  0.5.0-alpha.1).

### Added
- `docs/adrs/` with R001-R004 documenting previously-implicit relay design
  decisions (hot-fix flow, crypto-wasm vendoring, multi-stage Dockerfile,
  blind-store policy).
- README "Powered by paramant-core" section cross-referencing
  Apolloccrypt/paramant-core.

### Fixed
- Login regression: `email` is now persisted in the in-memory `apiKeys` map on key
  creation; `users.json` writes are atomic (tmp + rename); `/v2/reload-users`
  refuses to wipe a populated map from an empty/partial read.

## [0.9.0-beta] - 2026-04-20  <!-- session 4 additions -->

### Added
- Centralized email template module (`admin/lib/email-templates.js`) with
  5 enterprise-grade transactional emails: setup (new + reset variant),
  reset confirmation, welcome/API key, billing confirmation, billing
  cancellation. Dual plain-text + HTML body on all. Preheader, masked IP
  footer, List-Unsubscribe header.
- Per-user Force TOTP enforcement — admin can require TOTP setup before
  next login; active sessions revoked immediately on enable
- Two-stage TOTP reset flow: request email → confirmation email (1h TTL)
  → TOTP cleared only after user clicks confirmation link
- Email enumeration protection: request-totp-reset always returns 200
  regardless of whether email exists in system
- Rich per-user email action menu with preview-before-send flow
- Pagination on Users list (page, page_size, status, plan filters);
  admin.html loadUsers passes params + renders Prev/Next controls
- Audit logging on all mutating admin endpoints (resend-setup, revoke-all-keys)
- Global audit ZSET (`paramant:audit:global`) for O(log n) recent-events
- `email` and `created` fields persisted on all new user records; backfilled
  on 27 existing accounts
- API key masking in users list (first 8 + last 4 chars); full key only in
  user-detail endpoint (audited access)
- Clean JSON error responses on malformed admin input (no HTML stack traces)
- WCAG AA accessibility on admin panel: skip link, aria-live region,
  role=tab/tabpanel/menu, roving tabindex, scope=col, focus-visible CSS
- Admin panel comprehensive documentation (`admin/ADMIN.md`)
- Prometheus config (`monitoring/prometheus.yml`) + monitoring setup guide
  (`docs/monitoring-setup.md`)

### Changed
- From-address on all transactional emails: `noreply@` → `hello@paramant.app`
- Reply-To set on all transactional sends
- TOTP reset confirmation link TTL: 15 minutes → 60 minutes
- `delete_account` admin rate limit: 3/day → 50/day
- User list now filtered/paginated server-side instead of client-side

### Fixed
- Admin panel showing `—` instead of `0` for empty stat cards
- Relay dashboard showing 0h uptime — endpoint now merges /metrics + /health
- Delete-account causing "Error loading users" on next refresh
- Send ADMIN_TOKEN headers on all internal `callRelay()` calls (was missing,
  causing all relay admin calls to return 401)
- Correct modal element IDs to match JS function references
- Enable Delete button only when user has typed `DELETE` in confirmation field
- Blobs field mismatch between relay response and frontend expectation

### Security
- TOTP reset flow: two-stage confirmation prevents abuse via known email
  addresses; attacker needs inbox access to complete reset
- Rate limits on reset flow: 5/email/24h + 10/IP/1h
- Error responses return JSON, never HTML stack traces (no internal paths
  or server info leaked on malformed requests)

## [0.9.0-beta] - 2026-04-19

### Added
- User signup flow at `/signup` with TOTP enrollment (no password required)
- Admin: resend TOTP setup link button (commit `e0be667`)
- Admin: five-tab dashboard (Overview, Users, Audit, Billing, Relay) with v4 Denim Edit styling (commit `eb4f496`)
- Billing scaffold endpoints with Stripe placeholder — checkout, cancel, status, history (commit `a9bff81`)
- Chromium browser extension with dual-mode authentication (API key + TOTP)
- Outlook Add-in source scaffold (manifest, taskpane, commands)
- Navbar with auth-state aware Sign in / Create account CTAs (commit `7253853`)
- Security audit executed 2026-04-19 — 6-layer scope, low risk rating (0 critical, 0 high)
- Wazuh SIEM agent connected to Wazuh Manager via Tailscale

### Changed
- GitHub Actions pinned to commit SHAs for supply-chain security (PR #18)
- TOTP v2 user authentication rolled out to beta users; Q2 2026 rollout banners removed
- Setup flow now requires explicit user click before QR code generation (prevents email scanner consumption)
- `POST /api/user/auth/setup/:token` is idempotent: returns existing TOTP secret for provisional (unactivated) enrollments rather than 409
- `@noble/post-quantum` dependency updated to 0.6.1

### Fixed
- Setup token consumption bug: email link scanners (Gmail, Barracuda, Proofpoint) were pre-loading setup URLs, consuming the one-time token before the user clicked (commits `518138e`, `89fd530`)
- `INTERNAL_AUTH_TOKEN` missing from admin container environment — all internal relay calls returned 401
- `ENABLE_USER_TOTP` missing from relay container environment — TOTP endpoints were inactive
- Nginx `/rp/` proxy port mismatches per sector relay
- Wazuh agent outbound connectivity after UFW default-deny reboot side effect

### Security
- Setup tokens no longer consumed by email preview scanners; click-gate added to `setup.html`
- `POST /v2/user/setup-totp` returns existing provisional secret on repeat, eliminating orphaned TOTP state
- Full 6-layer automated security audit completed; findings fixed before close of session
- Load tested to 500 req/s with p95 latency 135 ms and zero errors; all containers remained healthy

---

## [2.4.5] — 2026-04-13

### Security
- Applied all 20 findings from R. Zwarts audits (2026-04-10 + 2026-04-11)
- Server hardening: SSH (`PermitRootLogin prohibit-password`, `MaxAuthTries 3`), HSTS on all 7 nginx server blocks, TLS restricted to 1.2/1.3 with forward-secret cipher suite (`ECDHE-*-GCM` + `CHACHA20-POLY1305`) on all 443 vhosts, CSP cleaned (Google Fonts removed), `.env` permissions (600) fixed, `atd` disabled, NATS moved to dedicated non-root user
- Docker containers confirmed running as non-root (admin + relay)
- Stale debug process killed (API key was visible in `ps aux`)
- Spurious `arm64` architecture removed from `apt` sources
- `/download` (outdated v0.2.0) and `/chat` (orphaned) return 410 Gone
- `/security` and `/changelog` redirect to GitHub
- CIS Ubuntu 24.04 benchmark: 114 checks applied (full results in SECURITY.md)

### Certificate Transparency
- Inclusion proofs (`GET /v2/ct/proof?index=N`) now included with every upload response — senders receive the Merkle audit path at time of upload without a second round-trip
- Delivery receipts (`POST /v2/verify-receipt`) — receiver gets an ML-DSA-65 signed receipt on download; any party can later submit it to confirm the blob was destroyed and the event is in the CT log
- STH persistence fix — `data/sth.json` now written atomically (write to `.tmp` then rename); prevents empty-file corruption on unclean shutdown
- Cross-relay gossip: STHs pushed to all registered peers after every tree update; peer STH history stored in `data/peer-sths/{pk_hash}.jsonl`
- RSS feed (`GET /ct/feed.xml`) — last 20 STHs as RSS items for independent archiving

### SDK
- **JS SDK**: added `verifyReceipt(receipt)` method — was present in Python SDK but missing from JS SDK
- **Python SDK**: version corrected to `2.4.5`; all Dutch docstrings and section headers translated to English; module docstring rewritten
- **`scripts/`**: `paramant_sdk.py` and `paramant-receipt` converted from stale file copies to symlinks `→ ../sdk-py/` — eliminates future drift between the pip package and the scripts directory

### CLI
- `paramant-verify-sth`: falls back to unauthenticated `GET /v2/sth` when admin token is unavailable; `--relay` flag selects target relay
- `paramant-verify-peers`: fetches mirrored STH history from each peer, verifies ML-DSA-65 signatures, cross-checks against source relay, reports tree-size rollbacks

### Infrastructure
- `docker-compose.yml` fully restored — file had been emptied, breaking self-hosting. Now contains all 5 relay services + admin with full security hardening (`cap_drop: ALL`, `no-new-privileges`, `read_only`, `tmpfs`, 1500 MB memory limit, `127.0.0.1` port binding)
- `install.sh` / `install-pi.sh` fixed — GitHub raw URL was returning 404 due to path change; both scripts updated to current repo layout
- Base image `node:20-alpine` → `node:22-alpine` (Node 20 EOL April 2026)
- `express` 4.x → 5.x
- 0 npm audit vulnerabilities across all packages

### Website
- Navbar rebuilt — horizontal scrolling eliminated; layout rewritten with flex wrap + scroll-on-overflow; all navigation links verified
- Dutch strings removed from frontend — UI is now fully English
- `/verwerkersovereenkomst` → `/dpa` (canonical URL, old URL still serves the page)
- `/government` page added (public sector use cases)
- HNDL risk indicator stripped from the homepage hero
- CT log widget added to homepage — shows live tree size + latest root
- Professional tier added to pricing page
- Request-key form (`/request-key`) fixed — form submission was silently failing due to wrong JSON field name

### Dependencies
- New Ed25519 license token (stricter validation in v2.4.4+)

### Fixed
- Admin login: `timingSafeEqual` + per-IP rate limiter (max 5/min)
- `safeEqual()` now enforced on all `ADMIN_TOKEN` paths (3 relay paths were bypassed)
- TOTP: full window scan + `_usedTotpCodes` set for replay prevention
- Blob deletion deferred until transfer complete (`res.finish()`)
- Async write queue for `users.json` — no more blocking I/O on key create/revoke
- Relay registry: cap enforced + `limit`/`offset` pagination added
- CT log: switched to async write stream + size-based rotation
- Webhook SSRF: DNS resolution before connect + port allowlist (443 + 80 only)
- DID lookup: O(1) via `didRegistry.get(did)` (was O(n) scan)
- WebSocket connections closed on key revocation (`ws.close(4401)`)
- `VALID_PLANS` allowlist — arbitrary plan strings no longer accepted
- `TOTP_SECRET` validated at startup with clear error on invalid Base32
- NEN 7510 finding #4 (plaintext filename in relay RAM) patched — filename now encrypted before relay storage

### Added
- `paramant-crypto-audit` — crypto inventory scanner: 10 categories (TLS, SSH, email, disk, VPN, database, code, deps, services, old files), HNDL risk scoring, JSON + human-readable output, `--remote HOST` mode via SSH self-pipe
- `paramant-migrate` — crypto-agility helper: `--tls` (RSA→ECDSA P-256), `--ssh` (RSA→Ed25519), `--backup` (age/BorgBackup re-encryption), `--check` verification, `--dry-run` mode
- Seven sector scripts for ParamantOS: `paramant-notary`, `paramant-payslip`, `paramant-legal`, `paramant-ticket`, `paramant-referral`, `paramant-firmware`, `paramant-cra`
- Self-service trial key page (`/request-key`) with rate-limited backend (`POST /v2/request-trial`, 1 request/email/7 days, Resend delivery)
- SLA page (`/sla`) — uptime commitments, downtime credits, support tiers, measurement methodology

---

## [2.4.4] — 2026-04-11

### Security — RAPTOR audit (relay findings)

- **H1 — Admin container read-only FS**: `docker-compose.yml` admin container now has `read_only: true` and `tmpfs: /tmp:size=32m,mode=1777` — matching the `relay-hardening` baseline applied to all relay containers since v2.3.3.
- **M1 — Timing-safe admin token**: `admin/server.js` replaced `token === ADMIN_TOKEN` with `crypto.timingSafeEqual(Buffer.from(token), Buffer.from(ADMIN_TOKEN))` — prevents timing-oracle attacks on the admin login endpoint.
- **M2 — MFA rate limiting**: `relay.js` now enforces a per-IP rate limit on `POST /v2/admin/verify-mfa`: max 5 attempts per minute. Excess requests receive `HTTP 429` with `Retry-After: 60`. Defends against brute-force TOTP attacks.
- **M3 — device_id length cap**: `POST /v2/pubkey` rejects `device_id` longer than 256 characters with HTTP 400. Prevents memory exhaustion via oversized Map keys.
- **M4 — sdk-py sync**: `sdk-py/paramant_sdk.py` (pip package) overwritten with `scripts/paramant_sdk.py` (v2.4.1). Brings the pip package up to date with the HKDF salt fix (finding #7), GCM AAD fix (finding #8), and full API surface. **Closes audit finding #3 (Python SDK missing zeroization).**
- **M5 — XSS in admin overview**: `admin/public/index.html` sector card now escapes the server-supplied sector name via `esc()` before inserting into `innerHTML`.
- **L4 — Email validation**: `relay.js` `POST /v2/admin/keys` validates the supplied email address (max 254 chars, basic format regex) and caps the label field at 128 chars.

---

## [2.4.2] — 2026-04-11

### Added

- **Relay registry via CT log** — Every relay announces itself at startup. New public endpoints (no API key required):
  - `POST /v2/relays/register` — ML-DSA-65 signed self-registration. Validates signature over `url|sector|version|timestamp`, rejects timestamps older than 5 minutes (replay prevention). Registration is appended to the CT log as a `relay_reg` entry, creating a tamper-evident audit trail.
  - `GET /v2/relays` — Returns all verified relays: `url`, `sector`, `version`, `edition`, `pk_hash`, `verified_since`, `last_seen`, `ct_index`.
  - Three new env vars: `RELAY_SELF_URL` (this relay's public URL), `RELAY_PRIMARY_URL` (where to POST registration, default: self), `RELAY_IDENTITY_FILE` (keypair path, default: `/data/relay-identity.json`).
  - On first boot each relay generates an ML-DSA-65 identity keypair and persists it to `/data/relay-identity.json`. On subsequent restarts the same keypair is reused — `verified_since` therefore proves how long a relay has been continuously running the same identity.

- **CT log `relay_reg` entries** — CT log now contains two entry types: `key_reg` (existing pubkey registrations) and `relay_reg` (relay self-registrations). Both share the same Merkle tree — every relay registration is provably included in the same tamper-evident audit chain as key registrations.

- **ct-log.html — "Registered Relays" tab** — Second tab on the CT log viewer shows all registered relays in a table: URL, sector, version, edition, verified_since, last_seen.

- **paramant-scan — registry-first discovery** — Queries `PARAMANT_PRIMARY/v2/relays` (default: `health.paramant.app`) before running nmap scan. Displays `verified_since`, `pk_hash`, and `ct_index` for each registered relay. Falls back to local network nmap scan when registry is empty or unreachable.

- **SDK-JS CJS+ESM dual exports** — `sdk-js/package.json` now includes `"require": "./index.js"` in the exports map alongside `"import"`. Works with both `require()` (Node.js 22+ CJS interop) and `import`.

### Fixed

- **ML-DSA-65 sign/verify argument order** — In the installed version of `@noble/post-quantum` the API is `sign(message, secretKey)` and `verify(signature, message, publicKey)` — reversed from the documented order. Fixed in relay registry sign and verify calls.

- **Relay deploy workflow** — Docker images are built from `/opt/paramant-relay/relay/relay.js`, not from `/home/paramant/relay/relay.js`. Correct deploy sequence: copy relay.js to the build context → `docker compose build` → `docker compose up -d`. Alias: `paramant-deploy`.

### Changed

- **SDK-JS version** — `2.4.1` → `2.4.2`

---

## [2.4.1] — 2026-04-10

### Fixed

- **ParaShare end-to-end flow** — Multiple runtime bugs in the browser-based session flow resolved:
  - `ghost_pipe` relay mode did not include `/v2/ws-ticket` in its ALLOWED paths → WS ticket endpoint returned 405 for relay-main. Added to allowed list.
  - WS ticket was fetched from sector relay (health) but WebSocket connected to relay-main — different containers, ticket not found. Fixed: ticket now always fetched from same host as WS (`wsHttpBase`).
  - Receiver keypair generation stuck: `noble-mlkem-loader.js` dispatched `mlkem-ready` on `document`, but `ontvang.html` listened on `window`. Fixed to use `window.dispatchEvent`.
  - Receiver pubkey registration inside `ws.onopen` — relay rejects unauthenticated WS upgrades (`!apiKeys.get(apiKey)?.active`) so `onopen` never fired. Moved pubkey HTTP POST before WS connection.
  - WS URL in `ontvang.html` missing `/v2/stream` path → relay destroyed socket at path check. Fixed.
  - `ws.send(fingerprint_ok)` in `confirmFingerprint()` threw on closed WS, aborting encryption. Wrapped in try/catch — file transfer is HTTP-based, WS is best-effort signaling only.

- **Admin panel CSP** — `admin/server.js` CSP lacked `'unsafe-inline'`, blocking all inline event handlers and styles generated by the JS-rendered admin UI. Added `'unsafe-inline'` to `script-src` and `style-src` (acceptable: admin is session-authenticated behind ADMIN_TOKEN + TOTP).

- **WASM blocked by CSP** — nginx CSP for paramant.app missing `'wasm-unsafe-eval'` → WASM instantiation from ArrayBuffer silently failed in Firefox and Chrome 91+. Added `'wasm-unsafe-eval'` to `script-src`.

- **Stale JS caching** — Browsers cached `noble-mlkem-loader.js` and `crypto-bridge.js`. Added `Cache-Control: no-store` nginx location for `*.js` and `*.wasm` files. Added `?v=4` cache-bust suffix on all module imports.

### Changed

- **`VERSION` constant** — bumped from `2.3.6` to `2.4.1` in `relay/relay.js`. The version in code now matches the CHANGELOG and git tags.
- **`/health` endpoint** — `edition` field now included in the public (unauthenticated) base response. Previously `edition` was only visible with `X-Admin-Token`. Self-hosters can now verify their license status without admin credentials: `curl https://your-relay/health | grep edition`.
- **Relay directory cleaned up** — Legacy sector shim files removed from `relay/`: `relay-core.js`, `relay-sector.js`, `ghost-pipe-relay.js`, `relay-health.js`, `relay-legal.js`, `relay-finance.js`, `relay-iot.js`. These were superseded by the unified `relay/relay.js` in v2.4.0. The `relay/` directory now contains only: `relay.js`, `Dockerfile`, `package.json`, `LICENSE`, `README.md`.

---

## [2.3.6] — 2026-04-10

### Security

- **Rust/WASM crypto core** — `crypto-wasm/` crate (wasm-pack, 112 KB) exposes `encrypt_blob` and `decrypt_blob` via `wasm_bindgen`. Implements the same hybrid KEM as the JS path: ML-KEM-768 + ECDH P-256 + HKDF-SHA256 + AES-256-GCM with identical wire format (`0x02 | ctKemLen | ctKem | senderPubLen | senderPub | nonce | ctLen | ct`, 5 MB random padding). `parashare.html` sender path migrated from inline JS to `crypto-bridge.js` → WASM; 30 lines of inline crypto replaced by one `encryptBlob()` call. `decrypt_blob` accepts noble-post-quantum's 2400-byte NIST FIPS 203 decapsulation key format for forward compatibility. **Fixes audit finding #18 (partial).**

- **CSP hardened — `unsafe-inline` removed (finding #18)** — `Content-Security-Policy` on `admin/server.js` and `relay/relay.js` updated: `unsafe-inline` removed from `script-src` and `style-src`; `wasm-unsafe-eval` added (required for WASM streaming instantiation). New policy: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'`.

- **SRI integrity hashes on all local `<script>` tags** — SHA-384 `integrity` + `crossorigin="anonymous"` attributes added to every local script reference in `frontend/*.html`: `jsQR.min.js`, `qrcode.min.js` (drop.html), `relay-status.js`, `ct-stats.js` (index.html). Browser will refuse to execute any of these files if their content is tampered with.

- **Security headers added to all responses** — `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, `Referrer-Policy: no-referrer`, `Permissions-Policy: interest-cohort=()` added to `admin/server.js` middleware and `relay/relay.js` `setHeaders()`. `HSTS` was absent from relay responses entirely.

- **Dead code removed — duplicate admin token checks (finding #16)** — Duplicate `GET /v2/did/:did` handler in `relay/relay.js` removed (second handler at line ~1443 was unreachable — preempted by identical unauthenticated handler before the `isAdminPath` gate). Five redundant `ADMIN_TOKEN` equality checks removed from individual admin handlers (`/v2/admin/verify-mfa`, `POST /v2/admin/keys`, `GET /v2/admin/keys`, `/v2/admin/keys/revoke`, `/v2/admin/send-welcome`) — all paths already verified by the constant-time `isAdminPath` gate using `safeEqual()`.

### Fixed

- **Service worker intercepting cross-origin requests** — `sw.js` called `e.respondWith()` for all requests including ArcGIS tile map requests and jsdelivr CDN assets (three-globe textures). When these cross-origin fetches failed, `caches.match()` returned `undefined`, which is not a valid `Response` — causing "A ServiceWorker passed a promise to FetchEvent.respondWith() that resolved with non-Response value 'undefined'" errors in the browser console. Fixed: fetch handler now returns immediately (no `respondWith`) for any request whose origin does not match `self.location.origin`. Cache version bumped to `paradrop-v2` to force SW update in existing clients.

### Added

- **JS build pipeline** — `build.sh` + `package.json` (devDependencies: `terser`, `javascript-obfuscator`). Runs terser minification then obfuscation (`controlFlowFlattening`, `stringArray`, `stringArrayEncoding: base64`, `selfDefending`) on all `frontend/*.js` → `frontend/dist/`. `frontend/dist/` gitignored.

### Changed

- **Code compression — 711 lines removed across 8 files** — Duplicate handlers, redundant checks, inline docstrings, and comment headers removed without changing any behaviour: `relay/relay.js` (−27), `admin/server.js` (−124), `sdk-js/src/index.js` (−203), `sdk-py/paramant_ghostpipe.py` (−196), `fly-relay/relay.js` (−56), `scripts/preflight.sh` (−78), `frontend/parashare.html` (−34 after WASM migration), `frontend/index.html` (−23).

- **relay VERSION** `2.3.3` → `2.3.6`.

---

## [2.3.5] — 2026-04-09

### Security

- **CT log Merkle tree standardised (finding #14)** — All 7 relay files. Previous implementation used SHA-256 with raw hex string concatenation — no domain separation between leaf and inner nodes, enabling second-preimage attacks. Fixed with RFC 6962-style domain separation using SHA3-256: leaf nodes use `SHA3-256(0x00 || leaf_data_bytes)`, inner nodes use `SHA3-256(0x01 || left_bytes || right_bytes)`. Binary Buffer operations replace hex string concatenation. Odd leaves are promoted unchanged (no self-duplication). `ctInclusionProof()` replaces `slice(-8)`: generates a proper Merkle audit path with `{ hash, position: 'left'|'right' }` per step, enabling O(log n) verifiable inclusion proofs.

---

## [2.3.4] — 2026-04-09

### Security

- **WebSocket API key no longer in URL (finding #13)** — All 7 relay files now expose `POST /v2/ws-ticket` which returns a 30-second one-time `wst_` token. WS upgrade handler prefers `?ticket=` over legacy `?k=` (still accepted with deprecation warning). `drop.html` and `parashare.html` fetch ticket asynchronously before connecting — API key is now only sent in the `X-Api-Key` header, never in the WebSocket URL.

- **Plaintext filename removed from relay metadata (finding #4)** — `file_name` is no longer stored in relay inbound metadata (`file_name: ''`). The confirm download page now shows "Encrypted file". The real filename remains in the encrypted payload and is recovered by the receiver after decryption. `drop.html` and `parashare.html` no longer include `file_name` in inbound meta.

- **Constant-time admin token comparison** — All 7 relay files. Admin token check replaced `===` with `crypto.timingSafeEqual()` via `safeEqual()` helper, preventing timing side-channel attacks on the admin token.

- **Remaining `?k=` query param usage removed from `drop.html`** — `check-key` and `pubkey` fetches migrated from `?k=${apiKey}` query param to `X-Api-Key` header.

- **`connectWebSocket()` made async in `drop.html` and `parashare.html` (finding #2)** — Functions now properly `await` the ticket fetch before constructing the WebSocket URL.

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

[2.4.5]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.4.4...v2.4.5
[2.4.4]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.4.2...v2.4.4
[2.4.2]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.3.6...v2.4.1
[2.3.6]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.3.5...v2.3.6
[2.3.5]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.3.4...v2.3.5
[2.3.4]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.3.3...v2.3.4
[2.3.3]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/Apolloccrypt/paramant-relay/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Apolloccrypt/paramant-relay/releases/tag/v2.0.0
