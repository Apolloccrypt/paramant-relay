# PARAMANT-RELAY ROADMAP

Status snapshot of paramant-relay specifically. For the crypto-core roadmap
see [paramant-core/BLUEPRINT.md](https://github.com/Apolloccrypt/paramant-core/blob/main/BLUEPRINT.md).

Last updated: 2026-05-27T21:00:05+02:00 (auto-maintained by overseer session)

## Current production state

- Live: 116.203.86.81 (Hetzner Frankfurt), 5 sector relays + admin (docker compose)
- Build: v2.5.0 marketing. NOTE: relay.js emits VERSION='3.0.0' via /health while
  commit 77bb8d3 reserves 3.0.0 for ParaSign GA -- see PROJECT-STATUS.md findings.
- Users: ~100 community + enterprise pilots
- Soak: M5b production 7-day clean signal in progress (started 2026-05-27 18:10,
  day 1 of 7)
- Crypto: ML-KEM-768 keygen via @paramant/core (M5b live); ML-DSA-65 via
  @paramant/core merged to main (PR #37), awaiting next routine deploy

## Active development (open PRs + in-flight sessions)

The authoritative live list is in docs/PROJECT-STATUS.md (regenerated each run).
All three parallel-session PRs merged while the overseer ran:

- PR #40: R006 crypto-mode opt-in (sessie 1.5) -- MERGED
- PR #41: R008 low-code routing scope + examples (sessie 5) -- MERGED
- PR #42: site-docs rechttrek for M5b reality (sessie 7) -- MERGED
- PR #43: this overseer PR (roadmap + status + R009/R010 + coordination docs)
- PR #28/#29: dependabot (setup-python, ws) -- routine

## Recently shipped (in main, awaiting next routine deploy)

- R001-R004 bootstrap ADRs + R005 onboarding + R006 crypto-mode + R007 add-on arch
- /setup onboarding wizard scaffold (frontend/setup.html + .js, /v2/setup stubs)
- Cards-per-product user dashboard (frontend)
- ML-DSA-65 STH-signing + receipt-verify migrated to @paramant/core
- crypto-wasm extended with ML-DSA-65 exports (ParaSign Sg1 step 2)
- "Powered by paramant-core" README section
- Version harmonization commit (marketing 2.5.0 / 3.0.0 reserved for ParaSign GA)
- docs/addons/ folder (README + example manifest + compose fragment) for R007
- CRYPTO_MODE bootstrap: production advertises 2 algorithms (down from 18)

## Near-term backlog

### ParamantOS deprecation (see R009)
- scripts/ ALREADY holds 53 paramant-* operator tools -- migration is largely done.
- Remaining: archive Apolloccrypt/ParamantOS repo, remove NixOS-image references
  from site/docs, confirm install.sh as the single plug-and-play entry-point.
- NOTE: install-pi.sh does not currently exist in this repo; if a Pi path is
  wanted it must be authored (or the plan should drop the reference).

### M5b deploy of pending changes
- Routine deploy of current main to production once the 7-day soak is clean.
- Brings R005-R007 + dashboard + /setup wizard + ML-DSA-65 migration + R006 live.
- Required: docker compose build dry-run, rolling restart, /health check per sector.

### Version label cleanup
- Decide whether /health should report 2.5.0 (marketing) instead of the
  reserved-for-GA 3.0.0 now emitted by relay.js:31.
- Bump install.sh VERSION pin from v2.4.5 to the current release tag.

### SDK migration completion
- sdk-js Node path: @noble/post-quantum -> @paramant/core (browser stays @noble or
  crypto-wasm).
- sdk-py: pyo3/NAPI binding to paramant-core, then migrate off pqcrypto.
- Both gated on M5b stability + audit-readiness.

### ParaSign Sg1 step 3 + Sg2
- /sign + /verify frontend routes (today only /v2/sign-dpa exists, unrelated).
- .psign container encoder/decoder.
- paramant-sign CLI tool.
- Beta launch to email signups.

### Plug-and-play packaging (see R010)
- GitHub Release tarball: docker-compose.yml + .env.template + install.sh.
- Single all-in-one docker-compose variant.
- Helm chart for Kubernetes self-hosters.
- Marketplace listings: DigitalOcean, Hetzner Cloud, Linode.

### Add-on framework implementation (R007)
- paramant-addon-install / -enable / -disable / -uninstall CLI scripts.
- Manifest validator + capability-grant flow.
- First-party add-ons: storage-mirror, notification-bridge, MQTT-bridge,
  OIDC/SAML, SIEM-exporter, STH-monitor.
- Admin panel addons tab.

### Low-code routing (R008 -- sessie 5 PR #41 in flight)
- YAML flow-definition format.
- Admin-CLI validator.
- Web-UI viewer (read-only first), then drag-and-drop editor.

### Audit prep (see audit-readiness-checklist.md)
- Cure53 + NCC Group external audit scheduling.
- Pre-audit cleanup: dead code, unused deps, doc coherence.
- Audit-trail report bundle.

## Out of scope

- ParamantOS as the primary distribution route (deprecated -- see R009).
- Multi-tenancy beyond apiKeys (until enterprise pricing tier matures).
- HSM integration (tracked as ParaSign Sg3+).
- Custom crypto-algorithm switching from low-code (security risk per R008).

## Cross-repo coordination

See docs/cross-repo-coordination.md. In short:
- New algorithm in core requires a NAPI binding + relay impl update.
- Wire-format changes lead from relay (canonical); core mirrors (core ADR-0014).
- SDK migrations coordinate per language.
