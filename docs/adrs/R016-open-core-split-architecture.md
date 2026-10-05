# R016. Open-core split architecture

Date: 2026-05-28

Status: Accepted

Relates to: R013 (license-server protocol), R014 (management plane),
R015 (release-channel model)

## Context

Paramant is evolving from a single source-available relay project to a commercial
product with managed-license tiers, fleet observability, and centrally-
administered customer deployments (R013, R014, R015).

This requires deliberate separation between:

- What customers run on their own infrastructure (must be open, auditable, and
  verifiable)
- What Paramant runs as a service to support customers (must protect customer
  privacy, billing details, internal workflow)

Industry precedent: HashiCorp (Terraform open, Cloud closed), GitLab (Community
Edition open, Enterprise closed), Elastic (open source + Elastic Cloud), Sentry
(self-hosted open + sentry.io closed). All use the open-core model successfully.

## Decision

### Two repositories

**paramant-relay** (existing, public, BUSL-1.1)

- Relay codebase (what every customer runs)
- Frontend (/setup, /admin/settings, /admin/cli, dashboard)
- SDKs (sdk-js, sdk-py, crypto-wasm)
- Documentation at paramant.app/docs
- ADRs R001-R016 (all architecture transparent)
- License-CLIENT module (check-in logic per R013)
- Capability-check middleware
- install.sh, install-pi.sh
- GitHub Actions release pipeline (R015)

**paramant-management** (new, private, all-rights-reserved Paramant)

- License-SERVER (R013 server-side implementation)
- Paramant Fleet (R014 management plane UI + API)
- Customer database schema + migrations
- Billing-integration (Stripe / Mollie / iDEAL)
- Internal support tools
- Email templates for customer communication
- Migration-scripts for customer data
- Audit-trail database (internal log of Paramant-team actions)
- Branding: "Paramant Fleet" (the operational dashboard)

### What customers can verify

Anyone with the public paramant-relay repository can:

1. Verify the code on their server matches GitHub (sha256 of binary)
2. Read the R013 license-protocol spec and confirm the client-side
   implementation matches
3. See exactly what telemetry fields the relay can send (if opt-in)
4. Read the R014 management-plane spec and understand what remote actions
   Paramant can request
5. Verify CT log entries show every Paramant-initiated remote action against
   their relay
6. Confirm capability-gates correctly enforce their license tier (no backdoor
   unlocks)

### What customers cannot see (and why)

- Paramant's customer list (privacy of other customers)
- Billing logic and payment processing (commercial-sensitive)
- Internal support workflow tooling (operational detail)
- Other customers' usage patterns (privacy + competitive sensitivity)
- Paramant team-member identities for specific actions (only "Paramant
  Support" or "Paramant Owner" in the customer-visible audit-trail)

### API contract between the two repos

The contract surface is small and stable.

**paramant-relay -> paramant-management:**

- POST /v1/license/check (R013 protocol)
- POST /v1/release/check (R015 update check)
- POST /v1/telemetry/submit (opt-in, R014 + privacy doc)
- POST /v1/support/audit (paramant-relay logs its own state to the private
  audit on remote-action completion)

**paramant-management -> paramant-relay:**

- Signed responses to the above POSTs
- Optional: signed remote-action commands embedded in the license-check
  response ("force_update", "drain_mode", "issue_support_key")

All cross-repo communication is ML-DSA-65 signed by paramant-management's
signing key (rotated yearly per R013). paramant-relay holds the verifier pubkey
embedded in the source-available binary.

Customers can verify ANY response from paramant-management against the embedded
pubkey -- if the signature is invalid, the response is ignored.

### Version coordination

paramant-relay and paramant-management version independently:

- paramant-relay: R015 stable/beta/edge channels, semver
- paramant-management: internal versioning, no public schedule

Both must remain compatible with the API contract above. The contract is
versioned (currently v1). Breaking changes to v1 require both repos to release
in a coordinated way, with a grace period for old clients.

Customer-relays on older versions continue working as long as v1 is supported
(committed for 24 months from each contract-version introduction).

### CT log discipline (customer transparency principle)

Every action Paramant takes that affects a customer-relay is logged to the
CUSTOMER's CT log (in their own relay), not just Paramant's internal
audit-trail.

Customer-visible CT log entries:

- "support_key_issued by Paramant Support, valid until 2026-06-16 14:32 UTC"
- "license_tier_changed from pro to enterprise by Paramant Owner"
- "force_update_requested target_version=3.2.0 by Paramant Owner"
- "drain_mode_requested by Paramant Support"
- "telemetry_config_modified" (only if the customer didn't initiate it)

The customer cannot see WHO at Paramant performed an action (privacy of the
Paramant team), but sees WHAT was done and WHEN. No surprise actions, no hidden
access.

This is enforced in code: every paramant-management write-action triggers a
write to the target customer-relay's CT log via the R013 check-in response
mechanism. The customer-relay verifies the signed audit-entry and appends it.

The internal audit-trail (private repo) additionally records WHO at Paramant
did what, for accountability + compliance + GDPR data-processing-records.

### Customer-facing /trust page

paramant.app/trust is a new public-facing page that explains:

1. **How license-check works** (link to R013)
   - When the relay calls home
   - What information is sent (license-key, relay-id, version, opt-in
     telemetry)
   - What is returned (signed capability-set)
   - Offline grace period

2. **What Paramant sees** (link to R014 + privacy doc)
   - Customer entity fields (email, company, tier, payment-status)
   - Telemetry fields (opt-in; customer can preview the exact payload)
   - What is NEVER collected (file content, user identities, IPs of transfer
     endpoints, file hashes)

3. **How to verify your deployment** (link to R015)
   - sha256 of Docker images (cosign verify)
   - GPG-signed release tarballs
   - SLSA provenance attestation
   - Diff your running binary against the GitHub release artifact

4. **What we can do remotely** (link to R014)
   - Issue a 24h support-key (you can revoke immediately)
   - Trigger a force-update (customer can defer per tier policy)
   - Set drain-mode (refuses new uploads, completes in-flight)
   - All logged in YOUR CT log, visible to you in real-time

5. **What we cannot do remotely**
   - Read your file content (the relay doesn't have decryption keys)
   - Modify your CT log retroactively (Merkle-tree integrity)
   - Bypass your local TOTP / admin-key (no backdoor)
   - Access your customer-data or other tenants

The /trust page is updated whenever R013, R014, or R015 change. Linked from
/docs, /pricing, and /security.

### License model per repo

- **paramant-relay**: BUSL-1.1 (Business Source License). Free for self-host
  until a threshold of users/revenue (currently 5 users). Converts to Apache
  2.0 after 4 years.
- **paramant-management**: all-rights-reserved Paramant. Not redistributed, not
  licensed externally, internal use only.

This is identical to how HashiCorp licenses (BUSL for OSS + closed Cloud),
Sentry (BSL + closed sentry.io), and similar players operate.

### Access control to the private repo

- Phase 1 (now): Mick only.
- Phase 2 (future): Mick + a delegated security-reviewer (e.g., Ryan Williams
  under NDA).
- Phase 3 (future): Mick + support-team (employees / contractors with signed
  access agreements).

Every access grant is logged. Repo activity audit-trail retained 7 years for
compliance.

### Migration path

No code in paramant-relay needs to move. The license-client module is written
for paramant-relay (per R013); it just needs to know HOW to call
paramant-management endpoints -- which is a configuration item, not a
code-couple.

paramant-management starts as a new empty repo. The license-server + Paramant
Fleet are built there over Phases 1-3 (per the R013/R014 implementation
roadmaps).

paramant.app self-hosting: paramant.app becomes the FIRST customer in this
model. It gets a license-key (unlimited capabilities, internal flag) and checks
in to license.paramant.app like any other customer. This dogfoods the
architecture and ensures it works.

## Consequences

Positive:

- Industry-standard model (HashiCorp, GitLab, Elastic -- a proven path)
- Customer trust: open verifiability of their own relay
- Commercial defensibility: private value (fleet management, billing) lives in
  the private repo
- Audit-readiness: a Cure53 audit can review the public surface in isolation
- GDPR-clean: data-processing records in the private repo, customer
  transparency via /trust + their own CT log
- Easier hiring: contributors to the public repo without exposure to customer
  data

Trade-offs:

- Two repos to maintain (CI/CD must coordinate)
- Cross-repo API contract requires discipline (cannot break v1 without
  24-month notice)
- Customer-transparency commitments (CT log discipline) constrain internal
  workflow
- Some commercial features must remain behind capability-gates rather than
  being entirely separate -- the audit reviews this code

## Alternatives considered

- **Single fully-open repo with no commercial product**: rejected. Cannot fund
  development, support team, infrastructure.
- **Single fully-private repo (relay closed-source too)**: rejected. Loses
  customer trust, audit-readiness, and the EU-sovereignty narrative advantage.
- **AGPL-style open with copyleft on hosted services**: rejected. AGPL
  hostility against commercial cloud-providers misaligns with Paramant's
  customer-as-cloud-provider model.
- **Single repo with a private/ subdirectory excluded from history**: rejected.
  Filter-branch is fragile, accidental leaks are possible, and history-rewrites
  are scary.
- **Source-available but not redistributable**: BUSL-1.1 is exactly this model.
  Adopted.

## References

- R013 License-server protocol (client-server communication)
- R014 Management plane architecture (Paramant Fleet UI + API)
- R015 Release-channel model (versioning + signed releases)
- HashiCorp BUSL adoption:
  https://www.hashicorp.com/blog/hashicorp-adopts-business-source-license
- Open-core defined: https://en.wikipedia.org/wiki/Open-core_model

## Implementation order

1. Create the private repo Apolloccrypt/paramant-management (Mick action)
2. Build the /trust page on paramant.app (parallel autonomous CLI)
3. R013 license-server MVP in paramant-management
4. R013 license-client module in paramant-relay
5. R014 Paramant Fleet UI in paramant-management
6. R015 GitHub Actions release pipeline in paramant-relay
7. paramant.app cuts over to consuming the stable channel via R015
8. First external customer onboarded through Paramant Fleet
