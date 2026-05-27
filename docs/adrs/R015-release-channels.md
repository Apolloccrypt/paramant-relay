# R015. Release-channel model

Date: 2026-05-27

Status: Draft (specification only)

Relates to: R001 (hotfix flow), R003 (multistage Dockerfile). Forward-references
two planned-but-unwritten ADRs reserved as R013 (license-server / license-tier
enforcement) and R014 (management plane / fleet control); this ADR is written
before them, so all R013/R014 mentions below are aspirational, not existing specs.

## Numbering note

ADRs R001-R011 exist today. R012-R014 are intentionally reserved for related
in-flight specs (R012 TBD, R013 license-server, R014 management plane) that are
not yet written. This release-channel ADR is filed as R015 to match the project
roadmap numbering; the gap is deliberate, not a mistake.

## Context

Today both Paramant and self-hosters update by pulling `main` HEAD and rebuilding
(`git pull` + `docker compose up -d --build`; see install.sh and the `paramant
upgrade` CLI). There are ad-hoc manual GitHub release tags (latest is v2.4.5,
created 2026-04-14), but they are not part of any systematic model. The
pre-deploy snapshot of 2026-05-27 confirms production still tracks an older main
(all relays reporting 2.5.0) rather than a pinned, signed release.

Problems with the current model:

- `main` HEAD includes work that has not been validated end-to-end.
- A customer cannot say "I want only stable releases".
- No version-pinning: a `git pull` jumps from one main state to another and can
  silently include breaking changes.
- No clean rollback target: "go back to last week's main" is brittle.
- No per-version release-notes: customers do not know what changed.
- Image builds happen on every customer's hardware (slow, non-reproducible, no
  signature to verify).

A commercial product needs versioned, signed, tagged releases on documented
channels, with customer control over the update path.

## Decision

### Three release channels

- **edge**: every successful main build. For development, internal testing, and
  contributors. Not recommended for production.
- **beta**: weekly cut from edge, after smoke tests + a 48h burn-in. For early
  adopters and advanced users.
- **stable**: monthly cut from beta, after a 14-day feedback window. The default
  for commercial customers.

Time targets (aspirational, adjustable):
- edge: continuous (every main merge)
- beta: weekly, Tuesday
- stable: first Tuesday of each month

### Version-tag scheme

Semantic versioning MAJOR.MINOR.PATCH:
- PATCH: backward-compatible bugfix (3.0.1, 3.0.2)
- MINOR: backward-compatible feature add (3.1.0, 3.2.0)
- MAJOR: breaking change (4.0.0)

Channel suffix lives on the git tag, not on the version string the relay reports:
- `3.0.0-edge.123` (build 123 of the edge stream)
- `3.0.0-beta.4` (4th beta cut toward 3.0.0)
- `3.0.0` (stable, no suffix)

Docker images (`mtty001/relay`):
- `mtty001/relay:edge`    (latest edge)
- `mtty001/relay:beta`    (latest beta)
- `mtty001/relay:stable`  (latest stable)
- `mtty001/relay:3`       (latest 3.x stable)
- `mtty001/relay:3.0`     (latest 3.0.x stable)
- `mtty001/relay:3.0.0`   (exact version, immutable)

### Customer-side channel selection

In `.env`:
- `CHANNEL=stable` (default when install.sh runs without flags)
- `CHANNEL=beta`
- `CHANNEL=edge` (NOT RECOMMENDED FOR PRODUCTION; install.sh shows a warning)
- `VERSION_PIN=3.0.0` (overrides CHANNEL, pins an exact immutable version)

install.sh asks during onboarding (and the M11 /setup wizard offers the same):
```
Which release channel do you want?
  [s] stable  (recommended for production)
  [b] beta    (early access, weekly updates)
  [e] edge    (development, every commit, NOT recommended)
```

### GitHub Actions workflow

On every merge to `main`:
1. Run the full test suite (the existing sdk-js / sdk-py / shell / relay crypto
   jobs).
2. Build the Docker image; push as `:edge` and `:edge-<short-sha>`.
3. Create a git tag `edge-build-<num>`.
4. Append to edge release-notes.

On manual trigger (the cut moment is a human decision by the maintainer):
1. Promote latest edge -> beta: re-tag the image, create the git tag, generate
   release-notes from edge commits since the last beta.
2. Promote latest beta -> stable: re-tag the image, create the git tag, generate
   the CHANGELOG.md entry from the beta notes, announce to customers.

Promotion is one-way. A bugfix on a stable line branches from the stable tag (not
from main) and ships as MAJOR.MINOR.(PATCH+1); see R001 for the hotfix flow.

### Signed releases

Every release asset is signed:
- Cosign for the Docker image (verifiable with `cosign verify`).
- GPG for the tarball + checksum.
- Optionally SLSA provenance attestation.

install.sh verifies the signature before extracting/running. A verification
failure aborts the install (clear message + non-zero exit).

### Release-notes

Auto-generated per release from PR titles + ADR commits since the last release on
that channel:
```
## v3.1.0 (stable) - 2026-07-15

### Added
- License-server check-in (planned license-server ADR)
- Fleet management UI (planned management-plane ADR)

### Changed
- Default crypto-mode now extended for paying tiers (R006 follow-up)

### Fixed
- admin/server.js TOTP refresh race condition (#XYZ)
```

Published to:
- https://paramant.app/changelog (auto-deployed from CHANGELOG.md)
- GitHub Releases (artifacts + signatures)
- Email to customers (opt-in; owner + support roles, once a management plane exists)

### Update mechanism on the customer relay

The relay checks every 24h:
- `GET https://releases.paramant.app/v1/check?channel=<channel>&current=<version>`
- Response: `{ "latest": "3.1.0", "url": "...", "signature": "...", "notes_url": "..." }`

If a newer version exists on the selected channel:
- Free tier: admin-panel banner "Update available".
- Pro tier: banner + opt-in auto-update within a defined maintenance window.
- Enterprise tier: explicit approval required; never auto-applies.

Update flow (when triggered):
1. Verify the signature on the new image.
2. `docker pull` the new image.
3. Enter drain mode (refuse new uploads).
4. Let in-flight transfers complete.
5. Replace the running container with the new image.
6. Health-check the new container (`/health` + ideally `/v2/health/deep`).
7. If unhealthy after 60s: automatic rollback to the previous image.
8. Audit-log the result + notify the customer.

### Rollback target

Each customer relay keeps the last 3 image tags locally (older auto-pruned).
- `paramant-rollback <version>` or `paramant-rollback --previous`.
- Rolling back across a MAJOR boundary requires an explicit override flag.

This complements the pre-deploy snapshot practice (docs/audit-reports/): the
snapshot records the externally-observable baseline, the local image cache is the
actual rollback artifact.

### Self-host without the release-server (air-gapped)

A future ADR will define offline-license bundles + a local release mirror. This
ADR assumes outbound internet connectivity to releases.paramant.app.

## Consequences

- GitHub Actions cost: low (runner-minutes only).
- Operational overhead: cutting beta + stable requires the maintainer's judgment
  and occasional fixes.
- Customer trust: signed releases + version-pinning are enterprise table stakes.
- Faster onboarding: the stable channel "just works" without building from source.
- More careful main commits: every merge becomes an edge release, so main quality
  directly affects edge users.

Trade-offs:
- Three channels = three surfaces to watch for regressions.
- Cut moments need human judgment (not fully automated).
- Supporting customers on older versions: likely scope to current + previous MINOR.

## Alternatives considered

- **Single rolling channel (current main HEAD)**: rejected. No version pin, no
  rollback target, no customer-controlled stability.
- **Two channels (stable + edge)**: rejected. No middle ground for early adopters
  to validate before stable.
- **Calendar-based releases (e.g. quarterly)**: rejected. Too slow for bugfixes,
  too rigid for feature pace.
- **SaaS-style continuous deploy (everyone always on latest)**: rejected.
  Enterprise customers require change-control windows.

## Implementation order

1. GitHub Actions workflow for edge builds (per main merge).
2. Cosign signing setup (Paramant's release-signing key).
3. install.sh + the M11 /setup wizard ask for the channel during onboarding.
4. /admin/settings shows the current channel + version.
5. Beta + stable promotion scripts (maintainer-triggered first; a management-plane
   button later).
6. Customer-side updater service (gated by license tier, maintenance window,
   auto-rollback).
7. The releases.paramant.app endpoint (or a new route on the license server).
8. paramant.app itself moves to consume the stable channel like any other customer.
