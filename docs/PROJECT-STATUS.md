# Project status

This file used to be a snapshot of open PRs, branches, ADR counts and production
state, generated once on 2026-05-27. It never regenerated. From its second line
onward it said so itself, and it kept being cited anyway, which is the worst of
both worlds: a document nobody trusts and nobody stops linking to.

The snapshot is gone. Nothing here goes stale on its own any more, because
nothing here is a snapshot.

## Where to look instead

| Question | Answer lives in |
|---|---|
| What is in each version, and what changed since the last one | `CHANGELOG.md` |
| How a release is cut, tagged, published and deployed | `docs/RELEASE.md` |
| How to deploy the current release | `deploy/DEPLOY-3.1.md` |
| What version is running | `/health` on the relay; it reports `package.json` |
| Which PRs and branches are open | `gh pr list`, `gh api repos/:owner/:repo/branches` |
| Why the architecture is what it is | `docs/adrs/` |
| Every environment variable, its default and where it is read | `deploy/.env.example` |
| Direction and milestones | `ROADMAP.md` |

## The findings this file logged

Other documents cite these by number (`docs/adrs/R010`,
`docs/cross-repo-coordination.md`, `docs/audit-readiness-checklist.md`), so they
are kept here rather than deleted with the rest. Status as measured on
2026-09-02.

1. **`relay.js` emitted a `VERSION` that disagreed with everything else.**
   Resolved in 3.1.0. `relay.js` now reads `relay/package.json`, the root
   `package.json` is the single source, and
   `tests/version-consistency.test.mjs` fails the build if any copy drifts.
2. **`install.sh` pinned a version two minors behind.** Still open. The pin is
   a git tag the installer clones, so it can only be bumped after that tag
   exists; `docs/RELEASE.md` step 9 is where that happens.
3. **`paramant-core` has both `docs/ARCHITECTURE.md` and `docs/architecture.md`.**
   Not measured here; it is a `paramant-core` matter.
4. **`install-pi.sh` referenced in deprecation plans but absent.** Superseded:
   `frontend/install-pi.sh` exists, and #310 dropped the Android APK and
   ParamantOS entirely.
5. **ParaSign Sg1 step 3 (`/sign`, `/verify`, `.psign`) not started.** Shipped.
   See the ParaSign entries in the 3.1.0 and `[Unreleased]` sections of
   `CHANGELOG.md`, and the `/v1` signing API in #283.
