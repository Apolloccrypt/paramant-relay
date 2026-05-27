# R009 -- Deprecate ParamantOS as the primary distribution route

Status: Accepted (documents an existing direction)
Date: 2026-05-27
Deciders: Mick (project owner)
Relates to: R005 (plug-and-play onboarding), R010 (packaging formats)

## Context

PARAMANT shipped two ways to stand up a relay:

1. ParamantOS -- a hardened NixOS image (repo Apolloccrypt/ParamantOS) with the
   Ghost Pipe relay baked in, aimed at operators who want a turnkey box.
2. The relay repo itself -- docker compose + install.sh, plus a large set of
   operator tools under scripts/.

Maintaining a full OS image is high-cost: NixOS pinning, kernel/security
updates, image rebuilds, and a separate release cadence, all for a small
operator audience. Meanwhile the docker + install.sh path has matured: scripts/
already contains 53 paramant-* operator tools (backup, doctor, keys, migrate,
notary, verify-sth, status, security, supply-chain, etc.), which is where most
of the operator value that ParamantOS bundled now lives.

## Decision

Deprecate ParamantOS as the primary distribution route. The supported path
becomes: any modern Linux host (Debian/RHEL family) + Docker + the relay repo's
install.sh, with operator tooling delivered via scripts/.

Concretely:

- Archive the Apolloccrypt/ParamantOS repository (read-only, with a deprecation
  notice in its README pointing at install.sh).
- Treat relay/scripts/ as the canonical home for operator tooling. The migration
  is effectively done -- new tools land here, not in an OS image.
- Keep install.sh as the single plug-and-play entry point. (NOTE: install-pi.sh
  does not currently exist; if a Raspberry-Pi-specific path is later wanted it
  should be authored deliberately rather than assumed.)
- Remove ParamantOS / NixOS-image references from the marketing site and docs as
  part of the sessie-7 site-rechttrek work.

## Consequences

Positive:
- One release cadence and one supported install path; less surface to keep
  patched.
- Operators on any host (cloud VM, bare metal, NUC) are first-class, not just
  ParamantOS users.

Negative / trade-offs:
- Operators who valued a fully baked, attested OS image lose that option. The
  hardened-host concern moves to documentation (recommended sysctl/firewall
  baseline) rather than a shipped image.
- Anyone running ParamantOS today needs a documented migration to docker +
  install.sh before the archive.

## Not in scope

- Building install-pi.sh (separate decision if a Pi path is wanted).
- Reproducible-build / image attestation (would return only if a turnkey
  appliance is reconsidered post-audit).
