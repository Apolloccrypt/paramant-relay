# R010 -- Plug-and-play package formats

Status: Proposed
Date: 2026-05-27
Deciders: Mick (project owner)
Relates to: R005 (onboarding), R009 (ParamantOS deprecation)

## Context

With ParamantOS deprecated (R009), the relay needs clear, low-friction
distribution formats so a self-hoster can go from zero to a running relay
without reading the whole repo. Today the entry point is git clone +
install.sh. That works for technical operators but is not "click to deploy".

## Decision

Offer a small, ordered set of distribution formats, each with explicit
criteria for when it is the right choice. Build them in this order:

### 1. GitHub Release tarball (highest priority)
- Contents: docker-compose.yml, .env.template, install.sh, scripts/, and a
  pinned image tag.
- Criteria: the default for an operator who has a Docker host and wants a
  versioned, signed artifact rather than a moving git checkout.
- Fixes finding from PROJECT-STATUS.md #2: the release tag becomes the single
  source of truth for "current version", so install.sh stops pinning a stale
  hardcoded version.

### 2. All-in-one docker-compose variant
- A single compose file that brings up all sectors + admin on one host with
  sensible defaults, for evaluation / small deployments.
- Criteria: trials, demos, single-tenant self-hosters who do not need per-sector
  isolation across hosts.

### 3. Helm chart (Kubernetes self-hosters)
- Chart with values for sector replicas, persistence, ingress, and CRYPTO_MODE.
- Criteria: organisations already running k8s who want the relay as a managed
  workload. Gated on demand -- do not build speculatively.

### 4. Marketplace listings
- DigitalOcean Marketplace, Hetzner Cloud Apps, Linode Marketplace.
- Criteria: only after the Release tarball + all-in-one compose are stable and
  the version story is clean, since marketplace images embed a snapshot and are
  costly to update.

## Versioning rule for packages

All package formats derive their version from the GitHub Release tag. No format
hardcodes a version independently (see PROJECT-STATUS.md finding #2). Marketing
version and the /health-reported version must be reconciled before the first
tagged Release so packages do not ship a confusing 2.5.0-vs-3.0.0 split.

## Consequences

- Lower onboarding friction; a documented "right format for your situation".
- Each format is a maintenance surface -- the ordered list keeps us from
  shipping a Helm chart or marketplace image before there is demand or a clean
  version story.

## Not in scope

- Hosted/SaaS relay (separate product decision).
- Auto-update of marketplace images (manual re-publish per Release).
