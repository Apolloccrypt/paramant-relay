# R006. Crypto mode: opt-in for extended algorithms

Date: 2026-05-27
Status: Accepted

## Context

paramant-relay's registry-based crypto-agility design supports 18 algorithms
(3x ML-KEM, 3x ML-DSA, 2x Falcon, 12x SLH-DSA). The bootstrap process loaded all
18 at startup and /v2/capabilities advertised them all as loaded.

Audit of usage shows:
- sdk-js hardcodes ML-KEM-768 + ML-DSA-65 (no API to choose another)
- sdk-py raises UnsupportedAlgorithm on non-ML-KEM-768 KEM IDs
- the browser crypto-wasm binding hardcodes the same defaults
- the frontend has no UI for selecting alternatives
- no documentation describes how to use the other 16 algorithms
- per docs/wire-format-v1.md, the relay loads only 0x0002 (ML-KEM-768) and 0x0002
  (ML-DSA-65) in practice; the other IDs are reserved

Effectively, 16 of the 18 loaded algorithms are unreachable by official tooling:
registered, advertised via /v2/capabilities, but never exercised on the hot path.
Raw-HTTP power-users could construct PQHB blobs with non-default algorithm IDs,
but no documentation enables this.

This creates audit surface (16 algorithms in scope for an external crypto review)
without operational value. Code-minimization (paramant-core ADR-0004) argues
against it.

## Decision

bootstrap() takes an optional mode parameter, resolved from the CRYPTO_MODE
environment variable (explicit argument > env > default). Two modes:

- 'core' (default): registers ML-KEM-768 (0x0002) and ML-DSA-65 (0x0002) only.
  /v2/capabilities advertises only these (plus the implicit 0x0000 "none" sig).
- 'extended': registers all 18 algorithms. For self-hosters with experimental
  clients using the raw HTTP API.

The impl files remain in tree under relay/crypto/impls/. They are required
eagerly so a syntax error in any impl fails at startup, not at first use. Only
the registration step is gated by mode.

Combined with the ML-DSA-65 migration earlier in this PR, the relay-crypto layer
is now both leaner (default core mode) and grounded on @paramant/core (audit
trail consolidated with the M5b ML-KEM-768 migration).

## Consequences

- Production defaults to 'core'. /v2/capabilities advertises 2 algorithms instead
  of 18. Audit surface for a default deployment drops from 18 to 2.
- A v1 (PQHB) blob that names a non-core algorithm ID is rejected at inbound
  validation in core mode (previously accepted). Official SDKs are unaffected;
  they only ever use 0x0002/0x0002.
- Self-hosters who relied (undocumented) on the other 16 algorithms via raw HTTP:
  set CRYPTO_MODE=extended in .env. No code change.
- Crypto-agility infrastructure remains intact: adding a 19th algorithm means
  adding it to bootstrap.js and optionally promoting it to 'core'.
- The wire-format spec (docs/wire-format-v1.md) still documents all 18 algorithm
  IDs as recognized values. /v2/capabilities is the runtime source of truth for
  what is actually accepted.
- Dependency surface: the two core impls (mlkem768.js, mldsa65.js) route to
  @paramant/core; only the 16 extended impls require @noble/post-quantum. In the
  core default @noble runs no crypto on the hot path (dormant), so the core
  audit surface is @paramant/core, not @noble. @noble cannot move to a
  devDependency, however: bootstrap.js requires all extended impls eagerly (so a
  broken impl fails at startup, not first use), which loads @noble into the
  process even in core mode. Pruning it from runtime deps would mean lazy
  require()s in the extended impls (deferred to extended mode), a separate change
  with its own startup-failure tradeoff.

## Alternatives considered

- Status quo: rejected. Audit-surface overhead for zero operational value.
- Hard delete the impl files: rejected. Loses the crypto-agility infrastructure,
  is a breaking change for hypothetical power-users, and has no rollback path.
- Hard delete with a deprecation period: rejected. A long warning serves nobody
  since no documented users exist.
- Three modes (minimal/core/extended): rejected. Two modes capture the actual
  decision (lean default vs everything).
