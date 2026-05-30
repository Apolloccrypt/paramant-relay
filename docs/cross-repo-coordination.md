# Cross-repo coordination: paramant-core <-> paramant-relay

How the Rust crypto-core (Apolloccrypt/paramant-core) and the Node relay
(Apolloccrypt/paramant-relay) evolve together. Companion to
paramant-core/docs/ARCHITECTURE.md (the authoritative cross-repo overview).

## Repository roles

- paramant-core: small, auditable Rust crate. Owns crypto primitives (ML-KEM-768,
  ML-DSA-65, hybrid ECDH-P256, AES-256-GCM, Argon2id/HKDF, BIP-0039), KATs, and
  the canonical wire-format spec docs. Exposes a NAPI binding (@paramant/core,
  ADR-0019) and a crypto-wasm path.
- paramant-relay: Node.js service. Owns transport, routing, sectors, admin,
  storage (blind-store, R004), SDKs, and operator tooling. Consumes core for all
  crypto via the registry (registry.getSig/getKem).

## Direction of authority

| Concern                         | Leads      | Mirrors    | Reference        |
|---------------------------------|------------|------------|------------------|
| Crypto primitives + KATs        | core       | relay      | core ADR-0005/12 |
| Wire format (bytes on the wire) | relay      | core       | core ADR-0014    |
| Algorithm registry / IDs        | core       | relay      | core ADR-0007    |
| Send/ParaShare envel.  | core       | relay      | core envelope-*  |
| Operator tooling / deployment   | relay      | --         | R009             |

Rule of thumb: anything that is "what bytes does a client see" is decided in the
relay (it is the live contract with deployed SDKs and HTTP clients) and the core
mirrors it byte-for-byte via its cross-impl KAT. Anything that is "how do we
compute crypto" is decided in core and the relay just calls it.

## Change protocols

### Adding a new algorithm
1. Implement + KAT in core; assign a registry ID (core ADR-0007).
2. Add the NAPI export (core ADR-0019).
3. Bump @paramant/core; publish.
4. In relay, add an impl under relay/crypto/impls/ that requires @paramant/core
   and register it in bootstrap.js. Decide core vs extended tier (R006).
5. If it should be client-visible, add to /v2/capabilities and document the wire
   id.

### Changing the wire format
1. Relay proposes the byte layout (it owns the live contract).
2. Core updates its wire-format-*.md spec + cross-impl KAT to match.
3. Both ship together; a wire bump uses PARAMANT_WIRE_VERSION gating (relay) so
   old clients are not broken silently.

### SDK migrations (per language, gated on M5b stability + audit)
- sdk-js (Node): @noble/post-quantum -> @paramant/core NAPI. Browser build stays
  on @noble or crypto-wasm (no native binding in the browser).
- sdk-py: add a pyo3/NAPI binding to core, then migrate off pqcrypto.
- Migrate one language at a time; keep the wire bytes identical (core KAT is the
  gate) so a migrated SDK and an un-migrated one interoperate.

## Version coordination

- @paramant/core is versioned independently (npm semver) and pinned by the relay.
- Relay images (docker) version independently of core.
- A relay release records the @paramant/core version it bundles, so an audit can
  reconstruct exactly which crypto crate was live.
- OPEN: reconcile the relay marketing version (2.5.0) with the /health-reported
  VERSION (3.0.0, reserved for ParaSign GA) before the first tagged Release
  (see PROJECT-STATUS.md finding #1, R010 versioning rule).

## Where to look

- core: docs/ARCHITECTURE.md, BLUEPRINT.md, docs/wire-format-*.md, docs/adrs/
- relay: README "Powered by paramant-core", docs/adrs/R*.md, ROADMAP.md,
  docs/PROJECT-STATUS.md
