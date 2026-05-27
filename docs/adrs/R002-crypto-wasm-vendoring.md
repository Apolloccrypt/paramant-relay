# R002. crypto-wasm vendored, not submoduled

Date: 2026-05-27
Status: Accepted

## Context

paramant-relay ships browser-side crypto via `crypto-wasm/` (RustCrypto, compiled
to wasm32). When consolidation was evaluated during paramant-core M6, three options
were on the table:

- G1: submodule paramant-core into paramant-relay.
- G2: extract crypto-wasm to its own Apolloccrypt repo.
- G3: keep it vendored (the current state).

## Decision

Stay vendored. paramant-core owns the cross-impl KAT governance: its
`cross-impl-validator` crate validates the RustCrypto crates that crypto-wasm
depends on against the same `@noble`-anchored KAT vectors the server stack uses
(paramant-core ADR-0020, ADR-0021).

## Consequences

- One repo for relay maintainers: crypto-wasm changes happen alongside relay code.
- The frontend build script finds crypto-wasm at a fixed relative path.
- Cross-impl validation runs in paramant-core CI; relay CI does not need the
  wasm-pack toolchain.
- A future relay-CI wasm-build-smoke job can live here without submodule
  complications.

## Alternatives

- G1 submodule: rejected; structurally invasive, pulls full relay history into the
  audit-facing core.
- G2 own repo: rejected for now; maintenance overhead exceeds the value until
  crypto-wasm has independent consumers.
