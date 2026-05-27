# R004. Blind-store policy for non-PQHB blobs

Date: 2026-05-27
Status: Accepted

## Context

paramant-relay stores three blob formats:

- PQHB (paramant-core SDK clients).
- 0x03 hybrid (browser crypto-wasm).
- Raw AES-GCM (browser /send, WebCrypto plus URL fragment).

Only PQHB has a relay-side decoder (for algorithm validation). The other two
formats are stored opaquely and served back to recipients without interpretation.

## Decision

Non-PQHB blobs pass through the inbound peek returning null, meaning the relay
accepts the blob, stores it, and serves it on download without inspecting contents.

## Consequences

- Zero-knowledge for browser flows: the relay cannot read what it stores for
  parashare, paradrop, and send.
- Three-format coexistence is permanent by design, not a migration target
  (paramant-core `docs/wire-format-boundaries.md`).
- Browser-side format changes do not affect relay-side decoding.
- Format convergence is functionally unnecessary.

## Alternatives

- Validate all formats at the relay: rejected; breaks the zero-knowledge guarantee
  for browser flows.
- Reject non-PQHB blobs: rejected; would break parashare, paradrop, and send in the
  browser.
