# Changelog

## 3.0.0 — 2026-04-24

**Breaking release.** See README for full migration notes.

### Real post-quantum crypto

- Added `@noble/post-quantum` `^0.6.1` as a runtime dependency.
- Replaced empty-array KEM placeholders (`new Uint8Array(0)`) and the
  ECDH-P256 fallback with real `ml_kem768.encapsulate` / `.decapsulate`.
- Signing is wired up to `ml_dsa65.sign` / `.verify`. The default `sigId`
  is `0x0002` (ML-DSA-65). Pass `sigId: SIG.NONE` (`0x0000`) for anonymous
  blobs with no signature section.
- New device keypair format (`version: 3`) stores real ML-KEM-768 and
  ML-DSA-65 material. Older 2.x keypairs are ignored.

### Wire format v1

- Removed the legacy v0 packet structure.
- Added `src/wire-format.js` with `encode`, `decode`, `buildAAD`, `isV1`,
  bit-exact against the test vectors in `docs/wire-format-v1.md`:
  - signed:    `002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a`
  - anonymous: `46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef`
- AES-256-GCM AAD now binds the 10-byte header plus a 4-byte chunk index.

### Capabilities negotiation

- Added `src/capabilities.js` with `fetchCapabilities(relayUrl)`.
- `GhostPipe` queries `/v2/capabilities` before the first `send()` and
  validates `wire_version`, `kemId`, `sigId` against the advertised set.
  Mismatches throw `UnsupportedAlgorithmError` — no silent fallback.
- New `checkCapabilities` constructor option (default: `true`).

### API changes

- `GhostPipeOptions` gained `kemId`, `sigId`, `checkCapabilities`.
- New public error class: `SignatureError`.
- New public method: `sendAnonymous(data, recipientKemPubHex, opts)`
  that posts a v1 blob (`sigId=0x0000`) to `/v2/anon-inbound`.
- Keypair fields renamed: `kyber_pub` → `kem_pub`, `kyber_priv` → `kem_priv`.
- Re-exports: `wireEncode`, `wireDecode`, `buildAAD`, `isV1`,
  `fetchCapabilities`, `KEM`, `SIG`, `WIRE_VERSION`.

### Documentation

- README rewritten. Removed the 2.x claim of ML-KEM-768 support (which was
  not actually wired up in the code path) and replaced it with an accurate
  description of the real crypto layer.
