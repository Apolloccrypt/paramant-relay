# Changelog

All notable changes to `paramant-sdk` (Python).

## [3.0.0] — 2026-04-24

### Breaking

- **Dropped `kyber-py` dependency.** Its own README explicitly warns against
  production use (not constant-time, timing-attack vulnerable). Replaced with
  [`pqcrypto`](https://pypi.org/project/pqcrypto/) (backbone-hq, Apache-2.0,
  thin CFFI over audited PQClean C code; pre-built wheels for Linux / macOS /
  Windows).
- **Removed the silent ECDH-P256 fallback.** v2.x quietly degraded to
  classical ECDH when `kyber-py` was absent while still advertising
  post-quantum protection. v3 raises `ImportError` at module load with a
  clear message instead.
- **Wire format v1** (`PQHB` magic, 10-byte header, KEM/SIG algorithm IDs,
  length-prefixed fields). See `docs/wire-format-v1.md`. v2 blobs
  (`0x02` legacy format) are not decryptable by v3.
- **Keypair file layout**: v2 `*.keypair.json` files without `ml_kem_pub` /
  `ml_dsa_pub` are renamed to `*.v2.bak` on first use and a fresh v3 keypair
  is generated.

### Added

- `paramant.wire_format` — byte-exact encoder / decoder matching
  `docs/wire-format-v1.md`. Test vectors reproduced:
    - signed:    `sha256=002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a`
    - anonymous: `sha256=46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef`
- `paramant.crypto` — pqcrypto wrappers for ML-KEM-768 and ML-DSA-65 plus
  AES-256-GCM with the spec's header-based AAD.
- `paramant.capabilities` — `/v2/capabilities` client + `negotiate()` that
  fetches and validates wire version and algorithm support before the first
  send. Unsupported combination raises `CapabilityMismatch`. No silent
  fallback.
- `GhostPipe(..., kem_id=, sig_id=, negotiate_on_init=)` constructor
  parameters for per-client algorithm override.
- `GhostPipe.capabilities()` — returns the relay's `RelayCapabilities`.
- CLI: `paramant-sdk capabilities --key ... --relay ...` prints the relay's
  advertised algorithms.

### Changed

- Default algorithms are now ML-KEM-768 (`0x0002`) + ML-DSA-65 (`0x0002`).
  Anonymous blobs use `sig_id=0x0000`.
- README rewritten to describe real v3 behaviour. v2 marketing claim of
  "ML-KEM-768" — which was only true when users happened to have `kyber-py`
  installed and never verified — removed.

### Required upgrades

1. `pip install 'paramant-sdk>=3'`
2. Environment must support `pqcrypto` wheels (Linux / macOS / Windows).
3. In-flight v2 blobs need to be re-encrypted under v3 (wire format
   incompatibility).
