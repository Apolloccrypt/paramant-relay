# Paramant SDK for Python — real post-quantum file encryption

Python client for the PARAMANT post-quantum relay.

**v3.0.0** swaps the v2.x `kyber-py` dependency (whose own README explicitly
warns against production use: not constant-time, timing-attack vulnerable)
and the silent ECDH fallback for [`pqcrypto`](https://pypi.org/project/pqcrypto/)
— a thin CFFI wrapper around the audited PQClean C implementations. The SDK
now produces wire-format v1 blobs (`PQHB` magic) and negotiates algorithm
support with the relay via `GET /v2/capabilities` before the first send.

Default algorithms: **ML-KEM-768** (NIST FIPS 203) for key encapsulation and
**ML-DSA-65** (NIST FIPS 204) for signatures.

## Install

```bash
pip install 'paramant-sdk>=3'
```

`pqcrypto` ships pre-built wheels for Linux, macOS and Windows — no compiler
needed. If the install fails because wheels are missing for your platform, the
SDK will raise a clear `ImportError` at module load rather than silently
degrading.

## Quick start

```python
from paramant_sdk import GhostPipe

# Defaults: ML-KEM-768 + ML-DSA-65, wire format v1
gp = GhostPipe(api_key='pgp_your_key', device='sender-001')
gp.receive_setup()

# Send
blob_hash, inclusion_proof = gp.send(b'encrypt me', recipient='receiver-001')

# Receive (burn-on-read)
data, receipt = gp.receive(blob_hash)
```

### Overriding algorithms

```python
# Anonymous (unsigned) blob: still ML-KEM-768, but no sender identity attached
gp = GhostPipe('pgp_...', 'device', sig_id=0x0000)

# Future: when the relay loads Falcon-512 for signatures
gp = GhostPipe('pgp_...', 'device', sig_id=0x0100)
```

The client calls `/v2/capabilities` before the first blob and validates that
the relay supports the requested `kem_id` / `sig_id`. Unsupported combination
→ `CapabilityMismatch`. No silent fallback.

### Capabilities introspection

```python
caps = gp.capabilities()
print(caps.wire_version)        # 1
print(caps.kem_names())         # ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']
print(caps.sig_names())         # ['none', 'ML-DSA-44', 'ML-DSA-65', 'Falcon-512', ...]
```

## Breaking changes from 2.x

- **Dependency swap**: `kyber-py` removed, `pqcrypto>=0.4,<1.0` required.
  kyber-py was author-declared not production-safe (see its own README).
- **ECDH silent fallback removed**. v2.x degraded to ECDH-P256 + AES-GCM when
  `kyber-py` was absent while still advertising post-quantum protection. v3
  raises `ImportError` at module load if `pqcrypto` is missing.
- **Wire format**: legacy 0x02 format is gone. v3 produces and consumes wire
  format v1 (`PQHB` magic, 10-byte header, algorithm IDs, length-prefixed
  fields). See `docs/wire-format-v1.md`.
- **Capability negotiation**: the client calls `/v2/capabilities` on
  construction. Disable with `negotiate_on_init=False` for offline testing only.
- **Keypair file** (`~/.paramant/<device>.keypair.json`): v2.x files without
  `ml_kem_pub` / `ml_dsa_pub` are renamed to `*.v2.bak` on first use and a
  fresh v3 keypair is generated. **v2 blobs cannot be decrypted by v3.**
- **Python**: minimum 3.10 (unchanged).

## Migration

```python
# 2.x: silent ECDH fallback, empty ML-KEM hex, wire format 0x02
from paramant_sdk import GhostPipe
gp = GhostPipe('pgp_...', 'device')     # may have silently used ECDH
gp.send(data)                           # blob starts with 0x00 00 00 ?? length prefix

# 3.x: real ML-KEM-768 + ML-DSA-65, wire format v1 (PQHB)
from paramant_sdk import GhostPipe
gp = GhostPipe('pgp_...', 'device')     # ImportError if pqcrypto missing
gp.send(data)                           # blob starts with 50 51 48 42 (PQHB)
```

In-flight 2.x blobs will not decrypt under v3 — plan a drain window or
re-upload.

## Algorithm matrix

| Component | Algorithm       | ID (wire) | Source                  |
|-----------|-----------------|-----------|--------------------------|
| KEM       | ML-KEM-768      | `0x0002`  | pqcrypto / PQClean       |
| Signature | ML-DSA-65       | `0x0002`  | pqcrypto / PQClean       |
| Signature | (none, anon)    | `0x0000`  | skips signature section  |
| AEAD      | AES-256-GCM     | —         | `cryptography`           |
| KDF       | HKDF-SHA-256    | —         | `cryptography`           |

The relay may load additional algorithms (ML-KEM-512/1024, ML-DSA-44/87,
Falcon-512/1024, SLH-DSA). Check `gp.capabilities()` at runtime.

## Security properties

- **Post-quantum KEM**: ML-KEM-768 meets NIST FIPS 203 category 3.
- **Post-quantum signatures**: ML-DSA-65 meets NIST FIPS 204 category 3.
- **Header integrity**: the 10-byte wire header (magic, version, KEM_ID,
  SIG_ID, FLAGS) is bound to the payload via GCM AAD. A bit-flip in the
  algorithm IDs aborts decryption.
- **Key zeroization**: best-effort `ctypes.memset` of shared secrets and
  derived AES keys on CPython. Non-CPython runtimes emit a warning.

## Version

Current: **3.0.0** — matches relay v3 wire format, interoperable with
`sdk-js >= 3` and the Chromium / Outlook clients.

[Full API docs](https://paramant.app/docs) · [GitHub](https://github.com/Apolloccrypt/paramant-relay)
