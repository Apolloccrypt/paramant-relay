# Paramant Wire Format v1

**Status**: approved 2026-04-24, pending implementation
**Replaces**: v0 (implicit ML-KEM-768 + ML-DSA-65, no magic bytes, no version)
**Breaking change**: yes, no backward compatibility (pre-launch, no production users)

## Why

The previous wire format had no magic bytes, no version byte, and no algorithm identifiers. Receivers had to guess which algorithm produced a blob based on length heuristics and hardcoded assumptions. This made crypto agility impossible in practice: swapping ML-KEM-768 for ML-KEM-1024, or adding Falcon signatures alongside ML-DSA, would have required a full protocol rewrite.

v1 introduces an explicit header that identifies the blob as Paramant, states the format version, declares which KEM and signature algorithms were used, and length-prefixes every variable field. The relay can parse blobs produced by any registered algorithm without being recompiled.

## Goals

- **Crypto agile**: adding a new algorithm requires one register() call, no wire format change
- **Self-describing**: a blob carries all information needed to decode it
- **Relay-blind**: the relay does not need to know the algorithms, only the IDs for routing and capability advertising
- **Integrity-bound**: header fields are included in GCM AAD so they cannot be tampered with in transit
- **Future-proof**: FLAGS byte reserved for compression, multi-recipient, or other v1.x features without requiring v2

## Non-goals

- **Backward compatibility with v0**: explicitly dropped, pre-launch acceptable
- **Negotiation protocol**: clients discover relay capabilities via the new /v2/capabilities endpoint; no in-band negotiation
- **Per-chunk algorithm switching**: one algorithm pair per blob

## Wire format

```
┌──────────────────────────────────────────────────────────────────┐
│ HEADER (10 bytes fixed)                                          │
│  MAGIC       4 bytes   'PQHB' (0x50 0x51 0x48 0x42)              │
│  VERSION     1 byte    0x01                                      │
│  KEM_ID      2 bytes   big-endian uint16                         │
│  SIG_ID      2 bytes   big-endian uint16 (0x0000 = no signature) │
│  FLAGS       1 byte    reserved, must be 0x00 in v1              │
├──────────────────────────────────────────────────────────────────┤
│ KEY ENCAPSULATION                                                │
│  CT_KEM_LEN  4 bytes   big-endian uint32                         │
│  CT_KEM      N bytes   KEM ciphertext                            │
│  SENDER_PUB_LEN 4 bytes big-endian uint32                        │
│  SENDER_PUB  N bytes   sender public key                         │
├──────────────────────────────────────────────────────────────────┤
│ SIGNATURE (skipped entirely if SIG_ID == 0x0000)                 │
│  SIG_LEN     4 bytes   big-endian uint32                         │
│  SIGNATURE   N bytes                                             │
├──────────────────────────────────────────────────────────────────┤
│ PAYLOAD                                                          │
│  NONCE       12 bytes  AES-256-GCM nonce                         │
│  CT_LEN      4 bytes   big-endian uint32                         │
│  CIPHERTEXT  N bytes   AES-256-GCM encrypted                     │
├──────────────────────────────────────────────────────────────────┤
│ PADDING      to nearest 4KB / 64KB / 512KB / 5MB block           │
└──────────────────────────────────────────────────────────────────┘
```

### Field sizes

Fixed overhead: 10 bytes header + 16 bytes length prefixes (4 x uint32) = 26 bytes without signature, 30 bytes with.

Variable content depends on registered algorithms. Reference sizes:

| Algorithm    | Public key  | Ciphertext / signature |
|--------------|-------------|------------------------|
| ML-KEM-512   | 800 bytes   | 768 bytes ciphertext   |
| ML-KEM-768   | 1184 bytes  | 1088 bytes ciphertext  |
| ML-KEM-1024  | 1568 bytes  | 1568 bytes ciphertext  |
| ML-DSA-44    | 1312 bytes  | 2420 bytes signature   |
| ML-DSA-65    | 1952 bytes  | 3309 bytes signature   |
| ML-DSA-87    | 2592 bytes  | 4627 bytes signature   |
| Falcon-512   | 897 bytes   | ~666 bytes signature   |
| Falcon-1024  | 1793 bytes  | ~1280 bytes signature  |
| SPHINCS+-128f| 32 bytes    | 17088 bytes signature  |

### GCM AAD

The AES-256-GCM AAD (additional authenticated data) binds the first 10 bytes of the header and the chunk index to the ciphertext:

```
AAD = MAGIC || VERSION || KEM_ID || SIG_ID || FLAGS || chunk_index_be32
```

This means: an attacker who flips a bit in KEM_ID or SIG_ID causes GCM verification to fail. The algorithm selection is integrity-protected, not just the ciphertext body.

### Padding

Payload is padded to one of {4 KB, 64 KB, 512 KB, 5 MB} to mask true size from a passive observer. Padding scheme identical to v0: zeros appended up to the chosen block size, smallest block that fits the payload is selected.

## Algorithm registry

Algorithm IDs are uint16. Ranges are assigned per family, 256 slots each.

### KEM registry

| ID       | Algorithm                 | Status           |
|----------|---------------------------|------------------|
| 0x0000   | reserved (none)           | invalid for encryption |
| 0x0001   | ML-KEM-512                | FIPS 203, available |
| 0x0002   | ML-KEM-768                | FIPS 203, loaded by default |
| 0x0003   | ML-KEM-1024               | FIPS 203, available |
| 0x0100   | Classic-McEliece-348864   | future |
| 0x0200   | HQC-128                   | future, if NIST standardizes |

### Signature registry

| ID       | Algorithm                 | Status           |
|----------|---------------------------|------------------|
| 0x0000   | none (anonymous blob)     | valid, skips signature section |
| 0x0001   | ML-DSA-44                 | FIPS 204, available |
| 0x0002   | ML-DSA-65                 | FIPS 204, loaded by default |
| 0x0003   | ML-DSA-87                 | FIPS 204, available |
| 0x0100   | Falcon-512                | FIPS 206, available |
| 0x0101   | Falcon-1024               | FIPS 206, available |
| 0x0200   | SPHINCS+-SHA2-128f        | FIPS 205, future |
| 0x0201   | SPHINCS+-SHA2-256f        | FIPS 205, future |

IDs are stable. A later version of this spec may add IDs but never reassigns or removes one. The relay MAY refuse to load specific IDs for policy reasons.

### Phase B scope

Phase B (the initial implementation) loads only ML-KEM-768 (0x0002) and ML-DSA-65 (0x0002). Other IDs are reserved and documented but not implemented. They become available in later phases when business need justifies adding them.

## Code structure

```
relay/crypto/
├── registry.js         KEM_REGISTRY + SIG_REGISTRY maps, register/get/list functions
├── wire-format.js      encode(header, ctKem, senderPub, sig, nonce, ct) + decode(bytes)
├── errors.js           UnsupportedAlgorithm, InvalidMagic, InvalidVersion, etc.
└── impls/
    ├── mlkem768.js     wraps @noble/post-quantum for KEM encapsulate/decapsulate
    └── mldsa65.js      wraps @noble/post-quantum for sign/verify
```

### Registry API

```javascript
const { registerKEM, registerSig, getKEM, getSig, listSupported } = require('./registry');

// Registration (called once at startup):
registerKEM(0x0002, {
  name: 'ML-KEM-768',
  pubKeySize: 1184,
  ctSize: 1088,
  encapsulate: (publicKey) => { ... },   // returns { ciphertext, sharedSecret }
  decapsulate: (ciphertext, secretKey) => { ... }  // returns sharedSecret
});

// Usage:
const kem = getKEM(0x0002);
if (!kem) throw new UnsupportedAlgorithm(0x0002);
const { ciphertext, sharedSecret } = kem.encapsulate(recipientPubKey);
```

Adding a new algorithm = one registerKEM/registerSig call + one impl file. No change to wire-format.js, no change to relay.js.

## Capabilities endpoint

```
GET /v2/capabilities
```

Returns the list of algorithms this relay will accept in inbound blobs and can advertise in outbound receipts.

```json
{
  "wire_version": 1,
  "kem": [
    {"id": 2, "name": "ML-KEM-768", "loaded": true}
  ],
  "sig": [
    {"id": 0, "name": "none", "loaded": true},
    {"id": 2, "name": "ML-DSA-65", "loaded": true}
  ]
}
```

Clients fetch /v2/capabilities before first send to discover what the relay supports, and fall back gracefully if their preferred algorithm is not available (either pick a supported one or refuse to send and log).

## Threat model implications

1. **Header tampering**: first 10 bytes are in GCM AAD. An attacker flipping KEM_ID or SIG_ID causes GCM tag verification to fail on decryption. The recipient sees a corrupt blob, not a downgraded algorithm.

2. **Unsupported algorithm DoS**: the relay returns HTTP 415 Unsupported Media Type if KEM_ID or SIG_ID are not in the registry. No crash, no partial processing.

3. **Magic byte collision**: 'PQHB' (0x50 0x51 0x48 0x42) is unlikely to collide with common file formats. The parser rejects blobs not starting with these 4 bytes.

4. **Version field abuse**: VERSION=0x00 is invalid, the parser rejects. Versions beyond what this relay supports return HTTP 415 with a body indicating supported versions.

5. **Signature-absent signaling**: SIG_ID=0x0000 means anonymous blob (no signature section present at all). The relay MUST NOT try to parse a signature section when SIG_ID=0x0000. The recipient MUST NOT assume a missing signature section equals a valid anonymous blob unless SIG_ID=0x0000 is explicitly set.

## Open questions (resolved for phase B implementation)

- Where does the registry live at runtime? Singleton module, or per-request context? **Decision**: singleton. Relays do not change capabilities at runtime.
- Who owns the ID assignment for third-party algorithms? **Decision**: IDs above 0x8000 are reserved for private use, anyone self-hosting can use them for experimental algorithms without needing our coordination.
- What happens if @noble/post-quantum changes API signatures between versions? **Decision**: pin the exact version in package.json, upgrade deliberately with test suite green.

## Out of scope for v1

- Hybrid KEMs (combining two KEMs in one blob). If needed later, add via new FLAG bit + additional length-prefixed field, no version bump.
- Multi-recipient blobs. Same approach, add FLAG bit.
- Compressed payloads. Same approach.
- Forward secrecy via ephemeral per-session keys. This is a session management concern, not wire format.

## References

- NIST FIPS 203 — Module-Lattice-Based KEM (ML-KEM)
- NIST FIPS 204 — Module-Lattice-Based Digital Signature (ML-DSA)
- NIST FIPS 205 — Stateless Hash-Based Digital Signature (SPHINCS+)
- NIST FIPS 206 — FN-DSA (Falcon)
- RFC 5116 — AEAD framework (guides our use of GCM)
