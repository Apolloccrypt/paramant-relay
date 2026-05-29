# SDK ↔ relay cross-implementation conformance suite

Proves that the **three real crypto stacks** agree on every byte of the shared
Paramant wire contract — with no mocks and no KAT-vectors-only shortcut. This
closes the ParaSign-audit gap: until now nothing exercised a blob/signature
produced by the client crypto (noble / pqcrypto) all the way through the relay
crypto (`@paramant/core`).

| Adapter | Real library | Stands in for |
|---------|--------------|---------------|
| `noble`    | `@noble/post-quantum` 0.6.x          | **sdk-js** crypto |
| `pqcrypto` | `pqcrypto` (PQClean C) + `cryptography` | **sdk-py** crypto |
| `core`     | `@paramant/core` NAPI binding         | **relay** crypto |

The oracle is **`docs/wire-format-v1.md`**, never an implementation. Expected
bytes (test-vector SHA-256s, header layout, canonicalJSON strings) are
transcribed from the spec in `spec-vectors.mjs` with line citations.

## What it proves

- **RT1 — wire-format v1 byte-exact.** Each shipped encoder (`sdk-js`,
  `sdk-py`, and `relay` when present) reproduces the spec's own test vectors 1
  & 2 (length, header, full-blob SHA-256).
- **RT2 — canonicalJSON.** sdk-js form (embedded, cited), real `relay/parasign.js`
  (when present) and the real sdk-py `json.dumps(sort_keys,separators)` form all
  match the spec-anchored bytes for ASCII receipts. The **non-ASCII divergence**
  (sdk-js raw UTF-8 vs sdk-py `\uXXXX`) is pinned as a documented boundary, not
  hidden — receipts must stay ASCII.
- **RT3 — ML-DSA-65 sign/verify cross-impl**, both signing surfaces:
  - **Vlak A** wire sender-signature input `ct_kem ‖ sender_pub ‖ nonce ‖ ciphertext ‖ aad` (spec line 92).
  - **Vlak B** `canonicalJSON(receipt)` (ParaSign/relay receipt path).
  Every impl signs with its own keypair; every other impl must verify, and a
  one-byte tamper must be rejected.
- **RT4a — ML-KEM-768 encaps/decaps cross-impl.** Recipient keygen+decaps with
  one impl, sender encaps with another, across all 9 pairs → identical 32-byte
  shared secret.
- **RT4b — HKDF(`paramant-v1-aes-key`) + AES-256-GCM envelope.** sdk-js
  (WebCrypto) ⇄ sdk-py (pyca) derive the same key and decrypt each other's
  ciphertext; wrong-AAD is rejected. (Off the `core` path on purpose — the relay
  stores blobs opaquely and never decrypts; that fact is itself asserted.)

## Running

From the repo root:

```bash
node --test tests/conformance/conformance.test.mjs
```

The suite spawns each adapter in its own runtime and exchanges hex-encoded
vectors over stdin/stdout (`lib/bus.mjs`). No network, no relay server.

### Dependencies & how they are located (`config.mjs`)

| Env var | Default search | Purpose |
|---------|----------------|---------|
| `PARAMANT_NOBLE_DIR` | `sdk-js/node_modules/@noble/post-quantum`, repo `node_modules`, dev fallback | sdk-js crypto |
| `PARAMANT_CORE_NODE` | `node_modules/@paramant/core/index.node`, dev build | relay crypto |
| `PARAMANT_PY`        | `.venv/bin/python`, dev venv | python with pqcrypto + cryptography |
| `PARAMANT_SDK_JS_WIRE` | `sdk-js/src/wire-format.js` | sdk-js wire encoder |
| `PARAMANT_SDK_PY_DIR`  | `sdk-py/` | sdk-py package |
| `PARAMANT_RELAY_WIRE`     | `relay/crypto/wire-format.js` | relay wire encoder (optional) |
| `PARAMANT_RELAY_PARASIGN` | `relay/parasign.js` | relay canonicalJSON (optional) |

An **explicitly-set env var is authoritative** — if it points nowhere the
adapter fails loudly naming the missing piece; it is never silently replaced by
a fallback. A conformance test that is green because a real implementation was
unavailable is worse than no test.

### No silent mocks

There is no mock code in this suite. If a real library cannot load, the adapter
prints `{"ok":false,"error":...}`, exits non-zero, and the test errors with the
exact missing dependency. Verified by pointing each of `PARAMANT_PY`,
`PARAMANT_CORE_NODE`, `PARAMANT_NOBLE_DIR` at a bad path → loud failure.

## Portability to the standalone SDK repo

This directory has **no dependency on the relay runtime** and is designed to be
copied verbatim into the future SDK repo. There, `relay/*` will be absent:
RT1-`relay` and the relay-`parasign` cross-check **skip with an explicit
message** (not silent pass), while all sdk-js/sdk-py/core cross-impl tests keep
running. Point the env vars at the new layout and `node --test` it.

Verified: copied to a relay-free repo root → 17 pass, 2 skip, 0 fail.

## Known limitation

`sdk-js`'s `canonicalJSON` is an internal, non-exported function (`index.js:154`),
so the JS form is checked via a **verbatim embedded copy** (cited) plus the real
`relay/parasign.js` sibling implementation. If `sdk-js` ever exports
`canonicalJSON`, switch the RT2 JS assertion to import it directly. Until then,
keep the embedded copy in sync with `index.js:154` — or, preferably, export it.
