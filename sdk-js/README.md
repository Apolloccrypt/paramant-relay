# paramant-sdk (JavaScript)

**Paramant SDK for JavaScript — real post-quantum encryption.**

Zero-plaintext, burn-on-read file transport, with real post-quantum key
encapsulation (ML-KEM-768 via [`@noble/post-quantum`][noble]) and real
post-quantum signatures (ML-DSA-65). Produces Paramant wire-format v1
(`PQHB` magic, see [docs/wire-format-v1.md](../docs/wire-format-v1.md)).
Negotiates supported algorithms with the relay's `/v2/capabilities` endpoint
before the first send.

**Version:** 3.0.0 · Node.js 18+ · browsers with WebCrypto

> ### Breaking changes from 2.x
>
> - The 2.x code advertised ML-KEM-768 but actually did ECDH-P256 + AES-GCM
>   with `new Uint8Array(0)` placeholders where the KEM ciphertext/shared secret
>   should have been. **2.x was not post-quantum.** 3.x is.
> - Wire format changed from the legacy v0 (no magic bytes) to **v1**
>   (`PQHB` header, length-prefixed fields, KEM/SIG IDs). Blobs produced by 2.x
>   cannot be decrypted by 3.x and vice-versa.
> - `@noble/post-quantum` is now a runtime dependency.
> - Persisted keypairs (`~/.paramant/<device>.keypair.json`) from 2.x are
>   ignored and regenerated; 3.x keypairs carry `version: 3` and include
>   real ML-KEM-768 public/secret key material.

[noble]: https://github.com/paulmillr/noble-post-quantum

---

## Install

```bash
npm install paramant-sdk@3
# or
yarn add paramant-sdk@3
pnpm add paramant-sdk@3
```

The package ships ESM and works in Node.js (via `import`) and bundled browsers.

```js
import GhostPipe, { KEM, SIG, VERSION } from 'paramant-sdk';
```

---

## Quickstart

```js
import GhostPipe from 'paramant-sdk';

// Receiver — register real ML-KEM-768 + ML-DSA-65 pubkeys once.
const recv = new GhostPipe({ apiKey: 'pgp_xxx', device: 'my-server' });
await recv.registerPubkeys();

// Sender — fetches recipient pubkey, encapsulates a shared secret,
// builds a v1 blob, uploads to the relay.
const send = new GhostPipe({ apiKey: 'pgp_xxx', device: 'my-laptop' });
const hash = await send.send(new TextEncoder().encode('Hello, post-quantum!'),
                              { recipient: 'my-server' });

// Receiver — fetch + decrypt (burn-on-read).
const data = await recv.receive(hash);
console.log(new TextDecoder().decode(data));   // → "Hello, post-quantum!"
```

---

## Algorithm matrix

The default configuration matches relay defaults and the wire-format-v1 spec:

| Slot | Default                | Override via    | Registry ID |
|------|------------------------|-----------------|-------------|
| KEM  | ML-KEM-768 (FIPS 203)  | `kemId:` option | `0x0002`    |
| SIG  | ML-DSA-65 (FIPS 204)   | `sigId:` option | `0x0002`    |
| AEAD | AES-256-GCM            | (fixed)         | —           |

To produce anonymous blobs (no signature section), pass `sigId: SIG.NONE`
(`0x0000`). The wire-format v1 spec drops the signature section entirely when
`sigId === 0x0000` — no zero-length prefix.

Other IDs (ML-KEM-512/1024, ML-DSA-44/87, Falcon, SLH-DSA) are reserved in the
registry and advertised by the relay's `/v2/capabilities` but not yet wired
up in this SDK.

---

## Constructor

```js
new GhostPipe({
    apiKey: string,                        // API key (pgp_...) — optional for anon-only
    device: string,                        // Stable device identifier
    relay?: string,                        // Relay URL (default: auto-detect)
    preSharedSecret?: string,              // PSS for HKDF (Layer 3)
    verifyFingerprints?: boolean,          // TOFU (default: true)
    timeout?: number,                      // HTTP timeout ms (default: 30000)
    kemId?: number,                        // Default: 0x0002 (ML-KEM-768)
    sigId?: number,                        // Default: 0x0002 (ML-DSA-65); 0x0000 = anonymous
    checkCapabilities?: boolean,           // Query /v2/capabilities before send (default: true)
})
```

The SDK validates `kemId` and `sigId` at construction time, then validates
against the relay's advertised capabilities before the first `send()`.

---

## Capabilities negotiation

```js
const gp = new GhostPipe({ apiKey: 'pgp_xxx', device: 'my-laptop' });
const caps = await gp.capabilities();
// → { wire_version: 1,
//     kem: [{ id: 2, name: 'ML-KEM-768', loaded: true }, ...],
//     sig: [{ id: 0, name: 'none', loaded: true },
//           { id: 2, name: 'ML-DSA-65', loaded: true }, ...] }
```

`send()` calls this automatically on first use. If the relay does not
advertise the client's `kemId`/`sigId`, the SDK throws
`UnsupportedAlgorithmError` — no silent fallback.

---

## Core methods

### `send(data, options?)`

```js
const hash = await gp.send(buffer, {
    recipient: 'pacs-001',               // default: self-device
    preSharedSecret: 'horse-battery',    // overrides constructor PSS
    ttl: 3600,
    maxViews: 1,
});
```

### `receive(hash, options?)`

```js
const data = await gp.receive(hash, { preSharedSecret: 'horse-battery' });
```

### `sendAnonymous(data, recipientKemPubHex, options?)`

Anonymous blob (`sigId=0x0000`) to `/v2/anon-inbound` — useful for pseudonymous
drops to a known recipient without a sender-side API key.

```js
const { hash } = await gp.sendAnonymous(buffer, recipientKemPubHex, { ttl: 86400 });
```

### `status(hash)` / `cancel(hash)`

Burn-before-read controls.

---

## Wire format (for interop)

The SDK re-exports the v1 encoder / decoder so callers can build or inspect
blobs directly. See [docs/wire-format-v1.md](../docs/wire-format-v1.md) for
the full specification and test vectors.

```js
import { wireEncode, wireDecode, buildAAD, isV1, KEM, SIG } from 'paramant-sdk';

const blob = wireEncode({
    kemId: KEM.ML_KEM_768,
    sigId: SIG.NONE,
    ctKem: new Uint8Array(1088),
    senderPub: new Uint8Array(1184),
    nonce: new Uint8Array(12),
    ciphertext: encryptedPayload,
});

isV1(blob);                // true
const parsed = wireDecode(blob);
const aad = buildAAD({ kemId: parsed.kemId, sigId: parsed.sigId });
```

The encoder is bit-exact against the test vectors in the spec:

- signed:    `sha256=002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a`
- anonymous: `sha256=46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef`

---

## Pubkey / TOFU

```js
await gp.registerPubkeys();
const fp = await gp.fingerprint('pacs-001');
await gp.trust('pacs-001');
gp.untrust('old-device');
gp.knownDevices();
```

The fingerprint is `SHA-256(kem_pub || sig_pub)[0:10]` formatted as
`XXXX-XXXX-XXXX-XXXX-XXXX`.

---

## BIP39 drop

```js
const phrase = await gp.drop(buffer, { ttl: 86400 });
// ...
const data = await gp.pickup(phrase);
```

---

## Migration from 2.x

1. `npm install paramant-sdk@3`.
2. Delete `~/.paramant/*.keypair.json` (they will be regenerated in v3
   format with real ML-KEM-768 material).
3. Re-call `registerPubkeys()` on every receiver — the relay's pubkey
   store records ML-KEM-768 public keys now, not the ECDH-P256 raw keys
   that 2.x sent under the `ecdh_pub` field.
4. Blobs produced by 2.x are not readable by 3.x. Any in-flight blobs
   should be drained or re-sent.
5. Remove any code that checks for a `kyber_pub` field — the field is now
   `kem_pub` and contains real ML-KEM-768 public key bytes.

---

## Error handling

```js
import {
    GhostPipeError, RelayError, AuthError, BurnedError,
    FingerprintMismatchError, LicenseError, RateLimitError, SignatureError,
} from 'paramant-sdk';

try {
    await gp.receive(h);
} catch (e) {
    if (e instanceof BurnedError) {/* already burned */}
    else if (e instanceof FingerprintMismatchError) {/* TOFU mismatch */}
    else throw e;
}
```

---

## License

BUSL-1.1 — see [LICENSE](../LICENSE).
