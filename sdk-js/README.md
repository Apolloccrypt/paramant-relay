# paramant-sdk (JavaScript)

JavaScript SDK for **PARAMANT Ghost Pipe** — zero-plaintext, burn-on-read file transport with post-quantum encryption (ML-KEM-768 + ECDH P-256) and optional pre-shared secret (PSS) for relay-MITM protection.

**Version:** 2.4.1 · [Security model](../docs/security.md) · [Relay API](../docs/api.md)

Works in **Node.js 18+** and modern **browsers** (via bundler or CDN).

---

## Install

```bash
npm install paramant-sdk
```

Or with yarn / pnpm:

```bash
yarn add paramant-sdk
pnpm add paramant-sdk
```

---

## Quickstart

```js
import { GhostPipe } from 'paramant-sdk';

// Sender
const gp = new GhostPipe({ apiKey: 'pgp_xxx', device: 'my-laptop' });
const h = await gp.send(new TextEncoder().encode('Hello, world!'));
console.log(h);   // → transfer hash

// Receiver (separate process / machine)
const gp2 = new GhostPipe({ apiKey: 'pgp_xxx', device: 'my-server' });
await gp2.registerPubkeys();            // register once
const data = await gp2.receive(h);
console.log(new TextDecoder().decode(data));   // → "Hello, world!"
```

---

## Self-hosting

```js
const gp = new GhostPipe({
    apiKey: 'pgp_xxx',
    device: 'my-device',
    relay: 'https://relay.example.com',   // default: https://relay.paramant.app
});
```

---

## Constructor

```js
new GhostPipe({
    apiKey: string,                        // API key (pgp_...)
    device: string,                        // Stable device identifier
    relay?: string,                        // Relay URL (default: relay.paramant.app)
    preSharedSecret?: string,              // PSS for relay-MITM protection (Layer 3)
    verifyFingerprints?: boolean,          // Enable TOFU (default: true)
    timeout?: number,                      // HTTP timeout ms (default: 30000)
})
```

---

## Core methods

### `send(data, options?)`

Encrypt and upload a blob. Returns the transfer hash.

```js
const h = await gp.send(buffer, {
    recipient: 'pacs-001',               // optional: encrypt to specific device
    preSharedSecret: 'horse-battery',    // optional: PSS (overrides constructor)
    ttl: 3600,                           // seconds until auto-burn
    maxViews: 1,                         // burn after N downloads
});
```

### `receive(hash, options?)`

Download and decrypt a blob. Burns on read.

```js
const data = await gp.receive(h, { preSharedSecret: 'horse-battery' });
```

### `status(hash)`

Check transfer status without consuming it.

```js
const info = await gp.status(h);
// → { ok: true, burned: false, views: 0, ttl: 3598, ... }
```

### `cancel(hash)`

Burn a transfer before it is downloaded.

```js
await gp.cancel(h);
```

---

## Pubkey / TOFU verification

### `registerPubkeys()`

Register this device's pubkeys (required before receiving).

```js
await gp.registerPubkeys();
```

### `fingerprint(deviceId?)`

Print and return the fingerprint for a device.

```js
const fp = await gp.fingerprint('pacs-001');
// Device:      pacs-001
// Fingerprint: A3F2-19BE-C441-8D07-F2A0
// Registered:  2026-04-10T09:23:11Z
```

### `verifyFingerprint(deviceId, fingerprint)`

Returns `true` if the relay-stored fingerprint matches.

```js
const ok = await gp.verifyFingerprint('pacs-001', 'A3F2-19BE-C441-8D07-F2A0');
```

### `trust(deviceId)` / `untrust(deviceId)`

```js
await gp.trust('pacs-001');
await gp.untrust('old-device');
```

### `knownDevices()`

```js
const devices = await gp.knownDevices();
```

---

## Anonymous drop (BIP39)

```js
const gp = new GhostPipe({ apiKey: '', device: '' });
const { mnemonic, hash } = await gp.drop(buffer, { ttl: 86400 });
console.log(mnemonic);   // → "correct horse battery ..."

// Receiver
const data = await gp.pickup(mnemonic);
```

---

## Sessions

```js
// Initiator
const sessionId = await gp.sessionCreate();

// Joiner
await gp2.sessionJoin(sessionId);

const info = await gp.sessionStatus(sessionId);
```

---

## WebSocket streaming

```js
// Stream all events for this device
for await (const event of gp.stream()) {
    console.log(event);
    await gp.ack(event.id);
}

// Wait for a specific transfer
await gp.listen(h, async (event) => {
    console.log('received:', event);
});
```

---

## Webhooks

```js
await gp.webhookRegister({
    url: 'https://myapp.example.com/hooks/paramant',
    events: ['transfer.burned', 'transfer.ready'],
    secret: 'hmac-secret',
});
```

---

## CT log / audit

```js
const entries = await gp.ctLog({ from: 0, limit: 50 });
const proof = await gp.ctProof(42);
const log = await gp.audit();
```

---

## DID

```js
await gp.didRegister({ did: 'did:paramant:abc123', pubkeyHex: '3059...' });
const doc = await gp.didResolve('did:paramant:abc123');
const dids = await gp.didList();
```

---

## Admin

```js
const admin = gp.admin('admin-secret');
await admin.stats();
await admin.keyAdd({ key: 'pgp_yyy', label: 'partner', sectors: ['health'] });
await admin.keyRevoke('pgp_old');
await admin.licenseStatus();
await admin.reload();
await admin.sendWelcome({ email: 'admin@hospital.org', name: 'IT Team' });
```

---

## TypeScript

Full type definitions are included. Import types:

```ts
import type { GhostPipe, GhostPipeOptions, TransferStatus } from 'paramant-sdk';
```

---

## Security layers

| Layer | What it is | Option |
|-------|-----------|--------|
| TOFU | First-use fingerprint pinning | `verifyFingerprints: true` (default) |
| Out-of-band | Verbal / QR fingerprint comparison | `fingerprint()` |
| PSS | Pre-shared secret in HKDF | `preSharedSecret:` |
| CT log | Merkle audit trail | `ctLog()` |

See [docs/security.md](../docs/security.md) for the full security model.

---

## Error handling

```js
import {
    GhostPipeError,
    RelayError,
    AuthError,
    BurnedError,
    FingerprintMismatchError,
    LicenseError,
    RateLimitError,
} from 'paramant-sdk';

try {
    const data = await gp.receive(h);
} catch (e) {
    if (e instanceof BurnedError) {
        console.log('Transfer already burned');
    } else if (e instanceof FingerprintMismatchError) {
        console.log(`TOFU mismatch for ${e.deviceId}: stored=${e.stored}, got=${e.received}`);
    } else if (e instanceof AuthError) {
        console.log('Invalid API key');
    } else if (e instanceof RateLimitError) {
        console.log('Rate limited');
    } else {
        throw e;
    }
}
```

---

## Browser / CDN

```html
<script type="module">
  import { GhostPipe } from 'https://cdn.paramant.app/sdk/2.4.1/index.js';
  const gp = new GhostPipe({ apiKey: 'pgp_xxx', device: 'browser' });
</script>
```

---

## License

MIT — see [LICENSE](../LICENSE)
