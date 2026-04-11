# paramant-sdk (Python)

Python SDK for **PARAMANT Ghost Pipe** — zero-plaintext, burn-on-read file transport with post-quantum encryption (ML-KEM-768 + ECDH P-256) and optional pre-shared secret (PSS) for relay-MITM protection.

**Version:** 2.4.1 · [Security model](../docs/security.md) · [Relay API](../docs/api.md)

> **Note (pending — C3):** Key zeroization (`_zero()`) is implemented in `scripts/paramant_sdk.py` but not yet in this pip package. The pip package will be updated in the next patch.

---

## Install

```bash
pip install paramant-sdk
```

Python 3.9+ required. No native dependencies — pure Python with `cryptography` and `requests`.

---

## Quickstart

```python
from paramant_sdk import GhostPipe

# Sender
gp = GhostPipe(api_key='pgp_xxx', device='my-laptop')
h = gp.send(b'Hello, world!')
print(h)   # → transfer hash

# Receiver (separate process / machine)
gp = GhostPipe(api_key='pgp_xxx', device='my-server')
gp.receive_setup()                  # register pubkeys once
data = gp.receive(h)
print(data)   # → b'Hello, world!'
```

---

## Self-hosting

Point the SDK at your own relay:

```python
gp = GhostPipe(
    api_key='pgp_xxx',
    device='my-device',
    relay='https://relay.example.com',   # default: https://relay.paramant.app
)
```

---

## Constructor

```python
GhostPipe(
    api_key: str,                        # API key (pgp_...)
    device: str,                         # Stable device identifier
    relay: str = 'https://relay.paramant.app',
    pre_shared_secret: str = '',         # PSS for relay-MITM protection (Layer 3)
    verify_fingerprints: bool = True,    # Enable TOFU key verification (Layer 1)
    timeout: int = 30,                   # HTTP timeout in seconds
)
```

---

## Core methods

### `send(data, *, ttl=3600, max_views=1, pad_block=5, recipient='', pre_shared_secret='')`

Encrypt and upload a blob. Returns the transfer hash.

```python
h = gp.send(
    b'...',
    recipient='pacs-001',               # optional: encrypt to specific device
    pre_shared_secret='horse-battery',  # optional: PSS (overrides constructor)
    ttl=3600,                           # seconds until auto-burn
    max_views=1,                        # burn after N downloads
)
```

### `receive(hash_, *, pre_shared_secret='')`

Download and decrypt a blob. Burns on read.

```python
data = gp.receive(h, pre_shared_secret='horse-battery')
```

### `status(hash_)`

Check transfer status without consuming it.

```python
info = gp.status(h)
# → {'ok': True, 'burned': False, 'views': 0, 'ttl': 3598, ...}
```

### `cancel(hash_)`

Burn a transfer before it is downloaded.

```python
gp.cancel(h)
```

---

## Pubkey / TOFU verification

### `receive_setup()` / `register_pubkeys()`

Register this device's pubkeys with the relay (required before receiving).

```python
gp.receive_setup()
```

### `fingerprint(device_id='')`

Print and return the fingerprint for a device. Use this for out-of-band verification.

```python
fp = gp.fingerprint('pacs-001')
# Device:      pacs-001
# Fingerprint: A3F2-19BE-C441-8D07-F2A0
# Registered:  2026-04-10T09:23:11Z
# CT index:    42
```

### `verify_fingerprint(device_id, fingerprint)`

Returns `True` if the relay-stored fingerprint matches.

```python
ok = gp.verify_fingerprint('pacs-001', 'A3F2-19BE-C441-8D07-F2A0')
```

### `trust(device_id)` / `untrust(device_id)`

Manually mark a device as trusted / remove from known_keys.

```python
gp.trust('pacs-001')
gp.untrust('old-device')
```

### `known_devices()`

List all locally trusted devices.

```python
for d in gp.known_devices():
    print(d)
```

---

## Anonymous drop (BIP39)

Send without an API key. Returns a 12-word BIP39 mnemonic.

```python
gp = GhostPipe(api_key='', device='')
mnemonic, h = gp.drop(b'secret document', ttl=86400)
print(mnemonic)   # → "correct horse battery staple ..."

# Receiver
data = gp.pickup(mnemonic)
```

---

## Sessions

End-to-end encrypted bidirectional sessions.

```python
# Initiator
session_id = gp.session_create()

# Joiner
gp2.session_join(session_id)

# Check status
info = gp.session_status(session_id)
```

---

## WebSocket streaming

```python
import asyncio

async def main():
    async for event in gp.stream():
        print(event)
        await gp.ack(event['id'])

asyncio.run(main())

# Or subscribe to a specific transfer:
async def on_event(event):
    print('received:', event)

await gp.listen(h, callback=on_event)
```

---

## Webhooks

```python
gp.webhook_register(
    url='https://myapp.example.com/hooks/paramant',
    events=['transfer.burned', 'transfer.ready'],
    secret='hmac-secret',
)
```

---

## CT log / audit

```python
entries = gp.ct_log(from_=0, limit=50)
proof = gp.ct_proof(42)
log = gp.audit()
```

---

## DID (Decentralized Identifiers)

```python
gp.did_register(did='did:paramant:abc123', pubkey_hex='3059...')
doc = gp.did_resolve('did:paramant:abc123')
dids = gp.did_list()
```

---

## Admin

```python
admin = gp.admin(token='admin-secret')
admin.stats()
admin.key_add(key='pgp_yyy', label='partner-firm', sectors=['health'])
admin.key_revoke(key='pgp_old')
admin.license_status()
admin.reload()
admin.send_welcome(email='admin@hospital.org', name='IT Team')
```

---

## Cluster (multi-relay failover)

```python
from paramant_sdk import GhostPipeCluster

cluster = GhostPipeCluster(
    api_key='pgp_xxx',
    device='my-device',
    relays=['https://relay1.example.com', 'https://relay2.example.com'],
)
h = cluster.send(b'data')
data = cluster.receive(h)
```

---

## Security layers

| Layer | What it is | API |
|-------|-----------|-----|
| TOFU | First-use fingerprint pinning | `verify_fingerprints=True` (default) |
| Out-of-band | Verbal / QR fingerprint comparison | `gp.fingerprint()` |
| PSS | Pre-shared secret in HKDF | `pre_shared_secret=` |
| CT log | Merkle audit trail of key registrations | `gp.ct_log()` |

See [docs/security.md](../docs/security.md) for the full security model.

---

## Error handling

```python
from paramant_sdk import (
    GhostPipeError,
    RelayError,
    AuthError,
    BurnedError,
    FingerprintMismatchError,
    LicenseError,
    RateLimitError,
)

try:
    data = gp.receive(h)
except BurnedError:
    print('Transfer already burned')
except FingerprintMismatchError as e:
    print(f'TOFU mismatch for {e.device_id}: stored={e.stored}, got={e.received}')
except AuthError:
    print('Invalid API key')
except RateLimitError:
    print('Rate limited — slow down')
except RelayError as e:
    print(f'Relay error: {e}')
```

---

## License

BUSL-1.1 — see [LICENSE](../LICENSE)
