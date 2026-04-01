# @paramant/connect

PARAMANT Ghost Pipe SDK for Node.js. Post-quantum burn-on-read secure transport.

Zero dependencies. Node.js >= 18.

## Install

```bash
npm install @paramant/connect
```

## Quick start

```js
const { GhostPipe } = require('@paramant/connect');

// Sender
const sender = new GhostPipe({ apiKey: 'pk_live_...', device: 'sender-001' });
const hash = await sender.send(Buffer.from('confidential payload'));
console.log('hash:', hash);

// Receiver (different process / machine)
const receiver = new GhostPipe({ apiKey: 'pk_live_...', device: 'receiver-001' });
const data = await receiver.receive(hash);
console.log('received:', data.toString());
// blob is burned after receive — subsequent calls return 404
```

## API

### `new GhostPipe(opts)`

| Option | Type | Description |
|--------|------|-------------|
| `apiKey` | `string` | API key (required) |
| `device` | `string` | Device identifier (required) |
| `relay` | `string` | Override relay URL |
| `sector` | `string` | Preferred sector: `health` `iot` `legal` `finance` |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `send(data, { ttl })` | `Promise<string>` | Encrypt and upload; returns hash |
| `receive(hash)` | `Promise<Buffer>` | Download and decrypt; burns blob |
| `status(hash)` | `Promise<object>` | Check blob status without consuming |
| `health()` | `Promise<object>` | Relay health info |
| `audit(limit)` | `Promise<Array>` | Fetch your audit log |
| `listen(onReceive)` | `Promise<void>` | Poll for incoming messages |

### `new GhostPipeCluster(opts)`

Multi-relay failover client. Same API as `GhostPipe`, automatically fails over to a healthy relay.

```js
const { GhostPipeCluster } = require('@paramant/connect');
const cluster = new GhostPipeCluster({ apiKey: 'pk_live_...', device: 'device-001' });
const hash = await cluster.send(data);
cluster.destroy(); // stop health monitor
```

## Protocol

- **Encryption**: ECDH P-256 + HKDF-SHA256 + AES-256-GCM
- **Burn-on-read**: blob is deleted server-side after first `receive()`
- **Zero persistence**: relay stores nothing after delivery
- **Sectors**: EU/DE Hetzner nodes + Fly.io anycast

## License

BUSL-1.1 — [paramant.app](https://paramant.app)
