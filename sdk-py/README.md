# paramant-sdk

PARAMANT Ghost Pipe SDK for Python. Post-quantum burn-on-read secure transport.

## Install

```bash
pip install paramant-sdk
```

## Quick start

```python
from paramant_sdk import GhostPipe

# Sender
sender = GhostPipe(api_key='pk_live_...', device='sender-001')
hash_ = sender.send(b'confidential payload')
print('hash:', hash_)

# Receiver
receiver = GhostPipe(api_key='pk_live_...', device='receiver-001')
data = receiver.receive(hash_)
print('received:', data)
# blob is burned after receive
```

## API

```python
gp = GhostPipe(api_key, device, relay='', sector='health')

hash_   = gp.send(data: bytes, ttl=300) -> str
data    = gp.receive(hash_: str) -> bytes
status  = gp.status(hash_: str) -> dict
entries = gp.audit(limit=100) -> list
info    = gp.health() -> dict
gp.listen(on_receive: callable, interval=3)
```

### Multi-relay cluster

```python
from paramant_sdk import GhostPipeCluster

cluster = GhostPipeCluster(
    api_key='pk_live_...',
    device='device-001',
    relays=['https://health.paramant.app', 'https://relay.paramant.app'],
)
hash_ = cluster.send(data)
```

## Protocol

- **Encryption**: ML-KEM-768 + ECDH P-256 + AES-256-GCM (hybrid PQC)
- **Burn-on-read**: blob deleted after first `receive()`
- **Sectors**: EU/DE Hetzner + Fly.io anycast

## License

BUSL-1.1 — [paramant.app](https://paramant.app)
