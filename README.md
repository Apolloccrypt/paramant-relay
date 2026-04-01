# PARAMANT Ghost Pipe

Post-quantum encrypted transport. ML-KEM-768 · Burn-on-read · EU/DE jurisdiction.

## Structure
- `relay/` — ghost-pipe-relay.js v2.0.0 (Node.js)
- `scripts/` — sender, receiver, SDK, admin CLI (Python)
- `frontend/` — paramant.app website
- `sdk-js/` — @paramant/connect npm package

## Quick start
```bash
# Send
python3 scripts/paramant-sender.py --key pgp_xxx --device my-device --heartbeat 15

# Receive  
python3 scripts/paramant-receiver.py --key pgp_xxx --device my-device --output /tmp/received/

# SDK
pip install paramant-sdk
from paramant_sdk import GhostPipe
gp = GhostPipe("pgp_xxx", "device-001")
hash = gp.send(b"hello")
data = gp.receive(hash)
```

## Live infrastructure
- health.paramant.app — Healthcare relay
- legal.paramant.app — Legal relay  
- finance.paramant.app — Finance relay
- iot.paramant.app — IoT relay
- paramant-ghost-pipe.fly.dev — Anycast (5 nodes)

## Crypto stack
ML-KEM-768 + ECDH P-256 + AES-256-GCM + HKDF-SHA256 + ML-DSA-65
