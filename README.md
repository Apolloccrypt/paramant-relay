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
python3 scripts/paramant-sender.py --key YOUR_API_KEY --device my-device --heartbeat 15

# Receive
python3 scripts/paramant-receiver.py --key YOUR_API_KEY --device my-device --output /tmp/received/

# SDK
from paramant_sdk import GhostPipe
gp = GhostPipe("YOUR_API_KEY", "device-001")
hash = gp.send(b"hello")
data = gp.receive(hash)
```

## Live infrastructure
- `health.paramant.app` — Healthcare relay
- `legal.paramant.app` — Legal relay
- `finance.paramant.app` — Finance relay
- `iot.paramant.app` — IoT relay
- `paramant-ghost-pipe.fly.dev` — Anycast

## Crypto stack
ML-KEM-768 + ECDH P-256 + AES-256-GCM + HKDF-SHA256 + ML-DSA-65

## Browser widget vs full E2E
The free browser widget on paramant.app uses AES-256-GCM with the key included in the blob. The full ML-KEM-768 post-quantum E2E stack is implemented in the relay protocol and SDK, not in the browser widget.

## Pricing
| Plan | Price | Rate limit |
|------|-------|------------|
| Dev | €9.99/mo | 50 req/min |
| Pro | €49.99/mo | 500 req/min |
| Enterprise | Custom | 1000+ req/min |

Get an API key at paramant.app

## License
BUSL-1.1 · © 2026 PARAMANT
