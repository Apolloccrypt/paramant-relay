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
- `health.paramant.app` — Healthcare relay
- `legal.paramant.app` — Legal relay
- `finance.paramant.app` — Finance relay
- `iot.paramant.app` — IoT relay
- `paramant-ghost-pipe.fly.dev` — Anycast (5 nodes)

## Crypto stack
ML-KEM-768 + ECDH P-256 + AES-256-GCM + HKDF-SHA256 + ML-DSA-65

---

## Deployment
```bash
# Sync relay to all Hetzner sectors
cd ~/paramant-master/relay
for sector in relay-health relay-legal relay-finance relay-iot; do
  scp ghost-pipe-relay.js root@YOUR_SERVER_IP:/home/paramant/$sector/ghost-pipe-relay.js
  scp ghost-pipe-relay.js root@YOUR_SERVER_IP:/home/paramant/$sector/relay.js
done
ssh root@YOUR_SERVER_IP "for s in paramant-relay-health paramant-relay-legal paramant-relay-finance paramant-relay-iot; do systemctl restart \$s; done"

# Deploy to Fly.io
cd ~/paramant-master/relay
fly deploy --app paramant-ghost-pipe

# Add new client
python3 ~/paramant-master/scripts/paramant-admin.py add --label client-name --plan pro --email client@example.com

# Emergency: rotate admin key
python3 ~/paramant-master/scripts/paramant-admin.py add --label admin-new --plan enterprise
python3 ~/paramant-master/scripts/paramant-admin.py revoke pgp_xxx_redacted
python3 ~/paramant-master/scripts/paramant-admin.py sync
```

---

## E2E test
```bash
# Terminal 1
mkdir -p /tmp/recv-test
python3 ~/paramant-master/scripts/paramant-receiver.py \
  --key pgp_xxx_redacted \
  --device e2e-test \
  --output /tmp/recv-test \
  --no-ws

# Terminal 2 (after "Pubkeys geregistreerd" in terminal 1)
echo "PARAMANT e2e test $(date)" | python3 ~/paramant-master/scripts/paramant-sender.py \
  --key pgp_xxx_redacted \
  --device e2e-test \
  --stdin

# Verify
cat /tmp/recv-test/recv_000001.json
```

---

## Admin panel

URL: `https://paramant.app/r34ct0r`
Auth: Admin API key + TOTP (Google Authenticator / Authy)

TOTP setup: `/etc/paramant/admin_mfa.json` on server (root-only, 0600)

---

## Pricing

| Plan | Price | Rate limit | Use case |
|------|-------|------------|----------|
| Dev | €9.99/mo | 50 req/min | Development, testing |
| Chat | €29/mo | — | Secure chat only |
| Pro | €49.99/mo | 500 req/min | Full API access |
| Enterprise | €499.99/mo | 1000+ req/min | Dedicated nodes, SLA |

Stripe price IDs:
- Dev: `price_1TGwtQJMhSdoTn1k6RM3agYr`
- Pro: `price_1TGwqbJMhSdoTn1kCWWLN5KY`
- Enterprise: `price_1TGwrzJMhSdoTn1k502jeobI`
- Chat: `price_1THJ0rJMhSdoTn1kwxxGadZJ`

---

*PARAMANT v2.0.0 · BUSL-1.1 · © 2026*
