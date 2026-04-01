# ghost-pipe-relay.js v2.0.0

Node.js relay for PARAMANT Ghost Pipe. Runs on Hetzner (4 sector instances) and Fly.io (5 anycast nodes).

## Requirements
- Node.js >= 20
- `npm install` (installs `@noble/post-quantum` for ML-DSA-65)

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| PORT | yes | Listen port (8080 on Fly, 3002-3005 on Hetzner) |
| USERS_JSON | yes (Fly) | JSON string of API keys (set via `fly secrets set`) |
| USERS_FILE | yes (Hetzner) | Path to users.json (`./users.json`) |
| ADMIN_TOKEN | yes | Admin API key for /v2/admin/* and /metrics |
| TOTP_SECRET | yes | Base32 TOTP secret for MFA |
| RELAY_MODE | no | `ghost_pipe` or `full` (default: ghost_pipe) |
| SECTOR | no | Sector label for logs (health/legal/finance/iot) |
| TTL_MS | no | Default blob TTL in ms (default: 300000 = 5min) |

## users.json format
```json
{
  "api_keys": [
    { "key": "pgp_xxx", "plan": "pro", "label": "client-name", "active": true }
  ]
}
```

Plans: `dev` · `chat` · `pro` · `enterprise`

## Startup
```bash
npm install
node relay.js
```

## Hetzner deployment
```bash
# Sector relay (runs as systemd service)
/home/paramant/relay-health/relay.js   → :3005
/home/paramant/relay-legal/relay.js    → :3002
/home/paramant/relay-finance/relay.js  → :3003
/home/paramant/relay-iot/relay.js      → :3004

# Sync + restart all (copies to both ghost-pipe-relay.js and relay.js)
for sector in relay-health relay-legal relay-finance relay-iot; do
  scp ghost-pipe-relay.js root@116.203.86.81:/home/paramant/$sector/ghost-pipe-relay.js
  scp ghost-pipe-relay.js root@116.203.86.81:/home/paramant/$sector/relay.js
done
ssh root@116.203.86.81 "for s in paramant-relay-health paramant-relay-legal paramant-relay-finance paramant-relay-iot; do systemctl restart \$s; done"
```

## Fly.io deployment
```bash
fly deploy --app paramant-ghost-pipe --no-cache

# Secrets
fly secrets set USERS_JSON="$(python3 -c "import json; print(json.dumps(json.load(open('users.json'))))")" --app paramant-ghost-pipe
fly secrets set ADMIN_TOKEN=pgp_xxx --app paramant-ghost-pipe
fly secrets set TOTP_SECRET=XXXXX --app paramant-ghost-pipe
```

## Key features

- ML-KEM-768 + ECDH P-256 hybrid encryption
- ML-DSA-65 digital signature verification
- ECDSA P-256 sender authentication
- Burn-on-read: RAM wiped after retrieval
- 5MB fixed padding (DPI masking)
- Merkle hash chain audit log
- W3C DID registry
- Certificate Transparency log (public Merkle tree)
- Hardware attestation (TPM 2.0, Apple Secure Enclave)
- WebSocket streaming (/v2/stream)
- NATS JetStream push
- Rate limiting per plan
- Prometheus metrics (/metrics)
- TOTP MFA for admin endpoints
- Session affinity on api-key header (Fly.io)

## Adding a new client (no redeploy needed)
```bash
python3 /opt/paramant/paramant-admin.py add --label acme --plan pro --email client@acme.com
# Generates a key, syncs to all relays via /v2/reload-users, emails the key via Resend
```

## Important: ExecStart note
The systemd services use `ExecStart=/usr/bin/node relay.js`. When deploying, always copy
`ghost-pipe-relay.js` to both filenames in each sector directory.
