# PARAMANT Ghost Pipe Relay — v2.4.2

Node.js relay for PARAMANT Ghost Pipe. One codebase, five sector containers.

## Requirements

- Node.js >= 20
- Docker 24+ (recommended — use `docker compose`, not bare Node)
- `npm install` in `relay/` to install `@noble/post-quantum` and other deps

## Quick start (Docker)

```bash
cd /path/to/paramant-relay
cp .env.example .env          # edit: set ADMIN_TOKEN
docker compose up -d --build
curl -s http://localhost:3001/health | python3 -m json.tool
```

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3000` | Listen port (containers all use 3000; host mapping is in docker-compose) |
| `SECTOR` | Set by Compose | `relay` | Sector label: `relay` / `health` / `finance` / `legal` / `iot` |
| `RELAY_MODE` | No | `ghost_pipe` | Endpoint set: `ghost_pipe`, `iot`, or `full` |
| `ADMIN_TOKEN` | Yes | — | Admin API token. Generate: `openssl rand -hex 32` |
| `TOTP_SECRET` | No | — | Base32 TOTP secret for admin MFA (TOTP-SHA256) |
| `USERS_FILE` | No | `./users.json` | Path to API key store |
| `CT_LOG_FILE` | No | — | Path to CT log persistence file (NDJSON). Opt-in. |
| `PARAMANT_LICENSE` | No | — | `plk_` relay license key — unlocks unlimited users |
| `RAM_LIMIT_MB` | No | `1024` | Max RAM for in-flight blob storage |
| `RAM_RESERVE_MB` | No | `256` | RAM headroom before uploads are rejected |
| `RESEND_API_KEY` | No | — | Resend API key for welcome emails |
| `RELAY_SELF_URL` | No | — | This relay's public URL (e.g. `https://relay.yourdomain.com`). Required for relay registry. |
| `RELAY_PRIMARY_URL` | No | self | Registry relay URL to POST self-registration to. |
| `RELAY_IDENTITY_FILE` | No | `/data/relay-identity.json` | ML-DSA-65 identity keypair path. |
| `NATS_URL` | No | — | NATS JetStream URL for push events (opt-in) |
| `TTL_MS` | No | `300000` | Default blob TTL in ms |
| `LOG_LEVEL` | No | `info` | Log verbosity: `debug` / `info` / `warn` / `error` |

## users.json format

```json
{
  "api_keys": [
    { "key": "pgp_xxx", "plan": "pro", "label": "alice", "active": true }
  ]
}
```

Plans: `free` · `pro` · `enterprise`

## Deploying a new relay.js

The Docker image bakes `relay.js` in at build time. A `docker restart` alone does **not** pick up changes — you must rebuild:

```bash
# 1. Copy relay.js to the Docker build context on the server
cp relay/relay.js /path/to/paramant-relay/relay/relay.js

# 2. Rebuild and restart
cd /path/to/paramant-relay
docker compose build relay-main relay-health relay-finance relay-legal relay-iot
docker compose up -d
```

Or use the `paramant-deploy` alias (see root README).

## Port mapping

| Container | Internal | Host | Subdomain |
|-----------|----------|------|-----------|
| relay-main | 3000 | 127.0.0.1:3000 | relay.paramant.app |
| relay-health | 3000 | 127.0.0.1:3001 | health.paramant.app |
| relay-finance | 3000 | 127.0.0.1:3002 | finance.paramant.app |
| relay-legal | 3000 | 127.0.0.1:3003 | legal.paramant.app |
| relay-iot | 3000 | 127.0.0.1:3004 | iot.paramant.app |

System nginx handles TLS and routes subdomains to these ports.

## Key features

- **ML-KEM-768 + ECDH P-256** hybrid key encapsulation (NIST FIPS 203)
- **ML-DSA-65** digital signatures (NIST FIPS 204) — relay identity + sender auth
- **AES-256-GCM** symmetric encryption with AAD (version byte + chunk index)
- **HKDF-SHA256** key derivation — salt from KEM ciphertext (matches browser)
- **Burn-on-read** — blob zeroed from RAM immediately after download
- **RAM-only blobs** — encrypted payloads never written to disk
- **5 MB fixed padding** — all blobs padded to 5 MB before upload (DPI masking)
- **Certificate Transparency log** — tamper-evident Merkle tree (SHA3-256, RFC 6962 style)
  - `key_reg` entries: pubkey registrations
  - `relay_reg` entries: ML-DSA-65 signed relay self-registrations
- **Relay registry** — `GET /v2/relays` + `POST /v2/relays/register` (public, no auth)
- **W3C DID registry** — `POST /v2/did/register`, `GET /v2/did/:did`
- **WebSocket streaming** — `/v2/stream` for live transfer signaling
- **NATS JetStream** — optional push transport (set `NATS_URL`)
- **Argon2id** — password-protected blob drops (`/v2/drop`)
- **Pre-shared secrets (PSS)** — relay-MITM prevention via `/v2/session`
- **Hardware attestation** — TPM 2.0 / Apple Secure Enclave via `/v2/attest`
- **Rate limiting** — per-key hourly limits (free: 50/h, pro: 500/h, enterprise: unlimited)
- **Prometheus metrics** — `/metrics` (requires `Authorization: Bearer $ADMIN_TOKEN`)
- **TOTP-SHA256 MFA** — admin endpoints protected by ADMIN_TOKEN + 6-digit TOTP
- **Self-integrity check** — SHA-256 of `relay.js` logged at startup

## Adding a user (zero downtime)

```bash
export $(grep -v '^#' .env | xargs)
python3 scripts/paramant-admin.py add --label alice --plan pro --email alice@example.com
python3 scripts/paramant-admin.py sync
# Syncs to all relay containers via /v2/reload-users — no restart needed
```

## Verifying relay registry

After setting `RELAY_SELF_URL` and `RELAY_PRIMARY_URL` in docker-compose.yml:

```bash
curl -s https://health.yourdomain.com/v2/relays | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'Relays: {d[\"count\"]}')
for r in d['relays']:
    print(f'  {r[\"sector\"]:10} {r[\"url\"]}  verified_since: {r[\"verified_since\"][:10]}')
"
```
