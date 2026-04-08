# PARAMANT Self-Hosting Guide

**Version:** v2.2.0  
**License:** BUSL-1.1 — source available, free for non-production use and up to 5 API keys  
**Change date:** 2029-01-01 → Apache 2.0

---

## Quick Start

One command installs everything — Docker, TLS, all 4 sector relays:

```bash
curl -fsSL https://paramant.app/install.sh | bash
```

Or manually in 4 steps:

```bash
git clone https://github.com/Apolloccrypt/paramant-relay
cd paramant-relay
cp .env.example .env        # edit: set ADMIN_TOKEN
docker compose up -d
curl -sk https://localhost/health
```

---

## Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Ubuntu 22.04+ / Debian 12+ / RHEL 9+ | Any Linux with Docker |
| RAM | 1 GB | 512 MB reserved per relay for blob storage |
| Disk | 10 GB | Logs + Docker images |
| Docker | 24.0+ | Auto-installed by install.sh |
| Swap | **Disabled** | Required — relay uses RAM-only storage |
| Ports | 80, 443 | Configurable via HTTP_PORT / HTTPS_PORT |

**Disable swap before starting:**
```bash
sudo swapoff -a
sudo sed -i '/swap/d' /etc/fstab
```

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
nano .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ADMIN_TOKEN` | **Yes** | — | Admin API token. Generate: `openssl rand -hex 32` |
| `PORT` | No | `3001` | Relay listen port (set per sector in docker-compose) |
| `SECTOR` | No | `health` | Relay sector: `health` / `legal` / `finance` / `iot` |
| `RAM_LIMIT_MB` | No | `512` | Max RAM for blob storage per relay |
| `RAM_RESERVE_MB` | No | `256` | RAM reserve before rejecting uploads |
| `RELAY_MODE` | No | `ghost_pipe` | Endpoint set: `ghost_pipe` or `iot` |
| `USERS_FILE` | No | `./users.json` | Path to API key store |
| `PARAMANT_LICENSE` | No | — | Pro license key (`plk_...`) for unlimited API keys |
| `RESEND_API_KEY` | No | — | For welcome emails when adding users |
| `HTTP_PORT` | No | `80` | Override if port 80 is in use |
| `HTTPS_PORT` | No | `443` | Override if port 443 is in use |
| `DOMAIN` | No | `localhost` | Your domain — used for self-signed cert CN |

---

## What Gets Deployed

```
docker compose up -d
```

Starts 5 containers:

| Container | Role | Internal Port |
|-----------|------|---------------|
| `relay-health` | Health sector relay | 3005 |
| `relay-legal` | Legal sector relay | 3002 |
| `relay-finance` | Finance sector relay | 3003 |
| `relay-iot` | IoT sector relay | 3004 |
| `nginx` | TLS termination + routing | 80, 443 |

**Networks:**
- `relay-internal` — relays only reachable via nginx (internal: true)
- `relay-external` — nginx uses this for Let's Encrypt ACME challenges

**TLS:**
- If no cert is found in the `paramant-certs` volume, a self-signed cert is auto-generated
- For production: use `install.sh` which runs Certbot automatically
- To bring your own cert: mount to `/etc/nginx/certs/cert.pem` and `/etc/nginx/certs/key.pem`

---

## Managing API Keys

### Add a user (zero downtime)

```bash
# On the host, with ADMIN_TOKEN exported
export $(grep -v '^#' .env | xargs)

python3 scripts/paramant-admin.py add \
  --label "alice" \
  --plan pro \
  --email alice@example.com

python3 scripts/paramant-admin.py sync
# ✓ health: 3 keys loaded (zero downtime)
# ✓ legal: 3 keys loaded
# ✓ finance: 3 keys loaded
# ✓ iot: 3 keys loaded
```

### List all keys

```bash
python3 scripts/paramant-admin.py list
```

### Revoke a key

```bash
python3 scripts/paramant-admin.py revoke --key pgp_xxxxx
python3 scripts/paramant-admin.py sync
```

### Plans

| Plan | Uploads/day | Max file size | Priority |
|------|-------------|---------------|----------|
| `free` | 10 | 20 MB | Low |
| `pro` | Unlimited | 500 MB | High |
| `enterprise` | Unlimited | Unlimited | Highest |

---

## Community Edition Limits

The Community Edition is **free** and includes full post-quantum encryption. It is limited to **5 active API keys**.

```bash
# Check current edition
curl -sk https://your-domain/health | python3 -m json.tool | grep edition
# "edition": "community"
```

To unlock unlimited keys, set a Pro license key in `.env`:

```bash
PARAMANT_LICENSE=plk_your_license_key_here
```

Licenses available at **paramant.app/pricing** (coming soon).

---

## paramant CLI

The installer adds a `paramant` command to your system:

```bash
paramant status          # show all relay health
paramant logs health     # tail logs for health relay
paramant logs legal      # tail logs for legal relay
paramant reload          # zero-downtime key reload
paramant upgrade         # pull latest and restart
paramant start           # docker compose up -d
paramant stop            # docker compose down
paramant restart         # restart all containers
paramant token           # show your ADMIN_TOKEN
```

---

## Pre-flight Check

Before starting, run the pre-flight check:

```bash
bash scripts/preflight.sh
```

Output:
```
PARAMANT pre-flight check
─────────────────────────
HTTP_PORT=80  HTTPS_PORT=443
✓ Port 80 free
✓ Port 443 free
✓ Docker 29.3.1
✓ Swap disabled
✓ Ready for docker compose up -d
```

If ports are in use, add to `.env`:
```bash
HTTP_PORT=8080
HTTPS_PORT=8443
```

---

## Production Setup

### With a domain + Let's Encrypt

```bash
# Set your domain in .env
echo "DOMAIN=relay.yourdomain.com" >> .env

# Use install.sh for automatic Let's Encrypt
curl -fsSL https://paramant.app/install.sh | bash
```

### Firewall

```bash
# Allow only necessary ports
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (ACME challenge + redirect)
ufw allow 443/tcp   # HTTPS
ufw enable
```

### Verify everything works

```bash
# All 4 sectors
for sector in health legal finance iot; do
  echo -n "$sector: "
  curl -sk https://your-domain/health \
    -H "Host: $sector.your-domain" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ok'), d.get('edition'))"
done
```

---

## Architecture

```
Internet
    │
    ▼
nginx (TLS termination)
    │
    ├── health.your-domain → relay-health:3005
    ├── legal.your-domain  → relay-legal:3002
    ├── finance.your-domain → relay-finance:3003
    └── iot.your-domain    → relay-iot:3004

relay-internal network (isolated)
    └── relays never directly reachable from outside
```

**Security properties:**
- All blobs stored in RAM only — never written to disk
- Burn-on-read — deleted from RAM after first download
- Swap disabled — RAM cannot be paged to disk
- Relay never sees plaintext (with proper E2E SDK usage)
- BUSL-1.1 tamper-detection: relay logs SHA-256 checksum of itself at startup

---

## Upgrade

```bash
paramant upgrade
# or manually:
cd /opt/paramant
git pull
docker compose build --no-cache
docker compose up -d
```

---

## Troubleshooting

### Port already in use

```bash
# Find what's using the port
sudo ss -tlnp | grep ':80'
# Add to .env:
echo "HTTP_PORT=8080" >> .env
echo "HTTPS_PORT=8443" >> .env
docker compose up -d
```

### Relay not responding

```bash
paramant logs health
# or:
docker logs paramant-relay-relay-health-1 --tail 20
```

### Reset everything

```bash
docker compose down -v    # removes volumes too
docker compose up -d
```

### Check edition and key count

```bash
curl -sk https://localhost/health | python3 -m json.tool
```

---

## Support

- **Docs:** paramant.app/docs
- **GitHub:** github.com/Apolloccrypt/paramant-relay
- **Issues:** github.com/Apolloccrypt/paramant-relay/issues
- **Email:** hello@paramant.app

Community Edition support is community-only (GitHub Issues).  
Pro license includes email support.
