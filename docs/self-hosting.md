# PARAMANT Self-Hosting Guide

**Version:** v2.3.1  
**License:** BUSL-1.1 — source available, free for up to 5 users per relay in production  
**Change date:** 2029-01-01 → Apache 2.0  
**License enforcement details:** [docs/licensing.md](licensing.md)

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
| `CT_LOG_FILE` | No | `/data/ct-log.json` | Path to CT log persistence file (health relay only) |
| `PARAMANT_LICENSE` | No | — | Relay license key (`plk_...`) — unlocks unlimited users |
| `RESEND_API_KEY` | No | — | For welcome emails when adding users |
| `HTTP_PORT` | No | `80` | Override if port 80 is in use |
| `HTTPS_PORT` | No | `443` | Override if port 443 is in use |
| `DOMAIN` | No | `localhost` | Your domain — used for self-signed cert CN |

---

## What Gets Deployed

```
docker compose up -d
```

Starts 6 containers:

| Container | Role | Internal Port |
|-----------|------|---------------|
| `relay-health` | Health sector relay | 3005 |
| `relay-legal` | Legal sector relay | 3002 |
| `relay-finance` | Finance sector relay | 3003 |
| `relay-iot` | IoT sector relay | 3004 |
| `admin` | Admin panel | 4200 (via nginx /admin/) |
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

These are **end-user plans** — they control what a `pgp_` API key holder can do.
Set when you create a key with `--plan`.

| Plan | Uploads/day | Max file size | TTL | Views/blob | Priority |
|------|-------------|---------------|-----|------------|----------|
| `free` | 10 | 20 MB | 1 hour | 1 | Low |
| `pro` | Unlimited | 500 MB | 24 hours | 10 | High |
| `enterprise` | Unlimited | Unlimited | 7 days | 100 | Highest |

> **Getting a free `pgp_` key on the managed relay:** email
> [privacy@paramant.app](mailto:privacy@paramant.app?subject=Free+API+key+request)
> with subject "Free API key request". No account or credit card needed.

---

## Community Edition Limits

The Community Edition is **free** for relay operators with up to **5 users** (active
API keys). This is a limit on the **operator** — how many `pgp_` API keys you can
issue to your users. The users themselves are unaffected by which edition you run.

Keys 6 and beyond are blocked at request time with HTTP 402. Hard enforcement in the
auth middleware. See [docs/licensing.md](licensing.md) for the full logic.

```bash
# Check edition and current user count
curl -s -H "X-Admin-Token: $ADMIN_TOKEN" https://your-domain/health \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    print('edition:', d.get('edition'), '| users:', d.get('active_keys'), '/', d.get('key_limit'))"
# edition: community | users: 3 / 5
```

To unlock unlimited users, add a relay license key to `.env`:

```bash
PARAMANT_LICENSE=plk_your_relay_license_key
```

After adding, restart the relay — logs will show `edition: licensed`.

> **Note:** `plk_` is a **relay operator license** — it unlocks more users on your
> relay. It is not what your users receive. Your users always get `pgp_` API keys.

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
- All blobs (encrypted payload) stored in RAM only — never written to disk
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
- **Email:** privacy@paramant.app

Community Edition support is community-only (GitHub Issues).  
Pro license includes email support.

---

## Web Interfaces

After deploying, the following interfaces are available at `https://your-domain`:

| URL | Access | Description |
|-----|--------|-------------|
| `/` | Public | Homepage |
| `/dashboard` | API key | User dashboard |
| `/parashare` | API key | File transfer |
| `/ct-log` | Public | Certificate transparency log |
| `/docs` | Public | API documentation |
| `/health` | Public | Relay health status |
| `/admin/` | IP + API key + TOTP | Admin panel |

---

### Dashboard — `/dashboard`

**Access:** any valid API key (`pgp_...`)

1. Go to `https://your-domain/dashboard`
2. Enter your API key (`pgp_...`)
3. Click **Connect**

Shows relay status, blob stats, and lets you test send/receive flows.

---

### ParaShare — `/parashare`

**Access:** any valid API key (`pgp_...`)

Browser-based end-to-end encrypted file transfer using ML-KEM-768:

1. Go to `https://your-domain/parashare`
2. Enter your API key
3. Select a file — a one-time link is generated
4. Share the link with the receiver
5. Receiver opens the link, file downloads once then burns

---

### CT Log — `/ct-log`

**Access:** public, no login required

Every key registration is recorded in a tamper-evident Merkle tree — without storing payload content.
Entries are persisted to `CT_LOG_FILE` (default: `/data/ct-log.json`) on each registration and reloaded on startup.
The log resets only if the file is deleted.

---

### Admin Panel — `/admin/`

**Access:** ADMIN_TOKEN (or enterprise `pgp_` key) + TOTP (6-digit authenticator)

> ⚠ Restrict access to your IP in nginx for extra security:
> ```nginx
> location /admin/ {
>     allow YOUR_ADMIN_IP;
>     deny all;
>     proxy_pass http://admin:4200/admin/;
>     ...
> }
> ```

**Login flow:**
1. Go to `https://your-domain/admin/`
2. Enter your `ADMIN_TOKEN` (from `.env`) or an enterprise `pgp_` key
3. Enter 6-digit TOTP code from your authenticator app
4. Access granted

**What you can do:**

| Tab | Actions |
|-----|---------|
| Relay Monitor | Version, edition, active keys vs limit, uptime, blobs in flight, CT log |
| API Keys | Load all keys (with BLOCKED indicator for over-limit keys), create, revoke, resend mail |
| Licenses | Generate `plk_` license key for a customer — shown once with install instructions |

**Set up TOTP:**
```bash
# Generate a TOTP secret (20 bytes = 160 bits, base32 encoded)
python3 -c "import base64, os; print(base64.b32encode(os.urandom(20)).decode())"
# Add to .env:
TOTP_SECRET=YOUR_BASE32_SECRET
# Scan the QR code or enter the secret in Aegis / Google Authenticator / Authy
```

> **Note:** PARAMANT uses **TOTP-SHA256** (RFC 6238 with HMAC-SHA256). When
> manually entering the secret in an authenticator app, select **SHA-256** as the
> algorithm if the app exposes that option. Aegis supports this. Google
> Authenticator defaults to SHA-1 and will generate incorrect codes.

---

### API Key Types

| Plan | Dashboard | ParaShare | Admin panel |
|------|-----------|-----------|-------------|
| `free` | ✓ | ✓ | ✗ |
| `pro` | ✓ | ✓ | ✗ |
| `enterprise` | ✓ | ✓ | ✓ |

Only enterprise keys can access `/admin/`.

---

### First User Setup

After deploying, create your first API key:

```bash
export $(grep -v '^#' .env | xargs)

# Create an enterprise key for yourself (admin)
python3 scripts/paramant-admin.py add \
  --label "admin" \
  --plan enterprise \
  --email you@example.com

# Reload all relays
python3 scripts/paramant-admin.py sync

# Your key is shown in the output — save it immediately
# pgp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Then go to `https://your-domain/dashboard` and enter your key.

---

## Security Notes

### ADMIN_TOKEN visibility
Anyone with `docker exec` access (i.e. root on the host) can read environment variables including `ADMIN_TOKEN`:
```bash
docker exec paramant-relay-relay-health-1 env | grep ADMIN_TOKEN
```
This is inherent to Docker. Mitigation:
- Restrict host root access
- Use Docker secrets for production deployments
- Rotate ADMIN_TOKEN regularly: update `.env` → `docker compose up -d`

### Swap
Only **disk swap** is a security risk for RAM-only blob storage. Ubuntu's default **zram** (RAM-based compression) is acceptable.

To disable disk swap only:
```bash
swapon --show=TYPE,NAME          # check what type is active
sudo swapoff /dev/sdX            # disable disk swap only
sudo sed -i '/\/dev\/sd/d' /etc/fstab
```

### Rate limiting
The nginx config includes rate limiting out of the box:
- `/v2/inbound`: 10 uploads/minute per IP (burst: 5)
- All other endpoints: 60 requests/minute per IP (burst: 30)
- Max 20 concurrent connections per IP

### Relay isolation
Relay containers are on an internal Docker network — not reachable directly from outside. All traffic goes through nginx.

### Non-root containers
All relay containers run as user `relay` (non-root). Files in `/app` are owned by root and not writable by the relay process.
