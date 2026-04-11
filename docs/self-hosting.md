# PARAMANT Self-Hosting Guide

**Version:** v2.4.2  
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
| `PORT` | No | `3000` | Relay listen port (all containers use 3000 internally; host port is set in docker-compose) |
| `SECTOR` | Set by Compose | — | Sector identifier (`relay` / `health` / `finance` / `legal` / `iot`). Injected per-container by docker-compose — do not set manually in `.env`. |
| `RAM_LIMIT_MB` | No | `1024` | Max RAM for blob storage per relay |
| `RAM_RESERVE_MB` | No | `256` | RAM reserve before rejecting uploads |
| `RELAY_MODE` | No | `ghost_pipe` | Endpoint set: `ghost_pipe` or `iot` |
| `USERS_FILE` | No | `./users.json` | Path to API key store |
| `CT_LOG_FILE` | No | `/data/ct-log.json` | Path to CT log persistence file (health relay only) |
| `PARAMANT_LICENSE` | No | — | Relay license key (`plk_...`) — unlocks unlimited users |
| `RESEND_API_KEY` | No | — | For welcome emails when adding users |
| `RELAY_SELF_URL` | No | — | This relay's public URL (e.g. `https://relay.yourdomain.com`). Required for relay registry self-registration. |
| `RELAY_PRIMARY_URL` | No | self | URL of the registry relay to POST registrations to (e.g. `https://health.yourdomain.com`). Defaults to posting to self. |
| `RELAY_IDENTITY_FILE` | No | `/data/relay-identity.json` | Path for ML-DSA-65 relay identity keypair. Generated on first boot, reused on subsequent starts. |
| `HTTP_PORT` | No | `80` | Override if port 80 is in use |
| `HTTPS_PORT` | No | `443` | Override if port 443 is in use |
| `DOMAIN` | No | `localhost` | Your domain — used for self-signed cert CN |

---

## What Gets Deployed

```
docker compose up -d --build
```

Starts 6 containers:

| Container | Role | Host port |
|-----------|------|-----------|
| `relay-main` | Main relay | 127.0.0.1:3000 |
| `relay-health` | Health sector relay | 127.0.0.1:3001 |
| `relay-finance` | Finance sector relay | 127.0.0.1:3002 |
| `relay-legal` | Legal sector relay | 127.0.0.1:3003 |
| `relay-iot` | IoT sector relay | 127.0.0.1:3004 |
| `admin` | Admin panel | 127.0.0.1:4200 |

All five relay containers run the **same image** (`build: ./relay`). The `SECTOR` environment variable — injected per-service in `docker-compose.yml` — is the only difference between them. No separate codebases.

**Networks:**
- `relay-net` — single bridge network; all containers communicate over it. All host-side ports are bound to `127.0.0.1` — not publicly reachable. System nginx proxies inbound traffic.

**TLS:**
- Handled by **system nginx** (not a Docker container). Install via Certbot / Let's Encrypt or bring your own cert.
- See `nginx-selfhost.conf` in the repo for a hardened nginx config with rate limiting, HSTS, and OCSP stapling.

**Dockerfile — two-stage build:**
- Stage 1 (`build`): `node:20-alpine` + `python3`/`make`/`g++` → compiles `argon2` native bindings
- Stage 2 (`runtime`): lean `node:20-alpine` → copies only compiled `node_modules` + `relay.js`. No compilers, no build tools in the production image.

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
| `free` | 10 | 5 MB | 1 hour | 1 | Low |
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
system nginx (TLS termination, ports 80/443)
    │
    ├── relay.your-domain    → 127.0.0.1:3000  (relay-main)
    ├── health.your-domain   → 127.0.0.1:3001  (relay-health)
    ├── finance.your-domain  → 127.0.0.1:3002  (relay-finance)
    ├── legal.your-domain    → 127.0.0.1:3003  (relay-legal)
    ├── iot.your-domain      → 127.0.0.1:3004  (relay-iot)
    └── your-domain/admin/   → 127.0.0.1:4200  (admin)

relay-net (Docker bridge, not public)
    └── containers communicate internally; only 127.0.0.1 ports exposed to host
```

**One codebase, five containers:**
```
relay/relay.js ──(build: ./relay)──► relay-main    (SECTOR=relay)
                                  ► relay-health  (SECTOR=health)
                                  ► relay-finance (SECTOR=finance)
                                  ► relay-legal   (SECTOR=legal)
                                  ► relay-iot     (SECTOR=iot)
```

**Security properties:**
- All blobs (encrypted payload) stored in RAM only — never written to disk
- Burn-on-read — deleted from RAM after first download
- Swap disabled — RAM cannot be paged to disk
- Relay never sees plaintext (with proper E2E SDK usage)
- BUSL-1.1 tamper-detection: relay logs SHA-256 checksum of itself at startup

---

## Upgrade

The Docker image is built from the `relay/` subdirectory in your clone. After pulling new code you must rebuild the images before restarting:

```bash
cd /path/to/paramant-relay   # wherever you cloned the repo
git pull

# Build new images (node_modules cached; only relay.js layer is rebuilt)
docker compose build relay-main relay-health relay-finance relay-legal relay-iot

# Recreate containers with new images
docker compose up -d

# Named volumes (users.json, CT log, relay-identity.json) are preserved across rebuilds
```

**One-command alias** (add to `~/.bashrc`):
```bash
alias paramant-deploy='
  rsync relay/relay.js root@YOUR_SERVER:/opt/paramant-relay/relay/relay.js &&
  ssh root@YOUR_SERVER "cd /opt/paramant-relay &&
    docker compose build relay-main relay-health relay-finance relay-legal relay-iot &&
    docker compose up -d"
'
```

> **Note:** `docker compose up -d --build` works too but rebuilds all services including admin. Using explicit service names (`relay-main relay-health ...`) skips rebuilding the admin container.

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
docker logs paramant-relay-health --tail 20
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

Every key registration and relay registration is recorded in a tamper-evident Merkle tree — without storing payload content. Two entry types:

- `key_reg` — pubkey registration (existing behaviour)
- `relay_reg` — relay self-registration (see Relay Registry below)

Entries are persisted to `CT_LOG_FILE` (default: `/data/ct-log.json`) on each registration and reloaded on startup. The log resets only if the file is deleted.

The CT log viewer has two tabs: **Key Registrations** (all pubkey entries) and **Registered Relays** (relay identity entries with `verified_since` per relay).

---

### Relay Registry — `/v2/relays`

**Access:** public, no login required  
**Endpoints:** `GET /v2/relays`, `POST /v2/relays/register`

On first boot each relay generates an ML-DSA-65 keypair and stores it in `/data/relay-identity.json`. After the server starts it signs a registration payload and POSTs it to `RELAY_PRIMARY_URL`. The registration is verified (ML-DSA-65 signature + timestamp freshness check) and appended to the CT log.

**To enable for your relay stack**, add to each service's environment in `docker-compose.yml`:

```yaml
# Per-service (different URL per sector):
RELAY_SELF_URL: "https://relay.yourdomain.com"       # relay-main
RELAY_SELF_URL: "https://health.yourdomain.com"      # relay-health
# ... etc.

# Same for all services — where to POST registrations:
RELAY_PRIMARY_URL: "https://health.yourdomain.com"
```

After restarting, verify registration:
```bash
curl -s https://health.yourdomain.com/v2/relays | python3 -m json.tool
```

Expected output (one entry per registered relay):
```json
{
  "ok": true,
  "relays": [
    {
      "url": "https://relay.yourdomain.com",
      "sector": "relay",
      "version": "2.4.2",
      "edition": "community",
      "pk_hash": "3d9b960c...",
      "verified_since": "2026-04-11T02:14:13Z",
      "last_seen": "2026-04-11T02:14:13Z",
      "ct_index": 0
    }
  ],
  "count": 1
}
```

`verified_since` is the timestamp of the first CT log entry for this relay's public key — it proves how long the relay has been running the same identity. `pk_hash` is SHA3-256 of the ML-DSA-65 public key — stable across relay restarts as long as `/data/relay-identity.json` is preserved.

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
