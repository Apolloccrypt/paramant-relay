# Deploy Runbook - paramant.app v3.0.0

Target server: `116.203.86.81` (Hetzner). Mick runs this manually over SSH.
The relays are **built from source** by docker-compose (`build: ./relay`), so
deploy = git pull + `docker compose build` + recreate. There is no registry
image to pull. Rollback restores the previously-built local images (see below),
not an earlier git commit.

Adjust `COMPOSE_DIR` below if the checkout is not at `/home/paramant/app`.

```
COMPOSE_DIR=/home/paramant/app
BACKUP_DIR=/home/paramant/backups
```

Service / port map (docker-compose.yml, all bound to 127.0.0.1):

| service        | container               | port |
|----------------|-------------------------|------|
| relay-main     | paramant-relay-main     | 3000 |
| relay-health   | paramant-relay-health   | 3001 |
| relay-finance  | paramant-relay-finance  | 3002 |
| relay-legal    | paramant-relay-legal    | 3003 |
| relay-iot      | paramant-relay-iot      | 3004 |
| admin          | paramant-relay-admin    | 4200 |

nginx (paramant.app) proxies: `/health` and `/v2/` -> relay-main:3000,
`/admin/` -> admin:4200, `/.well-known/` -> static, `/ /setup /dashboard /docs`
-> frontend upstream.

---

## Pre-deploy checklist

- [ ] All open 3.0.0 PRs merged to main in order (e.g. #58 admin CLI and any
      others), CI green on each.
- [ ] `main` HEAD updated; CI green on main.
- [ ] Version is 3.0.0 in `package.json` and `relay/package.json` (PR #57).
- [ ] M5b soak status acknowledged (we deploy regardless).
- [ ] `curl` and `jq` available on the machine you run the smoke test from.
- [ ] You can reach the server: `ssh root@116.203.86.81`.

---

## Deploy procedure

### Step 1: Backup current state + tag rollback images

This is what makes rollback possible. It tags every currently-running relay/
admin image and writes a manifest that `scripts/rollback-3.0.0.sh` reads.

```bash
ssh root@116.203.86.81
cd /home/paramant/app          # = $COMPOSE_DIR

TS=$(date +%Y%m%d-%H%M)
mkdir -p /home/paramant/backups
MANIFEST=/home/paramant/backups/rollback-images-$TS.txt
: > "$MANIFEST"

for svc in relay-main relay-health relay-finance relay-legal relay-iot admin; do
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  [ -z "$cid" ] && { echo "skip $svc (not running)"; continue; }
  img=$(docker inspect --format '{{.Config.Image}}' "$cid")
  rb="paramant-rollback/$svc:$TS"
  docker tag "$img" "$rb"
  echo "$svc|$img|$rb" >> "$MANIFEST"
  echo "tagged $svc -> $rb"
done

# Pointer the rollback script looks for first:
ln -sfn "$MANIFEST" /home/paramant/backups/rollback-images-latest.txt

# Snapshot compose state + env (env may hold secrets; keep backups dir private)
docker compose ps  > /home/paramant/backups/state-pre-3.0.0-$TS.txt
cp .env /home/paramant/backups/.env-pre-3.0.0-$TS

echo "Backup tagged at $TS; manifest: $MANIFEST"
```

Verify the manifest is non-empty before continuing:

```bash
cat /home/paramant/backups/rollback-images-latest.txt
```

### Step 2: Pull new code + build images

```bash
cd /home/paramant/app
git fetch origin
git status            # confirm clean; stash/commit any local edits first
git pull origin main

# Build from source (relays + admin share build contexts ./relay and ./admin)
docker compose build
```

### Step 3: Confirm .env

Only `CRYPTO_MODE` is relevant for the R006 crypto change. Core mode keeps a
single KEM (ML-KEM-768) loaded; it is the default, set it explicitly for clarity:

```bash
cd /home/paramant/app
grep -q "^CRYPTO_MODE=" .env || echo "CRYPTO_MODE=core" >> .env
```

The frontend is static and served by nginx (frontend upstream), not by the
relay - there is no SERVE_FRONTEND/FRONTEND_ROOT to set. `git pull` already
updated the frontend assets.

### Step 4: Recreate services + wait for health

```bash
cd /home/paramant/app

# Backend first
docker compose up -d --no-deps relay-main

# Wait for health (relay-main is on 127.0.0.1:3000)
for i in $(seq 1 30); do
  if curl -fs --max-time 3 http://127.0.0.1:3000/health >/dev/null; then
    echo "relay-main healthy"; break
  fi
  sleep 2
done

# Then the sector relays + admin
docker compose up -d --no-deps relay-health relay-finance relay-legal relay-iot admin

# If nginx config changed (it usually does not for this deploy):
# sudo nginx -t && sudo systemctl reload nginx
```

### Step 5: Smoke test

From your laptop (or on the server). On the server, pass the local relay URL as
the 2nd arg so the deep-health check runs too:

```bash
# From laptop (public only):
bash scripts/post-deploy-verify.sh https://paramant.app

# On the server (adds /health/deep):
bash scripts/post-deploy-verify.sh https://paramant.app http://127.0.0.1:3000
```

Exit codes:

- `0` = all green
- `1` = non-critical failures (investigate, no rollback)
- `2` = CRITICAL failure (health/version/capabilities) -> consider rollback

A markdown report is written to `/tmp/deploy-verify-<epoch>.md`.

### Step 6: Monitor ~30 minutes

```bash
# Tail relay logs
docker compose logs -f --tail=200 relay-main

# Spot-check the relay audit chain (admin token from .env)
curl -s -H "X-Admin-Token: $ADMIN_TOKEN" http://127.0.0.1:3000/v2/audit \
  | jq '.events[0:10]' 2>/dev/null
```

Watch for: 5xx spikes (code), 4xx spikes (config), memory growth (leak), or
user reports.

---

## Rollback (if needed)

Triggered by a CRITICAL smoke-test failure (exit 2) or clear breakage.

```bash
ssh root@116.203.86.81
cd /home/paramant/app
COMPOSE_DIR=/home/paramant/app bash scripts/rollback-3.0.0.sh
```

The script confirms (yes/no), restores the images tagged in Step 1's manifest,
recreates the containers **without rebuilding** (so the new source is ignored),
waits for `:3000/health`, and optionally restores `.env`.

Manual fallback (single service):

```bash
# Find a saved rollback tag
docker images | grep paramant-rollback
# Restore it to the compose image name the container expects, then recreate
IMG=$(docker inspect --format '{{.Config.Image}}' paramant-relay-main)
docker tag paramant-rollback/relay-main:<TS> "$IMG"
docker compose up -d --no-deps --force-recreate relay-main
```

---

## Post-deploy checklist

- [ ] Smoke test exits 0 (or only known non-critical failures understood).
- [ ] 30-minute soak monitored, no error spikes.
- [ ] Update `CHANGELOG.md` with the 3.0.0 live date.
- [ ] Announce in community channels.
- [ ] Close the deploy tracking issue.
- [ ] Tag the release: `git tag v3.0.0 && git push origin v3.0.0`.
