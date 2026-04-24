# Docker Hardening & Cleanup — 2026-04-24

Operational notes from a security sweep of the local Docker host running the
`paramant-relay` stack. Documents what was removed, what was changed, and
what remains as follow-up.

## 1. Residue cleanup

Pre-cleanup state: 57 images / 2.07 GB total, 79% reclaimable.

| Resource | Removed | Reason |
|----------|---------|--------|
| Containers | `intelligent_brattain`, `docker-admin-1` | Created state, never started; 9–14 days stale |
| Dangling images | ~40 untagged layers | Orphan build artifacts — 1.164 GB reclaimed |
| Networks | `docker_relay-internal`, `paramant-relay_relay-internal`, `paramant-relay_relay-external` | Left over from a previous compose project layout |
| Volumes | `paramant-relay_paramant-certs`, `paramant-relay_relay--data` (note the double-dash typo), `relay-{finance,health,iot,legal,main}-data` (unprefixed set) | Empty (4K each) — verified before delete. The `paramant-relay_relay-*-data` set (in use) was kept |
| Stale base images | `hello-world`, `busybox` (19 mo), `alpine`, `nginx:1.27-alpine` (12 mo), `nginx:alpine`, `mtty001/relay`, `paramant-admin` (old build), `node:20-alpine`, `node:20-alpine3.21` | Unreferenced by compose or any Dockerfile |

Post-cleanup state: 8 images / 218 MB, 7 running containers all healthy.

## 2. Container hardening

### Redis service (`docker-compose.yml`)

The Redis service was the only container without `read_only`, `cap_drop`, or
a `tmpfs` mount. PID 1 already ran as the `redis` user thanks to the image's
gosu entrypoint, but the container still had the full default capability
set and a writable rootfs.

Added:

```yaml
user: "redis"
cap_drop:
  - ALL
read_only: true
tmpfs:
  - /tmp:size=16m,mode=1777
```

The explicit `user: "redis"` removes reliance on the entrypoint's privilege
drop; the container starts without ever being root. Existing volume data
at `/data` is already owned by `redis:redis` (999:1000), so no chown
migration was needed.

### Image pinning by digest

All first-party Dockerfiles and the Redis service now pin base images by
SHA-256 digest alongside the tag. Tag-only references are mutable; a push
to the same tag will silently change the base image on the next rebuild.

| File | Old | New |
|------|-----|-----|
| `relay/Dockerfile` (build + runtime stages) | `node:22-alpine3.21` | `node:22-alpine3.21@sha256:af8023ec…f8885` |
| `admin/Dockerfile` | `node:22-alpine3.21` | `node:22-alpine3.21@sha256:af8023ec…f8885` |
| `docker-compose.yml` (redis service) | `redis:7.4.8-alpine` | `redis:7.4.8-alpine@sha256:7aec734b…8ee6` |

Digests resolved 2026-04-24 against Docker Hub. When bumping a base image,
refresh both the tag and the digest in the same commit.

## 3. Docker daemon configuration

Created `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true,
  "no-new-privileges": true,
  "icc": false,
  "userland-proxy": false
}
```

Rationale:

- **`log-opts`** — caps json-file driver at 50 MB per container (10 MB × 5
  rotation). Prevents an unbounded `/var/lib/docker/containers/*/*-json.log`
  on chatty services. Per-service `logging:` blocks in compose already set
  tighter limits; this is the host-wide safety net.
- **`live-restore: true`** — containers keep running across dockerd
  restarts. Enabled live via `systemctl reload docker` on 2026-04-24 (no
  container downtime). Required for safe future daemon restarts.
- **`no-new-privileges: true`** — host-wide default matching the
  `security_opt` already set on every service in compose.
- **`icc: false`** — disables cross-container traffic on the default
  bridge. User-defined networks (`relay-net`) are unaffected, so the
  stack's internal wiring still works; this only hardens the default
  bridge that nothing in our stack uses.
- **`userland-proxy: false`** — forces iptables DNAT instead of the
  `docker-proxy` process. Removes one unprivileged process per published
  port and a historical source of memory bloat.

Note: `live-restore` was applied via SIGHUP and is active. The other
options apply on the next `systemctl restart docker`. Since live-restore
is now on, that restart is safe to schedule at any quiet moment — the
running containers will not be killed.

## 4. Follow-ups — not applied

### User namespace remapping (`userns-remap`)

Recommended but **not enabled** in this pass. Turning it on:

1. Relocates the entire `/var/lib/docker` tree to
   `/var/lib/docker/<uid>.<gid>/`. Existing images, containers, and
   volumes become invisible until migrated.
2. Requires a daemon restart (safe now that live-restore is on, but
   containers will still need to be re-created against the remapped
   storage root).
3. Changes UID/GID ownership of bind-mounted host paths. The relay stack
   uses named volumes only, so this is less of a risk, but any future
   bind-mount (e.g. certs from `/etc/letsencrypt`) needs the subordinate
   UID/GID accounted for.

When scheduling this: `docker compose down`, back up
`/var/lib/docker/volumes`, add `"userns-remap": "default"` to
`daemon.json`, restart dockerd, rebuild and `docker compose up -d`.

### Rebuild to pick up pinned digests

The running `paramant-relay-*` images were built before the Dockerfile
digest pins were added. They're safe, but the pin only takes effect on
the next build:

```
cd /opt/paramant-relay && docker compose build --pull
docker compose up -d
```

Run this at the next regular deploy window; no urgency.

### Periodic `docker system prune`

Consider a weekly cron — `docker system prune -f --filter "until=168h"` —
to keep dangling images from re-accumulating between deploys. Volumes are
intentionally excluded.

## 5. Verification

Post-change state (2026-04-24):

```
$ docker ps --format '{{.Names}} {{.Status}}'
paramant-relay-redis    Up 43 seconds (healthy)
paramant-relay-admin    Up 2 days (healthy)
paramant-relay-legal    Up 2 days (healthy)
paramant-relay-finance  Up 2 days (healthy)
paramant-relay-health   Up 2 days (healthy)
paramant-relay-iot      Up 2 days (healthy)
paramant-relay-main     Up 2 days (healthy)

$ docker inspect paramant-relay-redis --format \
    'ReadOnly={{.HostConfig.ReadonlyRootfs}} User={{.Config.User}} CapDrop={{.HostConfig.CapDrop}}'
ReadOnly=true User=redis CapDrop=[ALL]

$ docker info --format '{{.LiveRestoreEnabled}}'
true
```
