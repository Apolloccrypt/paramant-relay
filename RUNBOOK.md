# Runbook: running Paramant without the usual operator

For whoever has to keep Paramant up when the usual operator, or the usual
assistant, is not there. Plain shell, no tool or model assumed. Every command
says where it runs:

- **[admin]** the admin machine: a checkout of this repo with the production SSH
  key. The deploy scripts refuse to run anywhere else.
- **[server]** the production host, as root, after `cd /opt/paramant-relay`.

The long versions live in [deploy/DEPLOY-3.1.md](deploy/DEPLOY-3.1.md) (deploy,
rollback, backup timer) and [docs/ONBOARDING.md](docs/ONBOARDING.md) (layout,
tests, monitoring). This file is the short path through them. It contains no
secret values and never will.

## 1. Access and escrow

### The rule

Secrets never go into git: not in code, not in a commit message, not in an
issue, not in this file. They live in `/opt/paramant-relay/.env` (mode 600) on
the server, in files on the server, or in the accounts below.

### Secrets in the production `.env` (names only)

| Name | What it guards |
|---|---|
| `MOLLIE_API_KEY`, `MOLLIE_TEST_API_KEY` (and any other `MOLLIE*`) | payments |
| `RESEND_API_KEY` (and any other `RESEND*`) | outgoing mail |
| `ADMIN_TOKEN` | the admin API and panel login |
| `ADMIN_TOTP_SECRET` | second factor of the admin login |
| `TOTP_SECRET` | relay-side TOTP |

Switching mail carrier: put the new keys in the production `.env` first, then
update `deploy/mail-provider.json` (`actief`, `naam`, `land`, `prod_sleutels`),
then /privacy, /dpa and every page that names the carrier, in both languages.
`tests/mail-provider-site.test.mjs` fails while those three disagree.
| `PARAMANT_TOTP_MASTER_KEY` | encrypts the stored user TOTP secrets |
| `RECIPIENT_HASH_KEY` | keyed hash of recipient addresses |
| `REDIS_PASSWORD` | redis, read by `docker-compose.yml` |
| `INTERNAL_AUTH_TOKEN` | admin to relay, and the deep health check |
| `PLK_KEY` | license key material |
| `PARAMANT_LICENSE` | license |
| `PARAMANT_WACHT_KEY` | **unknown**: no file in this repo reads this name. Check the server `.env` before assuming it matters |

`deploy/.env.example` documents every name the relay and admin read, with the
file that reads it.

### Secret files

| File | Where |
|---|---|
| `relay-identity.json` | one per relay, in that relay's `/data` volume. The relay's ML-DSA-65 signing key. A relay that cannot read it stops (exit 78) rather than make a new one |
| TLS certificates | `/etc/letsencrypt` for nginx; Caddy in front keeps its own under `/etc/caddy` or its data directory (**not verified** where exactly) |
| `/home/paramant/secrets` | host-side secrets, if present |
| `/root/.config/paramant-backup/key.txt` | the age key of the backups, root only |

### External accounts

Hetzner (the server), Bunny (DNS), the domain registrar, GitHub (code, CI,
heartbeat secrets), Mollie (payments), Resend (mail). Who holds the logins and
the second factors is kept outside this repo.

### Escrow

The backup bundle is the escrow. It holds the relay data, redis, the `.env`,
nginx, the certificates and `/home/paramant/secrets` (see section 5). Every
bundle is encrypted to two kinds of key:

1. the server key in `/root/.config/paramant-backup/key.txt`, so a restore on
   the server works;
2. an offline escrow key whose public half is in
   `/root/.config/paramant-backup/recipients.txt`. Its private half is **not on
   the server**. It is printed on paper and kept by the owner.

A lost or seized server therefore takes no key with it that the owner does not
also have. Check which keys the next backup uses:

```bash
# [server]
bash deploy/ops/backup-full-state.sh --recipients    # expect "recipients: 2" or more
```

## 2. Deploy and rollback

1. Only from **[admin]**. Read `deploy/DEPLOY-3.1.md` once before the first deploy.
2. `main` is green in CI for the commit you deploy. Nothing gets merged while a deploy runs: the script expects one HEAD from start to finish.
3. Preflight, read-only: `bash deploy/deploy-3.1.sh --preflight-only`
4. Start detached, so a dropped connection does not kill it halfway:
   `setsid nohup bash deploy/deploy-3.1.sh > deploy-$(date +%Y%m%d-%H%M).log 2>&1 < /dev/null &`
5. Follow it with `tail -f deploy-*.log`. Phase 2 prints a `TS`; write it down.
6. A deploy that died in the checks: `bash deploy/deploy-3.1.sh --verify-only`
7. Rollback, **[admin]**: `bash deploy/deploy-3.1.sh --rollback <TS>`
8. No TS at hand: **[server]** `cat /home/paramant/backups/rollback-images-latest.txt` names the images of the last deploy; the TS is in each tag (`paramant-rollback/<svc>:<TS>`).
9. By hand on **[server]**: `COMPOSE_DIR=/opt/paramant-relay BACKUP_DIR=/home/paramant/backups bash scripts/rollback-3.0.0.sh`
10. After either: `curl -s http://127.0.0.1:3000/health` on **[server]** returns 200 with the old version.

## 3. Incident: 502, health not 200, or the deny rules gone

**First roll back, then find out why.** A rollback takes minutes and is safe;
diagnosis on a broken production is neither.

```bash
# [admin] what the outside sees
curl -s -o /dev/null -w '%{http_code}\n' https://paramant.app/
curl -s -o /dev/null -w '%{http_code}\n' https://health.paramant.app/health
curl -s -o /dev/null -w '%{http_code}\n' https://paramant.app/.env      # 403 or 404, never 200

# [admin] roll back to the last deploy
bash deploy/deploy-3.1.sh --rollback <TS>
```

Only when the site is back:

```bash
# [server] cd /opt/paramant-relay first
docker compose ps                                        # which container is not Up (healthy)
docker compose logs --tail 100 relay-main                 # or the one that is down
curl -s http://127.0.0.1:3000/health                      # relay-main; 3001 to 3004 are the sectors
nginx -t                                                  # a broken conf is a 502 for everything
ls /etc/nginx/backups/                                     # the confs step 2 saved, per TS
journalctl -u nginx --since '1 hour ago' --no-pager | tail -50
```

A relay that logs `relay_identity_unreadable` and exits 78 found its identity
file but could not read it. Do not delete the file: restore it from the backup
(section 5), or fix its permissions. Deleting it makes a new key and breaks
every receipt signed under the old one.

The deny rules (`/.env`, `/.git` and similar answering 403/404) live in the
nginx confs. If they are gone, the conf on the server is not the one in the
repo: restore the conf from `/etc/nginx/backups/`, `nginx -t`, `systemctl
reload nginx`.

## 4. Monitoring without AI

- `.github/workflows/heartbeat.yml` runs every hour at :17 against production
  and needs no assistant. It is only live when the repository variable
  `HEARTBEAT_ENABLED` is `true`. On red it opens or reopens one GitHub issue
  titled `Heartbeat rood`; on green it closes it. Watch that issue, or GitHub's
  mail about it.
- It needs three repository secrets: `PARAMANT_CANARY_KEY` and
  `PARASIGN_CANARY_KEY` (required, a missing one is a named red run) and
  `PARAMANT_INTERNAL_AUTH_TOKEN` (optional, adds the deep health checks).
- Check the switch and run it by hand, **[admin]**:

```bash
gh variable list | grep HEARTBEAT_ENABLED
gh secret list                                 # names only, never values
gh workflow run heartbeat.yml && gh run list --workflow heartbeat.yml -L 3
```

- `python3 scripts/directie/signalen.py --tekst` is the wider status meter.
  Plain `gh` and `curl`, no model. Exit 1 means something is red.

Switching it on the first time is in `docs/heartbeat.md`.

## 5. Backup and restore

### What runs

`deploy/ops/backup-full-state.sh`, daily at 03:30 UTC through the systemd timer
in `deploy/systemd/` (installation in `deploy/DEPLOY-3.1.md`, section "Daily
backup (systemd timer)"), and once more inside every deploy. Output:
`/home/paramant/backups/full-state/daily/paramant-full-<ts>.tar.gz.age`, 30 days,
plus a monthly copy.

```bash
# [server] is the timer on, and did the last run succeed
systemctl list-timers paramant-backup.timer
journalctl -u paramant-backup.service -n 20 --no-pager
ls -lt /home/paramant/backups/full-state/daily/ | head -3
```

**Unknown:** whether an offsite copy exists. The script calls
`/home/paramant/scripts/backup-offsite.sh` if that file is there; this repo
does not contain it. Until someone confirms it on the server, assume the only
copies are on the server itself, and copy the newest bundle off by hand.

### Check a backup without touching anything

```bash
# [server]
bash deploy/ops/restore-full-state.sh --inspect
```

Decrypts, verifies every hash against the manifest, lists relays, redis and
host configuration, and removes the decrypted copy again. To keep it for
reading: `--extract-to /root/restore-work` (an empty directory; remove it
afterwards, it is every secret in the clear).

### Restore on the same server

```bash
# [server] destructive: overwrites the relay volumes and redis, restarts them
bash deploy/ops/restore-full-state.sh --from <bundle> --confirm
```

It restores relay data and redis. The host configuration under `host/` is put
back by hand, see below.

### Restore on an empty machine

What is known to work is the restore script above. The steps around it, for a
machine that has nothing yet, have **not been rehearsed**. Do them in order and
write down what differs.

1. New Debian or Ubuntu host. Install `docker` (with compose), `nginx`, `age`, `git`.
2. `git clone https://github.com/Apolloccrypt/paramant-relay /opt/paramant-relay`
3. Get the newest bundle off the old server or the offsite copy (see "Unknown" above).
4. Decrypt with the escrow key. Type the paper key into a file on this machine only:
   ```bash
   install -d -m 700 /root/restore-key && vi /root/restore-key/escrow.txt
   KEYFILE=/root/restore-key/escrow.txt bash deploy/ops/restore-full-state.sh \
     --from <bundle> --inspect --extract-to /root/restore-work
   ```
5. Put the host files back from `/root/restore-work/paramant-full-*/host/`:
   `opt/paramant-relay/.env` to `/opt/paramant-relay/.env` (mode 600),
   `etc/nginx` to `/etc/nginx`, `etc/letsencrypt` to `/etc/letsencrypt`,
   `etc/caddy` to `/etc/caddy` if present, `home/paramant/secrets` likewise.
   Caddy runs in front of nginx on the current server; its install is **not in
   this repo**.
6. `cd /opt/paramant-relay && docker compose build && docker compose up -d`
   (the build fetches `paramant-core` at the commit pinned in `relay/Dockerfile`).
7. With the containers up, restore their data:
   `KEYFILE=/root/restore-key/escrow.txt bash deploy/ops/restore-full-state.sh --from <bundle> --confirm`
8. Frontend docroot: copy `frontend/` to `/home/paramant/app` the way step 5 of `deploy/DEPLOY-3.1.md` does.
9. DNS at Bunny to the new address. TLS: the restored certificates work until they expire; renewal on the new host is **not verified**.
10. Remove `/root/restore-work` and `/root/restore-key`. Set up a new server key and the timer (section 5, "What runs").
11. Check: `curl -s http://127.0.0.1:3000/health`, then section 3's outside checks.

## 6. Working with another model or another person

- **Context files.** Read [AGENTS.md](AGENTS.md) (commit and GitHub style, dev
  caveats), [docs/ONBOARDING.md](docs/ONBOARDING.md) (layout, tests, where
  production runs), [CONTRIBUTING.md](CONTRIBUTING.md), and this file. They are
  written for any model and any person; none of them needs a particular tool.
- **Merge rules.** A pull request is merged only when every required check is
  green. Branch protection on `main` has `enforce_admins` on, so an admin
  cannot skip a red check either; do not turn that off to get something in.
  Merge through the API with a squash and a message in house style:
  ```bash
  gh pr checks <n>                                   # all green, or stop
  gh api -X PUT repos/Apolloccrypt/paramant-relay/pulls/<n>/merge \
    -f merge_method=squash -f commit_title='<title>' -f commit_message='<body>'
  ```
  No AI attribution in commits or PR texts, no em-dashes, no secrets
  (`scripts/check-commit-style.sh` enforces it).
- **A local model.** Qwen3-30B-A3B through `ollama` may help read logs,
  summarise a diff or draft a text. It is a helper, never an operator: nothing
  it proposes is run on the server without a person reading the command
  first, and nothing it writes is merged without the checks above.
