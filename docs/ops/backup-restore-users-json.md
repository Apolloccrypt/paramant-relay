# users.json backup & restore (paramant.app hosted service)

**Scope:** paramant.app's OWN `users.json` (the ~accounts on our hosted
relays). This is NOT self-host customer data — self-hosters back up their
own relays. This document covers our backup of our hosted users, for which
Mick is the data controller.

## Backup

- **Schedule:** daily 03:15 (server local time) via `/etc/cron.d/paramant-backup`
- **Script:** `/home/paramant/scripts/backup-users-json.sh`
- **What it does:** for every running `*relay*` container that has
  `/data/users.json`, copies it out, bundles all into one tarball, and
  encrypts the bundle with `age`.
- **Encryption:** `age` asymmetric (public-key). Only the private key can
  decrypt; the script only needs the public key.
- **Storage:** `/home/paramant/backups/users-json/`
  - `daily/`   — 30 days rolling (older files auto-pruned)
  - `monthly/` — first-of-month snapshots, kept permanently
- **Loud-fail guard:** if zero `users.json` files are captured, the script
  writes an ERROR to the log and exits non-zero **without** producing an
  empty (false-safe) backup. Check the log, do not assume success.
- **Optional offsite:** `/home/paramant/scripts/backup-offsite.sh` (NOT
  created yet; wire up a Hetzner Storage Box or S3-compatible target there.
  Until it exists, backups are on-box only — single point of failure).
- **Log:** `/var/log/paramant-backup.log`

## Encryption key

- **Private key:** `/root/.config/paramant-backup/key.txt` (mode 600, root)
- **Public key:** `age1xkhyw2ccdzyx98nrz08w9aslycz9x39dev3udcw8k2lwwsakf3eslxe7rz`
  (safe to share; this is what the script encrypts to)

**CRITICAL:** the private key is the ONLY way to decrypt every backup.
Lose it and all backups are permanently unreadable.

- Keep an OFFLINE copy of the private key (USB in a physical safe, or printed
  on paper). Retrieve it once with:
  `ssh root@116.203.86.81 'cat /root/.config/paramant-backup/key.txt'`
- NEVER commit the private key to any git repository, public or private.
- The private key sitting next to the backups on the same box is fine for
  availability but means a full-host compromise exposes both — the offline
  copy is the real disaster-recovery anchor.

## First verified run (REQUIRED before trusting the schedule)

The cron is installed and active, but the backup has not yet been run with a
real read of the production containers (that read was deliberately gated as a
production-data action). Run it once and confirm it captured non-empty data:

```
ssh root@116.203.86.81 'bash /home/paramant/scripts/backup-users-json.sh; tail -2 /var/log/paramant-backup.log'
# Expect: "backup OK: N file(s) -> ...users-<ts>.tar.gz.age (<size>)"
# If you see "ERROR: 0 users.json captured", the path /data/users.json is
# wrong for these containers — adjust the script before relying on it.
```

Then confirm the backup actually decrypts (full round-trip):

```
ssh root@116.203.86.81 '
  LATEST=$(ls -t /home/paramant/backups/users-json/daily/*.age | head -1)
  age -d -i /root/.config/paramant-backup/key.txt "$LATEST" | tar -tz
'
# Expect: a list of users-<container>.json entries.
```

## Restore (full)

```
LATEST=$(ls -t /home/paramant/backups/users-json/daily/*.age | head -1)

# Decrypt + extract
age -d -i /root/.config/paramant-backup/key.txt "$LATEST" > /tmp/restore.tar.gz
mkdir -p /tmp/restore && tar -xzf /tmp/restore.tar.gz -C /tmp/restore
ls /tmp/restore/

# Per relay container, copy back its users.json
for f in /tmp/restore/users-*.json; do
  CONT=$(basename "$f" .json | sed 's/users-//')
  docker cp "$f" "$CONT:/data/users.json"
  docker restart "$CONT"
done

# Verify
docker exec paramant-relay-main sh -c 'wc -l /data/users.json'
```

## Restore (single user, surgical)

```
# Decrypt + extract as above, then find the user:
jq '.[] | select(.email == "alice@example.com")' /tmp/restore/users-paramant-relay-main.json
# Merge the entry back into the live users.json (use /admin/cli, or edit the
# file in the container and restart it).
```

## Quarterly test-restore

Every 3 months, dry-run a restore into a staging container: decrypt, extract,
load, verify integrity. A backup you have never restored is not a backup.

## Future

When the private `paramant-management` repo exists, move this file there.
Until then it lives in the public repo. The script, the key, and the actual
backups are NEVER in any git repository — only on the live server.
