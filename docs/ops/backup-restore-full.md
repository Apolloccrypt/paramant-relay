# Full signing-critical backup & restore (paramant.app hosted docker stack)

**Scope:** the production docker-compose relay stack on the Hetzner host. This
covers the state that is UNRECOVERABLE on loss and that the older
`users.json`-only backup did NOT protect. See
`backup-restore-users-json.md` for the narrow accounts-only backup; this
document supersedes it for disaster recovery.

## What is at stake (and where it lives)

Every relay container mounts a named volume at `/data`. The redis container
mounts its own volume at `/data`. All persistent, signing-critical state is in
those volumes:

| File / dir (per relay `/data`)     | What it is                              | Lose it =                          |
|------------------------------------|-----------------------------------------|------------------------------------|
| `relay-identity.json` (0600)       | Relay signing/identity private key      | Relay identity gone, cannot re-sign |
| `paraid-demo-authority.sk.json` (0400) | ParaID demo authority private key   | ParaID issuance broken             |
| `paraid-issuers.json`              | ParaID issuer registry                  | Issuer trust set lost              |
| `ct-log.json`                      | Append-only CT log                      | Transparency history gone          |
| `sth-log.jsonl`                    | Merkle Signed-Tree-Head log             | Merkle continuity broken           |
| `peer-sths/`                       | Cross-signed peer STHs                  | Peer gossip state lost             |
| `code-manifest.json`               | Code-transparency manifest              | Code-provenance anchor lost        |
| `trial-keys.jsonl`                 | Trial keys                              | Trial state lost                   |
| `users.json`                       | Accounts (also in the old backup)       | All hosted accounts lost           |

| Redis `/data`                      | What it is                              |
|------------------------------------|-----------------------------------------|
| `dump.rdb`                         | Point-in-time snapshot                   |
| `appendonlydir/` (AOF)             | ParaSign sessions, signing blobs, mutable state |

Note on "blobs": message blobs passing through a relay in `ghost_pipe` mode are
NOT persisted to disk. The persistent ParaSign blobs/sessions live in redis, so
the redis AOF+RDB captures them.

Live production volumes (host paths, from `docker volume inspect`):
`/var/lib/docker/volumes/paramant-relay_relay-<sector>-data/_data` and
`/var/lib/docker/volumes/paramant-relay_relay-redis-data/_data`.

## Backup

- **Script:** `deploy/ops/backup-full-state.sh` (deploy to
  `/home/paramant/scripts/backup-full-state.sh` on prod).
- **What it does:** discovers running relay containers, resolves each `/data`
  mount, copies the WHOLE directory (allowlist-free, so a new state file is
  never silently missed), best-effort `BGSAVE` on redis then copies the redis
  volume, writes a `MANIFEST.txt` with a sha256 + size for every file, bundles
  to a tarball, and `age`-encrypts it.
- **Whole-directory by design:** we snapshot everything under `/data` rather
  than a fixed list, so future state files are captured automatically.
- **Encryption:** reuses the existing `age` public-key setup from the
  users-json backup. Key file `/root/.config/paramant-backup/key.txt`; the
  `# public key:` line inside it is the recipient. Only the offline private key
  decrypts. **The bundle contains private keys; treat every artifact as secret.**
- **Storage:** `/home/paramant/backups/full-state/`
  - `daily/` — rolling, kept `RETAIN_DAYS` (default 30). Each backup is
    `paramant-full-<ts>.tar.gz.age` plus a plaintext
    `paramant-full-<ts>.MANIFEST.txt` for integrity checks without decrypting.
  - `monthly/` — first-of-month snapshots, kept permanently.
- **Loud-fail guard:** if zero relay sources are captured, it writes an ERROR
  and exits non-zero WITHOUT producing a false-safe empty backup.
- **Consistency:** copied live, no downtime. `users.json` is written atomically
  by the relay (tmp+rename) so it is always consistent. Append-only logs
  (`ct-log.json`, `sth-log.jsonl`) are at worst missing a trailing partial
  line, which is recoverable. Redis runs `appendonly yes` (everysec) so the AOF
  is crash-consistent to ~1s; the best-effort `BGSAVE` adds a clean RDB point.
- **Log:** `/var/log/paramant-backup.log` (shared with the users-json backup).

### Install on prod (not yet done — gated as a production action)

```
# copy the script into place
scp deploy/ops/backup-full-state.sh root@<prod>:/home/paramant/scripts/
ssh root@<prod> 'chmod 700 /home/paramant/scripts/backup-full-state.sh'

# add a daily cron (separate line from the users-json job)
#   30 3 * * * root /home/paramant/scripts/backup-full-state.sh
```

### First verified run (REQUIRED before trusting the schedule)

```
ssh root@<prod> 'bash /home/paramant/scripts/backup-full-state.sh; tail -2 /var/log/paramant-backup.log'
# Expect: "OK: 5 relay(s) + redis=1, N file(s) -> ...paramant-full-<ts>.tar.gz.age"
```

Confirm the bundle decrypts and the manifest verifies (no live change):

```
ssh root@<prod> '
  LATEST=$(ls -t /home/paramant/backups/full-state/daily/*.age | head -1)
  age -d -i /root/.config/paramant-backup/key.txt "$LATEST" | tar -tz | head
'
```

## Restore

- **Script:** `deploy/ops/restore-full-state.sh`. Refuses to act without
  `--inspect` (safe) or `--confirm` (destructive), and the destructive path
  also requires typing `restore` at the prompt.

```
# Safe: decrypt, verify every manifest hash, list contents, touch nothing live
./restore-full-state.sh --from /path/to/paramant-full-<ts>.tar.gz.age --inspect

# Destructive: overwrite live volumes + restart containers (run as root on prod)
./restore-full-state.sh --from /path/to/paramant-full-<ts>.tar.gz.age --confirm
```

The restore verifies all sha256 hashes against the manifest BEFORE touching
anything. For relays it copies files into the container `/data` mount and
restarts the container. For redis it stops the container, clears the stale
`appendonlydir`/`dump.rdb`, copies the backed-up state, and restarts (redis
must be stopped first or it would overwrite the AOF on exit).

Post-restore health check:

```
for c in $(docker ps --format '{{.Names}}' | grep relay); do
  docker exec $c wget -qO- http://127.0.0.1:3000/health 2>/dev/null; echo
done
```

## Encryption key (disaster-recovery anchor)

Same key as the users-json backup: `/root/.config/paramant-backup/key.txt`
(mode 600, root). The private key is the ONLY way to decrypt every backup.
Keep an OFFLINE copy (USB in a safe, or printed). Never commit it to any repo.
A backup you have never restored is not a backup: dry-run a restore into a
staging container quarterly.

## Verification status (this branch)

- Dry-run on the NUC against dummy relay dirs + a throwaway redis with a real
  AOF/RDB: manifest hashed all 20 expected files (relay-identity, paraid keys,
  ct-log, sth-log, peer-sths, users, redis dump.rdb + appendonlydir).
- Full round-trip with `age`: encrypt -> decrypt -> extract -> all manifest
  hashes matched -> `--inspect` touched nothing.
- Loud-fail guard: zero relay sources exits non-zero, no empty backup written.
- NOT verified without touching prod: the live docker discovery + `BGSAVE`
  against the real redis password, and a real destructive restore. Run the
  "first verified run" above once, gated, to close that gap.
