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

Every outside party, with its status, the key names that belong to it and a
source for each claim, is in [deploy/partners.json](deploy/partners.json)
(section 7 below). The accounts with a login: Hetzner (the server), Bunny
(DNS), the registrar (Key-Systems, per RDAP), Proton (the mailbox behind the
MX), GitHub (code, CI, heartbeat secrets), Docker Hub (images), Mollie
(payments), Resend (mail). Who holds the logins and the second factors is kept
outside this repo.

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

## 7. Partners: adding, switching or retiring an outside party

`deploy/partners.json` is the one source for every outside party Paramant
depends on: hosting, DNS, registrar, TLS, mail, payments, bookkeeping, code
hosting, images, and the ones the code knows but production does not use. The
public page `/partners` reads a copy of it (`frontend/partners.json`), and
`tests/partners.test.mjs` holds the site, the code and the production `.env`
to it. Each party has a `status`: `actief` (production uses it now),
`in-code-niet-actief` (the code knows it, production has no keys; shown as "In
preparation") or `uitgefaseerd` (gone, with the date in `tot`).

### The order, always

1. **Keys on production.** Put the new party's keys in
   `/opt/paramant-relay/.env` **[server]**, and make sure
   `docker-compose.yml` passes each name to the container: `.env` only fills in
   `${VAR}`, a name not listed never arrives.
2. **partners.json.** Set the status, the key names (`sleutels`), `sinds` or
   `tot`, the legal name, country, parent company and `dpa_url`, each with a
   line under `bronnen`. Unknown stays `null` with `"onbekend"`. Then
   `cp deploy/partners.json frontend/partners.json`.
3. **The site.** `/privacy` and `/dpa` in both languages (the list under
   Subverwerkers/Subprocessors and the table in article 5), then every page the
   test names. A sub-processor change is announced to customers 14 days
   ahead (DPA article 5); step 3 is when that clock starts.
4. **Run** `node --test tests/partners.test.mjs`. It names what still
   disagrees. For the production half, from the admin machine:

   ```bash
   # [admin]
   PARTNERS_PROD_SSH=root@<server> PARTNERS_PROD_SSH_KEY=~/.ssh/<key> \
     node --test tests/partners.test.mjs
   ```

   It reads key **names** only (`cut -d= -f1`), never values. Without those
   variables that part is skipped with a message; CI has no key, so it skips
   there too. A skip is not a pass.

### Example: mail from Resend to Lettermint

Lettermint is a Dutch transactional mail provider (lettermint.co). The code
does not know it yet, so this switch starts in the code:

1. Add a `lettermint` sender to `relay/lib/mail.js` (`PROVIDERS`, the key
   names, the request), with its tests. Add its key to `docker-compose.yml`.
   Add a party `lettermint` to `partners.json` with status
   `in-code-niet-actief`, `code_keuze` pointing at `relay/lib/mail.js`, and
   remove it from `overwogen`. The test now fails until that is consistent.
2. After the contract: the key into the production `.env`, and `MAIL_PROVIDER`
   stays empty so the code picks the carrier whose keys are present, or set it
   to `lettermint` explicitly.
3. `partners.json`: `lettermint` to `actief` with `sinds`; `resend` to
   `uitgefaseerd` with `tot`, and while `RESEND_API_KEY` is still on the server
   list it under `dode_resten` with an `opruimen_voor` date. The test goes red
   on that date if the key is still there.
4. The site: the Resend line out of `/privacy` and `/dpa` (both languages),
   Lettermint in with its legal name and country, and every sentence the test
   flags ("gaat nu nog via Resend Inc. in de Verenigde Staten" and its English
   twin on home, /security, /press, /rules, /parasend, /parasign, /help).
5. Remove `RESEND_API_KEY` from the server, then its `dode_resten` line.

### Naming a non-active party on the site

Only inside an element with `data-partner-context="<id> <reason>"`, reason one
of `voorwaardelijk` (e.g. Moneybird: only when an administration is connected),
`historie`, `gepland` or `geen-partij` (the name appears but not as our
supplier, e.g. DigiCert in the ownership paragraph on home). The test rejects a
marker on an element that no longer contains the name.

### Dead keys on production today

`ANTHROPIC_API_KEY`, `FLY_API_TOKEN`, `GRAFANA_USER`, `GRAFANA_PASSWORD`,
`N8N_USER`, `N8N_PASSWORD`: read by no code, listed as `dode_resten` with
`opruimen_voor` 2026-10-31. Remove them from `/opt/paramant-relay/.env`
**[server]** (backup first), then their lines in `partners.json`.


## 8. E-mailbeleid: which addresses can open an account

`deploy/email-blocklist.json` lists the email domains that cannot open an
account. `admin/lib/email-policy.js` reads it; nothing else does.

### Where it applies, and where it never does

| Route | Checked as | Blocklist | MX check |
| --- | --- | --- | --- |
| `POST /api/user/signup` | `aanmelden` | yes | yes (unless `EMAIL_MX_CHECK=0`) |
| `POST /api/keys/all`, `/api/keys/sectors` (admin creates a key on an address) | `aanmelden` | yes | no |
| `POST /api/drop/upload` (sending without an account) | `verzenden` | yes | no |
| recipients: group sends, `/ontvang`, pickup codes, signing invitations | `ontvanger` | **never** | **never** |
| the client of a future "Veilig gesprek" | `gesprek-client` | **never** | **never** |

Recipients are never checked on purpose: someone looking for help may use a
throwaway address because their own inbox is read by someone else. Refusing
that person is the wrong way round. `/request-key` is retired (410) and
`/v2/claim/reveal` takes no address; the account behind a claim was checked
when it was created. `admin/test/email-policy.test.js` fails if the check
appears on a recipient route or anywhere in `relay/`.

The refusal is a 422 with `error: invalid_email`, `reason: domain_not_allowed`
and the message in both languages: "Dit e-mailadres kunnen we niet gebruiken
voor een account. Gebruik een adres dat u blijvend leest." The log line has
the purpose, the category and the domain, never the address:
`[email-policy] geweigerd doel=aanmelden categorie=wegwerp domein=mailinator.com`.

### What is in the file

- `wegwerp`: disposable and temporary mail, from
  [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains)
  (CC0-1.0, checked in its LICENSE.txt), plus a few manual entries carried over
  from the old list in `admin/server.js`.
- `misbruik`: known abuse domains. **Empty on purpose.** No source with a
  licence that allows commercial reuse was found (StopForumSpam is
  non-commercial only; see `overwogen`). Add a domain only by hand, under
  `handmatig`, with a reason, a date and a source you can point at.
- `gereserveerd`: `example.*`, `localhost` and the `.test`, `.example`,
  `.invalid`, `.localhost` and `.local` TLDs (RFC 2606, RFC 6762).
- `uitzonderingen`: the allowlist. Privacy-friendly providers (Proton, Tuta,
  mailbox.org, Posteo, Disroot, Riseup, StartMail, Mailfence, Runbox,
  Fastmail) and the large ordinary ones. It always wins, and
  `tests/email-blocklist.test.mjs` fails if one of them, or a domain above or
  below it, ends up on any list.

A listed domain also blocks its subdomains. Addresses are lowercased and IDN
domains are converted to punycode before the lookup.

The MX check refuses a domain with no MX and no A/AAAA record, or with a null
MX (RFC 7505). A DNS error or a timeout (1.5 s) never refuses anyone.

### Updating

```bash
# [admin] or any checkout
node scripts/update-email-blocklist.mjs            # show the diff, write nothing
node scripts/update-email-blocklist.mjs --write    # write deploy/email-blocklist.json
node --test tests/email-blocklist.test.mjs admin/test/email-policy.test.js
```

The workflow `email-blocklist` does this every Monday and opens a pull request
from `blocklist/update-<date>`. Never merge it without reading what came in.
A pull request opened with `GITHUB_TOKEN` does not start the normal CI; close
and reopen it to run the checks. If the weekly run stops, the test fails every
pull request once the source is 30 days old.

To unblock one domain: add it to `uitzonderingen` with a reason. To block one:
add it under `handmatig` in the right category with `reden`, `datum` and
`bron`. The change reaches production with the next admin image
(`admin/Dockerfile` copies the file).

A new outside source also goes into `deploy/partners.json` as a party with
role `blocklist-bron` (section 7); the test checks that.
