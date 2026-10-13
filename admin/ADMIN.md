# PARAMANT Admin Panel

The admin panel runs as a separate Express container on port 4200, proxied by nginx at `/admin/`. It provides a full operator interface for managing users, keys, billing, relay health, and audit logs.

## Access

```
https://paramant.app/admin/
```

Login requires:
- **Admin token** (`ADMIN_TOKEN` env var)
- **TOTP code** (if `ADMIN_TOTP_SECRET` is set — strongly recommended in production)

Sessions are stored in Redis under `paramant:admin:session:{sid}` with a 12-hour TTL. The session token is passed as `X-Session` header on every API request.

---

## Tabs

The panel speaks Dutch since 2026-10-05 and is built for one owner on a phone
as much as on a desktop: sentence case, touch targets of at least 44 px, tables
that turn into cards below 760 px. Every number is a button to its details.

| Tab | Description |
|-----|-------------|
| **Overview** (Overzicht) | One screen: health of the 5 relays (version, uptime), customers and paying customers, revenue this month and MRR (computed from the issued invoices), open problems (failed mails, 429 peaks, transparency-log growth, redis memory), latest signups and payments, latest audit events |
| **Users** (Klanten) | Search by email or label (client-side on the page, server-side `?q=` across pages), plan per product with paid-until date, last activity, usage this month, actions with confirmation; the customer name opens the customer info page |
| **Audit** | Time (local, relative), event in plain Dutch, who (email or label, key masked and folded away), one-line summary, details unfolded as a list. Filters on the events that really occur, a period, and a search on email. CSV export (semicolon, UTF-8 BOM) with every column filled |
| **Billing** (Betalingen) | Payments and invoices, credit notes, running paid terms and automatic renewals, failed collections, each with a status in plain language; gift codes |
| **Relay** (Relays) | Live health per relay, auto-refreshes every 10s; a relay opens its info page (health, metrics, deep check, transparency log) |

### Customer info page

`GET /admin/user-details/:key` (`:key` is the kid) returns everything about one
customer in one answer: account, plans per product with paid-until date, keys
(masked), usage this month, signing requests (status and counts, no file
names), payments and that customer's audit, translated. The panel shows it as
one sheet with the actions underneath.

### What the panel counts itself

Two counters live in redis under `paramant:admin:tel:*`, per hour, kept three
days, written by `admin/server.js` and read by `lib/beheer.js`: every 429 this
service answers, and every mail it could not send. The last twenty of each are
kept with their time and reason, never an address or a token. The
transparency-log size per relay is sampled once an hour on the same prefix, so
growth over 24 hours can be shown. These cover the admin/account side; mail the
relay sends itself (billing mails) is not in the count.

**No full key reaches the browser.** Audit rows, user rows, billing rows and
the customer page carry the kid as handle and the key masked; `lib/beheer.js
scrubKeys()` masks any `pgp_`/`psk_` inside event details too
(`admin/test/beheer.test.js` calls every panel route and fails on a full key).

## De standpagina (`/admin/stand`)

Een aparte pagina naast de tabs, in het Nederlands, voor de vraag "hoe staat het
ervoor" zonder eerst ergens in te loggen op een server. Zelfde inlog als de rest
van deze adminkant: `X-Session` uit `sessionStorage`, dus er komt geen nieuwe
openbare route bij. Het bestand `public/stand.html` is een leeg geraamte; alles
wat erop komt haalt `public/stand.js` op bij `GET /api/admin/stand`, en die zit
achter `authMiddleware`.

Vier blokken, in deze volgorde: werkt het, wordt het gebruikt, staat er iets
rood, en wat wacht er op de eigenaar. Gaat een blok goed, dan staat het dicht.

Twee regels worden in `lib/stand.js` afgedwongen en niet alleen beschreven:

- `punt()` zet elk punt zonder `meting` op "niet gemeten". Een getal dat er niet
  is kan dus niet als groen eindigen.
- In `RANG` staat "niet gemeten" boven "let op", zodat een weggevallen meting de
  kop wegtrekt van groen in plaats van mee te liften op wat wel lukte.

De metingen staan in `lib/stand.js`, de buitenwereld in `lib/stand-io.js`.
GitHub wordt zonder sleutel bevraagd (openbare repo, 60 vragen per uur, vijf
minuten cache in redis); lukt dat niet, dan staat er "niet gemeten".

De knop "doe de echte proef" stuurt via `POST /api/admin/stand/proef` werkelijk
een bestand door de relay, haalt het terug, vergelijkt de bytes en controleert
dat een tweede ophaalpoging 410 geeft. Dat is een echte handeling die in het
openbare transparantielogboek komt, dus hij draait op verzoek en niet bij elk
paginabezoek, en hij telt op de pagina zelf als zelftest en nooit als gebruik.
Eigen rem: een proef per vijf minuten.

Instellingen: `PARAMANT_SITE_URL`, `PARAMANT_REPO`, `STAND_ZELFTEST_ACCOUNTS`
(zie `deploy/.env.example`). De sabotagetoets is
`admin/test/stand-gate.test.js`.

---

## User action menu

Each row in the Users tab has a `···` menu with grouped actions:

### Email
| Action | What it does | Rate limit |
|--------|-------------|------------|
| Send welcome | Sends onboarding email with API key | 10/user/24h |
| Send TOTP setup link | Resends TOTP setup email | 10/user/24h |
| Send TOTP reset | Sends TOTP reset confirmation email | 5/user/24h |

> Email actions are greyed out when no email address is stored for that user (`paramant:user:meta:{key}` in Redis).

### Account
| Action | What it does | Rate limit |
|--------|-------------|------------|
| Change plan | Updates plan on all sector relays + optional email notification | 20/admin/24h |
| Revoke sessions | Deletes all active user sessions from Redis | — |
| **Require TOTP** | Forces TOTP setup before next login; revokes active sessions immediately | 20/admin/24h |
| **Remove TOTP requirement** | Removes forced-TOTP flag (user can still log in normally) | 20/admin/24h |

### Destructive
| Action | What it does | Rate limit |
|--------|-------------|------------|
| Disable key | Revokes the API key on all sector relays | 10/admin/24h |
| Delete account | Full deletion: revokes key, deletes TOTP, wipes all Redis data, triggers relay reload | 50/admin/24h |

> Delete account requires typing `DELETE` in the confirmation field before the button activates.

---

## API endpoints

All endpoints are mounted at `/admin/api/`. Authentication: `X-Session: <session_token>`.

### Dashboard data

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/overview` | Relays, customers, revenue and MRR, problems, latest signups/payments/audit (old `stats`/`plan_distribution` fields kept) |
| `GET` | `/admin/overview/failures` | The last failed mails and 429 answers behind the overview numbers |
| `GET` | `/admin/relay-info/:sector` | One relay: health, metrics, deep check, transparency log |
| `GET` | `/admin/users` | Paginated user list with TOTP status. Query: `?page=1&page_size=25&status=active&plan=pro` |
| `GET` | `/admin/user-details/:key` | Full user detail: meta, sessions, audit trail |
| `GET` | `/admin/audit` | Global audit log, translated rows. Query: `?limit=100&event=&since=&until=&q=` (`q` searches who, summary and details; `user` still matches a key or email server-side) |
| `GET` | `/admin/billing` | Revenue this/last month, MRR, payments, credit notes, running terms, renewals, failed collections |
| `GET` | `/admin/relay-detail` | Per-sector health + uptime + metrics |

### User actions

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/admin/send-welcome` | `{ key }` | Send welcome email |
| `POST` | `/admin/reset-totp` | `{ key }` | Send TOTP reset email |
| `POST` | `/admin/force-totp` | `{ key, required: bool, reason? }` | Require or remove TOTP for user |
| `POST` | `/admin/resend-setup` | `{ key }` or `{ user_id, email }` | Resend TOTP setup link (`key` may be the account kid; the address is then looked up) |
| `POST` | `/admin/change-plan` | `{ key, new_plan, notify }` | Change the legacy plan on every relay sector (`community`/`pro`/`enterprise`/`trial`) |
| `POST` | `/admin/set-product-plan` | `{ key, product, tier, notify }` | Change one product tier on every relay sector without changing the legacy plan |

Plan mutations retry failed sectors once. They return HTTP 207 with `ok:false`,
`failed_sectors`, and `read_back_failed` unless every mutation and effective
entitlement read-back succeeds. `entitlements_by_sector` contains the gate's
effective ParaSign and ParaSend result for every relay.
| `POST` | `/admin/revoke-sessions` | `{ key }` | Revoke all sessions |
| `POST` | `/admin/disable-key` | `{ key, reason, notify }` | Disable API key |
| `POST` | `/admin/delete-account` | `{ key, confirm: "DELETE", notify }` | Delete account |
| `POST` | `/admin/preview-email` | `{ type, key }` | Preview email HTML + text before sending. Types: `welcome`, `setup`, `reset-confirm` |

### Visual config editor

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET` | `/admin/config` | -- | Whitelisted config keys + current values. Secrets masked, never returned in plaintext. 503 if disabled. |
| `PUT` | `/admin/config` | `{ changes: [{ key, value }] }` | Validate (all-or-nothing) + atomic write + backup. Audit-logged per change. |
| `POST` | `/admin/config/restart` | -- | Returns 501 + manual restart instructions. Does NOT restart relays automatically (see below). |
| `GET` | `/admin/config/audit` | -- | Config-scoped audit feed (`admin_config_changed`, `*_backup_created`, `*_restart_requested`). |

UI: `/admin/settings.html` (linked from the dashboard header). Sidebar groups,
type-specific controls (toggle / slider / select / input), dirty-state
highlight, secret replace-modal, save-then-restart banner.

**Enabling it.** The editor is OFF until `ADMIN_CONFIG_ENV_PATH` points at the
env file the relays load. The admin runs as a separate process from the relays,
so that path is normally a file on a shared volume mounted into both the admin
and relay containers. If unset, `GET /admin/config` returns 503 and the page
shows an "not enabled" notice -- we never guess a path and edit the wrong file.

**Whitelist only.** Only keys defined in `admin/lib/config-schema.js` are
readable or writable; any other key in the env file is invisible and untouched.
Writes preserve comments, blank lines, and out-of-whitelist keys.

**Secrets.** Secret keys are masked on read and replace-only on write.
`ADMIN_TOKEN` and `TOTP_SECRET` (the credentials that protect this panel) are
read-only here on purpose -- rotate them on the host so a typo + restart cannot
lock you out of the panel.

**Restart is manual by design.** Saving writes the env file; relays read env at
startup, so changes apply on the next relay restart. The admin does NOT exec
`docker compose restart` / `systemctl` on the relays: that would be a shell exec
from the admin container and an automatic production action. The panel shows the
command to run instead.

---

## User document worklist

`GET /api/user/documents` is the session-authenticated ParaSign worklist used by
the normal dashboard. The browser cannot provide an account id. Admin derives it
from the session and calls the internal relay endpoint `POST /v2/user/envelopes`.
The account id stays in the JSON body because it is also a secret-shaped primary
key in the current account model and must not enter access-log query strings.
The response contains filenames, lifecycle status, timestamps and signer counts.
It never contains document bytes, document hashes, email hashes, invite tokens or
decryption keys.

The lookup uses the per-account envelope index. It does not scan all Redis keys.
New envelope records are checked against their stored `account_id` before they
are returned. Legacy records without that field rely on their backfilled,
account-scoped index membership.

---

## Redis key layout (admin-relevant)

| Key | Type | Content |
|-----|------|---------|
| `paramant:admin:session:{sid}` | string | JSON session object, TTL 12h |
| `paramant:user:meta:{key}` | string | JSON `{ email, created_at, plan, ... }` |
| `paramant:user:totp:{key}` | string | Encrypted TOTP secret (pending setup) |
| `paramant:user:totp_active:{key}` | string | `"true"` when TOTP is active |
| `paramant:user:session:{sid}` | string | User session JSON |
| `paramant:user:audit:{key}` | zset | Per-user audit events (score = timestamp ms) |
| `paramant:audit:global` | zset | Global audit log |
| `paramant:ratelimit:admin_{scope}:{id}` | string | Counter, TTL 24h. Scopes: `welcome`, `reset_totp`, `change_plan`, `disable_key`, `delete_account` |

---

## Email templates

Located in `admin/lib/email-templates.js`. All emails go via Resend (`RESEND_API_KEY`) from `Paramant <hello@paramant.app>`.

| Function | Subject | Trigger |
|----------|---------|---------|
| `setupEmail` | "Complete your Paramant account setup" / "Set up your new Paramant authenticator" | New account created or TOTP reset confirmed |
| `resetConfirmationEmail` | "Did you request a TOTP reset? — Paramant" | Two-stage TOTP reset step 1 |
| `welcomeEmail` | "Your Paramant API key is ready" | Manual send from admin panel |
| `billingConfirmationEmail` | "Paramant plan upgraded to {plan}" | Plan upgrade (admin or Mollie) |
| `billingCancellationEmail` | "Your Paramant plan cancellation is scheduled" | Subscription cancelled |

> `dropNotificationEmail` and `accountDeletionEmail` are defined in the module but not yet wired to a UI action.

---

## Rate limits (admin actions, per 24h)

| Action | Scope | Limit |
|--------|-------|-------|
| Send welcome | per user key | 10 |
| Send TOTP reset | per user key | 5 |
| Require/remove TOTP | global (admin) | 20 |
| Resend setup link | per user key | 10 |
| Change plan | global (admin) | 20 |
| Disable key | global (admin) | 10 |
| Delete account | global (admin) | 50 |

To reset a rate limit manually:
```bash
docker exec paramant-relay-redis redis-cli -u "$REDIS_URL" DEL paramant:ratelimit:admin_delete_account:admin
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_TOKEN` | Yes | Shared secret for relay auth + admin login |
| `ADMIN_TOTP_SECRET` | Recommended | TOTP secret for admin 2FA (base32) |
| `RESEND_API_KEY` | For email | Resend API key |
| `REDIS_URL` | Yes | `redis://:password@host:port/db` |
| `RELAY_HEALTH` | Yes | `http://relay-health:3000` |
| `RELAY_FINANCE` | Yes | `http://relay-finance:3000` |
| `RELAY_LEGAL` | Yes | `http://relay-legal:3000` |
| `RELAY_IOT` | Yes | `http://relay-iot:3000` |
| `INTERNAL_AUTH_TOKEN` | Yes | Shared secret for internal relay-to-relay calls |
| `SITE_URL` | No | Base URL for email links (default: `https://paramant.app`) |

---

## Deployment

```bash
# Rebuild admin container only
cd /opt/paramant-relay
docker compose up -d --build admin

# View logs
docker logs paramant-relay-admin -f

# Health check
curl http://localhost:4200/admin/
```

The static `admin.html` served at port 8080 by nginx must be kept in sync with the container's `public/index.html`:
```bash
cp /opt/paramant-relay/admin/public/index.html /home/paramant/app/admin.html
```
