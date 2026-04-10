# PARAMANT — License & Key System

**Version:** relay v2.4.1  
**License:** BUSL-1.1 — see [LICENSE](../LICENSE)  
**Last updated:** 2026-04-10

---

## Two key types, two different people

There are two completely separate key types in PARAMANT. They are for different
people and serve different purposes.

| Key | Format | Who gets it | What it does |
|-----|--------|-------------|--------------|
| **API key** | `pgp_<32 hex>` | End user / customer | Access to a relay — upload and download files |
| **License key** | `plk_<64 hex>` | Relay operator | Unlocks more than 5 users on a self-hosted relay |

A user who buys a plan or receives API access **always gets a `pgp_` key**.  
A relay operator who wants to run their own relay with more than 5 users **needs a `plk_` key**.  
These are never the same person in the same transaction.

---

## The three roles

### 1. End user / customer

Someone who uses a relay to send or receive files.

- Has a `pgp_` API key
- Uses it to call `/v2/inbound`, `/v2/outbound`, `/parashare`, etc.
- Has no knowledge of `plk_` keys — irrelevant to them
- Is on a **plan** (`free`, `pro`, `enterprise`) that determines feature limits

### 2. Relay operator — Community Edition (free)

Someone who self-hosts a relay for their own use or for up to 5 users.

- Runs `docker compose up -d` on their own server
- Manages their own `users.json` with up to **5 active `pgp_` keys**
- Their users each get a `pgp_` key from the operator
- No `plk_` key required — free forever under BUSL-1.1

### 3. Relay operator — Licensed

A relay operator who needs more than 5 users on their own relay.

- Receives a `plk_` license key from Paramant
- Adds `PLK_KEY=plk_...` to their `.env` and restarts
- Can now add unlimited `pgp_` keys to `users.json`
- Still manages their own users — the `plk_` only removes the cap

---

## Flow: how a paying customer gets access

```
Customer pays / signs up
        │
        ▼
Paramant operator creates a pgp_ key in the admin panel
  (API Keys tab → New key → label, plan, email)
        │
        ▼
pgp_ key shown once → admin copies → sends to customer
  (optionally: welcome email sent automatically)
        │
        ▼
Customer uses pgp_ key to call the relay
  X-Api-Key: pgp_xxxx
        │
        ▼
Relay looks up key → checks plan → applies feature limits
```

The customer never sees, touches, or knows about `plk_` keys.

---

## Flow: self-hoster who outgrows 5 users

```
Self-hoster running Community Edition
Has 5 pgp_ keys in users.json — all working fine
        │
        ▼
Tries to create a 6th key (via admin panel or POST /v2/admin/keys)
        │
        ▼
Relay returns HTTP 402 immediately:
  { "error": "Community Edition limit reached (5 keys).
              Add a plk_ license key to unlock unlimited users.",
    "upgrade_url": "https://paramant.app/pricing" }
        │
        ▼
Operator goes to paramant.app/pricing
Gets a plk_ license key
Adds PLK_KEY=plk_xxx to .env
Restarts relay → edition: licensed → no limit
```

---

## API key plans

Plans control what a `pgp_` key holder can do. Set in `users.json`.

| Feature | `free` | `dev` | `pro` | `enterprise` |
|---------|--------|-------|-------|--------------|
| Upload / download blobs | ✓ | ✓ | ✓ | ✓ |
| Max blob TTL | 1 hour | 1 hour | 24 hours | 7 days |
| Max views per blob | 1 | 1 | 10 | 100 |
| BIP39 drop TTL | 1 hour | 1 hour | 24 hours | 7 days |
| Webhooks | ✗ 403 | ✗ 403 | ✓ | ✓ |
| Streaming | ✗ 403 | ✗ 403 | ✓ | ✓ |
| CSV audit export | ✗ 403 | ✗ 403 | ✓ | ✓ |
| DID registration | ✗ 403 | ✗ 403 | ✓ | ✓ |
| Admin panel (/admin/) | ✗ | ✗ | ✗ | ✓ |

---

## Community Edition key limit — enforcement details

### What gets blocked

Creating a 6th active key is blocked at the API level — the relay returns HTTP 402
before the key is stored. Existing over-limit keys in `users.json` (loaded from a
previous community run) are additionally flagged `over_limit = true` at startup,
blocking their requests with HTTP 402.

### Code path

```
POST /v2/admin/keys (create key)
  └── if EDITION = 'community' AND active keys >= 5:
        → HTTP 402 { error: 'Community Edition limit reached (5 keys)...', upgrade_url }
        (key never created)

loadUsers() + checkLicense()
  └── applyKeyLimitEnforcement()
        EDITION = 'community' AND active keys > 5:
          keys 1-5 → over_limit = false  (work normally)
          keys 6+  → over_limit = true   (blocked at request time)

/health (public, no auth)
  └── { edition: 'community', max_keys: 5, ... }
      { edition: 'licensed',  max_keys: null, ... }
```

### Startup log

```
[PARAMANT] Edition: community (max 5 users)
[PARAMANT] Edition: licensed (unlimited users)
[PARAMANT] Edition: community (max 5 users) — license key invalid
```

### Relevant lines in relay.js

| Lines | What |
|-------|------|
| `COMMUNITY_KEY_LIMIT` | `parseInt(process.env.MAX_KEYS \|\| '5')` |
| `let EDITION` | `'community'` (default) |
| `checkLicense()` | reads `PLK_KEY` (or `PARAMANT_LICENSE` for compat), sets EDITION |
| 1639 | `applyKeyLimitEnforcement()` — marks over_limit keys |
| 649–659 | Auth middleware — checks `over_limit`, returns 402 |
| 851–865 | `POST /v2/reload-users` — calls `applyKeyLimitEnforcement()` after reload |

---

## plk_ license keys

### Format

```
plk_<64 hex characters>   (4 + 64 = 68 characters total)
```

A `plk_` key is a **relay operator license**. It goes in the relay's `.env`, not in
`users.json`. It removes the 5-user cap for that relay instance.

### Current validation (format-only)

```js
if (LICENSE_KEY.startsWith('plk_') && LICENSE_KEY.length >= 68) {
  EDITION = 'licensed';
}
```

The relay checks prefix (`plk_`) and minimum length (68 chars total).
It does not contact a license server, verify a cryptographic signature, or check
an expiry date. Full cryptographic validation is planned for a future release.

**Implication for auditors:** any string starting with `plk_` and at least 68 chars
will unlock the relay. Enforcement is currently legal (BUSL-1.1), not
cryptographic.

### How to generate (Admin panel — Licenses tab)

1. Open `/admin/` → **Licenses** tab
2. Enter operator/customer label and optional note
3. Click **Generate** → key created in browser via `crypto.getRandomValues`
4. Copy overlay → key shown once with install instructions for the operator

Keys are **not stored server-side**. Record them in a password manager or CRM.

### Install on self-hosted relay

```bash
# 1. Add to .env  (PLK_KEY is the canonical var; PARAMANT_LICENSE also accepted)
echo "PLK_KEY=plk_xxxx..." >> .env

# 2. Restart all containers to pick up the new env var
cd /path/to/paramant-relay
docker compose up -d

# 3. Verify — edition and max_keys are in the public /health response
curl -s https://your-relay/health \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['edition'], 'max_keys:', d['max_keys'])"
# licensed max_keys: None

# Full detail with admin token:
curl -s -H "X-Admin-Token: $ADMIN_TOKEN" https://your-relay/health \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    print(d['edition'], d['active_keys'], 'keys, limit:', d['key_limit'])"
# licensed  11 keys, limit: None
```

---

## Admin panel — key management

**API Keys tab** — manages `pgp_` keys (end users):
- Load all keys → shows plan, status, BLOCKED badge if over_limit
- Create new key → label + plan + optional email → shows key once in overlay
- Revoke → sets `active: false`, takes effect after next reload
- Resend welcome mail → sends `pgp_` key to customer via email

**Licenses tab** — manages `plk_` licenses (relay operators):
- Generate key → creates `plk_` license for an operator who needs >5 users
- Shows install instructions: add to `.env` + restart
- Session-only list — not persisted

---

## Known limitations

| # | Limitation | Impact |
|---|-----------|--------|
| 1 | License validation is format-only (`plk_` prefix + length >= 68, no signature or expiry) | Self-hosters can generate their own `plk_` keys — BUSL-1.1 is the enforcement mechanism |
| 2 | `MAX_KEYS` env var overrides the 5-key limit | Operator can raise limit without a license |
| 3 | `plk_` keys not tracked server-side | No revocation mechanism — if a license needs to be revoked, a relay update is required |
| 4 | `over_limit` is position-based (insertion order in users.json) | An enterprise `pgp_` key added at position 6 is blocked until a `plk_` license is present |
| 5 | `ADMIN_TOKEN` and `TOTP_SECRET` in environment | Any process with Docker exec or host root can read them — use Docker secrets in production |

---

*Questions: privacy@paramant.app — Security issues: see [SECURITY.md](../SECURITY.md)*
