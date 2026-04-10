# PARAMANT — License & Key System

**Version:** relay v2.4.1  
**License:** BUSL-1.1 — see [LICENSE](../LICENSE)  
**Last updated:** 2026-04-10

---

## Two key types, two different people

There are two completely separate key types in PARAMANT. They serve different
people and different purposes.

| Key | Format | Who gets it | What it does |
|-----|--------|-------------|--------------|
| **API key** | `pgp_<32 hex>` | End user / customer | Access to a relay — upload and download files |
| **License key** | `plk_<base64url>` | Relay operator | Unlocks more than 5 users on a self-hosted relay |

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
    "current_keys": 5,
    "max_keys": 5,
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

## plk_ license keys — cryptographic enforcement

### Format

```
plk_<base64url( utf8(JSON_payload) + ed25519_signature_64_bytes )>
```

Payload fields:
```json
{
  "max_keys": "unlimited",
  "expires_at": "2027-01-01",
  "issued_to": "Acme Corp",
  "issued_at": "2026-04-10T12:00:00.000Z"
}
```

`max_keys` is either the string `"unlimited"` or an integer.

### Security

- **Ed25519 signature** — all license keys are signed with a private key stored
  offline at `~/.paramant/license-signing-key.pem` (outside the repo, never committed).
- **Hardcoded public key** — `relay.js` contains the matching public key as a hex
  constant. Verification happens entirely in-process, with no network calls.
- **Cannot be forged** — Ed25519 provides 128-bit security. Any key that does not
  pass `crypto.verify(null, payloadBuf, pubKey, sig)` is rejected and the relay falls
  back to Community Edition.
- **Expiry** — the `expires_at` date is enforced at startup. An expired key logs a
  warning and falls back to Community Edition without crashing.
- **Graceful degradation** — an invalid or expired key never prevents the relay from
  starting; it only means the relay runs as Community Edition (max 5 keys).

### Startup log

```
[PARAMANT] Edition: community | max keys: 5
[PARAMANT] Edition: licensed | issued to: Acme Corp | expires: 2027-01-01 | max keys: unlimited
[PARAMANT] Edition: community (license expired 2025-01-01) | max keys: 5
[PARAMANT] Edition: community (invalid key: signature invalid — key not issued by Paramant) | max keys: 5
```

### /health response

```json
// Community Edition
{ "ok": true, "version": "2.4.1", "edition": "community", "max_keys": 5, "sector": "relay" }

// Licensed Edition
{ "ok": true, "version": "2.4.1", "edition": "licensed", "max_keys": null,
  "license_expires": "2027-01-01", "license_issued_to": "Acme Corp", "sector": "relay" }
```

### Install on self-hosted relay

```bash
# 1. Add to .env  (PLK_KEY is the canonical var; PARAMANT_LICENSE also accepted)
echo "PLK_KEY=plk_xxxx..." >> .env

# 2. Restart all containers to pick up the new env var
cd /path/to/paramant-relay
docker compose up -d

# 3. Verify
curl -s https://your-relay/health | jq '{edition, max_keys, license_expires}'
# { "edition": "licensed", "max_keys": null, "license_expires": "2027-01-01" }
```

### Verify a key without starting a relay

```bash
node scripts/verify-license.js plk_eyJtYXhfa2V5...
```

Output:
```
Payload: { max_keys: 'unlimited', expires_at: '2027-01-01', issued_to: 'Acme Corp', ... }
Signature: VALID
Expiry: 2027-01-01 (valid)
```

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
  └── if active keys >= LICENSE_MAX_KEYS:
        → HTTP 402 { error, current_keys, max_keys, upgrade_url }
        (key never created)

loadUsers() + checkLicense()
  └── applyKeyLimitEnforcement()
        EDITION = 'community' AND active keys > 5:
          keys 1-5 → over_limit = false  (work normally)
          keys 6+  → over_limit = true   (blocked at request time)

/health (public, no auth)
  └── { edition: 'community', max_keys: 5, ... }
      { edition: 'licensed',  max_keys: null, license_expires: '...', ... }
```

---

## Known limitations

| # | Limitation | Impact |
|---|-----------|--------|
| 1 | `plk_` keys not tracked server-side | No real-time revocation — to invalidate a key, rotate the signing keypair and redeploy relay |
| 2 | `over_limit` is position-based (insertion order in users.json) | An enterprise `pgp_` key added at position 6 is blocked until a `plk_` license is present |
| 3 | `ADMIN_TOKEN` and `TOTP_SECRET` in environment | Any process with Docker exec or host root can read them — use Docker secrets in production |

---

*Questions: privacy@paramant.app — Security issues: see [SECURITY.md](../SECURITY.md)*
