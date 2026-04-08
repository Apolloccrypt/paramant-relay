# PARAMANT — License Enforcement & API Key System

**Version:** relay v2.2.1  
**License:** BUSL-1.1 — see [LICENSE](../LICENSE)  
**Applies to:** self-hosted Community Edition  
**Last updated:** 2026-04-08

This document describes the complete license enforcement logic, API key system, and
plan-based feature gates as implemented in `relay/relay.js`. It is intended for
auditors, security reviewers, and operators evaluating self-hosted deployments.

---

## 1. Community Edition — Key Limit

### What the limit is

Community Edition allows **up to 5 active API keys** per relay instance. Keys beyond
this limit are blocked at request time with HTTP 402.

This is a **hard enforcement** at the relay's authentication layer, not a soft warning.

### Where it lives in the code

```
relay/relay.js
├── L1597  const COMMUNITY_KEY_LIMIT = parseInt(process.env.MAX_KEYS || '5');
├── L1598  let EDITION = 'community';
├── L1600  function checkLicense()          — runs once at startup
├── L1634  function applyKeyLimitEnforcement() — called at startup + after reload-users
└── L649   auth middleware                  — checks over_limit flag per request
```

### Enforcement flow

```
startup
  └── loadUsers()                 reads users.json → populates apiKeys Map
  └── checkLicense()
        └── reads PARAMANT_LICENSE from env
              ├── present + valid (plk_ prefix, ≥32 chars) → EDITION = 'licensed'
              └── absent or invalid                        → EDITION = 'community'
        └── applyKeyLimitEnforcement()
              ├── EDITION = 'licensed' → clear all over_limit flags, no action
              └── EDITION = 'community':
                    active keys = [...apiKeys.values()].filter(k => k.active !== false)
                    ├── count ≤ 5 → clear over_limit flags, log ok
                    └── count > 5 → keys 1-5 remain active
                                    keys 6+ flagged with over_limit = true
                                    log('warn', 'key_over_limit', { label, hint })

POST /v2/reload-users
  └── loadUsers()                 reloads users.json
  └── applyKeyLimitEnforcement()  re-evaluates limit on new key set

every request
  └── const keyData = apiKeys.get(apiKey)
  └── if (keyData?.over_limit)
        → HTTP 402, body: { error, upgrade, docs }
        → request terminated, no further processing
```

### What "first 5" means

Keys are ordered by their position in `users.json`. The first 5 active keys
(where `active !== false`) keep working. Keys 6 and beyond are blocked regardless
of their `plan` field.

There is no per-plan exemption — even an `enterprise` key at position 6 is blocked
in community edition without a license.

### Overriding MAX_KEYS

The community limit can be changed via environment variable:

```bash
MAX_KEYS=10  # not recommended — violates BUSL-1.1
```

This is intentionally left configurable for testing but constitutes a license
violation under BUSL-1.1 if used in production without a commercial license.

---

## 2. License Keys (plk_)

### Format

```
plk_<64 hex characters>
```

Example: `plk_8ad1c3690a3e4c325441def491894711591387cbb44f0098140354b6b6dbe9f4`

- Prefix: `plk_` (Paramant License Key)
- Body: 32 bytes of random data, hex-encoded (256-bit entropy)
- Total length: 68 characters

### Validation (relay-side)

```js
// relay.js L1615
if (LICENSE_KEY.startsWith('plk_') && LICENSE_KEY.length >= 32) {
  EDITION = 'licensed';
}
```

**Current validation is format-only.** The relay checks prefix and minimum length.
It does not:
- Contact a license server
- Verify a cryptographic signature
- Check an expiry date
- Verify the key against a registry

This means any string starting with `plk_` and ≥ 32 characters long will unlock
the relay. Full license validation (signature + expiry + registry lookup) is
planned for a future release.

### Generation

License keys are generated in the r34ct0r admin panel:

```js
// r34ct0r.html — runs in browser, no server contact
function generateLicenseKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return 'plk_' + Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}
```

Keys are generated client-side using `crypto.getRandomValues` (CSPRNG). They are
not stored server-side — the operator must save them immediately.

### Installation (customer side)

```bash
# 1. Edit .env on the self-hosted relay
echo "PARAMANT_LICENSE=plk_xxxx..." >> .env

# 2. Restart all relay processes or containers
systemctl restart paramant-relay-health paramant-relay-legal \
                  paramant-relay-finance paramant-relay-iot
# or:
docker compose restart

# 3. Verify
curl -s -H "X-Admin-Token: $ADMIN_TOKEN" https://your-relay/health \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('edition'))"
# licensed
```

---

## 3. API Key Plans

### Key format

```
pgp_<32 hex characters>
```

Example: `pgp_bd4fa8e92eebf3401e3737fb820a86ae`

Keys are stored in `users.json` (or `USERS_JSON` env var):

```json
{
  "api_keys": [
    {
      "key":    "pgp_xxxx",
      "plan":   "pro",
      "label":  "customer-name",
      "email":  "user@example.com",
      "active": true
    }
  ]
}
```

### Plans and feature gates

| Feature | `free` | `dev` | `pro` | `enterprise` |
|---------|--------|-------|-------|--------------|
| Upload blobs | ✓ | ✓ | ✓ | ✓ |
| Download blobs | ✓ | ✓ | ✓ | ✓ |
| Max blob TTL | 1 hour | 1 hour | 24 hours | 7 days |
| Max views per blob | 1 | 1 | 10 | 100 |
| BIP39 drop TTL | 1 hour | 1 hour | 24 hours | 7 days |
| Webhooks | ✗ 403 | ✗ 403 | ✓ | ✓ |
| Streaming (`/v2/stream`) | ✗ 403 | ✗ 403 | ✓ | ✓ |
| CSV audit export | ✗ 403 | ✗ 403 | ✓ | ✓ |
| DID registration | ✗ 403 | ✗ 403 | ✓ | ✓ |
| Pubkey registrations | Rate-limited | Rate-limited | Higher | Highest |
| Admin panel (r34ct0r) | ✗ | ✗ | ✗ | ✓ |

Plan checks are applied **per request** based on the `plan` field in the loaded
key data. Changing a key's plan in `users.json` takes effect after
`POST /v2/reload-users`.

### Plan enforcement location in code

```
relay.js
├── L1022  _planMaxTtl   — max TTL per plan
├── L1027  _planMaxViews — max views per plan
├── L875   free pubkey rate limit check
├── L1141  webhooks: free → 403
├── L1156  streaming: free → 403
├── L1174  CSV export: free → 403
├── L1185  DID registration: free → 403
└── L1473  _planDropTtl  — BIP39 drop TTL per plan
```

---

## 4. Authentication Flow

Every request goes through this sequence:

```
1. Extract API key from header X-Api-Key or query param ?k=
2. Look up key in apiKeys Map
3. Check over_limit flag → 402 if true
4. Check active flag → 401 if false or key not found
5. Check modeAllows(path) → 405 if endpoint unavailable in current RELAY_MODE
6. Apply plan-based feature gates per endpoint
```

There are two authentication bypass paths:

**DID authentication** (line 644):
```js
if (!apiKey && didHeader && didSig) {
  // verify ML-DSA-65 signature against registered DID
  // on success: keyData = { plan: 'pro', active: true }
}
```

**Receiver sessions** (inv_ prefix):
Receiver-side endpoints for ML-KEM key exchange accept a session token
instead of an API key. These are validated against the session store, not apiKeys.

---

## 5. Admin Endpoints

All admin endpoints require either:
- `X-Admin-Token` header matching `process.env.ADMIN_TOKEN`, **or**
- A key with `plan === 'enterprise'` in the `X-Api-Key` / `X-Admin-Token` header

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/v2/admin/keys` | GET | Admin | List all keys with plan, label, over_limit |
| `/v2/admin/keys` | POST | Admin | Create new API key |
| `/v2/admin/keys/revoke` | POST | Admin | Set active=false on a key |
| `/v2/admin/send-welcome` | POST | Admin | Send welcome email via Resend |
| `/v2/admin/verify-mfa` | POST | Admin key + TOTP | Verify TOTP for r34ct0r login |
| `/v2/reload-users` | POST | Admin | Reload users.json + re-apply limits |
| `/metrics` | GET | Admin token | Prometheus metrics |
| `/health` | GET | Public (limited) / Admin (full) | Relay status |

`/health` with admin token returns the full object including `edition`,
`active_keys`, `key_limit`, `stats`, and `audit` fields.
Without admin token it returns `{ ok, version, sector }` only.

---

## 6. r34ct0r Admin Panel

**URL:** `https://your-domain/r34ct0r`  
**Access:** IP whitelist (nginx) + enterprise API key + TOTP

### Login flow

```
1. Enter enterprise pgp_ key + 6-digit TOTP
2. Browser calls GET /v2/check-key?k=pgp_...       → validates key exists + returns plan
3. Browser calls POST /v2/admin/verify-mfa          → validates TOTP against TOTP_SECRET
4. On success: key stored in memory, used for all subsequent API calls
```

### What you can do

| Tab | Actions |
|-----|---------|
| Relay Monitor | View version, edition, active_keys, key_limit, uptime, blobs, CT log per sector |
| API Keys | Load all keys, create new key, revoke key, resend welcome email |
| Licenses | Generate plk_ license key, copy with install instructions |

### License generation (r34ct0r → Licenses tab)

1. Enter customer label and optional note
2. Click **Generate** → `plk_` key created in browser (never sent to server)
3. Overlay shows the key once + copy button + install instructions
4. Session list shows all generated keys (lost on page close)

**Important:** Generated license keys are not persisted anywhere. There is no
server-side registry of issued licenses. The operator must record them externally
(password manager, CRM, etc.).

---

## 7. Integrity Check

At startup, the relay logs a SHA3-256 checksum of its own source file:

```js
// relay.js L1604
const checksum = crypto2.createHash('sha3-256')
  .update(fs2.readFileSync(__filename))
  .digest('hex');
log('info', 'relay_integrity', { checksum, file: __filename });
```

This appears in the service log:

```json
{"level":"info","msg":"relay_integrity","checksum":"a3f2...","file":"/home/paramant/relay-health/relay.js"}
```

The checksum can be compared against the published hash for the same version to
detect unauthorized modifications to the relay binary.

---

## 8. Known Limitations for Auditors

| # | Limitation | Impact |
|---|-----------|--------|
| 1 | **License key validation is format-only.** Any `plk_` string ≥32 chars works. No signature, no expiry, no server check. | Self-hosters can generate their own license keys. |
| 2 | **Community key limit is in the same process as all other logic.** A modified relay.js can trivially bypass it. | BUSL-1.1 enforcement is legal, not technical. |
| 3 | **`MAX_KEYS` env var overrides the limit.** Not validated or logged as a violation. | Operator can silently raise the limit. |
| 4 | **No license key registry.** Issued plk_ keys are not tracked server-side. | No way to revoke a license key short of software update. |
| 5 | **Admin token in env.** Any process with `docker exec` or host root can read `ADMIN_TOKEN`. | Standard Docker limitation — mitigate with host access controls. |
| 6 | **TOTP secret in env.** Same exposure as ADMIN_TOKEN. | Same mitigation. |
| 7 | **over_limit ordering is insertion order.** Keys 6+ in users.json are always blocked, regardless of plan. | An enterprise key added after 5 free keys would be blocked. |

---

## 9. Operator Checklist

Before going to production:

- [ ] `ADMIN_TOKEN` set to a random 32+ char string (`openssl rand -hex 32`)
- [ ] `TOTP_SECRET` set and scanned into authenticator app
- [ ] `PARAMANT_LICENSE` set if running more than 5 API keys
- [ ] Swap disabled (`swapoff -a` + fstab entry removed)
- [ ] `/r34ct0r` restricted to admin IP in nginx (`allow YOUR_IP; deny all;`)
- [ ] `users.json` not committed to version control (in `.gitignore`)
- [ ] `.env` not committed to version control (in `.gitignore`)
- [ ] Relay integrity checksum at startup matches published hash for your version

---

## 10. Source References

All logic described here lives in a single file: `relay/relay.js`

| Line range | Topic |
|------------|-------|
| 421 | `apiKeys` Map declaration |
| 530–545 | `loadUsers()` — reads users.json |
| 637–680 | Request auth middleware (key lookup, over_limit, active check) |
| 851–865 | `POST /v2/reload-users` |
| 1022–1028 | Plan-based TTL and view limits |
| 1141–1185 | Feature gates (webhooks, streaming, CSV, DID) |
| 1285–1340 | Admin key management endpoints |
| 1591–1633 | `checkLicense()` + `applyKeyLimitEnforcement()` |
| 1597 | `COMMUNITY_KEY_LIMIT` constant |
| 1598 | `EDITION` variable |

---

*For questions or vulnerability reports: privacy@paramant.app*  
*Security policy: [SECURITY.md](../SECURITY.md)*
