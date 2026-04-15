# Security Fixes — 2026-04-15

Commit `8e6d4d2`. Seven findings from internal security review, all confirmed
code-level before fixing. Applies to the `paramant-master` codebase.

---

## Finding 1 — DOM XSS in relay registry viewer

**Severity:** High  
**File:** `frontend/ct-log.html`

### Root cause

`loadRelays()` fetched `/v2/relays` and inserted server-supplied relay fields
(`url`, `sector`, `version`, `edition`, `ct_index`) directly into `innerHTML`
with raw string concatenation. A single `"` in `relay.url` broke out of the
`title=""` attribute; any HTML/JS in `sector`, `version`, or `edition` executed.

The relay registration endpoint (`POST /v2/relays/register`) validates only
the ML-DSA-65 signature over the caller's own payload, not the content of those
fields. Anyone with a valid keypair can inject HTML.

API keys are stored in `localStorage` on `drop.html` and `parashare.html` from
the same origin, making key exfiltration the practical impact.

### Fix

Added `esc()` helper that encodes `&`, `<`, `>`, `"`. Applied to every
API-sourced value before insertion, including values in `title=""` attributes.

```js
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
                      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```

---

## Finding 2 — AES decryption key stored alongside ciphertext (Thunderbird FileLink)

**Severity:** High  
**File:** `thunderbird-filelink/background.js`, `frontend/parashare.html`

### Root cause

The 0x01 packet format was: `version(1) | nonce(12) | rawKey(32) | ctLen(4) | ct`.
The raw AES-256 key was serialised into the same blob uploaded to the relay.
Any party with server access (relay operator, host compromise, memory disclosure)
could extract the key and decrypt any stored attachment.

The main web send flow was unaffected — it uses ML-KEM-768+ECDH receiver keys
and the relay only holds ciphertext.

### Fix

**Packet v0x02:** `version(1) | nonce(12) | ctLen(4) | ct` — key omitted.

`encryptChunk()` now returns `{ padded, rawKey }`. The key is encoded as
URL-safe base64 and placed in the URL **fragment**:

```
https://paramant.app/parashare?t=TOKEN&n=NAME&c=1&r=RELAY_URL#k=BASE64_KEY
```

Browsers never send the fragment to any server. The relay receives only the
download tokens. The key is shared exclusively via the link the sender puts
in the email.

`parashare.html` gains a download mode: when `?t=` and `#k=` are both present
on load, it fetches each blob from the relay, decrypts client-side with the key
from the fragment, reassembles chunks, and triggers a browser file save.

**Backwards compatibility:** The relay's download endpoint (`/v2/dl/:token/get`)
is unchanged. Any previously uploaded v0x01 blob will fail decryption in the
new download page (it expects v0x02). Old links were already non-functional
(no download page existed before this fix).

---

## Finding 3 — Malformed percent-encoding crashes the relay process

**Severity:** High (public DoS, destroys in-flight blobs)  
**File:** `relay/relay.js`

### Root cause

Four public GET routes called `decodeURIComponent()` on path segments without a
local `try/catch`. A request to e.g. `/v2/did/%` throws a `URIError`. The global
`uncaughtException` handler calls `emergencyZeroAndExit()`, which zeroises and
discards all in-memory blobs before exiting the process.

Affected routes: `/v2/did/:did`, `/v2/pubkey/:device`,
`/v2/fingerprint/:device`, `/v2/attest/:device`.

### Fix

Each call site now wraps `decodeURIComponent()` in a `try/catch` and returns
HTTP 400 on failure:

```js
let _param;
try { _param = decodeURIComponent(raw); }
catch { res.writeHead(400); return res.end(J({ error: 'Invalid percent-encoding in path' })); }
```

---

## Finding 4 — X-Forwarded-For spoofing bypasses admin brute-force protection

**Severity:** High  
**File:** `admin/server.js`, `deploy/nginx-paramant-live.conf`

### Root cause

`/auth/login` and `/request-key` in the admin service derived the client IP
from the **first** entry of `X-Forwarded-For`:

```js
const ip = (req.headers['x-forwarded-for'] || ...).split(',')[0].trim();
```

The nginx configs forwarded `$proxy_add_x_forwarded_for`, which **appends**
to any attacker-supplied header value rather than overwriting it. An attacker
rotates the first entry to change IP buckets, bypassing the rate limiter.

### Fix

Use `X-Real-IP` instead, which nginx sets to `$remote_addr` (the actual TCP
connection IP, not influenced by any client-supplied header):

```js
const ip = req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
```

nginx already sets `proxy_set_header X-Real-IP $remote_addr` for the
`/api/request-key` path. This change makes the admin service consume it.

---

## Finding 5 — users.json read-modify-write race condition

**Severity:** Medium (access-control integrity)  
**File:** `relay/relay.js`

### Root cause

`_writeUsersJson()` serialised only the write operation, not the full
read-modify-write cycle. Three call sites (trial key creation, admin key
creation, admin key revocation) each read the file independently, mutated the
in-memory object, and then enqueued the write. Two concurrent operations could
read the same stale snapshot and overwrite each other, silently losing a key
creation or a revocation.

### Fix

Added `_mutateUsersJson(fn)`, which runs the `readFile` **inside** the serial
write queue:

```js
function _mutateUsersJson(fn) {
  _usersWriteQueue = _usersWriteQueue.then(async () => {
    const raw  = await fs.promises.readFile(USERS_FILE, 'utf8');
    const data = JSON.parse(raw);
    fn(data);
    await fs.promises.writeFile(USERS_FILE, JSON.stringify(data, null, 2));
  }).catch(e => log('warn', 'users_write_error', { err: e.message }));
  return _usersWriteQueue;
}
```

All three call sites replaced. The full read-modify-write is now atomic within
the queue.

---

## Finding 6 — Rate limits collapse to proxy IP

**Severity:** Medium  
**Files:** `relay/relay.js`, `deploy/nginx-paramant-live.conf`

### Root cause

`/v2/request-trial` and `/v2/admin/verify-mfa` keyed their rate limits off
`req.socket?.remoteAddress`. Behind nginx, this is always the loopback address,
so all clients share a single bucket. One client exhausting the trial-key or
MFA limit blocks every other client.

### Fix

Rate-limit lookups now use a proxy-aware IP chain:

```js
const clientIp =
  req.headers['cf-connecting-ip'] ||  // Cloudflare deployment
  req.headers['x-real-ip']        ||  // nginx $remote_addr (self-hosted)
  req.socket?.remoteAddress       ||  // direct / fallback
  'unknown';
```

`nginx-paramant-live.conf`: changed `proxy_set_header X-Real-IP ''` to
`proxy_set_header X-Real-IP $remote_addr` in the relay proxy server block,
so the relay receives the upstream connection IP even when CF-Connecting-IP
is not present.

The same IP chain is applied to the DPA audit log (`ip` field in
`dpa-signatures.jsonl`).

---

## Finding 7 — `/v2/sign-dpa` open to spam and operator mailbox abuse

**Severity:** Medium  
**Files:** `relay/relay.js`, `deploy/nginx-selfhost.conf`,
`deploy/nginx-paramant-live.conf`

### Root cause

`POST /v2/sign-dpa` was public, unauthenticated, and had no rate limiting.
Each accepted request appended a record to disk and, when `RESEND_API_KEY`
is configured, sent outbound email to both the submitted address and the
operator's `privacy@` inbox. No nginx `limit_req` was present on the endpoint.

### Fix

**relay.js** — in-process rate limiter:
- Max 3 DPA signatures per IP per 24 hours
- Max 1 DPA signature per email address per 24 hours
- Uses the same proxy-aware IP chain as Finding 6
- Map entries are cleaned up hourly

**nginx-selfhost.conf** — new `sign_dpa` zone (`3r/m`, burst 2) with a
dedicated `location = /v2/sign-dpa` block, preventing the endpoint from
sharing the generous general-API burst budget.

**nginx-paramant-live.conf** — added `limit_req` (reuses `api` zone) and
strips `X-Forwarded-For` on `/api/sign-dpa` so the relay sees a clean IP.

---

## Deployment checklist

- [ ] Pull `8e6d4d2` on each relay host
- [ ] `systemctl restart paramant-relay-*`
- [ ] Reload nginx: `nginx -t && systemctl reload nginx`
- [ ] For the admin service: `pm2 restart paramant-admin` (or equivalent)
- [ ] Verify `/v2/sign-dpa` returns 429 after 3 rapid requests from one IP
- [ ] Verify `GET /v2/did/%` returns 400, not 500/crash
- [ ] Verify ct-log.html relay registry renders correctly (no regression)
- [ ] Thunderbird FileLink: upload a test attachment, verify URL contains `#k=`
      and the download page decrypts successfully
- [ ] Confirm users.json is intact after a key creation (no race corruption)
