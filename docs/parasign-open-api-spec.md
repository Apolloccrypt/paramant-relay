# ParaSign Open Developer API (/v1) specification

Model A: hosted signing ceremony. Create an envelope from a PDF plus a signer
list, route each signer to a hosted signing page on paramant.app, and pull the
completed, offline-verifiable `.psign` proof from your own stack.

Implementation: `relay/lib/parasign-open-api.js` (thin public layer over the
internal `/v2` envelope machinery in `relay/envelope.js`).

## Base URL and auth

- Base URL: `https://paramant.app`
- Authenticate every request with a ParaSign API key:
  `Authorization: Bearer psk_live_...` (production) or `psk_test_...` (sandbox).
- The key must carry the `parasign` scope (enabled per key/account; part of the
  Pro plan). Mint keys in the developer dashboard.
- Creating an envelope (`POST /v1/envelopes`) also needs an account that still
  holds ParaSign, checked on every create with the same rule that decides
  whether the account may mint a key. When the paid term has ended, or after a
  refund or chargeback, a create is refused with 403 `parasign_not_entitled`,
  for live and sandbox keys alike, until the account is entitled again.
- Reading, fetching the evidence of (`/receipt`, `/document`) and voiding
  envelopes the account created earlier keep working after that, under the same
  owner and participant checks as for a paying account (see below): the proof
  of contracts that were already signed stays available.

Auth failures:

| Condition | Status | `error` |
|---|---|---|
| No / malformed Bearer, or not a `psk_` key | 401 | `unauthorized` |
| Key unknown or revoked (`active:false`) | 401 | `unauthorized` |
| Key valid but missing the `parasign` scope | 403 | `forbidden_scope` |
| `POST /v1/envelopes` on an account that no longer holds ParaSign | 403 | `parasign_not_entitled` |

## Authorization model (who may read what)

A scope only proves the caller may use ParaSign at all. Per-envelope access is
checked separately:

- OWNER = the key whose SHA3-256 fingerprint matches the envelope's stored
  `creator_api_hash` (durable, survives restarts), or a different key on the
  same account.
- PARTICIPANT = a signer proving membership with the per-party invite token from
  their signing link (`X-ParaSign-Invite-Token` header, or `?invite_token=` /
  `?t=` query).

`GET /v1/envelopes/:id/receipt` and `/document` require OWNER or PARTICIPANT.
`POST /v1/envelopes/:id/void` is OWNER-ONLY (a participant must not retract
everyone's envelope). Any other authenticated key gets a generic **404** for all
of these, so it cannot distinguish "not yours" from "does not exist" from "not
completed yet". `GET /v1/envelopes/:id` (status) is readable by any scoped key
but REDACTS signer names and creator metadata unless the caller is
OWNER/PARTICIPANT.

## Endpoints

### POST /v1/envelopes — create

```
curl -X POST https://paramant.app/v1/envelopes \
  -H "Authorization: Bearer psk_live_..." \
  -H "Idempotency-Key: quote-8842-v1" \
  -H "Content-Type: application/json" \
  -d '{
        "document": { "content_base64": "JVBERi0xLjc..." },
        "original_filename": "quote-8842.pdf",
        "signers": [ { "name": "A. Jansen", "email": "a@example.org", "order": 1 } ],
        "binding_mode": "email",
        "webhook_url": "https://your.app/hooks/parasign",
        "metadata": { "quote_id": "8842" },
        "ttl_days": 30
      }'
```

Body fields:

- `document.content_base64` OR `document.url` (fetched via the SSRF-guarded
  fetcher; HTTPS only, must return 200). Exactly one is required.
- `signers[]`: at least one; each `{ name, email, order? }`.
- `binding_mode`: `email` (default) binds each slot to its invited mailbox
  (signable only through the hosted ceremony); `open` = any holder of the
  envelope id + party index can sign.
- `webhook_url` (optional): HTTPS endpoint for lifecycle events. See Webhooks.
- `metadata` (optional): free-form object, echoed to OWNER/PARTICIPANT only.
- `ttl_days` (optional): record retention, clamped 1..MAX (default 30).

Size limit: the PDF must be `%PDF-` and at most `PARASIGN_MAX_PDF_BYTES`
(default 20 MB). NOTE: when sending via `content_base64`, base64 inflates the
body ~33%, and the request body is capped at the PDF limit + 1 MB; a PDF above
roughly 15 MB must therefore be delivered via `document.url`, not base64.

`201` response:

```json
{
  "id": "Us4rFoLj35sU_4cOlPJcs3eMZlw4xjMp",
  "status": "sent",
  "mode": "live",
  "doc_hash": "<sha3-256 hex>",
  "binding_mode": "email",
  "created_at": "...", "expires_at": "...",
  "signers": [
    { "index": 0, "name": "A. Jansen", "email": "a@example.org",
      "order": 1, "status": "pending", "sign_url": "https://paramant.app/co-sign?env=...&p=0&t=..." }
  ],
  "webhook_secret": "<hex, returned ONCE>",
  "metadata": { "quote_id": "8842" }
}
```

`webhook_secret` is returned only here; store it to verify webhook HMACs.

- `id` is a random string of 20 to 64 characters (`A-Z a-z 0-9 _ -`), with no
  prefix.
- `sign_url` points at the hosted page `/co-sign` on `PARASIGN_PUBLIC_ORIGIN`
  (see Operator configuration), one per signer.
- A signer's `status` is `pending` until that slot is signed and `signed` after
  it, in this response and in `GET /v1/envelopes/:id` alike. A `psk_test_`
  envelope comes back with every slot already `signed` (see Test mode).
- `documents` is `null` until the envelope is `completed`, then
  `{ "signed_pdf": "/v1/envelopes/<id>/document", "receipt": "/v1/envelopes/<id>/receipt" }`.

Create errors: `400 bad_json | invalid_idempotency_key | ambiguous_document |
invalid_binding_mode | invalid_metadata | missing_signers | invalid_signer_email |
missing_document | empty_document | too_many_signers | invalid_webhook_url`,
`422 not_a_pdf | document_unfetchable` (includes SSRF-guard rejections),
`413 document_too_large`, `429 rate_limited` (50 creations per key per clock
hour), `402 monthly_sign_quota_reached` (plan cap; `Retry-After: 86400`).
Every `/v1` error body is `{ "error": "<code>", "message": "<sentence>" }`, plus
the extra fields named below.

- `invalid_metadata`: `metadata` is set but is not a JSON object (a string or an
  array is refused, not silently replaced by `{}`).
- `missing_document`: neither `document.content_base64` nor `document.url`.
- `empty_document`: `document.content_base64` is the empty string.
- `too_many_signers`: more signers than the plan allows on one document; the
  body carries `max_signers` and `plan`.
- `402 monthly_sign_quota_reached` carries `plan`, `limit`, `used` and
  `reset_date`; no envelope is created and nothing is counted.

- `ambiguous_document`: both `document.content_base64` and `document.url` were sent.
- `invalid_binding_mode`: `binding_mode` is set but is not `email` or `open`.
- `invalid_signer_email`: with `binding_mode` `email` (the default) every signer
  needs a valid email address; the body names the first bad one in
  `signer_index`.
- The body shape is checked before the hourly quota, so a malformed request
  (400) does not spend one of the 50 creations.
- `429 rate_limited` carries `Retry-After` and `retry_after_s`: the seconds left
  until the current clock hour ends, not a flat 3600. The window is the clock
  hour (UTC), not a sliding hour: the count starts again at every full hour, so
  around the boundary up to 100 creations can land within a few minutes.

Idempotency: send an `Idempotency-Key` header (8-128 characters of
`A-Z a-z 0-9 _ . : -`) to make a retry safe. When the same key comes from the
same API key within 24 hours, the relay returns the first `201` response again,
with the header `Idempotent-Replay: true`, and creates no second envelope and
spends no quota. Only a successful `201` is stored; an error is not replayed, so
a retry after a 4xx or 5xx runs as a new request. A key in another format is a
`400 invalid_idempotency_key`.

### GET /v1/envelopes/:id — status

Returns external status (`sent | in_progress | completed | void | declined`),
per-signer progress, counts and timestamps. Signer `name` and creator
`metadata` are present only for OWNER/PARTICIPANT. When `completed`, includes a
`documents` block linking the receipt and signed PDF.

### GET /v1/envelopes/:id/receipt — the `.psign` proof

OWNER/PARTICIPANT only; `409 not_ready` until completed. Returns the full
multi-signer `.psign`: per-party raw ML-DSA-65 `public_key` + `signature`, the
`document_hash` (sha3-256), the `sign_recipe`, and a notary counter-signature
over the canonical JSON. Verifiable offline against the relay public key
(`/v2/pubkey`) and the CT log; see `/verify`.

### GET /v1/envelopes/:id/document — the signed PDF

OWNER/PARTICIPANT only; `409 not_ready` until completed. Returns a STAMPED
reading copy (`X-ParaSign-Stamped: true`): a footer on every page plus a
"ParaSign signature certificate" page, baked by `relay/lib/parasign-stamp.js`.
When stamping is unavailable the ORIGINAL bytes come back with
`X-ParaSign-Stamped: false`. The cryptographic proof lives in the `.psign`,
not in the visible stamp. Once the envelope's retention has expired the stored
PDF is gone and you get `404 document_gone` (see Storage caveats).

**Verifying: use the original, not the stamped copy.** Every party signed the
SHA3-256 of the ORIGINAL bytes (`document_hash` in the receipt). The stamp is
made after completion and its hash is in no signature, so `/verify` with the
stamped PDF reports "not the document that was signed" and names the hash of
the original. The certificate page prints that same hash (`Document SHA3-256`)
and says to upload the original. Keep the PDF you created the envelope with.

Protocol option, not implemented. The receipt could carry the hash of the
stamped copy as well, inside the notary signature (for example
`stamped_document_hash`), so `/verify` could accept the stamped PDF and say
"stamped copy of the signed original, stamped by Paramant". Two conditions
first: stamping has to be deterministic (pdf-lib output is not guaranteed
byte-stable across versions) or the stamped bytes have to be produced and
frozen before the receipt is notarised; and only receipts issued after the
change would carry the field, so the original stays the one file that always
verifies. Existing receipts and their bytes stay as they are.

### POST /v1/envelopes/:id/void — retract

OWNER-ONLY. Body: `{ "reason": "..." }` (optional). Flips a still-open envelope
to `void`; a `completed` envelope is immutable (`409 already_complete`).
Idempotent. The void is atomic against signing: once voided, no further
signature is accepted (`410`, `error: voided`), and a signature completing
concurrently cannot overwrite the void.

## Webhooks

Set `webhook_url` at create. Events POST a JSON body with headers:

- `X-Paramant-Event`: event name.
- `X-Paramant-Sig`: hex `HMAC_SHA256(webhook_secret, raw_body)` — verify this.
- `X-Paramant-Delivery`: unique id for replay dedupe.

Delivery uses the SSRF-guarded fetcher. A `webhook_url` that is not a public
HTTPS URL is refused at create with `400 invalid_webhook_url`.

Emitted in this build: `envelope.sent`, `signer.completed`,
`envelope.completed`, `envelope.voided`. Not produced: `envelope.declined`.

Delivery, retry and order:

- Each attempt has a 5 s timeout. An attempt that fails on the network or gets a
  5xx or 429 back is retried after 2 s and after 10 s: three attempts in all.
  Any other answer (2xx, 3xx, other 4xx) ends it. After the third failed attempt
  there is no further retry, so poll `GET /v1/envelopes/:id` as the source of
  truth.
- A retry repeats the same body, the same `X-Paramant-Sig` and the same
  `X-Paramant-Delivery`; dedupe on that id. `X-Paramant-Attempt` is 1, 2 or 3.
- The events of one envelope are delivered one after another in the order they
  happened: the next waits until the previous is delivered or has used its
  attempts. The order is kept within one relay process; it is not a queue that
  survives a restart.
- Every body carries `seq`, computed from the envelope's state, so it is the
  same on any relay and after a restart: `envelope.sent` = 1,
  `signer.completed` = 1 + `signed_count`, `envelope.completed` and
  `envelope.voided` = number of signers + 2.

## Test mode

`psk_test_` keys are accepted. Test envelopes are signed automatically by a
throwaway sandbox signer (when the relay has a signing engine; otherwise they
behave like live ones), and their receipt carries `mode: "test"` and
`sandbox: true` inside the notary signature. `/verify` shows such a receipt as
a test proof, never as a real valid signature.

## Storage and privacy caveats (Model A)

- The envelope record stores the document hash, per-party email HASH (SHA3-256),
  and metadata; the signed `.psign` carries only hashes and signatures.
- Model-A concession: for `/v1` envelopes the relay DOES hold the PDF bytes so it
  can serve `/document`. They are stored durably in redis, encrypted at rest
  (AES-256-GCM, `PARASIGN_STORE_KEY`, else the TOTP master key;
  `lib/parasign-store.js`), with the same TTL as the envelope, so the document
  survives a relay restart and is gone when the envelope expires. A relay with
  no redis falls back to memory, and then a restart loses it. The webhook target
  and secret live in the same store.
- `original_filename` and signer `label` are stored as given (not hashed); avoid
  putting sensitive data in filenames or labels.

## Operator configuration

- `PARASIGN_PUBLIC_ORIGIN` — REQUIRED on any non-`paramant.app` (self-hosted)
  deployment. It fixes the origin used to build `sign_url`s and the receipt's
  `notary.relay_pubkey_url`. If unset, a `*.paramant.app` request Host is
  trusted (forced to https); any other Host falls back to this relay's own
  `RELAY_SELF_URL` when that is set and not a paramant.app host, and only
  otherwise to `https://paramant.app`. The relay logs
  `parasign_public_origin_unset` at start with the origin it will use. A request
  header is never used outside paramant.app, so a spoofed
  `Host` / `X-Forwarded-Host` cannot poison the signing links.
- The receipt has no `relay_id` field. The notary block names the relay by its
  key: `relay_pk_hash` and `relay_public_key`. Pin those, not the URL.
- `PARASIGN_MAX_PDF_BYTES` — max document size (default 20 MB).
