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
  "id": "env_...",
  "status": "sent",
  "mode": "live",
  "doc_hash": "<sha3-256 hex>",
  "binding_mode": "email",
  "created_at": "...", "expires_at": "...",
  "signers": [
    { "index": 0, "name": "A. Jansen", "email": "a@example.org",
      "order": 1, "status": "pending", "sign_url": "https://paramant.app/sign/..." }
  ],
  "webhook_secret": "<hex, returned ONCE>",
  "metadata": { "quote_id": "8842" }
}
```

`webhook_secret` is returned only here; store it to verify webhook HMACs.

Create errors: `400 bad_json | invalid_idempotency_key | ambiguous_document |
invalid_binding_mode | missing_signers | invalid_signer_email | missing_document |
empty_document`, `422 not_a_pdf | document_unfetchable` (includes SSRF-guard
rejections), `413 document_too_large`, `429 rate_limited` (50 creations per key
per hour), `402 monthly_sign_quota_reached` (plan cap; `Retry-After: 86400`).

- `ambiguous_document`: both `document.content_base64` and `document.url` were sent.
- `invalid_binding_mode`: `binding_mode` is set but is not `email` or `open`.
- `invalid_signer_email`: with `binding_mode` `email` (the default) every signer
  needs a valid email address; the body names the first bad one in
  `signer_index`.
- The body shape is checked before the hourly quota, so a malformed request
  (400) does not spend one of the 50 creations.
- `429 rate_limited` carries `Retry-After` and `retry_after_s`: the seconds left
  until the current clock hour ends, not a flat 3600.

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
not in the visible stamp. If the ephemeral document store has expired the blob
you get `404 document_gone` (see Storage caveats).

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
- `X-Paramant-Timestamp` and `X-Paramant-Signature: t=<unix seconds>,v1=<hex HMAC_SHA256(webhook_secret, "<t>.<raw_body>")>`. The time is inside this signature: reject a delivery whose `t` is more than 300 seconds from your clock, so a captured delivery cannot be replayed later (`relay/lib/webhook-sign.js` `verifySignature`).
- `X-Paramant-Delivery`: unique id for replay dedupe.

Delivery uses the SSRF-guarded fetcher, so an internal/non-HTTPS `webhook_url`
is accepted at create but silently never delivers. Use a public HTTPS URL.

Emitted in this build: `envelope.sent`, `signer.completed`,
`envelope.completed`, `envelope.voided`. Not produced: `envelope.declined`.
Each event is one delivery attempt (5 s timeout), with no retry and no
ordering guarantee between events, so poll `GET /v1/envelopes/:id` as the
source of truth.

## Test mode

`psk_test_` keys are accepted. Test envelopes are signed automatically by a
throwaway sandbox signer (when the relay has a signing engine; otherwise they
behave like live ones), and their receipt carries `mode: "test"` and
`sandbox: true` inside the notary signature. `/verify` shows such a receipt as
a test proof, never as a real valid signature.

## Storage and privacy caveats (Model A)

- The envelope record stores the document hash, per-party email HASH (SHA3-256),
  and metadata; the signed `.psign` carries only hashes and signatures.
- Model-A concession: for `/v1` envelopes the relay DOES hold the PDF bytes, in
  an in-memory + TTL blobstore, so it can serve `/document`. This is ephemeral
  and NOT durable across restarts in this build; a production deployment must
  relocate it to encrypted-at-rest storage with the same TTL. The webhook target
  and secret live in the same ephemeral side-store.
- `original_filename` and signer `label` are stored as given (not hashed); avoid
  putting sensitive data in filenames or labels.

## Operator configuration

- `PARASIGN_PUBLIC_ORIGIN` — REQUIRED on any non-`paramant.app` (self-hosted)
  deployment. It fixes the origin used to build `sign_url`s. If unset, only a
  `*.paramant.app` request Host is trusted (forced to https); any other Host
  falls back to `https://paramant.app`. This prevents a spoofed
  `Host` / `X-Forwarded-Host` header from poisoning the signing links.
- `PARASIGN_MAX_PDF_BYTES` — max document size (default 20 MB).
