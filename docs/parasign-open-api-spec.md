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

Auth failures:

| Condition | Status | `error` |
|---|---|---|
| No / malformed Bearer, or not a `psk_` key | 401 | `unauthorized` |
| Key unknown or revoked (`active:false`) | 401 | `unauthorized` |
| Key valid but missing the `parasign` scope | 403 | `forbidden_scope` |

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

Create errors: `400 bad_json | missing_document | empty_document |
missing_signers`, `422 not_a_pdf | document_unfetchable` (includes SSRF-guard
rejections), `413 document_too_large`, `429 rate_limited` (50 creations per key
per hour), `402 monthly_sign_quota_reached` (plan cap; `Retry-After: 86400`).

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

OWNER/PARTICIPANT only; `409 not_ready` until completed. **This build has no
stamp-worker: the ORIGINAL (unstamped) PDF is returned, flagged with
`X-ParaSign-Stamped: false`.** The cryptographic proof lives in the `.psign`,
not in a visible stamp. If the ephemeral document store has expired the blob you
get `404 document_gone` (see Storage caveats).

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

Delivery uses the SSRF-guarded fetcher, so an internal/non-HTTPS `webhook_url`
is accepted at create but silently never delivers. Use a public HTTPS URL.

Emitted in this build: `envelope.sent`, `envelope.voided`. NOT yet auto-fired
(poll `GET /v1/envelopes/:id` instead): `signer.completed`,
`envelope.completed`, `envelope.declined`.

## Test mode

`psk_test_` keys are accepted and behave like live, EXCEPT there is no sandbox
auto-signer yet: a test envelope still needs a human to sign via the hosted
page. End-to-end automated sandbox signing is planned.

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
