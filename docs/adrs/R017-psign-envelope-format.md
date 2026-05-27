# R017. .psign envelope format (ParaSign Sg1 step 3)

Date: 2026-05-28

Status: Accepted

Deciders: Mick (project owner)

Relates to: paramant-core ADR-0021 (cross-impl ML-DSA-65 byte-equivalence),
R013 (CT-log usage), Sg1 step 2 (cross-impl verify, live).

## Context

ParaSign Sg1 step 3 makes document signing a real product feature: a user
signs a document via paramant.app, and anyone can verify the result without a
Paramant account. This needs a self-describing envelope that carries
everything a verifier requires.

The signature itself MUST be produced where the private key lives -- in the
signer's browser or CLI -- never on the relay. This is the same zero-knowledge
posture the rest of PARAMANT holds (the /trust page states plainly that the
relay never holds keys). The relay's role is therefore a *notary*, not a
signer: it verifies the signer's signature, records the event in its public CT
log, and counter-signs the envelope with its own relay-identity key. It never
receives the signer's private key, and it never needs the document content --
only the document hash.

## Decision

### Trust model

- **Signer (client):** holds a 32-byte ML-DSA-65 seed (the private key,
  mnemonic-derivable). Hashes the document locally with SHA3-256, signs the
  hash locally, and sends only `{document_hash, signature, public_key}` to the
  relay. The private key and the document bytes never leave the client.
- **Relay (notary):** verifies the signer's signature against the supplied
  public key and hash; if valid, appends a `parasign` entry to the CT log and
  counter-signs the full envelope with the relay-identity key
  (`registry.getSig(0x0002)`, ML-DSA-65). The relay can prove it accepted and
  logged the signature; it cannot forge the signer's signature.
- **Verifier (anyone):** needs only the `.psign` envelope and the original
  document. No account, no network call required (the CT-log check is
  optional). A public `POST /v2/verify` is offered for convenience.

### Envelope (.psign)

```json
{
  "version": "1",
  "algorithm": "ML-DSA-65",
  "document_hash": "<sha3-256 of the document, hex>",
  "document_hash_algo": "sha3-256",
  "signature": "<signer ML-DSA-65 signature over the 32-byte hash, base64>",
  "signer": {
    "public_key": "<signer ML-DSA-65 public key, base64>",
    "label": "Optional human-readable name or null"
  },
  "signed_at": "2026-05-28T20:00:00.000Z",
  "expires_at": "2027-05-28T20:00:00.000Z",
  "notary": {
    "relay_pk_hash": "<sha3-256 of the relay public key, hex>",
    "ct_log_index": 12345,
    "ct_log_url": "https://paramant.app/v2/ct/log",
    "relay_pubkey_url": "https://paramant.app/v2/pubkey"
  },
  "envelope_signature": "<relay ML-DSA-65 signature over the canonical JSON of every field above except envelope_signature, base64>"
}
```

Encoding conventions (matching the rest of the relay):
- hashes are lowercase hex (SHA3-256), as in the CT log;
- keys and signatures are base64, as returned by `/v2/pubkey` and
  `/v2/verify-receipt`.

`canonicalJSON` is the relay's existing canonicaliser: recursively
sorted-key JSON, no whitespace. The envelope signature is computed over
`canonicalJSON(envelope_without_envelope_signature)`.

### POST /v2/sign  (authentication required)

Notarises an already-made signature. Request body:

```json
{
  "document_hash": "<sha3-256 hex>",
  "signature": "<base64>",
  "signer_public_key": "<base64>",
  "signer_label": "optional",
  "ttl_days": 365
}
```

The relay:
1. verifies `mlDsa` + `relayIdentity` are available (else 503);
2. verifies the signer signature: `verify(signature, hash_bytes, signer_public_key)` (else 400 -- the relay refuses to notarise an invalid signature, so a `.psign` envelope never asserts a signature that does not check out);
3. appends a `parasign` CT-log entry committing to `document_hash` and the signer public-key hash;
4. builds the envelope and counter-signs it with the relay-identity key;
5. returns `{ ok: true, envelope }`.

The endpoint never accepts, stores, or logs a private key, and never receives
the document content.

### POST /v2/verify  (public, no authentication)

Stateless verification. Request body: `{ document_hash, envelope }`
(the client computes `document_hash` locally from the original document).
The relay checks, collecting all failures:
1. `envelope.document_hash === document_hash` (binds the envelope to this document);
2. signer signature verifies over the hash;
3. envelope signature verifies against the relay-identity public key;
4. `expires_at` is in the future.

Returns `{ valid, errors, verified_at, signer_label }`. HTTP 200 when valid,
422 when invalid. The same logic runs client-side, so verification does not
depend on the relay being reachable.

### File extension + MIME

- Extension: `.psign`
- MIME: `application/vnd.paramant.signature+json`
- Recognisable prefix: `{"version":"1","algorithm":"ML-DSA-65"`

## Consequences

- Verifiers need no account and can work fully offline.
- The relay stays key-free for signers and content-blind: it sees a hash and a
  signature, never a private key or a document.
- Forward-compatible: the `version` and `algorithm` fields allow future
  primitives without breaking existing envelopes.
- Browser and CLI signing use the ML-DSA-65 implementation already shipped in
  `crypto-bridge.js` (seed-based, byte-equivalent to the relay's `oqs`
  implementation per paramant-core ADR-0021), so signer and notary agree on
  the wire without a second implementation.

## Alternatives considered

- **Client sends its private key to /v2/sign and the relay signs.** Rejected:
  it would put signer private keys on the relay, contradicting the
  zero-knowledge model and making the relay able to forge signatures. The
  whole point of ParaSign is that the relay is a notary, not a key holder.
- **Relay receives the document and hashes it.** Rejected: the relay would see
  document content. Hashing client-side keeps the relay content-blind.
- **Classical signature (Ed25519) / JWS.** Rejected: ParaSign exists to be
  post-quantum; ML-DSA-65 keeps it consistent with the rest of the stack.
