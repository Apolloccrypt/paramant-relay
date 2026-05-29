# R018. ParaSign invite-to-sign + WebAuthn/passkey identity (eIDAS-SAM-ready seam)

Date: 2026-05-29

Status: Proposed

Deciders: Mick (project owner)

Relates to: R017 (.psign envelope format), R013 (CT-log usage), R006 (crypto-mode opt-in).
PR 2 of the account-signing vault (the `wraps[]` multi-wrap envelope in `frontend/vendor/vault.js`).

## Context

The DocuSign-style sign flow (`/sign`) collects recipients (label + email) but
the email is plain text "for the sender's reference". There is no real invite:
the relay's multi-party envelope returns public `/co-sign?env=..&p=..` links that
the sender must copy and send by hand, and **any holder of `(envelope_id,
party_index)` can sign a slot** — parties are not bound to a person
(`relay/envelope.js` stores `p{i}_email_hash` but never checks it).

The project owner wants a true invite-to-sign flow where:
1. each recipient is emailed a unique invite link;
2. clicking it lets them create an account bound to that email (mailbox control
   proven by the emailed token, mirroring signup-verify) and sign;
3. identity is **WebAuthn / passkeys** — device-bound, no Google/Microsoft IdP,
   the server stores only a public credential (consistent with the `pgp_` key
   model and the /trust zero-knowledge posture). The passkey, via the WebAuthn
   **PRF** extension, unlocks the signer's ML-DSA-65 key. This is what makes
   "verify that the signer is who they claim" real: verified email + device
   passkey + post-quantum signature.

### eIDAS forward-compatibility constraint (hard requirement, design-only)

ParaSign may later move toward eIDAS remote signing (CEN EN 419 241-2), which
mandates a strict separation between **signature activation** and **key use**
(SAP → SAM → key). We must NOT build anything tonight that welds those two
together. Specifically: the WebAuthn-PRF step is *activation*; use of the
ML-DSA-65 key is a *separate, replaceable* step; an HSM-backed SAM must be
insertable between them later **without rebuilding the flow**. This is a design
boundary, not added scope — no HSM, no SAM, no eIDAS implementation now.

The current code does **not** have this separation: signing is inline
(`resolveSignerKey()` returns `{secretKey}`; callers do
`ml_dsa65.sign(secretKey, msg)` directly in `sign-flow.js` and `co-sign.html`).
This ADR establishes the seam.

## Decision

### 1. The signer seam (eIDAS-SAM-ready) — the spine of the whole feature

Introduce one client abstraction; all signing goes through it:

```
ParaSigner.activate(context) -> ActivatedSigner     // ACTIVATION (replaceable)
ActivatedSigner.publicKey                            // signer identity (ML-DSA-65 pubkey)
ActivatedSigner.sign(message) -> signature           // KEY-USE (replaceable)
ActivatedSigner.dispose()                            // zeroize key material
```

- **Activation** proves the rightful signer authorizes *this* operation. Today:
  WebAuthn-PRF (or passphrase fallback). Later: a SAP exchange yielding SAD.
- **Key-use** is `sign(message)`. Today `LocalVaultSigner`: PRF-output → HKDF →
  AES-GCM KEK → unwrap the vault key → `ml_dsa65.sign`. The raw secret key and
  the PRF output live **only inside** the `ActivatedSigner` instance; the
  generic flow never sees them — it only calls `activate()` then `sign(message)`.
- **The seam:** a future `RemoteSamSigner.activate()` performs the SAP and
  `sign()` forwards `(handle, message)` to an HSM-backed SAM. Callers are
  unchanged. PRF output is never interwoven with key-use in an unreplaceable way.

"Fix within scope" this costs: refactor the existing inline
`ml_dsa65.sign(...secretKey...)` call sites behind `activated.sign(message)`.

### 2. Invite binding — layered (capability token + authenticated-email binding)

- **Capability token (open):** each party gets a relay-stored `p{i}_invite_token`
  (32 random bytes). The emailed link is `/co-sign?env=<id>&p=<i>&t=<token>`.
  The token gates per-party detail and `markViewed`. Forwarding the email =
  forwarding the capability (documented residual risk, same as any e-sign link).
- **Authenticated-email binding (the ParaSign-grade layer):** the relay `/sign`
  endpoint is public and stateless, so it cannot know the caller's verified
  email. Binding-critical signs route through a new **admin proxy**
  `POST /api/user/envelopes/:id/sign` (session-authed). Admin checks
  `sha3_256(session.email) === p{i}_email_hash` and the invite token, then
  forwards to the relay with `X-Internal-Auth` + `verified_email_hash`. The
  relay trusts `verified_email_hash` **only** when `X-Internal-Auth` is valid,
  and enforces it for `binding_mode='email'` envelopes.
- **Sign-message commits to the email (versioned):** add `recipe_version`. v2 =
  `sha3_256(envId || docHash || partyIndex || party_email_hash)`, so the
  signature itself commits to "party i, invited email hashes to H". v1 stays for
  existing/open envelopes; the relay selects by stored version. Email hash is
  namespaced + case-normalized (`sha3_256("paramant/party-email/v1" || lower(email))`)
  identically at create / admin-check / client-recompute.

### 3. WebAuthn placement

- **Ceremony** (challenge issue + attestation/assertion verify) lives in
  `admin/server.js` — it owns the session cookie and is same-origin with the
  frontend. `rpId='paramant.app'`, `expectedOrigin='https://paramant.app'`,
  **hardcoded from config, never derived from request Host/X-Forwarded-***
  (attacker-influenceable behind Caddy→nginx). Challenges in redis, EX 300,
  one-shot (consume before crypto, like `pow-captcha.js`). Attestation `none`.
- **Credential storage** lives in the relay: new `relay/lib/user-webauthn.js` +
  internal-auth `/v2/user/webauthn/*`, fanned across sectors, mirroring
  `user-signing.js` / `user-totp.js` (so passkeys are as durable as TOTP, not
  lost on an admin-redis flush). Stores `credId`, COSE pubkey, `signCount`,
  `transports`, `prf_supported`, `aaguid`, plus a random per-account
  `wa_user_handle` (+ reverse index) so the WebAuthn `user.id` carries no PII.
- **Passkey is a sufficient login factor** (issues the session without TOTP);
  TOTP stays intact for existing users. Login/options responses keep uniform
  shapes to preserve the existing anti-enumeration posture.
- **PRF:** per-wrap random salt (stored in the wrap), KEK =
  `HKDF-SHA256(prfOutput, salt, info="paramant/parasign/vault-kek/v1")`. The
  **passphrase wrap stays always-present**; the PRF wrap is additive. PRF is
  never the sole wrap (lockout class).

### 4. Library

Use `@simplewebauthn/server` (MIT, pure-JS, no network) in **admin** for
attestation/assertion verification — hand-rolling CBOR/COSE is the exact
"subtly wrong" surface to avoid. Vendor `@simplewebauthn/browser` (ESM) into
`frontend/vendor/` so CSP stays `script-src 'self'` (no CDN). The relay only
stores opaque credential records, so it gets no new dependency.

### 5. Phasing (independently deployable; relay changes are backward-compatible)

- **PR-0 (relay only, invisible):** envelope invite-binding primitives —
  `p{i}_invite_token`, `binding_mode`, `recipe_version` (v2 email-bound message),
  internal-auth `verified_email_hash` enforcement on `/sign`, token-gated party
  detail. Zero behaviour change for v1/open envelopes. De-risks the
  high-blast-radius sign-message change in isolation; fully unit-testable.
- **PR-A:** WebAuthn account auth (register + passkey login + storage), the
  `ParaSigner` seam scaffolding, `createAccountAllSectors()` helper factored out
  of signup-verify.
- **PR-B:** PRF-wrapped vault unlock (`vault.js` `webauthn-prf` wrap path +
  `LocalVaultSigner`); fix the latent `parseInt(pk_hash)` vault-id bug.
- **PR-C:** invite-to-sign end-to-end — session-proxied envelope creation
  (`POST /api/user/envelopes` using the session's own `pgp_` key as `X-Api-Key`),
  `coSignInviteEmail` template, recipient co-sign page does passkey
  register/login + PRF unlock + email-bound sign through the admin proxy.

## Consequences

- The existing public/open co-sign flow keeps working (versioned, opt-in).
- New dependency `@simplewebauthn/server` in admin only; client lib vendored.
- The party-0 (sender) auto-sign must recompute the **exact** v2 message the
  relay verifies, including the sender's email-hash convention — the single
  subtlest correctness trap; pinned by a relay test.
- Counter regression on synced passkeys is soft-fail + audit, never auto-revoke.
- `p{i}_email_hash` is an unsalted low-entropy identifier; namespaced but still
  dictionary-guessable — accepted/documented privacy property.

## Non-goals / boundary

No HSM, no SAM, no SAP/SAD implementation, no eIDAS conformance work. This ADR
only guarantees the activation⇄key-use seam stays intact so a SAM can be added
later. No new product features beyond the invite flow above.
