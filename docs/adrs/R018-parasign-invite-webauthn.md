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

## Authentication-factor model (deliberate choice)

Passkey login issues a session **without** a TOTP step. This is a deliberate
factor decision, not a side effect of reusing the TOTP login path: the TOTP
path is *email + TOTP* (two server-visible factors); a passkey is *possession
of the device + a local user-verification gesture (biometric/PIN)* resolved on
the device. We accept passkey as a **sufficient, sole login factor**, and a
passkey-authenticated session is allowed to reach ML-DSA document signing.

Why this is acceptable: a discoverable passkey with `userVerification:
'required'` is phishing-resistant (origin-bound, cannot be replayed to another
RP), hardware/device-bound, and gated by a local gesture — it is at least as
strong as email+TOTP against the realistic threats (phishing, credential
stuffing, shared-secret theft), and it removes the shared-secret class entirely
(the server stores only a public key). The residual risk — physical device loss
— is covered by the lockout gate below (email recovery must be able to enrol a
fresh passkey before a passkey may become an account's sole factor).

Consequence for sensitive relay ops: `/v2/user/signing-key` POST/DELETE are
TOTP-gated today, so a passkey-only account cannot enrol a signing key (and thus
cannot sign). PR-A/PR-C must let a **fresh passkey assertion act as a
TOTP-equivalent step-up** for those ops; until then, signing enrolment for
passkey-only accounts is blocked rather than bypassed. (Tracked as a PR-A/PR-C
acceptance item; not built in the login work itself.)

## Lockout prevention (mandatory gate before PR-A)

Introducing passkeys must never strand a user. This gate is a hard
prerequisite for PR-A and is enforced in code, not prose.

Two lockout dimensions:

1. **Account login (PR-A).** Independent login factors are TOTP, backup codes,
   and registered passkeys; the email recovery channel (the `/auth` reset flow)
   is the backstop. Guard: `admin/lib/account-recovery.js`
   (`assertCanRemoveFactor`, `assertNotLockedOut`), tested in
   `admin/test/account-recovery.test.js`. Every factor-mutating PR-A route MUST
   call it. The decisive rule: the email reset flow MUST be able to enrol a
   **fresh passkey** before a passkey is allowed to become an account's sole
   factor — otherwise a lost device is terminal. Until that capability exists,
   removing the last passkey from a passkey-only account is refused
   (`lockout_passkey_only_no_reenrol`).

2. **Vault key (PR-B).** The passphrase wrap stays the always-present primary
   wrap; the `webauthn-prf` wrap is strictly additive. PR-B MUST assert the
   vault never leaves a key with zero non-PRF wraps, and MUST probe PRF support
   (`prf.enabled`) before offering biometric unlock — a non-PRF authenticator
   may never become the only unlock path.

Status: account-login guard + tests landed (this gate). The vault invariant is
asserted within PR-B.

## Signing-identity model (definitive — one level, per-document PRF activation)

This is the binding acceptance criterion for the signing layer. It is distinct
from the *login* factor model above: login authenticates a session; signing is a
separate, per-document act.

### Invariant
Producing a ParaSign signature ALWAYS requires, together, every time, all four:
1. a **verified email address** (the account, mailbox-proven);
2. a **device-bound passkey** (WebAuthn, `userVerification: required`);
3. a **per-document PRF activation** (fresh, for exactly this document); and
4. an **ML-DSA-65** post-quantum signing key.

There is NO email-only and NO TOTP-only signing path. **One strength level — no
tiers** in signature strength.

### Login ≠ signing (sole control; eIDAS SAP/SAM seam)
A logged-in passkey *session* does NOT unlock the signing key. The key is
activated only at the moment of deliberate signing, for exactly one document,
and is **zeroized immediately after**. Authentication and signature-activation
are distinct ceremonies; a session conveys no signing capability. This preserves
the activation⇄key-use seam so an HSM-backed SAM can later sit between activation
and key-use without reworking the flow.

### Mail is a channel, not proof
Invitations and per-document sign-requests are delivered by email (binding the
request to an address), but email never authorizes a signature. The
cryptographic activation is always the passkey-PRF for that specific document.

### TOFU enrolment
An invitee with no passkey registers one as part of the first signing: prove
mailbox control (invite token) → register a passkey → that passkey-PRF activates
the signature. No passkey ⇒ no signature.

### Recovery / lockout (the vault-wrap invariant stays)
The vault key carries two wraps: `passphrase` (PBKDF2, ALWAYS present) and
`webauthn-prf` (added at passkey enrolment).
- The signing *flow* is ALWAYS passkey-PRF-activation; the PRF wrap is what the
  activation uses. The passphrase wrap is **not a second signing path**.
- The passphrase is **break-glass for key material, not a weaker signature**: the
  owner can always decrypt/export their own key bytes (sole control), so a
  passkey/PRF failure on a device that still holds the vault never permanently
  destroys the key. A signature produced that way is still full-strength
  ML-DSA-65 — the model never weakens a signature, it only guarantees the owner
  cannot lose their key.
- **Device loss** (the IndexedDB vault is device-local): recover by importing the
  passphrase-encrypted backup key file (downloadable at `/sign`) into the new
  device's vault and re-wrapping with a new passkey; or enrol a fresh signing key
  (new keypair + new passkey), with old signatures staying verifiable (revoke
  keeps history — the user-signing.js model).
- **Account/login recovery is separate** (another passkey, TOTP, or backup codes)
  and never by itself yields a signature.
- Forward: when the HSM-backed SAM lands, the key moves server-side under SAM
  sole control; the client passphrase-export no longer applies and recovery
  becomes SAM/operator-managed. The seam already accommodates that swap.

### Build acceptance criteria (applied during implementation, not yet built)
- `/v2/user/signing-key` use moves behind a **per-document PRF activation** (a
  server-issued, one-shot, short-TTL activation token bound to doc-hash +
  envelope-id + party-index + account_id), replacing pure-TOTP gating for the
  *signing* act. (TOTP step-up remains for adding a login passkey.)
- Every signed message carries a unique **domain-separation prefix**
  (e.g. `paramant/parasign/doc/v1`), byte-identical across relay + SDK + core, to
  close cross-context signature reuse (pentest H3).
- **Enforce a strong passphrase at key enrolment**: the passphrase wrap is the
  recovery floor, so the break-glass is only as strong as that passphrase. A weak
  passphrase must be rejected at enrol time.

### v3 sign-message wire format (BYTE-EXACT — relay + SDK + core MUST match)
Any implementation that signs a ParaSign document MUST hash exactly these bytes,
in this order, with NO separators other than the single NUL after the label.
A one-byte deviation = a silent signature mismatch (cf. the SDK conformity
report). Recipe v3:

    message = SHA3-256(
        utf8("paramant/parasign/doc/v1")   // domain label, 24 bytes, NO trailing slash/version drift
      ‖ 0x00                                // single NUL separator
      ‖ utf8(envelope_id)                   // base64url id string, as-is (NOT decoded)
      ‖ hex_decode(doc_hash)                // 32 bytes (SHA3-256 of the document)
      ‖ utf8(decimal(party_index))          // e.g. "0", "10" — ASCII decimal, no padding
      ‖ hex_decode(party_email_hash)        // 32 bytes, or 0 bytes when the party has no email
    )

Reference implementations (this PR): `relay/envelope.js signMessageBytes(...,3)`
and `frontend/js/parasign-signer.js buildDocSignMessage(...)` — verified to
produce identical digests. `party_email_hash` itself is
`SHA3-256("paramant/party-email/v1" ‖ 0x00 ‖ lower(trim(email)))` (see
`partyEmailHash`). When the SDK/core gain signing, they take these two formats
1:1; do not "improve" the byte layout.

### Non-ASCII canonicalization (cross-SDK signature safety)
Surfaced by the SDK↔relay conformance suite: sdk-js serializes JSON strings as
raw UTF-8 while sdk-py emits `\uXXXX` escapes, so any signed/canonicalized JSON
payload containing non-ASCII (e.g. a signer label "José", "Müller") yields a
**cross-SDK signature mismatch** — the same byte-identity class as the v3 domain
prefix. Rule: anything that is signed or cross-SDK-canonicalized
(sign-messages, receipts, envelope canonical forms) is **ASCII-only**, OR the
single canonicalization divergence is resolved first. The v3 sign-message above
is already safe by construction (it contains only the ASCII domain label, the
base64url envelope id, ASCII decimal party index, and raw hash BYTES — never a
raw name; emails are hashed, not embedded). Keep it that way: never fold a raw
display string into a signed message; carry such fields outside the signature.

## Non-goals / boundary

No HSM, no SAM, no SAP/SAD implementation, no eIDAS conformance work. This ADR
only guarantees the activation⇄key-use seam stays intact so a SAM can be added
later. No new product features beyond the invite flow above.
