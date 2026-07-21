// ParaSigner — the activation⇄key-use seam (ADR R018). The generic signing flow
// only ever calls: activate() -> sign(message) -> dispose(). It NEVER sees the
// raw ML-DSA secret key. Today this is LocalVaultSigner (a WebAuthn-PRF
// activation unlocks the IndexedDB vault key, signs one document, zeroizes).
// Tomorrow a RemoteSamSigner (SAP -> HSM-backed SAM) drops in behind the same
// interface without touching callers. Self-hosted deps only (CSP 'self').
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { vaultGetPrfWrapInfo, vaultUnlockPrf, vaultAddPrfWrap, vaultCreatePrfOnly, vaultAvailable, vaultList } from '/vendor/vault.js?v=5';

// Byte-identical to relay/envelope.js SIGN_DOMAIN_DOC (recipe v3). Keep in sync
// across relay + SDK + core.
export const SIGN_DOMAIN_DOC = 'paramant/parasign/doc/v1';

function hexToBytes(hex) {
  const h = (hex || '').toString();
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function concatBytes(parts) {
  let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function b64urlToBytes(s) {
  const t = (s || '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function b64EncodeStd(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64DecodeStd(value) {
  const bin = atob(String(value || ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function toHex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0');
  return s;
}

export function normaliseSigningAppearance(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  if (source.version !== undefined && source.version !== 1) throw new Error('Unsupported signature appearance version.');
  const input = source.fields === undefined ? [] : source.fields;
  if (!Array.isArray(input) || input.length > 8) throw new Error('Invalid signature appearance.');
  const fields = input.map((field) => {
    if (!field || typeof field !== 'object' || Array.isArray(field)) throw new Error('Invalid signature appearance field.');
    const type = String(field.type || '');
    if (type !== 'seal' && type !== 'date') throw new Error('Invalid signature appearance field type.');
    const pageIndex = Number(field.page_index);
    if (!Number.isInteger(pageIndex) || pageIndex < 0 || pageIndex > 999) throw new Error('Invalid signature appearance page.');
    const clean = { type, page_index: pageIndex };
    for (const name of ['x', 'y', 'w', 'h']) {
      const n = Number(field[name]);
      if (!Number.isFinite(n) || n < 0 || n > 1) throw new Error('Invalid signature appearance coordinate.');
      clean[name] = Math.round(n * 1000000) / 1000000;
    }
    if (clean.w < 0.02 || clean.h < 0.01 || clean.x + clean.w > 1.000001 || clean.y + clean.h > 1.000001) {
      throw new Error('Signature appearance is outside the page.');
    }
    return clean;
  });
  return { version: 1, fields };
}

export function signingAppearanceHash(value) {
  return sha3_256(new TextEncoder().encode(JSON.stringify(normaliseSigningAppearance(value))));
}

// Reconstruct exactly the relay's versioned document-signing message. Recipe 5
// binds both the enrolled signing key and a canonical visual-placement manifest.
export function buildDocSignMessage({ envelopeId, docHash, partyIndex, emailHash, recipeVersion = 3, signerPublicKey = '', appearance }) {
  const enc = new TextEncoder();
  const parts = [
    enc.encode(SIGN_DOMAIN_DOC),
    new Uint8Array([0]),
    enc.encode(String(envelopeId)),
    hexToBytes(docHash),
    enc.encode(String(partyIndex)),
    hexToBytes(emailHash || ''),
  ];
  if (Number(recipeVersion) >= 4) parts.push(b64DecodeStd(signerPublicKey));
  if (Number(recipeVersion) >= 5) parts.push(signingAppearanceHash(appearance));
  return sha3_256(concatBytes(parts));
}

// v4 signing-key resolution — the SINGLE definition of "what a signing key is",
// shared by /sign (self-sign) and /co-sign (recipient). The signing key is the
// account's ML-DSA-65 key in the vault, unlocked by the passkey's PRF (one tap).
// We read its PUBLIC half (pk_b64/pk_hash) from vault metadata WITHOUT unlocking.
// A passphrase wrap is no longer a signing-key source (R018 v4: passkey is the
// only persisted unlock; the non-PRF fallback is a TOTP-gated ephemeral key that
// is never written to the vault). If no PRF signing key is enrolled on this
// device, throws code 'no_signing_passkey'.
export async function resolvePasskeySigningKey() {
  if (!(await vaultAvailable())) throw new Error('This browser cannot store signing keys (IndexedDB/WebCrypto unavailable).');
  const keys = await vaultList();
  const candidates = keys.filter((k) => (k.kekSources || []).some((s) => s === 'webauthn-prf'));
  // Verify the PRF wrap is actually present (not just listed in kekSources). A
  // desynced row — kekSources says 'webauthn-prf' but vaultGetPrfWrapInfo returns
  // null — would otherwise resolve as a key that activate() can never unlock,
  // looping on 'need_passkey'. Skip such rows so we fall through to enrol/fallback.
  for (const k of candidates) {
    const info = await vaultGetPrfWrapInfo(k.id);
    if (!info) continue;
    return {
      vaultId: k.id, pk_b64: k.pk_b64, fingerprint: (k.pk_hash || '').slice(0, 16),
      kekSources: k.kekSources || [], hasPrf: true,
    };
  }
  const e = new Error('No signing key on this device yet. Set one up when you sign.');
  e.code = 'no_signing_passkey';
  throw e;
}

// One WebAuthn get() with PRF, portable across engines. The PRF extension shape
// that works differs by engine and there is no capability flag to read up front:
//   • Chromium needs prf.evalByCredential (keyed by the base64url credential id)
//     when allowCredentials has more than one entry, or it returns no prf result.
//   • Firefox (Gecko) and Safari (WebKit) understand a plain `eval`; evalByCredential
//     makes WebKit throw a synchronous NotSupportedError/SyntaxError/TypeError.
// So we lead with the shape the RUNNING engine prefers (one prompt in the common
// case). We retry the other shape ONLY on those synchronous parse errors, which
// are thrown BEFORE any UI (free, no extra prompt). A cancel/timeout, or a post-UI
// authenticator/provider failure (e.g. a passkey manager with no PRF extension
// that engages then errors), is NOT retried — re-prompting is pointless; the
// caller detects the failure and falls back to a TOTP-gated ephemeral key.
function _isChromiumEngine() {
  try {
    const brands = navigator.userAgentData && navigator.userAgentData.brands;
    if (Array.isArray(brands)) return brands.some((b) => /Chrom|Edge|Opera/i.test((b && b.brand) || ''));
  } catch { /* userAgentData unavailable — fall through to UA sniff */ }
  try { return /Chrom(e|ium)\//.test(navigator.userAgent || ''); } catch { return false; }
}
async function getAssertionWithPrf(publicKey, prfExt) {
  const hasByCred = !!(prfExt && prfExt.evalByCredential);
  const evalOnly = (prfExt && prfExt.eval)
    ? { eval: prfExt.eval }
    : (hasByCred ? { eval: Object.values(prfExt.evalByCredential)[0] } : prfExt);
  const primary   = (hasByCred && _isChromiumEngine()) ? prfExt : evalOnly;
  const secondary = (primary === prfExt) ? evalOnly : prfExt;
  try {
    return await navigator.credentials.get({ publicKey: { ...publicKey, extensions: { prf: primary } } });
  } catch (e) {
    const parseErr = e && (e.name === 'NotSupportedError' || e.name === 'SyntaxError' || e.name === 'TypeError');
    if (!parseErr || primary === secondary) throw e;   // cancel / post-UI failure: don't re-prompt
    return await navigator.credentials.get({ publicKey: { ...publicKey, extensions: { prf: secondary } } });
  }
}

// Reproduce the PRF output by running a WebAuthn get() with the SAME salt that
// was stored in the wrap at enrol (PRF output is deterministic per
// (credential, salt), independent of the challenge).
async function evalPrf({ rpId, credentialIdB64url, prfSaltB64url }) {
  const saltBytes = b64urlToBytes(prfSaltB64url);
  // Build BOTH PRF shapes (evalByCredential keyed by the base64url credential id,
  // and a plain eval) with the SAME salt. getAssertionWithPrf() then picks the
  // shape the running engine accepts (Chromium wants evalByCredential; Firefox
  // and Safari want eval) and falls back to the other. Same salt either way, so
  // the PRF output is byte-identical to enrol time and the unlock stays deterministic.
  const assertion = await getAssertionWithPrf({
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId,
    allowCredentials: [{ type: 'public-key', id: b64urlToBytes(credentialIdB64url) }],
    userVerification: 'required',
  }, { eval: { first: saltBytes }, evalByCredential: { [credentialIdB64url]: { first: saltBytes } } });
  const first = assertion.getClientExtensionResults()?.prf?.results?.first;
  if (!first) throw new Error('passkey returned no PRF result (PRF unsupported on this authenticator)');
  return new Uint8Array(first);
}

// One activated key. The raw secret lives ONLY in the private field and is
// zeroized by dispose() immediately after signing — no key material lingers.
class ActivatedSigner {
  #sk; #pkB64;
  constructor(secretKeyBytes, publicKeyB64) { this.#sk = secretKeyBytes; this.#pkB64 = publicKeyB64; }
  get publicKey() { return this.#pkB64; }              // base64 (for signer_public_key)
  async sign(message) {                                // KEY-USE — the replaceable step
    if (!this.#sk) throw new Error('signer disposed');
    return ml_dsa65.sign(this.#sk, message);
  }
  dispose() {                                          // zeroize
    if (this.#sk) { this.#sk.fill(0); this.#sk = null; }
  }
}

export class LocalVaultSigner {
  // ACTIVATION — the replaceable step. Unlocks the vault's ML-DSA key for exactly
  // one signature via the passkey's PRF output (one tap), then the caller disposes
  // (zeroize). A vault entry with no PRF wrap is not a usable signing key here
  // (R018 v4: passkey PRF is the only persisted unlock); throws 'need_passkey'.
  async activate({ vaultId, rpId } = {}) {
    const info = await vaultGetPrfWrapInfo(vaultId);
    if (!info) {
      const e = new Error('This signing key can no longer be unlocked on this browser. Sign again to set up a fresh one.');
      e.code = 'need_passkey';
      throw e;
    }
    const prfOutput = await evalPrf({ rpId, credentialIdB64url: info.credentialId, prfSaltB64url: info.prfSalt });
    let unlocked;
    try {
      unlocked = await vaultUnlockPrf(vaultId, { prfOutput, credentialId: info.credentialId });
    } finally {
      prfOutput.fill(0);
    }
    return new ActivatedSigner(unlocked.secretKeyBytes, unlocked.pk_b64);
  }
}

// ── "Your sign-in passkey IS your signing key" — one-tap resolve-or-enrol ─────
// The single entry point /sign and /co-sign call. If this device already has a
// passkey-PRF signing key, return it. Otherwise enrol one WITHOUT a passphrase
// and WITHOUT TOTP, reusing the very passkey the user signs in with:
//   1. generate the ML-DSA-65 key in the browser;
//   2. ask the admin for a step-up assertion challenge over THIS account's
//      passkeys (POST .../step-up/options);
//   3. run ONE navigator.credentials.get() with that challenge + a PRF eval —
//      the platform offers the account's passkey (the sign-in passkey); the
//      assertion proves possession AND yields the PRF output in a single tap;
//   4. wrap the ML-DSA key with the PRF output locally (vaultCreatePrfOnly) —
//      the PRF output never leaves the browser;
//   5. send ONLY the assertion (no PRF) + the public key to the admin, which
//      verifies the step-up and binds the pubkey via the relay attested route.
// Reuses the sign-in passkey by allowCredentials, so it never mints a second
// passkey and never depends on a registration-time prfSupported flag (the old
// false-negative that spawned a duplicate passkey + the "set up a signing
// passkey" loop). Respects the [[feedback_eidas_sam_seam]] seam: PRF only
// UNLOCKS the stored ML-DSA key (activation) — key-use stays behind the signer.
export async function ensureSigningKey({ rpId, label, onStatus } = {}) {
  const say = (m) => { try { if (onStatus) onStatus(m); } catch { /* status is best-effort */ } };

  // Fast path: a passkey signing key already exists on this device.
  try {
    return await resolvePasskeySigningKey();
  } catch (e) {
    if (!e || e.code !== 'no_signing_passkey') throw e;   // a real error, not "needs enrol"
  }

  if (!(await vaultAvailable())) {
    const err = new Error('This browser cannot store signing keys (IndexedDB/WebCrypto unavailable).');
    err.code = 'vault_unavailable';
    throw err;
  }
  if (!(typeof PublicKeyCredential !== 'undefined' && navigator.credentials && navigator.credentials.get)) {
    const err = new Error('This browser does not support passkeys, so it cannot set up signing.');
    err.code = 'no_webauthn';
    throw err;
  }
  rpId = rpId || location.hostname;

  // 1) ML-DSA-65 keypair, generated + held only in the browser.
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const kp = ml_dsa65.keygen(seed);
  seed.fill(0);   // the keypair is derived; the seed is key material, zeroize it
  const pk_b64 = b64EncodeStd(kp.publicKey);
  const pk_hash = toHex(sha3_256(kp.publicKey));
  try {
    // 2) Step-up challenge over THIS account's passkeys.
    say('Setting up signing with your passkey…');
    let opt;
    try {
      opt = await _postJSON('/api/user/account/signing-key/step-up/options', {});
    } catch (e) {
      if (e && e.status === 409 && e.data && e.data.error === 'no_passkey') {
        const err = new Error('Add a passkey to your account first, then you can sign with it.');
        err.code = 'no_passkey';
        throw err;
      }
      throw e;
    }
    // opt: { flowId, options } — options.allowCredentials are the account's passkeys.

    // 3) ONE WebAuthn get(): server challenge + per-wrap PRF eval salt. The
    //    platform offers the account's sign-in passkey from allowCredentials.
    const prfSalt = crypto.getRandomValues(new Uint8Array(16));
    say('Confirm with Face ID / Touch ID / your security key…');
    const allowList = (opt.options.allowCredentials || []);
    // Build BOTH PRF shapes with one shared salt: a per-credential evalByCredential
    // map (keyed by each passkey's base64url id, which Chromium needs when several
    // are offered) plus a plain eval (which Firefox and Safari accept).
    // getAssertionWithPrf() sends the shape the running engine prefers and falls
    // back to the other, so the user's chosen credential yields its PRF on every
    // engine. Same salt for every credential; whichever the user picks yields that
    // credential's PRF and we wrap with exactly that.
    const prfExt = { eval: { first: prfSalt } };
    if (allowList.length) {
      prfExt.evalByCredential = {};
      for (const c of allowList) prfExt.evalByCredential[c.id] = { first: prfSalt };
    }
    let cred;
    try {
      cred = await getAssertionWithPrf({
        challenge: b64urlToBytes(opt.options.challenge),
        rpId,
        allowCredentials: allowList.map((c) => ({
          type: 'public-key',
          id: b64urlToBytes(c.id),
          ...(c.transports ? { transports: c.transports } : {}),
        })),
        userVerification: 'required',
        timeout: opt.options.timeout || 60000,
      }, prfExt);
    } catch (e) {
      if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) throw e;   // user cancelled / timed out
      // The authenticator/provider engaged but could not complete a PRF assertion
      // (e.g. a passkey manager like Proton Pass that implements passkeys but not
      // the PRF extension). Signal the caller to fall back to a TOTP ephemeral key.
      const err = new Error('Your passkey provider can’t do the PRF unlock that one-tap signing needs.');
      err.code = 'prf_unsupported'; err.cause = e;
      throw err;
    }
    const prfFirst = cred.getClientExtensionResults()?.prf?.results?.first;
    if (!prfFirst) {
      // The assertion succeeded but produced no PRF result — same outcome: this
      // passkey can't be a one-tap signing key. The caller falls back to TOTP.
      const err = new Error('This passkey doesn’t support the PRF extension that one-tap signing needs.');
      err.code = 'prf_unsupported';
      throw err;
    }
    const prfOutput = new Uint8Array(prfFirst);

    // 4) Wrap the ML-DSA key with the PRF output — PRF ONLY, no passphrase. The
    //    PRF output stays in the browser; only the assertion goes to the server.
    const credentialId = _b64urlFromBuffer(cred.rawId);
    try {
      await vaultCreatePrfOnly({ alg: 'ML-DSA-65', label: label || 'Signing key', pk_b64, pk_hash, secretKeyBytes: kp.secretKey, credentialId, prfSalt, prfOutput });
    } finally {
      prfOutput.fill(0);
    }

    // 5) Bind the PUBLIC key to the account: the admin verifies the step-up
    //    assertion, then the relay records the pubkey (TOTP-free attested route).
    say('Linking your signing key to your account…');
    await _postJSON('/api/user/account/signing-key/step-up/bind', {
      flowId: opt.flowId,
      response: _serializeAssertion(cred),
      pk_b64,
      label: label || 'Signing key',
    });
  } finally {
    kp.secretKey.fill(0);   // zeroize the plaintext key
  }

  // Closed loop: resolve the way /sign does, proving the key is usable now.
  return await resolvePasskeySigningKey();
}

// ── TOTP-gated ephemeral signing key — the fallback when one-tap passkey-PRF
// signing isn't available: the account's passkey provider can't do WebAuthn-PRF
// (e.g. a passkey manager such as Proton Pass), or the account has no passkey at
// all. A fresh ML-DSA-65 key is generated in the browser and its PUBLIC half is
// bound to the account gated by a 6-digit authenticator code (the existing
// TOTP-gated enrol route). The SECRET key is NEVER written to the vault — without
// a passphrase or a PRF there is no KEK to wrap it at rest — so it lives only in
// the returned signer for this one signing session and is zeroized by dispose().
// Signing this way is "enter your authenticator code", repeated each time you sign
// on a device without a one-tap passkey. Old signatures stay verifiable: the relay
// keeps every enrolled public key (GitHub-SSH-style multi-key list).
export async function enrolEphemeralSigningKeyWithTotp({ label, totp, onStatus } = {}) {
  const say = (m) => { try { if (onStatus) onStatus(m); } catch { /* status is best-effort */ } };
  const code = String(totp == null ? '' : totp).trim();
  if (!/^\d{6}$/.test(code)) {
    const err = new Error('Enter the 6-digit code from your authenticator app.');
    err.code = 'totp_required';
    throw err;
  }

  // ML-DSA-65 keypair, generated + held only in the browser. Ownership of the
  // secret transfers to the returned ActivatedSigner, which zeroizes on dispose().
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const kp = ml_dsa65.keygen(seed);
  seed.fill(0);   // the keypair is derived; the seed is key material, zeroize it
  const pk_b64 = b64EncodeStd(kp.publicKey);
  const pk_hash = toHex(sha3_256(kp.publicKey));

  // Bind the PUBLIC key to the account, gated by the TOTP code (relay verifies it).
  say('Linking your signing key to your account…');
  let enrolRes = null;
  try {
    enrolRes = await _postJSON('/api/user/account/signing-key', { pk_b64, label: label || 'Signing key', totp: code });
  } catch (e) {
    kp.secretKey.fill(0);   // bind failed — drop the secret, nothing was stored
    const errCode = (e && e.data && e.data.error) || '';
    // Relay gates the TOTP enrol: 403 invalid_totp (wrong code) / 403 no_totp_setup
    // (account has no authenticator), 400 totp_required (malformed — caught above).
    if (errCode === 'no_totp_setup') { const err = new Error('Set up an authenticator app on your account first, then sign with its code.'); err.code = 'totp_unavailable'; throw err; }
    if (errCode === 'invalid_totp' || e.status === 403 || e.status === 401) { const err = new Error('That authenticator code didn’t match. Try the current 6-digit code.'); err.code = 'totp_invalid'; throw err; }
    if (e && (e.status === 400 || e.status === 409) && /totp/i.test(errCode)) { const err = new Error('That authenticator code didn’t match. Try the current 6-digit code.'); err.code = 'totp_invalid'; throw err; }
    throw e;
  }

  const signer = new ActivatedSigner(kp.secretKey, pk_b64);   // holds the in-memory secret; caller disposes
  return {
    signer,
    signKey: { pk_b64, fingerprint: pk_hash.slice(0, 16), ephemeral: true, hasPrf: false },
    // Surfaced so the sign flow can show a soft SHA-1 note (dual-verify accepted it).
    totpAlgorithm: (enrolRes && enrolRes.totp_algorithm) || null,
  };
}

// Serialize a raw PublicKeyCredential assertion to the JSON shape
// @simplewebauthn/server verifyAuthenticationResponse expects. The PRF result is
// deliberately NOT included — it is key material and stays in the browser.
function _serializeAssertion(cred) {
  const r = cred.response;
  const out = {
    id: cred.id,
    rawId: _b64urlFromBuffer(cred.rawId),
    type: cred.type,
    clientExtensionResults: {},
    response: {
      clientDataJSON:    _b64urlFromBuffer(r.clientDataJSON),
      authenticatorData: _b64urlFromBuffer(r.authenticatorData),
      signature:         _b64urlFromBuffer(r.signature),
    },
  };
  if (r.userHandle) out.response.userHandle = _b64urlFromBuffer(r.userHandle);
  return out;
}

function _b64urlFromBuffer(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── Same-origin admin calls for the per-document signing chain (R018) ────────
async function _postJSON(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}), credentials: 'include' });
  let data = null; try { data = await r.json(); } catch { /* non-JSON */ }
  if (!r.ok) { const e = new Error((data && data.error) || ('http_' + r.status)); e.status = r.status; e.data = data; throw e; }
  return data;
}
// Create the envelope. Self-sign/co-sign include the requester as party 0;
// request-signatures sets includeRequester=false and contains recipients only.
export function createSigningEnvelope({ docHash, recipients, originalFilename, signerLabel, creatorPublicKey, includeRequester = true }) {
  return _postJSON('/api/user/envelopes', {
    doc_hash: docHash,
    recipients: recipients || [],
    original_filename: originalFilename,
    signer_label: signerLabel,
    creator_public_key: creatorPublicKey,
    include_requester: includeRequester,
  });
}
// Authorize + issue the per-document activation (pre-unlock gate). Returns
// { activation_id, email_hash, recipe_version }.
export function requestSignActivation({ envelopeId, partyIndex, docHash, inviteToken }) {
  return _postJSON('/api/user/sign/activation', { envelope_id: envelopeId, party_index: partyIndex, doc_hash: docHash, invite_token: inviteToken });
}
// Submit the signature; the admin consumes the activation atomically + forwards
// to the relay. Returns { ok, signed_count, party_count, status }.
export function submitSignature({ activationId, signerPublicKey, signature, appearance }) {
  return _postJSON('/api/user/sign/submit', { activation_id: activationId, signer_public_key: signerPublicKey, signature, appearance });
}
