// ParaSigner — the activation⇄key-use seam (ADR R018). The generic signing flow
// only ever calls: activate() -> sign(message) -> dispose(). It NEVER sees the
// raw ML-DSA secret key. Today this is LocalVaultSigner (a WebAuthn-PRF
// activation unlocks the IndexedDB vault key, signs one document, zeroizes).
// Tomorrow a RemoteSamSigner (SAP -> HSM-backed SAM) drops in behind the same
// interface without touching callers. Self-hosted deps only (CSP 'self').
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { vaultGetPrfWrapInfo, vaultUnlockPrf, vaultStore, vaultUnlock, vaultAddPrfWrap, vaultCreatePrfOnly, vaultAvailable, vaultList, assertStrongPassphrase } from '/vendor/vault.js?v=3';

// Re-exported so the sign UIs can strength-check a new passphrase before enrol.
export { assertStrongPassphrase };

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
function toHex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0');
  return s;
}

// Reconstruct EXACTLY the relay's recipe-v3 sign-message:
//   sha3_256("paramant/parasign/doc/v1" || 0x00 || envId || docHash || pi || emailHash)
// This is what binds a signature to THIS document (doc_hash), party and email.
export function buildDocSignMessage({ envelopeId, docHash, partyIndex, emailHash }) {
  const enc = new TextEncoder();
  return sha3_256(concatBytes([
    enc.encode(SIGN_DOMAIN_DOC),
    new Uint8Array([0]),
    enc.encode(String(envelopeId)),
    hexToBytes(docHash),
    enc.encode(String(partyIndex)),
    hexToBytes(emailHash || ''),
  ]));
}

// v3 signing-key resolution — the SINGLE definition of "what a signing key is",
// shared by /sign (self-sign) and /co-sign (recipient). The signing key is the
// account's ML-DSA-65 key in the vault, unlocked either by the passkey's PRF
// (one tap, preferred) or by a passphrase (the fallback for passkey providers
// without PRF, e.g. some password managers). We read its PUBLIC half
// (pk_b64/pk_hash) from vault metadata WITHOUT unlocking, plus which KEK sources
// it has so the caller knows whether to do a one-tap PRF unlock or to ask for the
// passphrase. If no signing key is enrolled, throws code 'no_signing_passkey'.
export async function resolvePasskeySigningKey() {
  if (!(await vaultAvailable())) throw new Error('This browser cannot store signing keys (IndexedDB/WebCrypto unavailable).');
  const keys = await vaultList();
  const usable = keys.filter((k) => (k.kekSources || []).some((s) => s === 'webauthn-prf' || s === 'passphrase'));
  if (usable.length === 0) {
    const e = new Error('No signing key on this device yet. Set one up when you sign.');
    e.code = 'no_signing_passkey';
    throw e;
  }
  // Prefer a PRF-capable key (one tap) over a passphrase-only one.
  const k = usable.find((x) => (x.kekSources || []).includes('webauthn-prf')) || usable[0];
  const sources = k.kekSources || [];
  return {
    vaultId: k.id, pk_b64: k.pk_b64, fingerprint: (k.pk_hash || '').slice(0, 16),
    kekSources: sources, hasPrf: sources.includes('webauthn-prf'), hasPassphrase: sources.includes('passphrase'),
  };
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
// caller detects the failure and falls back to a passphrase-protected key.
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
  // one signature, then the caller disposes (zeroize). Two unlock sources:
  //   • passphrase (when given): PBKDF2 -> AES-GCM unwrap, no WebAuthn.
  //   • otherwise the passkey's PRF output (one tap).
  // A passphrase-only key with no PRF wrap throws code 'need_passphrase' so the UI
  // can ask for it and call again with { passphrase }.
  async activate({ vaultId, rpId, passphrase } = {}) {
    if (passphrase) {
      const unlocked = await vaultUnlock(vaultId, passphrase);
      return new ActivatedSigner(unlocked.secretKeyBytes, unlocked.pk_b64);
    }
    const info = await vaultGetPrfWrapInfo(vaultId);
    if (!info) {
      const e = new Error('This signing key is protected by a passphrase on this browser.');
      e.code = 'need_passphrase';
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

// Convenience: full per-document activation. activate -> sign(doc message) ->
// dispose, returning the signature + public key for /api/user/sign/submit.
// The raw key is never returned and is zeroized even if signing throws.
export async function signDocumentWithPasskey({ vaultId, rpId, envelopeId, docHash, partyIndex, emailHash }) {
  const active = await new LocalVaultSigner().activate({ vaultId, rpId });
  try {
    const message = buildDocSignMessage({ envelopeId, docHash, partyIndex, emailHash });
    const signature = await active.sign(message);
    return { signer_public_key: active.publicKey, signature };
  } finally {
    active.dispose();
  }
}

// ── TOFU enrol-as-needed — a SEPARATE sub-step (ADR R018) ────────────────────
// Runs ONCE for a first-time signer who has no passkey/PRF wrap yet, BEFORE the
// per-document activation-gate. It is deliberately NOT fused with activate()/
// sign(): this moment combines passkey registration + ML-DSA key enrolment, so
// it must be auditable as one distinct block. Three explicit stages; the signing
// of an actual document is a separate act (signDocumentWithPasskey) afterwards.
//
// WebAuthn create()/get() and the server enrol call are injected as callbacks so
// the ceremony plumbing stays out of this orchestration:
//   registerPasskey()              -> { credentialId }              (WebAuthn create + server store)
//   evalNewPrf({credentialId,prfSalt}) -> Uint8Array prfOutput      (WebAuthn get, prf eval=salt)
//   enrolPublicKey({pk_b64,pk_hash,label})                         (server: bind pubkey to account)
export async function enrolSigningPasskey({ label, passphrase, registerPasskey, evalNewPrf, enrolPublicKey }) {
  // ── stage 1: key material + recovery floor (passphrase wrap; enforced strong) ──
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const kp = ml_dsa65.keygen(seed);
  const pk_b64 = b64EncodeStd(kp.publicKey);
  const pk_hash = toHex(sha3_256(kp.publicKey));
  try {
    await vaultStore({ alg: 'ML-DSA-65', label: label || null, pk_b64, pk_hash, secretKeyBytes: kp.secretKey, passphrase });

    // ── stage 2: obtain a passkey-PRF output, with a one-shot fallback ──────────
    // registerPasskey() may REUSE an existing PRF-capable passkey (fast path, no
    // new credential). But a credential the server flagged prfSupported can still
    // fail to actually produce a PRF result here (it was created before PRF, or
    // the platform won't eval it) — that is the loop users hit: the enrolment
    // dies, the orphan is swept, /sign keeps asking to "set up a signing passkey".
    // So when PRF fails on a REUSED credential we don't give up: we mint a FRESH
    // PRF-capable passkey and try once more. Only a FRESH passkey that STILL can't
    // PRF is a genuine device/browser limitation (surfaced to the user).
    const prfSalt = crypto.getRandomValues(new Uint8Array(16));   // the eval salt; stored in the wrap
    let reg = await registerPasskey({ forceFresh: false });
    let prfOutput;
    try {
      prfOutput = await evalNewPrf({ credentialId: reg.credentialId, prfSalt });
    } catch (e) {
      if (reg && reg.reused && e && e.code === 'no_prf') {
        reg = await registerPasskey({ forceFresh: true });
        prfOutput = await evalNewPrf({ credentialId: reg.credentialId, prfSalt });
      } else {
        throw e;
      }
    }
    try {
      await vaultAddPrfWrap({ pk_hash, secretKeyBytes: kp.secretKey, credentialId: reg.credentialId, prfSalt, prfOutput });
    } finally {
      prfOutput.fill(0);
    }

    // ── stage 3: bind the public key to the account (server) ──
    await enrolPublicKey({ pk_b64, pk_hash, label: label || null });
  } finally {
    kp.secretKey.fill(0);   // zeroize the plaintext key once both wraps + enrol are done
  }
  return { pk_hash, pk_b64 };
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
      // the PRF extension). Signal the caller to fall back to a passphrase key.
      const err = new Error('Your passkey provider can’t do the PRF unlock that one-tap signing needs.');
      err.code = 'prf_unsupported'; err.cause = e;
      throw err;
    }
    const prfFirst = cred.getClientExtensionResults()?.prf?.results?.first;
    if (!prfFirst) {
      // The assertion succeeded but produced no PRF result — same outcome: this
      // passkey can't be a one-tap signing key. The caller falls back to a passphrase.
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

// ── Passphrase-protected signing key — the fallback when the account's passkey
// provider cannot do WebAuthn-PRF (e.g. a password manager such as Proton Pass
// that implements passkeys but not the PRF extension). The passkey is STILL used
// to prove account possession (a NORMAL step-up assertion, no PRF — exactly what
// login does, so a non-PRF provider handles it); the local ML-DSA key is wrapped
// with a user passphrase (PBKDF2 -> AES-256-GCM via vaultStore) instead of a PRF
// KEK. Same account binding and same server route as the one-tap path; only the
// local key-wrap differs. Signing later unlocks via LocalVaultSigner.activate
// ({ passphrase }). Recovery floor is the passphrase, so it is enforced strong.
export async function enrolSigningKeyWithPassphrase({ rpId, label, passphrase, onStatus } = {}) {
  const say = (m) => { try { if (onStatus) onStatus(m); } catch { /* status is best-effort */ } };
  assertStrongPassphrase(passphrase);   // fail closed on weak input (vaultStore re-checks)
  if (!(await vaultAvailable())) {
    const err = new Error('This browser cannot store signing keys (IndexedDB/WebCrypto unavailable).');
    err.code = 'vault_unavailable';
    throw err;
  }
  rpId = rpId || location.hostname;

  // 1) ML-DSA-65 keypair, generated + held only in the browser.
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const kp = ml_dsa65.keygen(seed);
  const pk_b64 = b64EncodeStd(kp.publicKey);
  const pk_hash = toHex(sha3_256(kp.publicKey));
  try {
    // 2) Wrap the ML-DSA key with the passphrase locally (no PRF, no WebAuthn).
    await vaultStore({ alg: 'ML-DSA-65', label: label || 'Signing key', pk_b64, pk_hash, secretKeyBytes: kp.secretKey, passphrase });

    // 3) Prove account possession with a NORMAL passkey step-up (no PRF — this is
    //    what login does, so a provider without PRF still handles it).
    say('Confirm with your passkey to link this signing key…');
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
    const allowList = (opt.options.allowCredentials || []);
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBytes(opt.options.challenge),
        rpId,
        allowCredentials: allowList.map((c) => ({
          type: 'public-key',
          id: b64urlToBytes(c.id),
          ...(c.transports ? { transports: c.transports } : {}),
        })),
        userVerification: 'required',
        timeout: opt.options.timeout || 60000,
      },
    });

    // 4) Bind the PUBLIC key to the account — same admin route as the one-tap path.
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

  // Resolve the way /sign does, proving the key is usable now.
  return await resolvePasskeySigningKey();
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
// Create the envelope (party 0 = self). Returns { envelope: { id, party_links, ... } }.
export function createSigningEnvelope({ docHash, recipients, originalFilename, signerLabel, creatorPublicKey }) {
  return _postJSON('/api/user/envelopes', { doc_hash: docHash, recipients: recipients || [], original_filename: originalFilename, signer_label: signerLabel, creator_public_key: creatorPublicKey });
}
// Authorize + issue the per-document activation (pre-unlock gate). Returns
// { activation_id, email_hash, recipe_version }.
export function requestSignActivation({ envelopeId, partyIndex, docHash, inviteToken }) {
  return _postJSON('/api/user/sign/activation', { envelope_id: envelopeId, party_index: partyIndex, doc_hash: docHash, invite_token: inviteToken });
}
// Submit the signature; the admin consumes the activation atomically + forwards
// to the relay. Returns { ok, signed_count, party_count, status }.
export function submitSignature({ activationId, signerPublicKey, signature }) {
  return _postJSON('/api/user/sign/submit', { activation_id: activationId, signer_public_key: signerPublicKey, signature });
}
