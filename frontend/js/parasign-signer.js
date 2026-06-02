// ParaSigner — the activation⇄key-use seam (ADR R018). The generic signing flow
// only ever calls: activate() -> sign(message) -> dispose(). It NEVER sees the
// raw ML-DSA secret key. Today this is LocalVaultSigner (a WebAuthn-PRF
// activation unlocks the IndexedDB vault key, signs one document, zeroizes).
// Tomorrow a RemoteSamSigner (SAP -> HSM-backed SAM) drops in behind the same
// interface without touching callers. Self-hosted deps only (CSP 'self').
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { vaultGetPrfWrapInfo, vaultUnlockPrf, vaultStore, vaultAddPrfWrap, vaultAvailable, vaultList } from '/vendor/vault.js?v=2';

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

// v3-only signing-key resolution — the SINGLE definition of "what a signing key
// is", shared by /sign (self-sign) and /co-sign (recipient). The signing key is
// the account's passkey-protected ML-DSA-65 key in the vault. We read its PUBLIC
// half (pk_b64/pk_hash) from vault metadata WITHOUT unlocking; the secret is only
// unlocked by the per-document passkey-PRF activation (LocalVaultSigner.activate,
// the explicit step-2 action). No ephemeral/file/passphrase key source. If no
// passkey signing key is enrolled, this throws with code 'no_signing_passkey' so
// the caller can branch to the TOFU enrol sub-step (stuk 2 UI / enrolSigningPasskey).
export async function resolvePasskeySigningKey() {
  if (!(await vaultAvailable())) throw new Error('This browser cannot store signing keys (IndexedDB/WebCrypto unavailable).');
  const keys = await vaultList();
  const usable = keys.filter((k) => (k.kekSources || []).includes('webauthn-prf'));
  if (usable.length === 0) {
    const e = new Error('No passkey signing key on this device yet. Enrol a passkey for signing first.');
    e.code = 'no_signing_passkey';
    throw e;
  }
  const k = usable[0];   // single signing identity for now
  return { vaultId: k.id, pk_b64: k.pk_b64, fingerprint: (k.pk_hash || '').slice(0, 16) };
}

// Reproduce the PRF output by running a WebAuthn get() with the SAME salt that
// was stored in the wrap at enrol (PRF output is deterministic per
// (credential, salt), independent of the challenge).
async function evalPrf({ rpId, credentialIdB64url, prfSaltB64url }) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      allowCredentials: [{ type: 'public-key', id: b64urlToBytes(credentialIdB64url) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: b64urlToBytes(prfSaltB64url) } } },
    },
  });
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
  // ACTIVATION — the replaceable step. WebAuthn-PRF unlocks the vault key.
  // Returns an ActivatedSigner; the caller signs exactly one document then
  // calls dispose(). The PRF output (key-deriving material) is wiped here.
  async activate({ vaultId, rpId }) {
    const info = await vaultGetPrfWrapInfo(vaultId);
    if (!info) throw new Error('no passkey-PRF wrap on this key — enrol a passkey first');
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
