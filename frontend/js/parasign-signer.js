// ParaSigner — the activation⇄key-use seam (ADR R018). The generic signing flow
// only ever calls: activate() -> sign(message) -> dispose(). It NEVER sees the
// raw ML-DSA secret key. Today this is LocalVaultSigner (a WebAuthn-PRF
// activation unlocks the IndexedDB vault key, signs one document, zeroizes).
// Tomorrow a RemoteSamSigner (SAP -> HSM-backed SAM) drops in behind the same
// interface without touching callers. Self-hosted deps only (CSP 'self').
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { vaultGetPrfWrapInfo, vaultUnlockPrf } from '/vendor/vault.js';

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
