// ParaID demo credential issuer (server-side). Loads the demo-authority key and
// issues a real, signed credential bound to a holder key. Uses the SAME noble
// ML-DSA-65 as the browser, so a credential signed here verifies in the wallet.
//
// This is the Paramant Demo Authority: a registered issuer that issues DEMO
// credentials so logged-in users have a real, registry-anchored credential to
// try the flow with, until passport-grade issuance (NFC eMRTD) lands.
import { readFileSync } from 'fs';
import crypto from 'crypto';
// Vendored next to this module so the relative path resolves identically in the
// repo and in the flattened container image (where relay/ becomes /app).
import { ml_dsa65, sha3_256 } from './paramant-pqc.js';

const te = new TextEncoder();
const hex = (u8) => Buffer.from(u8).toString('hex');
const b64 = (u8) => Buffer.from(u8).toString('base64');
const b64url = (u8) => Buffer.from(u8).toString('base64url');
const concat = (...parts) => { const t = parts.reduce((n, p) => n + p.length, 0); const o = new Uint8Array(t); let k = 0; for (const p of parts) { o.set(p, k); k += p.length; } return o; };
const rand = (n) => { const b = crypto.randomBytes(n); return new Uint8Array(b.buffer, b.byteOffset, n); };

const leafHash = (salt, key, value) => sha3_256(concat(salt, te.encode(key + ':' + value)));
function merkleRoot(leaves) {
  let lvl = leaves.slice();
  while (lvl.length > 1) { const nx = []; for (let i = 0; i < lvl.length; i += 2) { if (i + 1 === lvl.length) { nx.push(lvl[i]); continue; } nx.push(sha3_256(concat(lvl[i], lvl[i + 1]))); } lvl = nx; }
  return lvl[0];
}

// Presence tier: the only thing the camera liveness check honestly proves is
// that a live human was present. No name, age or nationality: those come only
// from a document read, which is a separate, higher tier. We never fabricate.
const FIELDS_PRESENCE = ['presence_verified', 'holder_binding'];
const FIELDS_MRZ = ['age_over_18', 'nationality', 'holder_binding'];

// The assurance label on a credential says what the issuer actually checked, and
// nothing more. This one used to read 'substantial', which is the eIDAS word for
// a legally defined level of identity assurance. A caller supplies two lines of
// text; the issuer recomputes the ICAO check digits and signs the result. Check
// digits are a typo guard, not a signature: anyone can write an MRZ that passes
// them, because the algorithm is public and the input is the caller's own. So
// the document is never seen, its authenticity is never tested, and no person is
// tied to it. Claiming eIDAS substantial on that is a claim the evidence does
// not carry, and a verifier filtering on the word gets a wrong answer.
//
// 'mrz-unverified' says the true thing: an MRZ whose form checks out, from a
// document nobody authenticated. The real substantial rung needs the passport
// chip (eMRTD SOD, passive authentication), and that is what TIER_CHIP is
// reserved for. Nothing issues it yet, and nothing pretends to.
const TIER_PRESENCE = 'presence';
const TIER_MRZ = 'mrz-unverified';
const TIER_CHIP = 'high';

// Older credentials in the wild carry 'substantial' from before this rename.
// They mean exactly what mrz-unverified means; a verifier must read them as the
// same rung, never as the eIDAS level the word suggests.
const LEGACY_TIER_ALIASES = Object.freeze({ substantial: TIER_MRZ });

// Server-side MRZ re-validation, so the issuer never signs an attribute the
// document does not actually check out to. Same ICAO 9303 TD3 logic as the
// client; re-run here as defence in depth (the client cannot just claim 18+).
function mrzCharVal(c) { if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48; if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 55; if (c === '<') return 0; return -1; }
function mrzCheck(field) { const w = [7, 3, 1]; let s = 0; for (let i = 0; i < field.length; i++) { const v = mrzCharVal(field[i]); if (v < 0) return -1; s += v * w[i % 3]; } return s % 10; }
function dig(c) { return (c >= '0' && c <= '9') ? c.charCodeAt(0) - 48 : -1; }
function validateTD3(l1, l2) {
  l1 = (l1 || '').toUpperCase().replace(/\s/g, ''); l2 = (l2 || '').toUpperCase().replace(/\s/g, '');
  if (l1.length !== 44 || l2.length !== 44 || l1[0] !== 'P') return null;
  const dob = l2.slice(13, 19), nationality = l2.slice(10, 13).replace(/</g, '');
  if (mrzCheck(l2.slice(0, 9)) !== dig(l2[9])) return null;
  if (mrzCheck(dob) !== dig(l2[19])) return null;
  if (mrzCheck(l2.slice(21, 27)) !== dig(l2[27])) return null;
  const composite = l2.slice(0, 10) + l2.slice(13, 20) + l2.slice(21, 43);
  if (mrzCheck(composite) !== dig(l2[43])) return null;
  return { dob, nationality };
}
function ageOver18(dobYYMMDD, now) {
  const yy = +dobYYMMDD.slice(0, 2), mm = +dobYYMMDD.slice(2, 4), dd = +dobYYMMDD.slice(4, 6);
  const nowYY = now.getUTCFullYear() % 100, year = (yy > nowYY ? 1900 : 2000) + yy;
  let age = now.getUTCFullYear() - year;
  const m = (now.getUTCMonth() + 1) - mm;
  if (m < 0 || (m === 0 && now.getUTCDate() < dd)) age--;
  return age >= 18;
}

// Read a credential's assurance rung, mapping the pre-rename word onto the rung
// it always meant. Verifiers must go through this instead of comparing tier
// strings, so one old credential cannot read as a level it never had.
export function assuranceOf(credential) {
  const t = (credential && credential.tier) || TIER_PRESENCE;
  return LEGACY_TIER_ALIASES[t] || t;
}

// Ascending order of what the issuer actually verified. Anything unknown sorts
// below presence rather than above it: an unrecognised label is never a reason
// to trust a credential more.
export const ASSURANCE_RANK = Object.freeze([TIER_PRESENCE, TIER_MRZ, TIER_CHIP]);
export function assuranceAtLeast(credential, required) {
  const have = ASSURANCE_RANK.indexOf(assuranceOf(credential));
  const need = ASSURANCE_RANK.indexOf(required);
  if (have < 0 || need < 0) return false;
  return have >= need;
}

export function createIssuer({ keyFile }) {
  const raw = JSON.parse(readFileSync(keyFile, 'utf8'));
  const secretKey = new Uint8Array(Buffer.from(raw.secretKey, 'base64'));
  const publicKey = new Uint8Array(Buffer.from(raw.publicKey, 'base64'));
  const did = 'did:paramant:' + b64url(sha3_256(publicKey)).slice(0, 32);

  // Issue a presence credential for a holder that passed the liveness check.
  // holderBindingB64url = b64url(sha3-256(holderPk)). Only two sealed fields, and
  // both are true: a live person was present, bound to this device key.
  function issue({ holderBindingB64url }) {
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(holderBindingB64url || '')) {
      return { ok: false, error: 'holder_binding must be a b64url sha3-256 hash' };
    }
    const order = FIELDS_PRESENCE;
    const fields = { presence_verified: 'yes', holder_binding: holderBindingB64url };
    const salts = {};
    const leaves = order.map((k) => { salts[k] = rand(16); return leafHash(salts[k], k, fields[k]); });
    const root = merkleRoot(leaves);
    const rootSig = ml_dsa65.sign(secretKey, root);
    return {
      ok: true,
      credential: {
        v: 1,
        tier: TIER_PRESENCE,
        fieldOrder: order,
        issuerDid: did,
        issuerPublicKey: b64(publicKey),
        fields,
        salts: Object.fromEntries(Object.entries(salts).map(([k, v]) => [k, b64url(v)])),
        root: hex(root),
        rootSig: b64(rootSig),
        issued_at: raw._now || null,
      },
    };
  }

  // Substantial tier: issue from a passport MRZ. The server re-validates the
  // check digits and derives the attributes itself, so it never signs a claim
  // the document does not check out to. Only age_over_18 and nationality are
  // sealed: never the name, birthdate or document number.
  function issueFromMrz({ holderBindingB64url, mrzLine1, mrzLine2, now }) {
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(holderBindingB64url || '')) {
      return { ok: false, error: 'holder_binding must be a b64url sha3-256 hash' };
    }
    const v = validateTD3(mrzLine1, mrzLine2);
    if (!v) return { ok: false, error: 'MRZ failed validation (format or check digits)' };
    const order = FIELDS_MRZ;
    const fields = {
      age_over_18: ageOver18(v.dob, now instanceof Date ? now : new Date()) ? 'yes' : 'no',
      nationality: v.nationality,
      holder_binding: holderBindingB64url,
    };
    const salts = {};
    const leaves = order.map((k) => { salts[k] = rand(16); return leafHash(salts[k], k, fields[k]); });
    const root = merkleRoot(leaves);
    const rootSig = ml_dsa65.sign(secretKey, root);
    return {
      ok: true,
      credential: {
        v: 1, tier: TIER_MRZ, fieldOrder: order,
        // Spelled out on the credential itself, so a verifier that never reads
        // our docs still cannot mistake this for a checked document.
        checked: 'mrz_check_digits',
        not_checked: ['document_authenticity', 'chip_signature', 'holder_identity', 'liveness'],
        issuerDid: did, issuerPublicKey: b64(publicKey),
        fields, salts: Object.fromEntries(Object.entries(salts).map(([k, s]) => [k, b64url(s)])),
        root: hex(root), rootSig: b64(rootSig),
      },
    };
  }

  // issueSubstantial is kept as an alias so every existing caller keeps working
  // while the name moves to what the function actually does. The credential it
  // returns now carries the honest tier either way, so the alias cannot be used
  // to get the old claim back.
  return {
    did, issue, issueFromMrz, issueSubstantial: issueFromMrz,
    publicKeyB64: b64(publicKey),
  };
}
