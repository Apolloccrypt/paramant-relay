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
        tier: 'presence',
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

  return { did, issue, publicKeyB64: b64(publicKey) };
}
