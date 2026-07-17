// ParaID issuer registry: which issuer DIDs the relay vouches for.
//
// The registry answers one question for verifiers: "is this issuer key one the
// operator has registered, and is it still active?". Every mutation is meant to
// be anchored in the public CT log by the caller (relay.js), so an operator can
// not silently add or remove issuers: the log keeps the history append-only.
//
// The DID is derived from the ML-DSA-65 public key exactly like the frontend
// does (did:paramant:<b64url(sha3-256(pk)).slice(0,32)>), so a registry entry
// can never be re-pointed at a different key.
'use strict';

const crypto = require('crypto');
const fs = require('fs');

const MLDSA65_PK_BYTES = 1952;

function didFromPublicKey(pkBuf) {
  const h = crypto.createHash('sha3-256').update(pkBuf).digest();
  return 'did:paramant:' + h.toString('base64url').slice(0, 32);
}

function createRegistry({ file }) {
  let issuers = new Map(); // did -> { did, label, public_key, status, since, revoked_at }
  let writeQueue = Promise.resolve();

  function load() {
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const data = JSON.parse(raw);
      issuers = new Map((data.issuers || []).map((i) => [i.did, i]));
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      issuers = new Map();
    }
    return issuers.size;
  }

  function persist() {
    const snapshot = JSON.stringify({ issuers: [...issuers.values()] }, null, 2);
    writeQueue = writeQueue.then(() =>
      fs.promises.writeFile(file + '.tmp', snapshot)
        .then(() => fs.promises.rename(file + '.tmp', file))
    ).catch(() => {});
    return writeQueue;
  }

  // Register an issuer. Returns { ok, issuer } or { ok: false, error }.
  function add({ label, publicKeyB64 }) {
    if (!label || typeof label !== 'string' || label.length > 120) {
      return { ok: false, error: 'label required (max 120 chars)' };
    }
    let pk;
    try { pk = Buffer.from(publicKeyB64 || '', 'base64'); } catch { pk = Buffer.alloc(0); }
    if (pk.length !== MLDSA65_PK_BYTES) {
      return { ok: false, error: 'public_key must be a base64 ML-DSA-65 public key (' + MLDSA65_PK_BYTES + ' bytes)' };
    }
    const did = didFromPublicKey(pk);
    if (issuers.has(did) && issuers.get(did).status === 'active') {
      return { ok: false, error: 'issuer already registered', did };
    }
    const issuer = {
      did, label: label.trim(),
      public_key: pk.toString('base64'),
      status: 'active',
      since: new Date().toISOString(),
    };
    issuers.set(did, issuer);
    persist();
    return { ok: true, issuer };
  }

  function revoke(did) {
    const issuer = issuers.get(did);
    if (!issuer) return { ok: false, error: 'unknown issuer did' };
    if (issuer.status === 'revoked') return { ok: false, error: 'already revoked' };
    issuer.status = 'revoked';
    issuer.revoked_at = new Date().toISOString();
    persist();
    return { ok: true, issuer };
  }

  // Public view: active AND revoked entries. Revocations must be visible,
  // otherwise "issuer disappeared" and "issuer never existed" look the same.
  function list() {
    return [...issuers.values()].map((i) => ({
      did: i.did, label: i.label, public_key: i.public_key,
      status: i.status, since: i.since,
      ...(i.revoked_at ? { revoked_at: i.revoked_at } : {}),
    }));
  }

  function get(did) { return issuers.get(did) || null; }

  return { load, add, revoke, list, get, didFromPublicKey };
}

module.exports = { createRegistry, didFromPublicKey, MLDSA65_PK_BYTES };
