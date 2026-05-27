'use strict';
// ParaSign Sg1 step 3 -- .psign envelope build + verify (see docs/adrs/R017).
//
// The relay is a NOTARY, not a signer. The signer's ML-DSA-65 signature is
// produced client-side (browser/CLI) over the SHA3-256 document hash; this
// module never sees a signer private key and never sees document content --
// only the hash, the signature, and the signer's public key.
//
// Pure module: ML-DSA-65 sign/verify are injected by the caller (relay.js
// passes registry.getSig(0x0002)), so the logic is unit-testable in isolation.

// Canonical JSON: recursively sorted keys, no whitespace. Must match the
// canonicalJSON used elsewhere in the relay so signatures interoperate.
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(obj).sort()
    .map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

// Build and notary-sign a .psign envelope.
//   input: { documentHashHex, signatureB64, signerPubB64, signerLabel, ttlDays, ctLogIndex }
//   deps:  { relaySign(Buffer)->Uint8Array|Buffer, relayPkHash, ctLogUrl?, relayPubkeyUrl? }
function buildEnvelope(input, deps) {
  const now = new Date();
  const ttl = Number.isFinite(input.ttlDays) && input.ttlDays > 0 ? input.ttlDays : 365;
  const envelope = {
    version: '1',
    algorithm: 'ML-DSA-65',
    document_hash: input.documentHashHex,
    document_hash_algo: 'sha3-256',
    signature: input.signatureB64,
    signer: { public_key: input.signerPubB64, label: input.signerLabel || null },
    signed_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl * 86400 * 1000).toISOString(),
    notary: {
      relay_pk_hash: deps.relayPkHash,
      ct_log_index: input.ctLogIndex,
      ct_log_url: deps.ctLogUrl || 'https://paramant.app/v2/ct/log',
      relay_pubkey_url: deps.relayPubkeyUrl || 'https://paramant.app/v2/pubkey',
    },
  };
  const sig = deps.relaySign(Buffer.from(canonicalJSON(envelope), 'utf8'));
  envelope.envelope_signature = Buffer.from(sig).toString('base64');
  return envelope;
}

// Verify a .psign envelope. Collects every failure rather than short-circuiting.
//   input: { documentHashHex (optional -- binds envelope to a document), envelope }
//   deps:  { sigVerify(sigBuf, msgBuf, pubBuf)->bool, relayPub: Buffer }
function verifyEnvelope(input, deps) {
  const errors = [];
  const env = input.envelope;
  if (!env || typeof env !== 'object') return { valid: false, errors: ['missing or invalid envelope'] };
  if (env.version !== '1') errors.push('unsupported envelope version: ' + env.version);
  if (env.algorithm !== 'ML-DSA-65') errors.push('unsupported algorithm: ' + env.algorithm);

  if (input.documentHashHex && env.document_hash !== input.documentHashHex) {
    errors.push('document_hash mismatch (envelope ' + String(env.document_hash).slice(0, 16) +
      '… vs document ' + String(input.documentHashHex).slice(0, 16) + '…)');
  }

  // 1. Signer signature over the document hash.
  try {
    const ok = deps.sigVerify(
      Buffer.from(env.signature || '', 'base64'),
      Buffer.from(env.document_hash || '', 'hex'),
      Buffer.from((env.signer && env.signer.public_key) || '', 'base64'),
    );
    if (!ok) errors.push('signer signature invalid');
  } catch (e) { errors.push('signer signature verify error: ' + e.message); }

  // 2. Notary (envelope) signature over canonical envelope minus the signature field.
  try {
    const rest = Object.assign({}, env);
    delete rest.envelope_signature;
    const ok = deps.sigVerify(
      Buffer.from(env.envelope_signature || '', 'base64'),
      Buffer.from(canonicalJSON(rest), 'utf8'),
      deps.relayPub,
    );
    if (!ok) errors.push('notary (envelope) signature invalid');
  } catch (e) { errors.push('envelope signature verify error: ' + e.message); }

  // 3. Expiry.
  if (env.expires_at && new Date(env.expires_at) < new Date()) {
    errors.push('envelope expired at ' + env.expires_at);
  }

  return { valid: errors.length === 0, errors };
}

module.exports = { canonicalJSON, buildEnvelope, verifyEnvelope };
