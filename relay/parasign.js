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

const crypto = require('crypto');

// Domain separation for the single-signer notary message (pentest #3/#4).
// Until v2, the signer signed the BARE 32-byte document hash, so an ML-DSA
// signature made over any unrelated 32-byte value (a co-sign digest, a session
// challenge, a receipt hash) could be replayed into /v2/sign and notarised as a
// "document signature". v2 binds the signature to THIS protocol+purpose with a
// mandatory, distinct domain label (the multi-party flow uses
// 'paramant/parasign/doc/v1'; the single-signer notary gets its own so the two
// cannot cross-replay either). Construction mirrors envelope.js signMessageBytes:
//   v2 message = sha3_256("paramant/parasign/notary/v1" || 0x00 || doc_hash_bytes)
const SIGN_DOMAIN_NOTARY = 'paramant/parasign/notary/v1';

// The bytes the signer's ML-DSA key signs for a v2 single-signer envelope.
function singleSignerMessage(docHashHex) {
  return crypto.createHash('sha3-256')
    .update(Buffer.from(SIGN_DOMAIN_NOTARY, 'utf8'))
    .update(Buffer.from([0]))
    .update(Buffer.from(docHashHex, 'hex'))
    .digest();
}

// The bytes verifyEnvelope / /v2/sign check the signer signature against, given
// the envelope version. v1 = bare hash (legacy, still verifiable); v2 = domain-
// separated. Returns a Buffer.
function signerVerifyBytes(docHashHex, version) {
  return String(version) === '2'
    ? singleSignerMessage(docHashHex)
    : Buffer.from(docHashHex, 'hex');
}

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
  // version '2' = signer signed the domain-separated message (default for new
  // envelopes). '1' = legacy bare-hash signer signature, only minted when the
  // relay is explicitly run in legacy-accept mode for an old client.
  const version = String(input.version || '2') === '1' ? '1' : '2';
  const envelope = {
    version,
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
  if (env.version !== '1' && env.version !== '2') errors.push('unsupported envelope version: ' + env.version);
  if (env.algorithm !== 'ML-DSA-65') errors.push('unsupported algorithm: ' + env.algorithm);

  if (input.documentHashHex && env.document_hash !== input.documentHashHex) {
    errors.push('document_hash mismatch (envelope ' + String(env.document_hash).slice(0, 16) +
      '… vs document ' + String(input.documentHashHex).slice(0, 16) + '…)');
  }

  // 1. Signer signature over the (version-appropriate) signer message.
  //    v2 = domain-separated message, v1 = bare document hash (legacy).
  try {
    const ok = deps.sigVerify(
      Buffer.from(env.signature || '', 'base64'),
      signerVerifyBytes(env.document_hash || '', env.version),
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

module.exports = {
  canonicalJSON, buildEnvelope, verifyEnvelope,
  singleSignerMessage, signerVerifyBytes, SIGN_DOMAIN_NOTARY,
};
