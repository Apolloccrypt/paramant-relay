// Round-trip proof for the ParaSign verify chain (audit 1.2 / 1.3 / 1.7).
// A document signed on /sign (v3 parasign-doc-3) must verify as VALID on /verify,
// WITHOUT an API key, using ONLY the client-side ML-DSA-65 + SHA3-256 math. This
// test builds the .psign with the exact field set the browser (sign-flow.js)
// emits, then:
//   1.2  drives it through relay/parasign.js verifyEnvelope -> VALID
//        (one flipped document byte / signature byte -> INVALID)
//   1.3  reconstructs the signed message the way the keyless client verifier
//        (parasign-verify.js buildDocSignMessage) does and asserts it is
//        byte-identical to relay/envelope.js signMessageBytes(...,3), so the
//        offline no-key path verifies the very same bytes the relay would.
//
// Lives under crypto/ so the CI relay-crypto job (node --test crypto/*.test.js)
// runs it against the real ML-DSA-65 binding.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { bootstrap } = require('./bootstrap');
const { getSig } = require('./registry');
const parasign = require('../parasign');
const { signMessageBytes } = require('../envelope');

bootstrap('core');
const sig = getSig(0x0002); // ML-DSA-65

const verifyDeps = {
  sigVerify: (s, m, p) => { try { return sig.verify(s, m, p); } catch { return false; } },
  relayPub: Buffer.alloc(0), // v3 has no notary signature
};

// The keyless client verifier (parasign-verify.js) rebuilds the message from
// primitives; replicate that construction here to prove parity with the relay.
function clientMessage(envelopeId, docHashHex, partyIndex, emailHashHex) {
  return crypto.createHash('sha3-256')
    .update(Buffer.from('paramant/parasign/doc/v1', 'utf8'))
    .update(Buffer.from([0]))
    .update(Buffer.from(String(envelopeId), 'utf8'))
    .update(Buffer.from(docHashHex, 'hex'))
    .update(Buffer.from(String(partyIndex), 'utf8'))
    .update(Buffer.from(emailHashHex || '', 'hex'))
    .digest();
}

// Build a v3 .psign the way sign-flow.js doSign() does (pdf/image or document).
function makeFrontendV3(mode = 'pdf', opts = {}) {
  const signer = sig.generateKeyPair();
  const docBytes = Buffer.from(opts.doc || 'a freshly signed contract');
  const signedHashHex = crypto.createHash('sha3-256').update(docBytes).digest('hex');
  const envelopeId = 'env_' + crypto.randomBytes(16).toString('hex');
  const partyIndex = 0;
  const emailHash = opts.emailHash != null
    ? opts.emailHash
    : crypto.createHash('sha3-256').update(Buffer.from('demo@example.com')).digest('hex');

  const msg = signMessageBytes(envelopeId, signedHashHex, partyIndex, emailHash, 3);
  const signature = sig.sign(msg, signer.secretKey);

  const common = {
    version: 'parasign-doc-3', recipe_version: 3, sign_domain: 'paramant/parasign/doc/v1',
    algorithm: 'ML-DSA-65', hash_algorithm: 'SHA3-256',
    signer_public_key: Buffer.from(signer.publicKey).toString('base64'),
    signer_pk_fingerprint: crypto.createHash('sha3-256').update(Buffer.from(signer.publicKey)).digest('hex').slice(0, 32),
    party_email_hash: emailHash,
    signature: Buffer.from(signature).toString('base64'),
    signed_at: new Date().toISOString(),
    multiparty: { envelope_id: envelopeId, party_index: partyIndex, party_count: 1 },
    disclaimer: 'Advanced electronic signature (AES).',
  };
  const envelope = mode === 'document'
    ? { ...common, original_filename: 'contract.txt', document_hash: signedHashHex, signer_name: 'Demo' }
    : { ...common, original_filename: 'contract.pdf', stamped_filename: 'signed-contract.pdf', stamped_hash: signedHashHex, original_hash: signedHashHex };
  return { envelope, signedHashHex, emailHash, envelopeId, partyIndex };
}

test('1.2: a fresh v3 pdf .psign verifies VALID on /verify (was INVALID before D3)', () => {
  const { envelope, signedHashHex } = makeFrontendV3('pdf');
  const r = parasign.verifyEnvelope({ documentHashHex: signedHashHex, envelope }, verifyDeps);
  assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
});

test('1.2: a fresh v3 document .psign verifies VALID', () => {
  const { envelope, signedHashHex } = makeFrontendV3('document');
  const r = parasign.verifyEnvelope({ documentHashHex: signedHashHex, envelope }, verifyDeps);
  assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
});

test('1.2: flipping one document byte -> INVALID (hash mismatch)', () => {
  const { envelope } = makeFrontendV3('pdf');
  const tampered = crypto.createHash('sha3-256').update(Buffer.from('a DIFFERENT contract')).digest('hex');
  const r = parasign.verifyEnvelope({ documentHashHex: tampered, envelope }, verifyDeps);
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some(e => e.includes('document_hash mismatch')), JSON.stringify(r.errors));
});

test('1.2: flipping one signature byte -> INVALID', () => {
  const { envelope, signedHashHex } = makeFrontendV3('pdf');
  const sb = Buffer.from(envelope.signature, 'base64');
  sb[0] ^= 0xff;
  envelope.signature = sb.toString('base64');
  const r = parasign.verifyEnvelope({ documentHashHex: signedHashHex, envelope }, verifyDeps);
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some(e => e.includes('signer signature invalid')), JSON.stringify(r.errors));
});

test('1.3: keyless client message reconstruction is byte-identical to the relay', () => {
  const { envelope, signedHashHex, emailHash, envelopeId } = makeFrontendV3('pdf');
  const relayMsg = signMessageBytes(envelopeId, signedHashHex, 0, emailHash, 3);
  const browserMsg = clientMessage(envelopeId, signedHashHex, 0, emailHash);
  assert.ok(relayMsg.equals(browserMsg), 'client and relay must sign-verify the same bytes');
  // And that message must match the signature the signer produced (offline verify).
  const ok = sig.verify(Buffer.from(envelope.signature, 'base64'), browserMsg, Buffer.from(envelope.signer_public_key, 'base64'));
  assert.strictEqual(ok, true);
});

test('1.3: wrong email_hash breaks the offline signature (email is bound in)', () => {
  const { envelope, signedHashHex } = makeFrontendV3('pdf');
  envelope.party_email_hash = crypto.createHash('sha3-256').update(Buffer.from('mallory@example.com')).digest('hex');
  const r = parasign.verifyEnvelope({ documentHashHex: signedHashHex, envelope }, verifyDeps);
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some(e => e.includes('signer signature invalid')), JSON.stringify(r.errors));
});
