'use strict';
// Domain-separation for the single-signer notary (#3/#4). parasign.js is a pure
// module: the ML-DSA sign/verify are INJECTED, so we test the security-critical
// logic -- which message bytes get signed/verified per envelope version -- with
// a mock sig engine and no native crypto dep (so it runs in the deps-free relay
// unit CI job). A real-ML-DSA end-to-end round-trip is exercised separately
// against a live relay; this locks the byte-level contract.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const parasign = require('../parasign');
const { signMessageBytes, appearanceHash } = require('../envelope');

// Mock signature scheme: a "signature" IS the exact bytes that were signed.
//   sign(msg)            -> msg            (Buffer)
//   verify(sig, msg, pk) -> sig === msg    (the signer signed exactly this message)
// So an envelope verifies iff verifyEnvelope feeds sigVerify the SAME bytes the
// signer committed to -- exactly what domain separation must get right.
const deps = {
  relaySign: (msg) => Buffer.from(msg),
  relayPkHash: 'relaypkhash',
  relayPub: Buffer.from('relay-pub'),
  sigVerify: (sigBuf, msgBuf) => Buffer.compare(Buffer.from(sigBuf), Buffer.from(msgBuf)) === 0,
};
// A signer "signature" over `bytes`, as the base64 string buildEnvelope stores.
const signOver = (bytes) => Buffer.from(bytes).toString('base64');

const docHashHex = crypto.createHash('sha3-256').update(Buffer.from('a contract')).digest('hex');

test('singleSignerMessage = sha3_256(domain || 0x00 || hash), distinct from the bare hash', () => {
  const expected = crypto.createHash('sha3-256')
    .update(Buffer.from('paramant/parasign/notary/v1', 'utf8'))
    .update(Buffer.from([0]))
    .update(Buffer.from(docHashHex, 'hex')).digest();
  assert.deepEqual(parasign.singleSignerMessage(docHashHex), expected);
  assert.notDeepEqual(parasign.singleSignerMessage(docHashHex), Buffer.from(docHashHex, 'hex'));
});

test('signerVerifyBytes dispatches v2 -> domain-separated, v1 -> bare hash', () => {
  assert.deepEqual(parasign.signerVerifyBytes(docHashHex, '2'), parasign.singleSignerMessage(docHashHex));
  assert.deepEqual(parasign.signerVerifyBytes(docHashHex, '1'), Buffer.from(docHashHex, 'hex'));
});

test('v2 envelope: signer must have signed the domain-separated message', () => {
  const env = parasign.buildEnvelope({
    documentHashHex: docHashHex,
    signatureB64: signOver(parasign.singleSignerMessage(docHashHex)), // correct v2 signer sig
    signerPubB64: Buffer.from('signer-pub').toString('base64'),
    signerLabel: 'tester', ttlDays: 365, ctLogIndex: 1, version: '2',
  }, deps);
  assert.equal(env.version, '2');
  const r = parasign.verifyEnvelope({ envelope: env, documentHashHex: docHashHex }, deps);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test('legacy v1 envelope (signer signed the bare hash) still verifies', () => {
  const env = parasign.buildEnvelope({
    documentHashHex: docHashHex,
    signatureB64: signOver(Buffer.from(docHashHex, 'hex')), // bare-hash signer sig
    signerPubB64: Buffer.from('signer-pub').toString('base64'),
    signerLabel: 'legacy', ttlDays: 365, ctLogIndex: 0, version: '1',
  }, deps);
  assert.equal(env.version, '1');
  const r = parasign.verifyEnvelope({ envelope: env }, deps);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test('cross-protocol replay: a signature over an unrelated 32-byte value is NOT a valid v2 envelope', () => {
  const unrelated = crypto.createHash('sha3-256').update(Buffer.from('a multi-party co-sign digest')).digest();
  const env = parasign.buildEnvelope({
    documentHashHex: docHashHex,                 // claims to be over docHashHex...
    signatureB64: signOver(unrelated),           // ...but the signer signed `unrelated`
    signerPubB64: Buffer.from('attacker-pub').toString('base64'),
    signerLabel: 'attacker', ttlDays: 365, ctLogIndex: 2, version: '2',
  }, deps);
  const r = parasign.verifyEnvelope({ envelope: env }, deps);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => /signer signature invalid/.test(e)), JSON.stringify(r.errors));
});

test('a bare-hash signature does NOT verify as a v2 envelope (the closed attack)', () => {
  const env = parasign.buildEnvelope({
    documentHashHex: docHashHex,
    signatureB64: signOver(Buffer.from(docHashHex, 'hex')), // bare-hash sig...
    signerPubB64: Buffer.from('signer-pub').toString('base64'),
    signerLabel: 'downgrade', ttlDays: 365, ctLogIndex: 3, version: '2', // ...labelled v2
  }, deps);
  const r = parasign.verifyEnvelope({ envelope: env }, deps);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => /signer signature invalid/.test(e)), JSON.stringify(r.errors));
});

test('unsupported envelope version is rejected', () => {
  const env = parasign.buildEnvelope({
    documentHashHex: docHashHex, signatureB64: signOver(parasign.singleSignerMessage(docHashHex)),
    signerPubB64: Buffer.from('p').toString('base64'), ttlDays: 365, ctLogIndex: 4, version: '2',
  }, deps);
  const tampered = Object.assign({}, env, { version: '9' });
  const r = parasign.verifyEnvelope({ envelope: tampered }, deps);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => /unsupported envelope version/.test(e)), JSON.stringify(r.errors));
});

test('recipe 5 offline proof verifies the signed visual placement and rejects tampering', () => {
  const publicKey = Buffer.from('generic-signing-key').toString('base64');
  const emailHash = crypto.createHash('sha3-256').update('demo@example.com').digest('hex');
  const appearance = { version: 1, fields: [
    { type: 'seal', page_index: 0, x: .4, y: .7, w: .36, h: .105 },
  ] };
  const envelopeId = 'env_demo_recipe5';
  const message = signMessageBytes(envelopeId, docHashHex, 0, emailHash, 5, publicKey, appearanceHash(appearance));
  const envelope = {
    version: 'parasign-doc-3', recipe_version: 5, algorithm: 'ML-DSA-65',
    document_hash: docHashHex, signer_public_key: publicKey,
    party_email_hash: emailHash, appearance, appearance_hash: appearanceHash(appearance),
    signature: signOver(message), multiparty: { envelope_id: envelopeId, party_index: 0 },
  };
  assert.equal(parasign.verifyEnvelope({ envelope, documentHashHex: docHashHex }, deps).valid, true);
  const tampered = JSON.parse(JSON.stringify(envelope));
  tampered.appearance.fields[0].x = .2;
  const result = parasign.verifyEnvelope({ envelope: tampered, documentHashHex: docHashHex }, deps);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => /appearance_hash mismatch/.test(error)), JSON.stringify(result.errors));
});
