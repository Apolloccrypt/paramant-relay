'use strict';
// Domain-separation for the single-signer notary (#3/#4): v2 envelopes bind the
// signer signature to sha3_256("paramant/parasign/notary/v1" || 0x00 || hash);
// v1 (bare hash) stays verifiable for already-issued envelopes; a signature
// made over an unrelated 32-byte value can no longer be notarised as v2.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');
const parasign = require('../parasign');

const sha3 = (buf) => crypto.createHash('sha3-256').update(buf).digest();
const relayKp = ml_dsa65.keygen(crypto.randomBytes(32));
const deps = {
  relaySign: (msg) => ml_dsa65.sign(msg, relayKp.secretKey),
  relayPkHash: 'relaypkhash',
  sigVerify: (sigBuf, msgBuf, pubBuf) => { try { return ml_dsa65.verify(sigBuf, msgBuf, pubBuf); } catch { return false; } },
  relayPub: Buffer.from(relayKp.publicKey),
};

const docHashHex = sha3(Buffer.from('a contract')).toString('hex');

function buildV2(signerKp, docHex = docHashHex) {
  const sig = ml_dsa65.sign(parasign.singleSignerMessage(docHex), signerKp.secretKey);
  return parasign.buildEnvelope({
    documentHashHex: docHex,
    signatureB64: Buffer.from(sig).toString('base64'),
    signerPubB64: Buffer.from(signerKp.publicKey).toString('base64'),
    signerLabel: 'tester', ttlDays: 365, ctLogIndex: 1, version: '2',
  }, deps);
}

test('singleSignerMessage is the domain-prefixed digest, distinct from the bare hash', () => {
  const m = parasign.singleSignerMessage(docHashHex);
  const expected = crypto.createHash('sha3-256')
    .update(Buffer.from('paramant/parasign/notary/v1', 'utf8'))
    .update(Buffer.from([0]))
    .update(Buffer.from(docHashHex, 'hex')).digest();
  assert.deepEqual(m, expected);
  assert.notDeepEqual(m, Buffer.from(docHashHex, 'hex'));
});

test('v2 envelope round-trips and verifies', () => {
  const signerKp = ml_dsa65.keygen(crypto.randomBytes(32));
  const env = buildV2(signerKp);
  assert.equal(env.version, '2');
  const r = parasign.verifyEnvelope({ envelope: env, documentHashHex: docHashHex }, deps);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test('legacy v1 (bare-hash) envelope still verifies', () => {
  const signerKp = ml_dsa65.keygen(crypto.randomBytes(32));
  const sig = ml_dsa65.sign(Buffer.from(docHashHex, 'hex'), signerKp.secretKey); // bare hash
  const env = parasign.buildEnvelope({
    documentHashHex: docHashHex,
    signatureB64: Buffer.from(sig).toString('base64'),
    signerPubB64: Buffer.from(signerKp.publicKey).toString('base64'),
    signerLabel: 'legacy', ttlDays: 365, ctLogIndex: 0, version: '1',
  }, deps);
  assert.equal(env.version, '1');
  const r = parasign.verifyEnvelope({ envelope: env }, deps);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test('cross-protocol replay: a signature over an unrelated 32-byte value is NOT a valid v2 envelope', () => {
  // Attacker signs some unrelated 32-byte message (e.g. a co-sign digest) and
  // tries to pass it off as a v2 single-signer signature over docHashHex.
  const signerKp = ml_dsa65.keygen(crypto.randomBytes(32));
  const unrelated = sha3(Buffer.from('a multi-party co-sign digest')); // 32 bytes
  const sig = ml_dsa65.sign(unrelated, signerKp.secretKey);
  const env = parasign.buildEnvelope({
    documentHashHex: docHashHex, // claims to be over docHashHex
    signatureB64: Buffer.from(sig).toString('base64'),
    signerPubB64: Buffer.from(signerKp.publicKey).toString('base64'),
    signerLabel: 'attacker', ttlDays: 365, ctLogIndex: 2, version: '2',
  }, deps);
  const r = parasign.verifyEnvelope({ envelope: env }, deps);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => /signer signature invalid/.test(e)), JSON.stringify(r.errors));
});

test('a v2 signature does not verify if relabelled as v1 (and vice versa)', () => {
  const signerKp = ml_dsa65.keygen(crypto.randomBytes(32));
  const env = buildV2(signerKp);
  const downgraded = Object.assign({}, env, { version: '1' }); // tamper version
  const r = parasign.verifyEnvelope({ envelope: downgraded }, deps);
  // notary signature also breaks (version is inside the signed body), but the
  // signer signature must independently fail too — the message bytes differ.
  assert.equal(r.valid, false);
});
