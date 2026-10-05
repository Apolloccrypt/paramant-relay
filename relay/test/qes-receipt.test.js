'use strict';
// The .psign receipt gains exactly one field and loses nothing.
//
// The trap this guards against: the relay counter-signs the canonical JSON of
// the whole receipt minus notary_signature. A field added anywhere after that
// signature, in a route or a proxy or a client, silently invalidates every
// receipt. So the marker has to go in before the signature, and this test is
// what says it did.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const openApi = require('../lib/parasign-open-api');

// Byte-identical to relay/parasign.js canonicalJSON: sorted keys, all the way down.
function canonicalJSON(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
  }
  return JSON.stringify(value === undefined ? null : value);
}

// A stand-in notary: an HMAC over the same canonical bytes the real ML-DSA-65
// signer covers. What matters here is which bytes get signed, not the algorithm.
const notaryKey = crypto.randomBytes(32);
const sigEngine = {
  sign: (message) => crypto.createHmac('sha256', notaryKey).update(message).digest(),
};
const relayIdentity = { pk_hash: 'relay-pk-hash', pk: Buffer.from('relay-public-key'), sk: Buffer.alloc(32) };

function envelope(extra = {}) {
  return {
    id: 'envCompleted0000000001',
    doc_hash: 'a'.repeat(64),
    binding_mode: 'open',
    recipe_version: 4,
    effective_recipe: 4,
    created_at: '2026-09-03T10:00:00Z',
    completed_at: '2026-09-03T10:05:00Z',
    expires_at: '2026-10-03T10:00:00Z',
    parties: [{
      index: 0, label: 'Signer', email_hash: 'b'.repeat(64), status: 'signed',
      signed_at: '2026-09-03T10:05:00Z', pk_b64: 'UEs=', sig_b64: 'U0lH', signer_pk_hash: 'c'.repeat(64),
    }],
    ...extra,
  };
}

function build(env) {
  return openApi.buildEnvelopePsign({
    env, meta: null, canonicalJSON, sigEngine, relayIdentity, publicOrigin: 'https://example.com',
  });
}

function notaryVerifies(psign) {
  const unsigned = { ...psign };
  delete unsigned.notary_signature;
  const expected = crypto.createHmac('sha256', notaryKey).update(Buffer.from(canonicalJSON(unsigned), 'utf8')).digest();
  return expected.toString('base64') === psign.notary_signature;
}

test('without a qualified signature the receipt has no qes field at all', () => {
  const psign = build(envelope());
  assert.strictEqual('qes' in psign, false, 'the default receipt must be unchanged');
  assert.ok(notaryVerifies(psign));
});

test('with one, the receipt carries a three-key pointer and still counter-verifies', () => {
  const qes = {
    provider: 'cleverbase-sandbox',
    certificate_fingerprint: 'd'.repeat(64),
    signed_at: '2026-09-03T10:05:30Z',
  };
  const psign = build(envelope({ qes }));
  assert.deepStrictEqual(psign.qes, qes);
  assert.deepStrictEqual(Object.keys(psign.qes).sort(), ['certificate_fingerprint', 'provider', 'signed_at']);
  assert.ok(notaryVerifies(psign), 'the marker must be inside the notary signature, not bolted on after it');
  // Nothing else moved.
  assert.strictEqual(psign.type, 'parasign-envelope-receipt');
  assert.strictEqual(psign.version, '2');
  assert.strictEqual(psign.algorithm, 'ML-DSA-65');
  assert.strictEqual(psign.parties[0].signature, 'U0lH');
});

test('adding the marker after signing breaks the counter-signature, which is the point', () => {
  const psign = build(envelope());
  psign.qes = { provider: 'cleverbase-sandbox', certificate_fingerprint: 'e'.repeat(64), signed_at: null };
  assert.strictEqual(notaryVerifies(psign), false);
});

test('a half-filled marker is ignored rather than written half-true', () => {
  assert.strictEqual('qes' in build(envelope({ qes: { provider: 'cleverbase-sandbox' } })), false);
  assert.strictEqual('qes' in build(envelope({ qes: { certificate_fingerprint: 'f'.repeat(64) } })), false);
  assert.strictEqual('qes' in build(envelope({ qes: 'yes' })), false);
});
