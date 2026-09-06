'use strict';
// The gate on the `<session>_ready` slot, which is the technical measure behind
// one line of an article 28 agreement customers sign:
//
//   /dpa:280  "Data minimisation | Filenames not stored in plaintext
//              (enc_meta ciphertext only)"
//
// Until 5 September 2026 that line was false on the live hand-over path. The
// sender put the file name in `kyber_pub` and, for a multi-file send, every
// name and size in `ecdh_pub`; relay.js stored both verbatim for an hour and
// GET /v2/pubkey/:device handed them back without an API key.
//
// The client was fixed too (frontend/js/handshake-meta.js has no parameter that
// could carry a name), but a client-side convention is not a measure. These are
// the cases the relay must refuse whoever is talking to it.
//
// Run: node --test relay/test/handshake-record.test.js

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isReadyMeta, isReadyLocation, isCleanReadyRecord } = require('../lib/handshake-record');

const TOK = (c) => String(c).repeat(48);
const A = TOK('a');
const B = TOK('b');

test('the record our own client sends is accepted', () => {
  assert.ok(isCleanReadyRecord('file|1|86400000', A));
  assert.ok(isCleanReadyRecord('file|3|3600000', [A, B].join(',')));
  assert.ok(isCleanReadyRecord('vault|2|604800000',
    JSON.stringify([{ tokens: [A] }, { tokens: [A, B] }])));
});

test('a file name in the meta field is refused', () => {
  // Exactly what the sender used to write.
  assert.equal(isReadyMeta('opzegging-huurcontract.pdf|1|86400000'), false);
  assert.equal(isReadyMeta('IMG_4276.jpeg|1|86400000'), false);
  // And the near-misses: a name that looks like a kind, a fourth field.
  assert.equal(isReadyMeta('file.pdf|1|3600000'), false);
  assert.equal(isReadyMeta('file|1|3600000|opzegging.pdf'), false);
  assert.equal(isReadyMeta('vaults|1|3600000'), false);
  assert.equal(isReadyMeta(''), false);
  assert.equal(isReadyMeta(null), false);
  assert.equal(isCleanReadyRecord('opzegging-huurcontract.pdf|1|86400000', A), false,
    'and the whole record goes down with it');
});

test('a vault manifest that names its files is refused', () => {
  // Exactly what a multi-file send used to write.
  const leaky = JSON.stringify([
    { name: 'loonstrook-2026-09.pdf', size: 51200, tokens: [A] },
    { name: 'opzegging-huurcontract.pdf', size: 8192, tokens: [B] },
  ]);
  assert.equal(isReadyLocation(leaky), false);
  // One extra key is one too many, whatever it is called. A whitelist would
  // quietly admit whichever field somebody adds next.
  assert.equal(isReadyLocation(JSON.stringify([{ tokens: [A], size: 1 }])), false);
  assert.equal(isReadyLocation(JSON.stringify([{ tokens: [A], label: 'x' }])), false);
  assert.equal(isReadyLocation(JSON.stringify([{ tokens: [A] }, { name: 'x', tokens: [B] }])), false,
    'one bad entry spoils the manifest');
});

test('nothing that is not a download token gets into the location field', () => {
  assert.equal(isReadyLocation(''), false);
  assert.equal(isReadyLocation('opzegging-huurcontract.pdf'), false);
  assert.equal(isReadyLocation(A + ',not-a-token'), false);
  assert.equal(isReadyLocation(A.toUpperCase()), false, 'hex is lowercase, as randomBytes writes it');
  assert.equal(isReadyLocation(A.slice(0, 47)), false, 'a short token is not a token');
  assert.equal(isReadyLocation(JSON.stringify([])), false, 'an empty vault says nothing and is not a vault');
  assert.equal(isReadyLocation(JSON.stringify([{ tokens: [] }])), false);
  assert.equal(isReadyLocation(JSON.stringify({ tokens: [A] })), false, 'a manifest is a list');
  assert.equal(isReadyLocation(JSON.stringify(Array.from({ length: 1001 }, () => ({ tokens: [A] })))), false);
  assert.equal(isReadyLocation(null), false);
});

test('the counts are counts and cannot be smuggled through', () => {
  assert.equal(isReadyMeta('file|1|'), false);
  assert.equal(isReadyMeta('file||3600000'), false);
  assert.equal(isReadyMeta('file|1|3600000 '), false, 'no trailing room to hide in');
  assert.equal(isReadyMeta('file|12345678901|3600000'), false, 'a count has a ceiling');
  assert.ok(isReadyMeta('file|1234567890|999999999999999'));
});

test('and the route actually asks, on the slot that needs it', () => {
  // A grammar nobody calls is a comment. This pins the wiring: the `_ready`
  // branch of POST /v2/pubkey refuses before it stores, and the branch that
  // registers a receiver's real ML-KEM key is left alone, because that one
  // legitimately holds 2368 hex characters of public key.
  const fs = require('node:fs');
  const path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
  const invite = src.match(/if \(INVITE_RE\.test\(d\.device_id\)\) \{[\s\S]*?pubkeys\.set\(/);
  assert.ok(invite, 'the invite branch of POST /v2/pubkey exists');
  assert.match(invite[0], /d\.device_id\.endsWith\('_ready'\) && !isCleanReadyRecord\(/,
    'the refusal runs on the _ready slot, before the store');
  assert.match(invite[0], /res\.writeHead\(400\)/, 'and it is a refusal, not a repair');
  assert.match(src, /require\('\.\/lib\/handshake-record'\)/);
});
