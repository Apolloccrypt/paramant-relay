'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const relaySource = fs.readFileSync(path.join(__dirname, '..', '..', 'relay', 'relay.js'), 'utf8');

test('new authenticated envelopes request recipe 5', () => {
  const route = source.match(/api\.post\("\/user\/envelopes"[\s\S]*?\n\}\);/);
  assert.ok(route, 'envelope route exists');
  assert.match(route[0], /recipe_version: 5/);
});

test('recipient proof download requires session, invite and verified email', () => {
  const route = source.match(/api\.get\("\/user\/envelopes\/:id\/receipt"[\s\S]*?\n\}\);/);
  assert.ok(route, 'recipient receipt proxy exists');
  assert.match(route[0], /authUser/);
  assert.match(route[0], /X-Internal-Auth/);
  assert.match(route[0], /X-Verified-Email-Hash/);
  assert.match(relaySource, /envParticipantReceiptMatch[\s\S]*?getForParty/);
  assert.match(relaySource, /envParticipantReceiptMatch[\s\S]*?safeHexEqual/);
  assert.match(relaySource, /envParticipantReceiptMatch[\s\S]*?env\.status !== 'complete'/);
});

test('appearance is bounded before the one-shot activation is consumed', () => {
  const route = source.match(/api\.post\("\/user\/sign\/submit"[\s\S]*?\n\}\);/);
  assert.ok(route, 'submit route exists');
  const sizeGate = route[0].indexOf('appearanceSize > 4096');
  const consume = route[0].indexOf('getDel(`paramant:sign:activation:');
  assert.ok(sizeGate >= 0 && consume > sizeGate, 'appearance gate precedes GETDEL');
  assert.match(route[0], /appearance,/);
  assert.match(route[0], /appearance_hash: body\.appearance_hash/);
});

// The requester's ONE requested signing position, added for the invite flow on
// /sign. It travels on envelope CREATION, not on a signature, so it needs its
// own bound on the way in and it must never be mistaken for signed data.
test('the requested signing position is bounded before the relay is called', () => {
  const route = source.match(/api\.post\("\/user\/envelopes"[\s\S]*?\n\}\);/);
  assert.ok(route, 'envelope route exists');
  const gate = route[0].indexOf('requestedSize > 4096');
  const call = route[0].indexOf('await fetch(');
  assert.ok(gate >= 0, 'the requested position has a size ceiling');
  assert.ok(call > gate, 'the ceiling is checked before the relay call');
  // The SAME ceiling as POST /user/sign/submit, so one number governs both
  // appearance manifests and neither route can drift on its own.
  const submit = source.match(/api\.post\("\/user\/sign\/submit"[\s\S]*?\n\}\);/);
  assert.match(submit[0], /appearanceSize > 4096/);
  assert.match(route[0], /error: "invalid_requested_appearance"/);
  assert.match(route[0], /requested_appearance: requestedAppearance/);
});

test('a non-object requested position is refused, whatever its size', () => {
  const route = source.match(/api\.post\("\/user\/envelopes"[\s\S]*?\n\}\);/);
  // An array and a bare scalar both stringify small, so the size gate alone
  // would wave them through into the relay's normaliser.
  assert.match(route[0], /Array\.isArray\(requestedAppearance\)/);
  assert.match(route[0], /typeof requestedAppearance !== "object"/);
  // undefined stays legal: an invite may ask for no position at all.
  assert.match(route[0], /requestedAppearance !== undefined/);
});

// The ceiling is a bound on junk, not on legitimate input: prove it can never
// reject a manifest the relay itself would accept. Behaviour, not source text.
test('4096 bytes is above anything the relay normaliser can produce', () => {
  const { normaliseAppearance } = require('../../relay/envelope.js');
  const fields = [];
  for (let i = 0; i < 8; i++) {
    fields.push({ type: i % 2 ? 'date' : 'seal', page_index: 999, x: 0.123456, y: 0.123456, w: 0.123456, h: 0.123456 });
  }
  const biggest = normaliseAppearance({ version: 1, fields });
  assert.strictEqual(biggest.fields.length, 8, 'eight fields is the relay maximum');
  assert.ok(Buffer.byteLength(JSON.stringify(biggest), 'utf8') < 4096,
    'the largest manifest the relay accepts fits inside the admin ceiling');
  assert.throws(() => normaliseAppearance({ version: 1, fields: fields.concat(fields[0]) }),
    /invalid appearance fields/, 'a ninth field is refused by the relay');
});
