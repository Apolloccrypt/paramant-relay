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
