'use strict';
// Unit tests for maskApiKey — the helper that keeps GET /v2/admin/keys from
// returning full pgp_ secrets in its bulk list (blast-radius hygiene). Pure:
// imports the helper only, never starts the relay server.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { maskApiKey } = require('../lib/keys-table');

const FULL = 'pgp_' + 'a'.repeat(60) + 'beef'; // 4 + 64 = 68 chars

test('masks a full pgp_ key to prefix + … + last4', () => {
  const m = maskApiKey(FULL);
  assert.equal(m, 'pgp_aaaa…beef');
});

test('mask never contains the full secret', () => {
  const m = maskApiKey(FULL);
  assert.ok(!m.includes(FULL));
  assert.ok(m.length < FULL.length);
});

test('mask reveals at most 8-char prefix + 4-char suffix', () => {
  const m = maskApiKey(FULL);
  // The visible characters must be a strict subset: 8 from the front, 4 from
  // the back. An attacker who sees the mask learns <= 12 of the 64 hex chars.
  assert.ok(FULL.startsWith(m.slice(0, 8)));
  assert.ok(FULL.endsWith(m.slice(-4)));
});

test('two distinct keys with shared prefix stay distinguishable by suffix', () => {
  const a = 'pgp_' + '0'.repeat(60) + 'aaaa';
  const b = 'pgp_' + '0'.repeat(60) + 'bbbb';
  assert.notEqual(maskApiKey(a), maskApiKey(b));
});

test('short / non-key strings pass through unchanged', () => {
  assert.equal(maskApiKey('short'), 'short');
  assert.equal(maskApiKey('pgp_12345678'), 'pgp_12345678'); // exactly 12, not masked
});

test('null / undefined / empty are safe', () => {
  assert.equal(maskApiKey(null), '');
  assert.equal(maskApiKey(undefined), '');
  assert.equal(maskApiKey(''), '');
});
