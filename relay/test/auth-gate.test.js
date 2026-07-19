'use strict';
// Auth-gate coverage: the constant-time compare, the X-Internal-Auth gate that
// fronts every /v2/user/* session endpoint, and the PSS session-expiry predicate.
// Exercises the REAL decisions in ../lib/auth-gate that relay.js now delegates to.
const { test } = require('node:test');
const assert = require('assert');
const { safeEqual, internalAuthOk, sessionValid } = require('../lib/auth-gate');

test('safeEqual: equal strings match, unequal do not', () => {
  assert.strictEqual(safeEqual('correct-token', 'correct-token'), true);
  assert.strictEqual(safeEqual('correct-token', 'wrong-token'), false);
});

test('safeEqual: length mismatch is false without throwing (no length oracle path)', () => {
  assert.strictEqual(safeEqual('short', 'a-much-longer-value'), false);
  assert.strictEqual(safeEqual('', ''), true, 'empty vs empty is a real equal compare');
});

test('safeEqual: non-string / nullish inputs are coerced, never throw', () => {
  assert.strictEqual(safeEqual(null, null), true, 'both coerce to ""');
  assert.strictEqual(safeEqual(undefined, 'x'), false);
  assert.strictEqual(safeEqual(12345, '12345'), true, 'numbers coerce via String()');
});

test('internalAuthOk: closed when no token is configured', () => {
  assert.strictEqual(internalAuthOk('', 'anything'), false);
  assert.strictEqual(internalAuthOk(undefined, 'anything'), false);
});

test('internalAuthOk: closed when the header is missing or not a string', () => {
  assert.strictEqual(internalAuthOk('secret', undefined), false);
  assert.strictEqual(internalAuthOk('secret', ['secret']), false, 'array header (duplicate) is not a string => closed');
  assert.strictEqual(internalAuthOk('secret', 123), false);
});

test('internalAuthOk: open only on an exact string match', () => {
  assert.strictEqual(internalAuthOk('secret', 'secret'), true);
  assert.strictEqual(internalAuthOk('secret', 'Secret'), false);
  assert.strictEqual(internalAuthOk('secret', 'secret '), false);
});

test('sessionValid: a live session in the future is valid', () => {
  const now = 1_000_000;
  assert.strictEqual(sessionValid({ expires_ms: now + 1 }, now), true);
});

test('sessionValid: an expired session is invalid; the exact expiry ms is still live', () => {
  const now = 1_000_000;
  assert.strictEqual(sessionValid({ expires_ms: now - 1 }, now), false, 'past expiry => invalid');
  assert.strictEqual(sessionValid({ expires_ms: now }, now), true, 'now === expires_ms is the complement of relay cleanup (now > expires)');
});

test('sessionValid: a missing session is invalid', () => {
  assert.strictEqual(sessionValid(undefined, 1_000_000), false);
  assert.strictEqual(sessionValid(null, 1_000_000), false);
});
