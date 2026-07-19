'use strict';
// TOTP-verify coverage for the relay auth path (RFC 6238). Exercises the REAL
// extracted core in ../lib/totp (which relay.js now delegates to), not a copy.
// Replaces the former test/test-verify-totp.js, which (a) never ran in CI because
// its name missed the test/*.test.js glob and (b) required a live Redis. This
// version runs under `node --test` with a builtin-only in-memory replay stub, so
// it gates in the no-deps relay-unit-tests job.
const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const totp = require('../lib/totp');

// In-memory Redis-shaped replay store: supports the single op verifyTotpGeneric
// uses — async set(key,val,{NX,EX}) returning 'OK' or null (NX collision).
function fakeReplayStore() {
  const store = new Map();
  return {
    _store: store,
    async set(k, v, opts) {
      if (opts && opts.NX && store.has(k)) return null;
      store.set(k, v);
      return 'OK';
    },
  };
}

function freshSecret() {
  return totp.base32Encode(crypto.randomBytes(20));
}
function slotNow() {
  return Math.floor(Date.now() / 1000 / 30);
}

test('base32 round-trips and rejects invalid characters', () => {
  const raw = crypto.randomBytes(20);
  const enc = totp.base32Encode(raw);
  assert.ok(/^[A-Z2-7]+$/.test(enc), 'encoding uses the RFC 4648 alphabet');
  assert.ok(totp.base32Decode(enc).equals(raw), 'decode(encode(x)) === x');
  assert.throws(() => totp.base32Decode('ABC!'), /Invalid Base32 character/);
});

test('valid SHA-256 code is accepted (relay default algorithm)', async () => {
  const secret = freshSecret();
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const r = await totp.verifyTotpGeneric(code, secret, { replayKey: 't1' }, fakeReplayStore());
  assert.strictEqual(r.valid, true);
});

test('valid SHA-1 code is accepted when algorithm is set', async () => {
  const secret = freshSecret();
  const code = totp.totpCode(secret, slotNow(), 'sha1');
  const r = await totp.verifyTotpGeneric(code, secret, { algorithm: 'sha1', replayKey: 't2' }, fakeReplayStore());
  assert.strictEqual(r.valid, true);
});

test('wrong code is rejected', async () => {
  const secret = freshSecret();
  const r = await totp.verifyTotpGeneric('000000', secret, { replayKey: 't3' }, fakeReplayStore());
  assert.strictEqual(r.valid, false);
});

test('replay of a still-in-window code is rejected (per-slot NX)', async () => {
  const secret = freshSecret();
  const store = fakeReplayStore();
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const first = await totp.verifyTotpGeneric(code, secret, { replayKey: 't4' }, store);
  const second = await totp.verifyTotpGeneric(code, secret, { replayKey: 't4' }, store);
  assert.strictEqual(first.valid, true, 'first use passes');
  assert.strictEqual(second.valid, false, 'immediate reuse is refused');
});

test('replay keys are namespaced (admin vs per-user do not collide)', async () => {
  const secret = freshSecret();
  const store = fakeReplayStore();
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const admin = await totp.verifyTotpGeneric(code, secret, { replayKey: 'paramant:admin:replay' }, store);
  const user = await totp.verifyTotpGeneric(code, secret, { replayKey: 'paramant:user:replay:42' }, store);
  assert.strictEqual(admin.valid, true);
  assert.strictEqual(user.valid, true, 'same code, different replay namespace, still valid');
});

test('malformed inputs are rejected as invalid (never a match)', async () => {
  const secret = freshSecret();
  for (const bad of ['', '12345', '1234567', 'abcdef', '12 345', null, undefined]) {
    const r = await totp.verifyTotpGeneric(bad, secret, { replayKey: 't6' }, fakeReplayStore());
    assert.strictEqual(r.valid, false, `"${bad}" must be rejected`);
  }
});

test('the +/-1 window is tolerated but +/-2 is not', async () => {
  const secret = freshSecret();
  const c = slotNow();
  const minus1 = await totp.verifyTotpGeneric(totp.totpCode(secret, c - 1, 'sha256'), secret, { window: 1, replayKey: 't7a' }, fakeReplayStore());
  const plus1 = await totp.verifyTotpGeneric(totp.totpCode(secret, c + 1, 'sha256'), secret, { window: 1, replayKey: 't7b' }, fakeReplayStore());
  const plus2 = await totp.verifyTotpGeneric(totp.totpCode(secret, c + 2, 'sha256'), secret, { window: 1, replayKey: 't7c' }, fakeReplayStore());
  assert.strictEqual(minus1.valid, true, '-1 slot accepted');
  assert.strictEqual(plus1.valid, true, '+1 slot accepted');
  assert.strictEqual(plus2.valid, false, '+2 slot outside the window is rejected');
});

test('algorithm mismatch rejects an otherwise-correct code', async () => {
  const secret = freshSecret();
  const sha1Code = totp.totpCode(secret, slotNow(), 'sha1');
  const r = await totp.verifyTotpGeneric(sha1Code, secret, { algorithm: 'sha256', replayKey: 't8' }, fakeReplayStore());
  assert.strictEqual(r.valid, false);
});

test('match-only mode (no store) verifies without touching a replay store', async () => {
  const secret = freshSecret();
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const r = await totp.verifyTotpGeneric(code, secret, { replayKey: 't9' }, null);
  assert.strictEqual(r.valid, true, 'no store => match-only, still valid');
});

test('a store error fails OPEN so a Redis blip never locks out first use', async () => {
  const secret = freshSecret();
  const throwingStore = { async set() { throw new Error('redis down'); } };
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const r = await totp.verifyTotpGeneric(code, secret, { replayKey: 't10' }, throwingStore);
  assert.strictEqual(r.valid, true, 'store error => .catch(=>OK) => valid');
});

test('matchTotpSlot returns the exact matched counter slot', () => {
  const secret = freshSecret();
  const c = slotNow();
  assert.strictEqual(totp.matchTotpSlot(totp.totpCode(secret, c, 'sha256'), secret, {}), c);
  assert.strictEqual(totp.matchTotpSlot('000000', secret, {}), null);
});
