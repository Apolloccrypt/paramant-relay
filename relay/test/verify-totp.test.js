'use strict';
// TOTP-verify coverage for the relay auth path (RFC 6238). Exercises the REAL
// extracted core in ../lib/totp (which relay.js now delegates to), not a copy.
// Replaces the former test/test-verify-totp.js, which (a) never ran in CI because
// its name missed the test/*.test.js glob and (b) required a live Redis. This
// version runs under `node --test` with a builtin-only in-memory replay stub, so
// it gates in the no-deps relay-unit-tests job.
//
// Dual-verify: the relay now accepts a code that matches under SHA-256 OR SHA-1
// (the RFC 6238 default), so Google/Microsoft Authenticator and iCloud Keychain
// work. verifyTotpGeneric reports WHICH algorithm matched so the call sites can
// flag SHA-1 use. These tests pin that behaviour with the real lib.
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

test('valid SHA-256 code is accepted and reports algorithm sha256 (dual-verify default)', async () => {
  const secret = freshSecret();
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const r = await totp.verifyTotpGeneric(code, secret, { replayKey: 't1' }, fakeReplayStore());
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.algorithm, 'sha256', 'a SHA-256 code reports algorithm sha256');
});

test('valid SHA-1 code is accepted by default and reports algorithm sha1', async () => {
  // The load-bearing proof of the dual-verify fix: with the DEFAULT opts (no
  // algorithm pinned — exactly how the relay call sites now invoke it) a SHA-1
  // code from Google/Microsoft Authenticator is accepted, and the match is
  // reported as 'sha1' so the call site can log it and the UI can nudge.
  const secret = freshSecret();
  const code = totp.totpCode(secret, slotNow(), 'sha1');
  const r = await totp.verifyTotpGeneric(code, secret, { replayKey: 't2' }, fakeReplayStore());
  assert.strictEqual(r.valid, true, 'a SHA-1 code is now valid under dual-verify');
  assert.strictEqual(r.algorithm, 'sha1', 'the SHA-1 match is reported as algorithm sha1');
});

test('valid SHA-1 code is accepted when algorithm is pinned to sha1', async () => {
  const secret = freshSecret();
  const code = totp.totpCode(secret, slotNow(), 'sha1');
  const r = await totp.verifyTotpGeneric(code, secret, { algorithm: 'sha1', replayKey: 't2b' }, fakeReplayStore());
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.algorithm, 'sha1');
});

test('wrong code is rejected', async () => {
  const secret = freshSecret();
  const r = await totp.verifyTotpGeneric('000000', secret, { replayKey: 't3' }, fakeReplayStore());
  assert.strictEqual(r.valid, false);
});

test('random wrong 6-digit codes are rejected', async () => {
  const secret = freshSecret();
  for (let i = 0; i < 20; i++) {
    // Pick a 6-digit string that is not the current SHA-256 or SHA-1 code.
    const cur256 = totp.totpCode(secret, slotNow(), 'sha256');
    const cur1 = totp.totpCode(secret, slotNow(), 'sha1');
    let bad;
    do { bad = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); } while (bad === cur256 || bad === cur1);
    const r = await totp.verifyTotpGeneric(bad, secret, { replayKey: `t3r${i}` }, fakeReplayStore());
    assert.strictEqual(r.valid, false, `random code ${bad} must be rejected`);
  }
});

test('replay of a still-in-window SHA-256 code is rejected (per-slot NX)', async () => {
  const secret = freshSecret();
  const store = fakeReplayStore();
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const first = await totp.verifyTotpGeneric(code, secret, { replayKey: 't4' }, store);
  const second = await totp.verifyTotpGeneric(code, secret, { replayKey: 't4' }, store);
  assert.strictEqual(first.valid, true, 'first use passes');
  assert.strictEqual(second.valid, false, 'immediate reuse is refused');
});

test('replay of an accepted SHA-1 code is rejected too', async () => {
  const secret = freshSecret();
  const store = fakeReplayStore();
  const code = totp.totpCode(secret, slotNow(), 'sha1');
  const first = await totp.verifyTotpGeneric(code, secret, { replayKey: 't4s1' }, store);
  const second = await totp.verifyTotpGeneric(code, secret, { replayKey: 't4s1' }, store);
  assert.strictEqual(first.valid, true, 'first SHA-1 use passes');
  assert.strictEqual(first.algorithm, 'sha1');
  assert.strictEqual(second.valid, false, 'replayed SHA-1 code is refused on the matched slot');
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

test('non-6-digit codes are rejected before any slot scan', async () => {
  const secret = freshSecret();
  // A correct 6-digit code padded/altered to a different length must not match.
  const good = totp.totpCode(secret, slotNow(), 'sha256');
  const tooShort = good.slice(0, 5);
  const tooLong = good + '0';
  const rs = await totp.verifyTotpGeneric(tooShort, secret, { replayKey: 't6a' }, fakeReplayStore());
  const rl = await totp.verifyTotpGeneric(tooLong, secret, { replayKey: 't6b' }, fakeReplayStore());
  assert.strictEqual(rs.valid, false, '5-digit input rejected');
  assert.strictEqual(rl.valid, false, '7-digit input rejected');
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

test('dual-verify accepts a SHA-1 code (former algorithm-mismatch rejection, now flipped)', async () => {
  // This was 'algorithm mismatch rejects an otherwise-correct code' and asserted
  // that a SHA-1 code was refused. Dual-verify reverses that: with the default
  // opts the SHA-1 code is now VALID and is reported as algorithm 'sha1'.
  const secret = freshSecret();
  const sha1Code = totp.totpCode(secret, slotNow(), 'sha1');
  const r = await totp.verifyTotpGeneric(sha1Code, secret, { replayKey: 't8' }, fakeReplayStore());
  assert.strictEqual(r.valid, true, 'SHA-1 code is accepted under dual-verify');
  assert.strictEqual(r.algorithm, 'sha1', 'and the match is attributed to sha1');
});

test('match-only mode (no store) verifies without touching a replay store', async () => {
  const secret = freshSecret();
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const r = await totp.verifyTotpGeneric(code, secret, { replayKey: 't9' }, null);
  assert.strictEqual(r.valid, true, 'no store => match-only, still valid');
  assert.strictEqual(r.algorithm, 'sha256');
});

test('a store error fails OPEN so a Redis blip never locks out first use', async () => {
  const secret = freshSecret();
  const throwingStore = { async set() { throw new Error('redis down'); } };
  const code = totp.totpCode(secret, slotNow(), 'sha256');
  const r = await totp.verifyTotpGeneric(code, secret, { replayKey: 't10' }, throwingStore);
  assert.strictEqual(r.valid, true, 'store error => .catch(=>OK) => valid');
});

test('matchTotpSlot returns the exact matched counter slot and algorithm', () => {
  const secret = freshSecret();
  const c = slotNow();
  const m256 = totp.matchTotpSlot(totp.totpCode(secret, c, 'sha256'), secret, {});
  assert.strictEqual(m256.slot, c, 'SHA-256 code maps to the current slot');
  assert.strictEqual(m256.algorithm, 'sha256');
  const m1 = totp.matchTotpSlot(totp.totpCode(secret, c, 'sha1'), secret, {});
  assert.strictEqual(m1.slot, c, 'SHA-1 code maps to the current slot');
  assert.strictEqual(m1.algorithm, 'sha1');
  assert.strictEqual(totp.matchTotpSlot('000000', secret, {}), null);
});
