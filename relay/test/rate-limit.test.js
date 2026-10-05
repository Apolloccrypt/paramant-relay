'use strict';
// Fixed-window rate-limit coverage. Exercises the REAL decision in ../lib/rate-limit
// that relay.js's per-IP / per-key limiters now delegate to (mfa-verify, claim,
// check-key, lookup-signer, status, envelope view/sign/create). Deterministic:
// the injected `now` removes wall-clock flake.
const { test } = require('node:test');
const assert = require('assert');
const { fixedWindowAllow } = require('../lib/rate-limit');

test('allows exactly `limit` requests inside one window, then refuses', () => {
  const map = new Map();
  const t0 = 1_000_000;
  for (let i = 0; i < 5; i++) {
    assert.strictEqual(fixedWindowAllow(map, 'ip', 5, 60_000, t0 + i), true, `hit ${i + 1} allowed`);
  }
  assert.strictEqual(fixedWindowAllow(map, 'ip', 5, 60_000, t0 + 5), false, '6th hit refused');
});

test('refusal does not advance the counter (no lockout inflation)', () => {
  const map = new Map();
  const t0 = 1_000_000;
  for (let i = 0; i < 5; i++) fixedWindowAllow(map, 'ip', 5, 60_000, t0);
  fixedWindowAllow(map, 'ip', 5, 60_000, t0); // refused
  fixedWindowAllow(map, 'ip', 5, 60_000, t0); // refused
  assert.strictEqual(map.get('ip').count, 5, 'count stays pinned at the limit while refusing');
});

test('window resets lazily on the first request after resetAt', () => {
  const map = new Map();
  const t0 = 1_000_000;
  for (let i = 0; i < 5; i++) fixedWindowAllow(map, 'ip', 5, 60_000, t0);
  assert.strictEqual(fixedWindowAllow(map, 'ip', 5, 60_000, t0 + 60_000), false, 'at resetAt (now === resetAt) still refused');
  assert.strictEqual(fixedWindowAllow(map, 'ip', 5, 60_000, t0 + 60_001), true, 'just past resetAt: window rolls, allowed again');
});

test('distinct keys have independent budgets', () => {
  const map = new Map();
  const t0 = 1_000_000;
  for (let i = 0; i < 5; i++) fixedWindowAllow(map, 'a', 5, 60_000, t0);
  assert.strictEqual(fixedWindowAllow(map, 'a', 5, 60_000, t0), false, 'key a exhausted');
  assert.strictEqual(fixedWindowAllow(map, 'b', 5, 60_000, t0), true, 'key b unaffected');
});

test('matches the real relay limiter budgets (table of live caps)', () => {
  // limit, windowMs pairs lifted from relay.js so a future edit that changes a
  // cap without updating intent is caught here.
  const cases = [
    ['mfa-verify', 5, 60_000],
    ['claim-reveal', 20, 60_000],
    ['check-key', 30, 60_000],
    ['lookup-signer', 30, 60_000],
    ['status-hash', 60, 60_000],
    ['env-view', 30, 60_000],
    ['env-sign', 10, 60_000],
    ['env-create', 50, 3_600_000],
  ];
  for (const [name, limit, windowMs] of cases) {
    const map = new Map();
    const t0 = 5_000_000;
    for (let i = 0; i < limit; i++) {
      assert.strictEqual(fixedWindowAllow(map, 'k', limit, windowMs, t0), true, `${name}: hit ${i + 1} allowed`);
    }
    assert.strictEqual(fixedWindowAllow(map, 'k', limit, windowMs, t0), false, `${name}: hit ${limit + 1} refused`);
    // still refused just before the window rolls, allowed just after
    assert.strictEqual(fixedWindowAllow(map, 'k', limit, windowMs, t0 + windowMs), false, `${name}: at resetAt refused`);
    assert.strictEqual(fixedWindowAllow(map, 'k', limit, windowMs, t0 + windowMs + 1), true, `${name}: after window allowed`);
  }
});
