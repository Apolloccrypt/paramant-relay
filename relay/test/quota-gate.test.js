'use strict';
// Quota enforcement tests — proves the Phase 4 gate: NEW active use is declined
// over the monthly cap, dedup'd multi-chunk uploads and Redis outages pass
// (fail-open), and a declined transfer is never counted (no retry-bypass).

const { test } = require('node:test');
const assert = require('assert');
const quota = require('../lib/quota');

// Minimal in-memory Redis stub covering the ops gateTransfer/gateSign use.
function fakeRedis() {
  const store = new Map();
  return {
    isReady: true,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async exists(k) { return store.has(k) ? 1 : 0; },
    async incr(k) { const n = (parseInt(store.get(k) || '0', 10)) + 1; store.set(k, String(n)); return n; },
    async expire() { return 1; },
    async set(k, v, opts) {
      if (opts && opts.NX && store.has(k)) return null;
      store.set(k, v); return 'OK';
    },
    _store: store,
  };
}

test('transfer under cap is allowed and counted', async () => {
  const r = fakeRedis();
  const g = await quota.gateTransfer(r, 'acct1', 'hashA', 10, null);
  assert.strictEqual(g.allowed, true);
  assert.strictEqual(g.counted, true);
});

test('transfer AT cap is declined and NOT counted', async () => {
  const r = fakeRedis();
  r._store.set(quota.transfersKey('acct1'), '10'); // already at community cap
  const g = await quota.gateTransfer(r, 'acct1', 'newHash', 10, null);
  assert.strictEqual(g.allowed, false);
  assert.strictEqual(g.over_limit, true);
  // count unchanged
  assert.strictEqual(await r.get(quota.transfersKey('acct1')), '10');
});

test('declined transfer cannot be bypassed by retrying the same chunk', async () => {
  const r = fakeRedis();
  r._store.set(quota.transfersKey('acct1'), '10');
  const g1 = await quota.gateTransfer(r, 'acct1', 'chunkX', 10, null);
  const g2 = await quota.gateTransfer(r, 'acct1', 'chunkX', 10, null);
  assert.strictEqual(g1.allowed, false);
  assert.strictEqual(g2.allowed, false, 'retry of a declined chunk stays declined');
  // seen key was never claimed on decline
  assert.strictEqual(await r.exists(quota.seenKey('acct1', 'chunkX')), 0);
});

test('continuing a multi-chunk (dedup) upload is allowed even at cap', async () => {
  const r = fakeRedis();
  // simulate the file already counted this month: seen key set, count at cap
  r._store.set(quota.seenKey('acct1', 'fileHash'), '1');
  r._store.set(quota.transfersKey('acct1'), '10');
  const g = await quota.gateTransfer(r, 'acct1', 'fileHash', 10, null);
  assert.strictEqual(g.allowed, true);
  assert.strictEqual(g.deduped, true);
});

test('unlimited plan (Infinity) always allowed, still counted', async () => {
  const r = fakeRedis();
  r._store.set(quota.transfersKey('ent'), '99999');
  const g = await quota.gateTransfer(r, 'ent', 'h', Infinity, null);
  assert.strictEqual(g.allowed, true);
});

test('Redis not ready => fail open (allowed)', async () => {
  const g = await quota.gateTransfer({ isReady: false }, 'acct1', 'h', 10, null);
  assert.strictEqual(g.allowed, true);
});

test('sign under cap allowed; at cap declined and not counted', async () => {
  const r = fakeRedis();
  const ok = await quota.gateSign(r, 'acct1', 2, null);
  assert.strictEqual(ok.allowed, true);
  r._store.set(quota.signsKey('acct1'), '2');
  const no = await quota.gateSign(r, 'acct1', 2, null);
  assert.strictEqual(no.allowed, false);
  assert.strictEqual(await r.get(quota.signsKey('acct1')), '2');
});
