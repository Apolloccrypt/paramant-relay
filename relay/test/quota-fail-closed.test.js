'use strict';
// Signatures are counted or refused, never waved through, and a retry is not
// charged twice.
//   * quota.gateSign answered allowed:true when redis was not ready or the
//     script threw: signatures went through uncounted (fase 1, item 5).
//   * sweep-chaos finding 2: redis cut right after the count, the store write
//     failed, the 503 released nothing, the retry counted again. One signature,
//     two units; a free sender's month gone after one signature.
// Run: REDIS_URL=redis://127.0.0.1:6398 node --test test/quota-fail-closed.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const quota = require('../lib/quota');
const { requireRedis, summary } = require('./_requires');

let checks = 0; let rc = null;
after(async () => { if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } summary('quota-fail-closed', checks); });

test('capped plan + redis not ready -> refused as unavailable, not allowed', async () => {
  const r = await quota.gateSign({ isReady: false }, 'acct_x', 2, () => {});
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.unavailable, true);
  const thrown = await quota.gateSign({ isReady: true, eval: async () => { throw new Error('boom'); } }, 'acct_x', 2, () => {});
  assert.strictEqual(thrown.allowed, false);
  assert.strictEqual(thrown.unavailable, true);
  const unlimited = await quota.gateSign({ isReady: false }, 'acct_x', Infinity, () => {});
  assert.strictEqual(unlimited.allowed, true, 'an unlimited plan has nothing to enforce');
  checks++;
});

test('a retry for the same party slot is not counted twice; a release hands the slot back', async () => {
  rc = await requireRedis('redis://127.0.0.1:6398');
  if (!rc) return;
  const acct = 'acct_hold_' + crypto.randomBytes(4).toString('hex');
  const hold = `paramant:quota:signhold:env_${acct}:0`;
  const a = await quota.gateSign(rc, acct, 2, () => {}, { holdKey: hold });
  assert.strictEqual(a.counted, true);
  const b = await quota.gateSign(rc, acct, 2, () => {}, { holdKey: hold });
  assert.strictEqual(b.allowed, true);
  assert.strictEqual(b.counted, false, 'the retry finds the hold');
  assert.strictEqual((await quota.readUsage(rc, acct)).signs_this_month, 1);
  // Both requests hold a reference on the one unit (review #555, H4): the
  // first release gives nothing back, the last one does.
  const first = await quota.releaseSign(rc, acct, () => {}, { holdKey: hold });
  assert.strictEqual(first.released, false);
  assert.strictEqual((await quota.readUsage(rc, acct)).signs_this_month, 1);
  await quota.releaseSign(rc, acct, () => {}, { holdKey: hold });
  assert.strictEqual(await rc.exists(hold), 0);
  assert.strictEqual((await quota.readUsage(rc, acct)).signs_this_month, 0);
  checks++;
});
