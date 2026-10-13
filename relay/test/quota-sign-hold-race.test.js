'use strict';
// Review #555, H4: the sign hold let a signature land uncounted. Request A
// (a bad signature) counted and set the hold, request B (a good one) saw the
// hold and went through uncounted, A failed and released (deleted the hold,
// gave the unit back), B landed. Repro on cc931c2f: plan limit 2, five
// signatures landed, counter 0. The route's flow is mirrored here exactly
// (gate, store, release / finalize), against a real redis.
// Run: REDIS_URL=redis://127.0.0.1:6398 node --test test/quota-sign-hold-race.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const quota = require('../lib/quota');
const { requireRedis, summary } = require('./_requires');

let checks = 0; let rc = null;
after(async () => { if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } summary('quota-sign-hold-race', checks); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The sign route, step by step (relay.js POST .../sign): gate, store.sign,
// then release on failure, release a NEW unit on idem, finalize on new.
function makeRoute(acct, limit, landed) {
  const gate = (hold) => quota.gateSign(rc, acct, limit, null, { holdKey: hold });
  async function finish(g, hold, good) {
    const reserved = g.counted || g.ref === true;
    if (!good) {
      if (reserved) await quota.releaseSign(rc, acct, null, { holdKey: hold });
      return 'fail';
    }
    if (landed.has(hold)) {
      if (reserved) await quota.releaseSign(rc, acct, null, { holdKey: hold });
      return 'idem';
    }
    landed.add(hold);
    await quota.finalizeSign(rc, hold, null);
    return 'new';
  }
  return { gate, finish };
}

test('the interleaving from the review: A counts, B rides the hold, A fails, B lands -> B is counted', async (t) => {
  rc = await requireRedis('redis://127.0.0.1:6398');
  if (!rc) return t.skip('no redis');
  const acct = 'acct_race_' + crypto.randomBytes(4).toString('hex');
  const landed = new Set();
  const route = makeRoute(acct, 2, landed);
  for (let env = 0; env < 5; env++) {
    const hold = `paramant:quota:signhold:env_${acct}_${env}:0`;
    const A = await route.gate(hold);
    const B = await route.gate(hold);
    if (A.allowed) await route.finish(A, hold, false);
    if (B.allowed) await route.finish(B, hold, true);
  }
  const used = (await quota.readUsage(rc, acct)).signs_this_month;
  assert.ok(landed.size <= 2, `${landed.size} signatures landed on a plan of 2`);
  assert.strictEqual(used, landed.size, `landed ${landed.size}, counted ${used}`);
  checks++;
});

test('parallel requests, good and bad, on many slots never exceed the limit and every landed signature is counted', async (t) => {
  if (!rc) return t.skip('no redis');
  for (let round = 0; round < 5; round++) {
    const acct = 'acct_racep_' + crypto.randomBytes(4).toString('hex');
    const limit = 3;
    const landed = new Set();
    const route = makeRoute(acct, limit, landed);
    const jobs = [];
    for (let slot = 0; slot < 8; slot++) {
      const hold = `paramant:quota:signhold:env_${acct}_${slot}:0`;
      for (let k = 0; k < 4; k++) {
        const good = k % 2 === 1;
        jobs.push((async () => {
          await sleep(Math.random() * 5);
          const g = await route.gate(hold);
          if (!g.allowed) return 'refused';
          await sleep(Math.random() * 10);
          return route.finish(g, hold, good);
        })());
      }
    }
    await Promise.all(jobs);
    const used = (await quota.readUsage(rc, acct)).signs_this_month;
    assert.ok(landed.size <= limit, `round ${round}: ${landed.size} landed on a plan of ${limit}`);
    assert.strictEqual(used, landed.size, `round ${round}: landed ${landed.size}, counted ${used}`);
  }
  checks++;
});
