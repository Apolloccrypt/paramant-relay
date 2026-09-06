'use strict';
// Quota enforcement tests — proves the Phase 4 gate: NEW active use is declined
// over the monthly cap, dedup'd multi-chunk uploads and Redis outages pass
// (fail-open), and a declined transfer is never counted (no retry-bypass).
//
// WHY THIS RUNS AGAINST A REAL REDIS NOW. It used to drive an in-memory stub
// implementing get/exists/incr/expire/set, which was enough while the gates were
// written in JavaScript. They are Lua scripts since the 2026-09-05 review's
// finding 8, because read-decide-write in JavaScript let concurrent requests
// share one slot, and the stub has no EVAL. That would not have shown up as a
// failure: quota fails OPEN by design, so a stub that cannot run the script
// throws, the catch answers `allowed: true`, and every cap test goes green while
// enforcing nothing. A stub that can be satisfied by the absence of the feature
// is worse than no test, so this suite asks for the real thing and says so.
//
// A second reason not to teach the stub EVAL: a JavaScript reimplementation of
// the script inside the test is the test mirroring the implementation, which is
// the exact habit the review called out twice.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/quota-gate.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const quota = require('../lib/quota');
const { requireRedis, summary } = require('./_requires');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const RUN = crypto.randomBytes(6).toString('hex');

let rc = null;
let checks = 0;
const did = () => { checks++; };

// A fresh account per case: the counters are month-keyed and shared, so reusing
// one id would make the cases depend on their order.
let _n = 0;
const acct = () => `acct_quota_${RUN}_${++_n}`;

const written = [];
function track(...keys) { written.push(...keys); return keys[keys.length - 1]; }

before(async () => { rc = await requireRedis(DEFAULT_REDIS); });

after(async () => {
  if (rc) {
    for (const k of written) { try { await rc.del(k); } catch (_) {} }
    try { await rc.disconnect(); } catch (_) {}
  }
  summary('quota-gate', checks);
});

test('transfer under cap is allowed and counted', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.transfersKey(a), quota.seenKey(a, 'hashA'));
  const g = await quota.gateTransfer(rc, a, 'hashA', 10, null);
  assert.strictEqual(g.allowed, true); did();
  assert.strictEqual(g.counted, true); did();
  assert.strictEqual(await rc.get(quota.transfersKey(a)), '1'); did();
});

test('transfer AT cap is declined and NOT counted', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.transfersKey(a), quota.seenKey(a, 'newHash'));
  await rc.set(quota.transfersKey(a), '10'); // already at community cap
  const g = await quota.gateTransfer(rc, a, 'newHash', 10, null);
  assert.strictEqual(g.allowed, false); did();
  assert.strictEqual(g.over_limit, true); did();
  assert.strictEqual(await rc.get(quota.transfersKey(a)), '10', 'count unchanged'); did();
});

test('declined transfer cannot be bypassed by retrying the same chunk', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.transfersKey(a), quota.seenKey(a, 'chunkX'));
  await rc.set(quota.transfersKey(a), '10');
  const g1 = await quota.gateTransfer(rc, a, 'chunkX', 10, null);
  const g2 = await quota.gateTransfer(rc, a, 'chunkX', 10, null);
  assert.strictEqual(g1.allowed, false); did();
  assert.strictEqual(g2.allowed, false, 'retry of a declined chunk stays declined'); did();
  assert.strictEqual(await rc.exists(quota.seenKey(a, 'chunkX')), 0,
    'the seen key must not be claimed on a decline, or the retry would dedup through'); did();
});

test('continuing a multi-chunk (dedup) upload is allowed even at cap', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.transfersKey(a), quota.seenKey(a, 'fileHash'));
  // The file was already counted this month: seen key set, count at cap.
  await rc.set(quota.seenKey(a, 'fileHash'), '1');
  await rc.set(quota.transfersKey(a), '10');
  const g = await quota.gateTransfer(rc, a, 'fileHash', 10, null);
  assert.strictEqual(g.allowed, true); did();
  assert.strictEqual(g.deduped, true); did();
  assert.strictEqual(await rc.get(quota.transfersKey(a)), '10', 'a continuation is not a second transfer'); did();
});

test('unlimited plan (Infinity) always allowed, still counted', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.transfersKey(a), quota.seenKey(a, 'h'));
  await rc.set(quota.transfersKey(a), '99999');
  const g = await quota.gateTransfer(rc, a, 'h', Infinity, null);
  assert.strictEqual(g.allowed, true); did();
});

test('Redis not ready => fail open (allowed)', async () => {
  // Deliberate, and load-bearing: lib/quota.js:3 says a Redis outage MUST NOT
  // block an upload. Needs no server, so it runs even where redis is a declared
  // skip. See the 2026-09-05 review finding 17, which is this line on purpose.
  const g = await quota.gateTransfer({ isReady: false }, 'acct_never', 'h', 10, null);
  assert.strictEqual(g.allowed, true); did();
});

test('sign under cap allowed; at cap declined and not counted', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.signsKey(a));
  const ok = await quota.gateSign(rc, a, 2, null);
  assert.strictEqual(ok.allowed, true); did();
  await rc.set(quota.signsKey(a), '2');
  const no = await quota.gateSign(rc, a, 2, null);
  assert.strictEqual(no.allowed, false); did();
  assert.strictEqual(await rc.get(quota.signsKey(a)), '2'); did();
});

// ── The rule may not live in two places ──────────────────────────────────────
// gateSign enforces the cap inside a Lua script; signGateDecision is the same
// rule as a pure function, and the /v1 create gate reads THAT one. Two copies of
// a comparison drift, and the boundary is where they drift first, so both are
// asked the same question at used = limit-1, limit and limit+1.
test('the Lua gate and signGateDecision agree at the boundary', async () => {
  if (!rc) return;
  const limit = 3;
  const ent = { quotas: { signs_month: limit } };
  for (const used of [limit - 1, limit, limit + 1]) {
    const a = acct();
    track(quota.signsKey(a));
    await rc.set(quota.signsKey(a), String(used));
    const lua  = await quota.gateSign(rc, a, limit, null);
    const pure = quota.signGateDecision(used, ent);
    assert.strictEqual(lua.allowed, pure.allowed,
      `at used=${used}, limit=${limit} the script says ${lua.allowed} and signGateDecision says ${pure.allowed}. ` +
      'One of the two sign paths would let a signature through that the other refuses.'); did();
  }
});

// ── The reservation gives the slot back ──────────────────────────────────────
// The gate counts BEFORE the signature is stored. Anything that then fails to
// store one owes the month a release, and a release must never mint a unit out
// of nothing.
test('releaseSign hands a reserved slot back, and never below zero', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.signsKey(a));
  await quota.gateSign(rc, a, 5, null);
  await quota.gateSign(rc, a, 5, null);
  assert.strictEqual(await rc.get(quota.signsKey(a)), '2'); did();
  const r = await quota.releaseSign(rc, a, null);
  assert.strictEqual(r.released, true); did();
  assert.strictEqual(await rc.get(quota.signsKey(a)), '1'); did();

  const b = acct();
  track(quota.signsKey(b));
  await quota.releaseSign(rc, b, null);
  const after = parseInt((await rc.get(quota.signsKey(b))) || '0', 10);
  assert.strictEqual(after, 0,
    'a release without a reservation must not leave a negative counter, which would be a free unit'); did();
});

// Moved here from tiers-sign-quota.test.js, which has no redis: the two monthly
// counters are separate keys and a transfer must never touch the signs one.
test('transfer gating is untouched by the sign tiers', async () => {
  if (!rc) return;
  const a = acct();
  track(quota.transfersKey(a), quota.signsKey(a), quota.seenKey(a, 'hashA'));
  const g = await quota.gateTransfer(rc, a, 'hashA', 10, null);
  assert.strictEqual(g.allowed, true); did();
  assert.strictEqual(g.counted, true); did();
  assert.strictEqual(await rc.exists(quota.signsKey(a)), 0, 'a transfer is not a signature'); did();
});
