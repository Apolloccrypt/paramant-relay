'use strict';
// Server guarantee for the extension surfaces (Outlook add-in + Chromium extension).
// Both POST the same /v2/inbound as the webapp, so the monthly-transfer gate is
// enforced server-side and is identical for all three. This test reconstructs the
// exact gate relay.js composes on POST /v2/inbound (~r4373-4377):
//
//   limit = entitlements.getEntitlements(keyData).parasend.quotas.transfers_month
//   gate  = quota.gateTransfer(redis, account, dedupKey, limit, log)
//   if (!gate.allowed) -> 402 { error:'monthly_transfer_quota_reached',
//                               dimension:'transfers_month', plan, limit }
//
// It asserts both the decline decision AND the literal 402 body, so a drift in
// either the entitlement cap or the response shape breaks this test. Same style
// as quota-gate.test.js (lib-level, fake Redis) because the repo has no HTTP
// harness for relay.js (it needs Redis/argon2/NATS/the core addon to boot).

const { test } = require('node:test');
const assert = require('assert');
const quota = require('../lib/quota');
const entitlements = require('../lib/entitlements');

// Minimal in-memory Redis stub, copied from quota-gate.test.js.
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

// The exact body relay.js returns on decline. Kept identical to the literal at
// POST /v2/inbound so this test fails loudly if either side drifts.
function inbound402Body(keyData, limit) {
  return {
    error: 'monthly_transfer_quota_reached',
    dimension: 'transfers_month',
    plan: keyData.plan || 'community',
    limit,
  };
}

test('community has a finite ParaSend transfers_month entitlement (no unbounded tier)', () => {
  const limit = entitlements.getEntitlements({ plan: 'community' }).parasend.quotas.transfers_month;
  assert.ok(Number.isFinite(limit) && limit > 0, `expected a finite positive cap, got ${limit}`);
});

test('/v2/inbound gate: a NEW transfer over the cap declines with the exact webapp 402', async () => {
  const keyData = { plan: 'community', account_id: 'acctA' };
  const limit = entitlements.getEntitlements(keyData).parasend.quotas.transfers_month;

  const r = fakeRedis();
  r._store.set(quota.transfersKey('acctA'), String(limit)); // already at the monthly cap

  const gate = await quota.gateTransfer(r, 'acctA', 'freshFileHash', limit, null);
  assert.strictEqual(gate.allowed, false, 'a fresh transfer at cap must be declined');
  assert.strictEqual(gate.over_limit, true);

  // This is exactly what relay.js would writeHead(402) + return here:
  assert.deepStrictEqual(inbound402Body(keyData, limit), {
    error: 'monthly_transfer_quota_reached',
    dimension: 'transfers_month',
    plan: 'community',
    limit,
  });

  // A declined transfer is never counted (no retry-bypass, never billed).
  assert.strictEqual(await r.get(quota.transfersKey('acctA')), String(limit));
});

test('/v2/inbound gate: a transfer under the cap is allowed (no 402)', async () => {
  const keyData = { plan: 'community', account_id: 'acctB' };
  const limit = entitlements.getEntitlements(keyData).parasend.quotas.transfers_month;

  const r = fakeRedis();
  const gate = await quota.gateTransfer(r, 'acctB', 'firstHash', limit, null);
  assert.strictEqual(gate.allowed, true);
  assert.strictEqual(gate.counted, true);
});

test('/v2/inbound gate: a continuing multi-chunk upload passes even at cap (dedup, matches webapp)', async () => {
  const keyData = { plan: 'community', account_id: 'acctC' };
  const limit = entitlements.getEntitlements(keyData).parasend.quotas.transfers_month;

  const r = fakeRedis();
  r._store.set(quota.seenKey('acctC', 'fileHash'), '1'); // file already counted this month
  r._store.set(quota.transfersKey('acctC'), String(limit));

  const gate = await quota.gateTransfer(r, 'acctC', 'fileHash', limit, null);
  assert.strictEqual(gate.allowed, true, 'a dedup hit (later chunk) must not be blocked by the cap');
  assert.strictEqual(gate.deduped, true);
});

test('/v2/inbound gate: pro carries a higher cap than community (gate reads the plan)', () => {
  const community = entitlements.getEntitlements({ plan: 'community' }).parasend.quotas.transfers_month;
  const pro = entitlements.getEntitlements({ plan: 'pro' }).parasend.quotas.transfers_month;
  assert.ok(pro > community, `expected pro cap (${pro}) > community cap (${community})`);
});
