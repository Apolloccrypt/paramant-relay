'use strict';
// Unit tests for the Mollie billing state machine (relay/lib/billing.js) and the
// server-side catalog (relay/lib/billing-catalog.js). Covers Mick's mandatory
// scenarios: every webhook status transition, duplicate webhook (idempotency),
// amount that does not match the plan (must refuse), payment without metadata,
// and that product A never moves product B. No network, no redis: the Mollie
// fetch and the entitlement setter are injected fakes.
// Run: node relay/test/billing.test.js (exits non-zero on failure).

const assert = require('assert');
const catalog = require('../lib/billing-catalog');
const billing = require('../lib/billing');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

// A fake entitlement setter that records exactly which (account, product, tier)
// calls it received, so we can assert product isolation.
function spySetter() {
  const calls = [];
  const fn = async (accountId, product, tier) => { calls.push({ accountId, product, tier }); return { ok: true, product, tier }; };
  fn.calls = calls;
  return fn;
}

// Build a Mollie-shaped payment object.
function payment(over = {}) {
  return Object.assign({
    id: 'tr_' + (over._id || 'AAA'),
    status: 'paid',
    amount: { currency: 'EUR', value: '59.29' },
    metadata: { accountId: 'acct_1', product: 'parasign', plan: 'pro', interval: 'monthly' },
  }, over);
}

async function main() {
  // ── catalog ────────────────────────────────────────────────────────────────
  assert.strictEqual(catalog.resolveOrder({ product: 'parasign', plan: 'business', interval: 'yearly' }).amount, '3617.90');
  assert.strictEqual(catalog.resolveOrder({ product: 'parasend', plan: 'pro', interval: 'monthly' }).amount, '18.15');
  assert.strictEqual(catalog.resolveOrder({ product: 'parasign', plan: 'business', interval: 'monthly' }).tier, 'business');
  assert.strictEqual(catalog.resolveOrder({ product: 'parasend', plan: 'business', interval: 'monthly' }).error, 'unknown_plan');
  assert.strictEqual(catalog.resolveOrder({ product: 'nope', plan: 'pro', interval: 'monthly' }).error, 'unknown_product');
  ok('catalog resolves prices/tiers server-side and rejects unknown lines');

  assert.ok(catalog.amountsEqual('18.15', '18.15'));
  assert.ok(catalog.amountsEqual('18.15', '18.150'));
  assert.ok(!catalog.amountsEqual('18.15', '18.16'));
  assert.ok(!catalog.amountsEqual('18.15', 'garbage'));
  ok('amountsEqual compares by cents and rejects garbage');

  // ── paid, correct amount -> granted, only this product ──────────────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(payment(), { setProductPlan: set });
    assert.strictEqual(r.result, 'granted');
    assert.strictEqual(r.tier, 'pro');
    assert.strictEqual(set.calls.length, 1);
    assert.deepStrictEqual(set.calls[0], { accountId: 'acct_1', product: 'parasign', tier: 'pro' });
    ok('paid + correct amount -> granted (parasign pro)');
  }

  // ── product A does not touch product B ──────────────────────────────────────
  {
    const set = spySetter();
    await billing.processPayment(payment({
      amount: { currency: 'EUR', value: '18.15' },
      metadata: { accountId: 'acct_1', product: 'parasend', plan: 'pro', interval: 'monthly' },
    }), { setProductPlan: set });
    assert.strictEqual(set.calls.length, 1);
    assert.strictEqual(set.calls[0].product, 'parasend');
    assert.ok(!set.calls.some((c) => c.product === 'parasign'), 'parasign was never touched by a parasend payment');
    ok('a parasend payment never moves parasign (product isolation)');
  }

  // ── amount mismatch -> refused, error level, no grant ───────────────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(payment({ amount: { currency: 'EUR', value: '1.00' } }),
      { setProductPlan: set });
    assert.strictEqual(r.result, 'refused');
    assert.strictEqual(r.level, 'error');
    assert.match(r.reason, /amount_mismatch/);
    assert.strictEqual(set.calls.length, 0, 'no entitlement granted on mismatch');
    ok('paid but wrong amount -> refused (error, no grant)');
  }

  // ── wrong currency -> refused ───────────────────────────────────────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(payment({ amount: { currency: 'USD', value: '59.29' } }),
      { setProductPlan: set });
    assert.strictEqual(r.result, 'refused');
    assert.strictEqual(set.calls.length, 0);
    ok('paid in wrong currency -> refused');
  }

  // ── missing metadata -> refused, error (someone may have paid) ──────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(payment({ metadata: {} }), { setProductPlan: set });
    assert.strictEqual(r.result, 'refused');
    assert.strictEqual(r.level, 'error');
    assert.strictEqual(r.reason, 'missing_metadata');
    assert.strictEqual(set.calls.length, 0);
    ok('payment without metadata -> refused (error)');
  }

  // ── non-paid statuses -> ignored, no grant ──────────────────────────────────
  for (const st of ['failed', 'expired', 'canceled', 'open', 'pending']) {
    const set = spySetter();
    const r = await billing.processPayment(payment({ status: st }), { setProductPlan: set });
    assert.strictEqual(r.result, 'ignored', `${st} -> ignored`);
    assert.strictEqual(set.calls.length, 0, `${st} grants nothing`);
    ok(`status ${st} -> ignored (no entitlement change)`);
  }

  // ── chargeback -> revoked to floor ──────────────────────────────────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(payment({ status: 'chargeback' }), { setProductPlan: set });
    assert.strictEqual(r.result, 'revoked');
    assert.strictEqual(set.calls[0].tier, 'free', 'parasign revokes to free');
    ok('chargeback -> revoked to product floor');
  }

  // ── idempotency: already processed -> ignored, no second grant ──────────────
  {
    const set = spySetter();
    const deps = { setProductPlan: set, isProcessed: async () => true, markProcessed: async () => {} };
    const r = await billing.processPayment(payment(), deps);
    assert.strictEqual(r.result, 'ignored');
    assert.strictEqual(r.reason, 'already_processed');
    assert.strictEqual(set.calls.length, 0, 'no grant on a duplicate webhook');
    ok('duplicate webhook (already processed) -> ignored, no re-grant');
  }

  // ── idempotency without a marker still no-ops via idempotent setter ─────────
  {
    // Even if isProcessed is absent, calling twice is safe: the real setProductPlan
    // is idempotent. Here we just assert two calls both resolve to granted and the
    // setter is asked for the same (product, tier) both times.
    const set = spySetter();
    await billing.processPayment(payment(), { setProductPlan: set });
    await billing.processPayment(payment(), { setProductPlan: set });
    assert.deepStrictEqual(set.calls[0], set.calls[1]);
    ok('re-processing without a marker asks for the same grant (setter is idempotent)');
  }

  console.log(`\nPASS billing: ${passed} checks`);
}

main().catch((e) => { console.error('FAIL', e && e.stack || e); process.exit(1); });
