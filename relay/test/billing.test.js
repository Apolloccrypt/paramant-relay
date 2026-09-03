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

  // ── classification of a failed re-fetch decides Mollie's retry behaviour ────
  {
    const keyMissing = billing.classifyFetchError(new Error('mollie_key_missing:live'));
    assert.strictEqual(keyMissing.retry, true, 'a missing key must still be retried once it is set');
    assert.strictEqual(keyMissing.level, 'error', 'a missing key is an alert, not a warning');
    assert.strictEqual(keyMissing.reason, 'mollie_key_missing');
    ok('missing MOLLIE_API_KEY -> retryable, logged at error level');
  }
  {
    const rejected = billing.classifyFetchError(Object.assign(new Error('mollie_get_failed'), { status: 401 }));
    assert.strictEqual(rejected.retry, true);
    assert.strictEqual(rejected.level, 'error', 'a rejected key must be as loud as a missing one');
    ok('rejected Mollie key (401) -> retryable, error level');
  }
  {
    for (const status of [404, 410, 422]) {
      const permanent = billing.classifyFetchError(Object.assign(new Error('mollie_get_failed'), { status }));
      assert.strictEqual(permanent.retry, false, `${status} can never resolve, so do not ask Mollie to retry`);
      assert.strictEqual(permanent.level, 'warn');
      assert.strictEqual(permanent.reason, `mollie_permanent:${status}`);
    }
    ok('unknown payment id (404/410/422) -> not retryable, acknowledged');
  }
  {
    const transient = billing.classifyFetchError(Object.assign(new Error('mollie_get_failed'), { status: 502 }));
    assert.strictEqual(transient.retry, true, 'a Mollie outage must be retried');
    assert.strictEqual(transient.level, 'warn');
    const timeout = billing.classifyFetchError(new Error('mollie_timeout'));
    assert.strictEqual(timeout.retry, true, 'a timeout must be retried');
    assert.strictEqual(timeout.reason, 'mollie_timeout');
    ok('Mollie 5xx and timeout -> retryable, warn level');
  }

  // ── a reversal arrives on the id of the payment it reverses ────────────────
  // The marker is per payment id, and Mollie sends a chargeback under the SAME
  // tr_ id as the payment. A guard that only asked "have I seen this id" let the
  // account keep the tier after the money had gone back.
  {
    const set = spySetter();
    const marker = { 'tr_CB': 'granted' };
    const deps = {
      setProductPlan: set,
      isProcessed: async (id) => marker[id] || false,
      markProcessed: async (id, val) => { marker[id] = val; },
    };
    const paid = await billing.processPayment(payment({ _id: 'CB', id: 'tr_CB' }), deps);
    assert.strictEqual(paid.result, 'ignored', 'a repeat of the SAME outcome stays a no-op');
    assert.strictEqual(paid.reason, 'already_processed');
    assert.strictEqual(set.calls.length, 0, 'a duplicate paid webhook must not touch the entitlement');

    const back = await billing.processPayment(payment({ _id: 'CB', id: 'tr_CB', status: 'chargeback' }), deps);
    assert.strictEqual(back.result, 'revoked', 'money taken back must revoke even though the id was seen');
    assert.strictEqual(back.tier, 'free', 'parasign floors to free');
    assert.strictEqual(set.calls.length, 1);
    assert.strictEqual(set.calls[0].tier, 'free');
    assert.strictEqual(marker['tr_CB'], 'revoked', 'the marker records the new outcome');

    const again = await billing.processPayment(payment({ _id: 'CB', id: 'tr_CB', status: 'chargeback' }), deps);
    assert.strictEqual(again.result, 'ignored', 'a repeated chargeback is a no-op');
    assert.strictEqual(set.calls.length, 1, 'and does not revoke twice');
    ok('chargeback on an already-granted payment id revokes, and only repeats are ignored');
  }
  // A boolean-shaped marker is what every deployment wrote before the outcome
  // was recorded, so it has to keep meaning 'granted'.
  {
    const set = spySetter();
    const r = await billing.processPayment(payment({ _id: 'LEG', id: 'tr_LEG' }), {
      setProductPlan: set, isProcessed: async () => true,
    });
    assert.strictEqual(r.result, 'ignored', 'a legacy boolean marker still blocks a duplicate grant');
    assert.strictEqual(set.calls.length, 0);
    ok('a legacy boolean idempotency marker is read as granted');
  }
  // A duplicate grant must not buy a second period. The guard is what stops it:
  // extendFrom starts from the paid_until already on file, so a grant that runs
  // twice adds a month twice off one payment.
  {
    const set = spySetter();
    const until = new Date(Date.now() + 30 * 86_400_000).toISOString();
    const r = await billing.processPayment(payment({ _id: 'DUP', id: 'tr_DUP' }), {
      setProductPlan: set,
      currentPaidUntil: async () => until,
      isProcessed: async () => 'granted',
    });
    assert.strictEqual(r.result, 'ignored');
    assert.strictEqual(set.calls.length, 0, 'one payment, one period');
    ok('a duplicate paid webhook cannot extend the paid period');
  }

  console.log(`\nPASS billing: ${passed} checks`);
}

main().catch((e) => { console.error('FAIL', e && e.stack || e); process.exit(1); });
