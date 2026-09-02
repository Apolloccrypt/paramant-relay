'use strict';
// Unit tests for the collecting half of billing (relay/lib/billing-recurring.js).
// The rules this guards, in the order they cost money if broken:
//   1. a subscription starts on the day the paid period ENDS, never today
//   2. a renewal collected by the subscription never creates a second one
//   3. cancelling stops the next collection and leaves the paid period alone
//   4. a renewal webhook extends the period instead of overwriting it
//   5. a chargeback wipes the period with the tier
// Rules 4 and 5 live in billing.js; they are asserted here too because the two
// halves only work as a pair, and a change to either one breaks the pair.
// Run: node relay/test/billing-recurring.test.js (exits non-zero on failure).

const assert = require('assert');
const rec = require('../lib/billing-recurring');
const billing = require('../lib/billing');
const catalog = require('../lib/billing-catalog');

let passed = 0;
const pending = [];
function test(name, fn) {
  const run = async () => {
    try { await fn(); passed++; console.log(`ok   ${name}`); }
    catch (e) { console.error(`FAIL ${name}\n     ${e.message}`); process.exitCode = 1; }
  };
  pending.push(run);
}

const PLAN = { product: 'parasign', plan: 'pro', interval: 'monthly' };
const ORDER = catalog.resolveOrder(PLAN);
const PAID_UNTIL = new Date('2026-10-01T12:00:00.000Z');

// Every ensureSubscription call below passes recurring: true. That flag is the
// brake from mollie.billingStance(): it is only true when BILLING_MODE was set
// by hand, and without it the layer is a no-op (see billing-stance.test.js).
// This suite tests the layer in its enabled state.
const mollieFake = (over) => Object.assign({
  mollieInterval: (i) => (i === 'monthly' ? '1 month' : i === 'yearly' ? '12 months' : null),
  validMandates: async () => [{ id: 'mdt_1', status: 'valid' }],
  createSubscription: async (mode, cust, payload) => ({ id: 'sub_1', _payload: payload, _cust: cust }),
  cancelSubscription: async () => ({ status: 'canceled' }),
}, over);

const paidPayment = (over) => Object.assign({
  id: 'tr_first', status: 'paid', sequenceType: 'first', customerId: 'cst_1',
  amount: { value: ORDER.amount, currency: 'EUR' },
  metadata: { accountId: 'acct_1', ...PLAN },
}, over);

const grant = (over) => Object.assign({
  result: 'granted', account: 'acct_1', product: 'parasign', tier: 'pro', paidUntil: PAID_UNTIL,
}, over);

// ── 1. the date that costs a double charge ───────────────────────────────────

test('the subscription starts on the day the paid period ends, not today', () => {
  const built = rec.subscriptionPayload({
    order: ORDER, paidUntil: PAID_UNTIL, accountId: 'acct_1',
    webhookUrl: 'https://paramant.app/v2/billing/webhook',
    mollieInterval: mollieFake().mollieInterval,
  });
  assert.ok(!built.error, `payload refused: ${built.error}`);
  assert.strictEqual(built.payload.startDate, '2026-10-01');
  assert.strictEqual(built.payload.interval, '1 month');
});

test('a missing paid_until refuses the payload instead of starting today', () => {
  const built = rec.subscriptionPayload({
    order: ORDER, paidUntil: null, accountId: 'acct_1',
    mollieInterval: mollieFake().mollieInterval,
  });
  assert.strictEqual(built.error, 'no_start_date');
  assert.strictEqual(built.payload, undefined);
});

test('an unparseable paid_until refuses too', () => {
  assert.strictEqual(rec.startDateFor('not a date'), null);
  const built = rec.subscriptionPayload({
    order: ORDER, paidUntil: 'not a date', accountId: 'acct_1',
    mollieInterval: mollieFake().mollieInterval,
  });
  assert.strictEqual(built.error, 'no_start_date');
});

// The trap that the first version of this file walked straight into: new
// Date(null) is 1 January 1970, not an invalid date, so a NaN check alone lets
// a startDate 56 years in the past through and Mollie collects at once.
test('null is refused because new Date(null) is 1970, not an invalid date', () => {
  assert.strictEqual(new Date(null).getTime(), 0, 'sanity: new Date(null) is the epoch, not NaN');
  assert.strictEqual(rec.startDateFor(null), null);
  assert.strictEqual(rec.startDateFor(undefined), null);
  assert.strictEqual(rec.startDateFor(''), null);
});

test('a startDate that is not in the future is refused: Mollie would collect at once', () => {
  const now = new Date('2026-09-01T00:00:00.000Z');
  assert.strictEqual(rec.startDateFor(new Date('2026-08-31T23:59:59.000Z'), now), null);
  assert.strictEqual(rec.startDateFor(now, now), null, 'the exact present is not a future start');
  assert.strictEqual(rec.startDateFor(new Date('2026-09-01T00:00:01.000Z'), now), '2026-09-01');
});

test('an already expired period cannot become the start of the next one', async () => {
  let created = 0;
  const r = await rec.ensureSubscription(paidPayment(), grant({ paidUntil: new Date('2026-01-01T00:00:00.000Z') }), {
    recurring: true, mode: 'test', now: new Date('2026-09-01T00:00:00.000Z'),
    getAccount: async () => ({}), saveSubscription: async () => {},
    mollie: mollieFake({ createSubscription: async () => { created++; return { id: 'sub_x' }; } }),
  });
  assert.strictEqual(r.result, 'failed');
  assert.strictEqual(r.reason, 'payload:no_start_date');
  assert.strictEqual(created, 0, 'a subscription was created that would bill immediately');
});

test('the subscription carries the metadata a renewal is attributed by', () => {
  const built = rec.subscriptionPayload({
    order: ORDER, paidUntil: PAID_UNTIL, accountId: 'acct_1',
    mollieInterval: mollieFake().mollieInterval,
  });
  assert.deepStrictEqual(built.payload.metadata, {
    accountId: 'acct_1', product: 'parasign', plan: 'pro', interval: 'monthly',
  });
});

test('an interval Mollie does not speak refuses the payload', () => {
  const built = rec.subscriptionPayload({
    order: { ...ORDER, interval: 'weekly' }, paidUntil: PAID_UNTIL, accountId: 'acct_1',
    mollieInterval: mollieFake().mollieInterval,
  });
  assert.strictEqual(built.error, 'no_interval:weekly');
});

// ── 2. never a second subscription ───────────────────────────────────────────

test('a recurring collection does not create another subscription', async () => {
  let created = 0;
  const r = await rec.ensureSubscription(
    paidPayment({ id: 'tr_renewal', sequenceType: 'recurring' }), grant(),
    { recurring: true, mode: 'test', getAccount: async () => ({}), mollie: mollieFake({ createSubscription: async () => { created++; return { id: 'sub_x' }; } }) },
  );
  assert.strictEqual(r.result, 'skipped');
  assert.strictEqual(r.reason, 'recurring_collection');
  assert.strictEqual(created, 0, 'a renewal created a second subscription');
});

test('an account that already has a subscription for this product is left alone', async () => {
  let created = 0;
  const r = await rec.ensureSubscription(paidPayment(), grant(), {
    recurring: true, mode: 'test',
    getAccount: async () => ({ mollie_subscription_parasign: 'sub_existing' }),
    mollie: mollieFake({ createSubscription: async () => { created++; return { id: 'sub_x' }; } }),
  });
  assert.strictEqual(r.result, 'skipped');
  assert.strictEqual(r.subscriptionId, 'sub_existing');
  assert.strictEqual(created, 0);
});

test('a subscription for the OTHER product does not block this one', async () => {
  const r = await rec.ensureSubscription(paidPayment(), grant(), {
    recurring: true, mode: 'test',
    getAccount: async () => ({ mollie_subscription_parasend: 'sub_send' }),
    saveSubscription: async () => {},
    mollie: mollieFake(),
  });
  assert.strictEqual(r.result, 'created');
  assert.strictEqual(r.subscriptionId, 'sub_1');
});

// ── 3. the failure modes that must not cost an entitlement ───────────────────

test('a first payment without a customer id is flagged, not thrown', async () => {
  const r = await rec.ensureSubscription(paidPayment({ customerId: null }), grant(), {
    recurring: true, mode: 'test', getAccount: async () => ({}), mollie: mollieFake(),
  });
  assert.strictEqual(r.result, 'failed');
  assert.strictEqual(r.level, 'error');
  assert.strictEqual(r.reason, 'no_customer_on_payment');
});

test('no valid mandate refuses rather than creating a subscription Mollie will reject', async () => {
  let created = 0;
  const r = await rec.ensureSubscription(paidPayment(), grant(), {
    recurring: true, mode: 'test', getAccount: async () => ({}),
    mollie: mollieFake({
      validMandates: async () => [],
      createSubscription: async () => { created++; return { id: 'sub_x' }; },
    }),
  });
  assert.strictEqual(r.result, 'failed');
  assert.strictEqual(r.reason, 'no_valid_mandate');
  assert.strictEqual(created, 0);
});

test('a Mollie failure is reported, never thrown at the webhook', async () => {
  const r = await rec.ensureSubscription(paidPayment(), grant(), {
    recurring: true, mode: 'test', getAccount: async () => ({}),
    mollie: mollieFake({ createSubscription: async () => { throw new Error('mollie_subscription_failed'); } }),
  });
  assert.strictEqual(r.result, 'failed');
  assert.ok(r.reason.startsWith('create_failed:'), r.reason);
});

test('the customer id on the payment beats a stale one on the account', async () => {
  let billedCustomer = null;
  await rec.ensureSubscription(paidPayment({ customerId: 'cst_fresh' }), grant(), {
    recurring: true, mode: 'test',
    getAccount: async () => ({ mollie_customer_id: 'cst_stale' }),
    saveSubscription: async () => {},
    mollie: mollieFake({ createSubscription: async (m, cust) => { billedCustomer = cust; return { id: 'sub_1' }; } }),
  });
  assert.strictEqual(billedCustomer, 'cst_fresh');
});

// ── 4. cancelling ────────────────────────────────────────────────────────────

test('cancelling stops the collection and leaves the paid period untouched', async () => {
  const account = { mollie_customer_id: 'cst_1', mollie_subscription_parasign: 'sub_1', paid_until_parasign: PAID_UNTIL.toISOString(), plan_parasign: 'pro' };
  const r = await rec.cancelForProduct('acct_1', 'parasign', {
    recurring: true, mode: 'test',
    getAccount: async () => account,
    saveSubscription: async (a, p, id) => { account[rec.subscriptionFieldOf(p)] = id; },
    mollie: mollieFake(),
  });
  assert.strictEqual(r.result, 'cancelled');
  assert.strictEqual(account.mollie_subscription_parasign, null, 'the subscription pointer was not cleared');
  assert.strictEqual(account.paid_until_parasign, PAID_UNTIL.toISOString(), 'cancelling shortened the paid period');
  assert.strictEqual(account.plan_parasign, 'pro', 'cancelling downgraded the tier immediately');
});

test('a failed cancel keeps the pointer, so the next attempt still finds it', async () => {
  const account = { mollie_customer_id: 'cst_1', mollie_subscription_parasign: 'sub_1' };
  const r = await rec.cancelForProduct('acct_1', 'parasign', {
    recurring: true, mode: 'test',
    getAccount: async () => account,
    saveSubscription: async (a, p, id) => { account[rec.subscriptionFieldOf(p)] = id; },
    mollie: mollieFake({ cancelSubscription: async () => { throw new Error('mollie_cancel_failed'); } }),
  });
  assert.strictEqual(r.result, 'failed');
  assert.strictEqual(account.mollie_subscription_parasign, 'sub_1');
});

test('cancelling what was never subscribed is a no-op, not an error', async () => {
  const r = await rec.cancelForProduct('acct_1', 'parasign', {
    recurring: true, mode: 'test', getAccount: async () => ({ mollie_customer_id: 'cst_1' }), mollie: mollieFake(),
  });
  assert.strictEqual(r.result, 'noop');
  assert.strictEqual(r.reason, 'no_subscription');
});

// ── 5. the pair: what billing.js must keep doing for this to hold ────────────

test('a renewal webhook extends the period instead of overwriting it', async () => {
  // Paying three days before the period ends must add a month to the END, not
  // throw those three days away.
  const current = new Date('2026-10-01T12:00:00.000Z');
  const now = new Date('2026-09-28T09:00:00.000Z');
  let granted = null;
  const out = await billing.processPayment(paidPayment({ id: 'tr_renew', sequenceType: 'recurring' }), {
    now,
    currentPaidUntil: async () => current.toISOString(),
    setProductPlan: async (a, p, t, until) => { granted = until; return { ok: true }; },
  });
  assert.strictEqual(out.result, 'granted');
  assert.strictEqual(granted.toISOString(), '2026-11-01T12:00:00.000Z',
    'the renewal did not extend from the end of the running period');
});

test('a payment after a lapse starts from today, not from the old end', async () => {
  const lapsed = new Date('2026-07-01T12:00:00.000Z');
  const now = new Date('2026-09-28T09:00:00.000Z');
  let granted = null;
  await billing.processPayment(paidPayment({ id: 'tr_late' }), {
    now,
    currentPaidUntil: async () => lapsed.toISOString(),
    setProductPlan: async (a, p, t, until) => { granted = until; return { ok: true }; },
  });
  assert.strictEqual(granted.toISOString(), '2026-10-28T09:00:00.000Z',
    'a gap was retroactively covered');
});

test('a chargeback wipes the paid period along with the tier', async () => {
  let seen = { tier: undefined, until: undefined };
  const out = await billing.processPayment(paidPayment({ id: 'tr_cb', status: 'chargeback' }), {
    setProductPlan: async (a, p, tier, until) => { seen = { tier, until }; return { ok: true }; },
  });
  assert.strictEqual(out.result, 'revoked');
  assert.strictEqual(seen.tier, catalog.floorTier('parasign'));
  assert.strictEqual(seen.until, null, 'a chargeback left paid time on record');
});

test('the same payment id twice grants once', async () => {
  const done = new Set();
  let grants = 0;
  const deps = {
    setProductPlan: async () => { grants++; return { ok: true }; },
    isProcessed: async (id) => done.has(id),
    markProcessed: async (id) => { done.add(id); },
  };
  await billing.processPayment(paidPayment({ id: 'tr_dup' }), deps);
  await billing.processPayment(paidPayment({ id: 'tr_dup' }), deps);
  assert.strictEqual(grants, 1, 'a replayed webhook granted twice');
});

(async () => {
  for (const run of pending) await run();
  console.log(`\nbilling-recurring: ${passed} checks passed`);
})();
