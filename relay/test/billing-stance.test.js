'use strict';
// The brake on the recurring layer. Production runs with BILLING_MODE empty and
// a live_ key; billingMode() infers 'live' from that key, which was fine while
// the relay only made one-off payments (the code of 2026-08-08) and is not
// fine for opening mandates and subscriptions against a real Mollie account
// with code that has never seen a real Mollie answer. So the recurring layer
// runs only when BILLING_MODE was set by hand, and an inferred mode bills
// exactly as 08-08 did. Three stances are pinned here, plus the edges:
//   1. empty + live key    -> live, one-off only (the production stance today)
//   2. BILLING_MODE=test   -> test, recurring on
//   3. BILLING_MODE=live   -> live, recurring on
// Run: node relay/test/billing-stance.test.js (exits non-zero on failure).

const assert = require('assert');
const mollie = require('../lib/mollie');
const rec = require('../lib/billing-recurring');
const catalog = require('../lib/billing-catalog');

let passed = 0;
const pending = [];
function test(name, fn) {
  pending.push(async () => {
    try { await fn(); passed++; console.log(`ok   ${name}`); }
    catch (e) { console.error(`FAIL ${name}\n     ${e.message}`); process.exitCode = 1; }
  });
}

// Every test sets the three variables it cares about and clears the rest, so
// the runner's own environment can never leak a stance into a check.
function env(vars) {
  for (const k of ['BILLING_MODE', 'MOLLIE_API_KEY', 'MOLLIE_TEST_API_KEY']) delete process.env[k];
  Object.assign(process.env, vars);
}

// ── the three stances ────────────────────────────────────────────────────────

test('stance 1: BILLING_MODE empty with a live key is live, one-off only (production today)', () => {
  env({ MOLLIE_API_KEY: 'live_abcdef' });
  const s = mollie.billingStance();
  assert.deepStrictEqual(s, { mode: 'live', recurring: false, source: 'inferred', key_present: true });
  // And the mode is the same one 08-08 computed, so checkout and webhook still
  // talk to the same Mollie account.
  assert.strictEqual(mollie.billingMode(), 'live');
});

test('stance 2: BILLING_MODE=test with a test key is test, recurring on', () => {
  env({ BILLING_MODE: 'test', MOLLIE_TEST_API_KEY: 'test_abcdef' });
  const s = mollie.billingStance();
  assert.deepStrictEqual(s, { mode: 'test', recurring: true, source: 'explicit', key_present: true });
});

test('stance 3: BILLING_MODE=live with a live key is live, recurring on', () => {
  env({ BILLING_MODE: 'live', MOLLIE_API_KEY: 'live_abcdef' });
  const s = mollie.billingStance();
  assert.deepStrictEqual(s, { mode: 'live', recurring: true, source: 'explicit', key_present: true });
});

// ── the edges ────────────────────────────────────────────────────────────────

test('a live key alone never turns recurring on, whatever else is set', () => {
  env({ MOLLIE_API_KEY: 'live_abcdef', MOLLIE_TEST_API_KEY: 'test_abcdef' });
  assert.strictEqual(mollie.billingStance().recurring, false);
  env({ BILLING_MODE: 'yes', MOLLIE_API_KEY: 'live_abcdef' });
  const s = mollie.billingStance();
  assert.strictEqual(s.recurring, false, 'an unknown BILLING_MODE value must not count as explicit');
  assert.strictEqual(s.mode, 'live', 'and the mode still falls back on the key, as billingMode() always did');
  assert.strictEqual(s.source, 'inferred');
});

test('BILLING_MODE is case-insensitive, as billingMode() already was', () => {
  env({ BILLING_MODE: 'LIVE', MOLLIE_API_KEY: 'live_abcdef' });
  assert.deepStrictEqual(mollie.billingStance(), { mode: 'live', recurring: true, source: 'explicit', key_present: true });
});

test('an explicit mode without its key is explicit and keyless: the boot log turns red, nothing bills', () => {
  env({ BILLING_MODE: 'test', MOLLIE_API_KEY: 'live_abcdef' });
  const s = mollie.billingStance();
  assert.strictEqual(s.mode, 'test');
  assert.strictEqual(s.recurring, true);
  assert.strictEqual(s.key_present, false, 'a live key must never serve a test stance');
  assert.strictEqual(mollie.apiKeyFor('test'), '');
});

test('no mode and no key at all: live, inferred, keyless', () => {
  env({});
  assert.deepStrictEqual(mollie.billingStance(), { mode: 'live', recurring: false, source: 'inferred', key_present: false });
});

// ── what the stance does to a checkout ───────────────────────────────────────

const calls = () => {
  const c = { getCustomer: 0, createCustomer: 0, validMandates: 0, createSubscription: 0 };
  const m = {
    getCustomer: async (mode, id) => { c.getCustomer++; return { id }; },
    createCustomer: async () => { c.createCustomer++; return { id: 'cst_new' }; },
    validMandates: async () => { c.validMandates++; return [{ id: 'mdt_1', status: 'valid' }]; },
    createSubscription: async () => { c.createSubscription++; return { id: 'sub_1' }; },
    mollieInterval: mollie.mollieInterval,
  };
  return { c, m };
};

test('one-off stance: the checkout asks Mollie for no customer, even when one is stored', async () => {
  const { c, m } = calls();
  let saved = null;
  const out = await rec.ensureCustomer('acct_1', {
    recurring: false, mode: 'live',
    getAccount: () => ({ [rec.CUSTOMER_FIELD]: 'cst_stored', email: 'a@b.c' }),
    saveCustomer: (aid, id) => { saved = id; },
    mollie: m,
  });
  assert.deepStrictEqual(out, { customerId: null, result: 'skipped', reason: 'recurring_disabled' });
  assert.strictEqual(c.getCustomer + c.createCustomer, 0, 'no Mollie call may be made');
  assert.strictEqual(saved, null);
  // The payload the relay builds from that is the 08-08 one: no customerId, no
  // sequenceType. This mirrors the exact expression in relay.js.
  const extras = out.customerId ? { customerId: out.customerId, sequenceType: 'first' } : {};
  assert.deepStrictEqual(extras, {});
});

test('explicit stance: the checkout reuses the stored customer, or creates and saves one', async () => {
  const { c, m } = calls();
  const reused = await rec.ensureCustomer('acct_1', {
    recurring: true, mode: 'live',
    getAccount: () => ({ [rec.CUSTOMER_FIELD]: 'cst_stored' }),
    mollie: m,
  });
  assert.deepStrictEqual(reused, { customerId: 'cst_stored', result: 'reused' });
  assert.strictEqual(c.getCustomer, 1);

  let saved = null;
  const created = await rec.ensureCustomer('acct_2', {
    recurring: true, mode: 'live',
    getAccount: () => ({ email: 'a@b.c' }),
    saveCustomer: (aid, id) => { saved = `${aid}:${id}`; },
    mollie: m,
  });
  assert.deepStrictEqual(created, { customerId: 'cst_new', result: 'created' });
  assert.strictEqual(saved, 'acct_2:cst_new');
  assert.strictEqual(c.createCustomer, 1);
});

test('explicit stance: a stale stored customer falls through to a new one, a failing Mollie falls back to one-off', async () => {
  const { c, m } = calls();
  m.getCustomer = async () => { c.getCustomer++; const e = new Error('mollie_customer_get_failed'); e.status = 404; throw e; };
  const out = await rec.ensureCustomer('acct_1', {
    recurring: true, mode: 'live', getAccount: () => ({ [rec.CUSTOMER_FIELD]: 'cst_gone' }), mollie: m,
  });
  assert.strictEqual(out.customerId, 'cst_new');
  assert.strictEqual(c.createCustomer, 1);

  m.createCustomer = async () => { const e = new Error('mollie_customer_failed'); e.status = 500; throw e; };
  const failed = await rec.ensureCustomer('acct_1', { recurring: true, mode: 'live', getAccount: () => null, mollie: m });
  assert.strictEqual(failed.customerId, null, 'the sale must still go through as a one-off');
  assert.strictEqual(failed.result, 'failed');
  assert.strictEqual(failed.level, 'error');
  assert.strictEqual(failed.status, 500);
});

// ── what the stance does to a webhook ────────────────────────────────────────

const PLAN = { product: 'parasign', plan: 'pro', interval: 'monthly' };
const ORDER = catalog.resolveOrder(PLAN);
const payment = { id: 'tr_1', status: 'paid', sequenceType: 'first', customerId: 'cst_1',
  amount: { value: ORDER.amount, currency: 'EUR' }, metadata: { accountId: 'acct_1', ...PLAN } };
const grant = { result: 'granted', account: 'acct_1', product: 'parasign', tier: 'pro',
  paidUntil: new Date(Date.now() + 30 * 86400e3) };

test('one-off stance: after a grant no mandate is read and no subscription is created, and the grant stands', async () => {
  const { c, m } = calls();
  let saved = 0;
  const sub = await rec.ensureSubscription(payment, grant, {
    recurring: false, mode: 'live', webhookUrl: 'https://paramant.app/v2/billing/webhook',
    getAccount: () => ({}), saveSubscription: () => { saved++; }, mollie: m,
  });
  assert.deepStrictEqual(sub, { result: 'skipped', reason: 'recurring_disabled' });
  assert.strictEqual(c.validMandates + c.createSubscription, 0, 'no Mollie call may be made');
  assert.strictEqual(saved, 0);
  // 'skipped' is what the relay stays silent on; anything else would log an
  // error for a stance that is deliberate.
  assert.notStrictEqual(sub.level, 'error');
});

test('explicit stance: the same webhook creates the subscription', async () => {
  const { c, m } = calls();
  const sub = await rec.ensureSubscription(payment, grant, {
    recurring: true, mode: 'live', webhookUrl: 'https://paramant.app/v2/billing/webhook',
    getAccount: () => ({}), saveSubscription: () => {}, mollie: m,
  });
  assert.strictEqual(sub.result, 'created');
  assert.strictEqual(c.validMandates, 1);
  assert.strictEqual(c.createSubscription, 1);
});

test('a deps object without the flag is one-off: the switch defaults to closed', async () => {
  assert.strictEqual(rec.recurringAllowed({}), false);
  assert.strictEqual(rec.recurringAllowed(null), false);
  assert.strictEqual(rec.recurringAllowed({ recurring: 'true' }), false, 'only the boolean true opens it');
  assert.strictEqual(rec.recurringAllowed({ recurring: true }), true);
  const { c, m } = calls();
  const sub = await rec.ensureSubscription(payment, grant, { mode: 'live', getAccount: () => ({}), mollie: m });
  assert.strictEqual(sub.reason, 'recurring_disabled');
  assert.strictEqual(c.createSubscription, 0);
});

(async () => {
  for (const run of pending) await run();
  console.log(`\nbilling-stance: ${passed} checks passed`);
})();
