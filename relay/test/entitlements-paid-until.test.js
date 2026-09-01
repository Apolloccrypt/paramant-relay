'use strict';
// Unit tests for the paid-until axis on the entitlement layer
// (relay/lib/entitlements.js). The rule this guards: a paid tier stops granting
// when the period it was paid for has passed, and an account with no recorded
// period is never treated as expired.
//
// Why it matters: a one-off payment used to set the tier and nothing ever took
// it back, so one payment bought the tier forever. The date makes the grant
// bounded; the read path honours it even if no webhook or cron ever runs.
// Run: node relay/test/entitlements-paid-until.test.js (exits non-zero on failure).

const assert = require('assert');
const ent = require('../lib/entitlements');

let passed = 0;
const pending = [];
function test(name, fn) {
  const run = async () => {
    try { await fn(); passed++; console.log(`ok   ${name}`); }
    catch (e) { console.error(`FAIL ${name}\n     ${e.message}`); process.exitCode = 1; }
  };
  pending.push(run);
}

const T0 = Date.parse('2026-09-01T00:00:00Z');
const MONTH = Date.parse('2026-10-01T00:00:00Z');

test('a tier without a recorded period keeps granting', () => {
  const rec = { plan_parasend: 'pro' };
  const r = ent.effectiveProductTier(rec, 'parasend', MONTH);
  assert.strictEqual(r.tier, 'pro');
  assert.strictEqual(r.expired, false);
});

test('a grant writes the period it was paid for', () => {
  const rec = {};
  const out = ent.applyProductTier(rec, 'parasend', 'pro', MONTH);
  assert.strictEqual(rec.plan_parasend, 'pro');
  assert.strictEqual(rec.paid_until_parasend, new Date(MONTH).toISOString());
  assert.strictEqual(out.changed, true);
});

test('inside the paid period the tier stands', () => {
  const rec = {};
  ent.applyProductTier(rec, 'parasend', 'pro', MONTH);
  assert.strictEqual(ent.effectiveProductTier(rec, 'parasend', T0).tier, 'pro');
});

test('past the paid period the tier falls to its floor', () => {
  const rec = {};
  ent.applyProductTier(rec, 'parasend', 'pro', MONTH);
  const r = ent.effectiveProductTier(rec, 'parasend', MONTH + 1);
  assert.strictEqual(r.tier, 'community');
  assert.strictEqual(r.expired, true);
});

test('expiry is exact: at the boundary the period is over', () => {
  const rec = {};
  ent.applyProductTier(rec, 'parasign', 'pro', MONTH);
  assert.strictEqual(ent.effectiveProductTier(rec, 'parasign', MONTH - 1).tier, 'pro');
  assert.strictEqual(ent.effectiveProductTier(rec, 'parasign', MONTH).tier, 'free');
});

test('parasign floor is free, parasend floor is community', () => {
  const a = {}; ent.applyProductTier(a, 'parasign', 'business', T0);
  const b = {}; ent.applyProductTier(b, 'parasend', 'pro', T0);
  assert.strictEqual(ent.effectiveProductTier(a, 'parasign', MONTH).tier, 'free');
  assert.strictEqual(ent.effectiveProductTier(b, 'parasend', MONTH).tier, 'community');
});

test('dropping to the floor clears the period', () => {
  const rec = {};
  ent.applyProductTier(rec, 'parasend', 'pro', MONTH);
  ent.applyProductTier(rec, 'parasend', 'community');
  assert.strictEqual(rec.paid_until_parasend, undefined);
});

test('an omitted period leaves an existing one alone', () => {
  const rec = {};
  ent.applyProductTier(rec, 'parasend', 'pro', MONTH);
  ent.applyProductTier(rec, 'parasend', 'pro');
  assert.strictEqual(rec.paid_until_parasend, new Date(MONTH).toISOString());
});

test('an unparseable period is read as absent, never as expired', () => {
  const rec = { plan_parasign: 'business', paid_until_parasign: 'niet-een-datum' };
  const r = ent.effectiveProductTier(rec, 'parasign', MONTH);
  assert.strictEqual(r.tier, 'business');
  assert.strictEqual(r.expired, false);
});

test('renewal extends the period without touching the tier', () => {
  const rec = {};
  ent.applyProductTier(rec, 'parasign', 'pro', MONTH);
  const next = Date.parse('2026-11-01T00:00:00Z');
  ent.applyProductTier(rec, 'parasign', 'pro', next);
  assert.strictEqual(rec.plan_parasign, 'pro');
  assert.strictEqual(ent.effectiveProductTier(rec, 'parasign', MONTH + 1).tier, 'pro');
});

test('the other product is never moved by a period on this one', () => {
  const rec = { plan_parasign: 'business' };
  ent.applyProductTier(rec, 'parasend', 'pro', T0);
  assert.strictEqual(rec.plan_parasign, 'business');
  assert.strictEqual(rec.paid_until_parasign, undefined);
  assert.strictEqual(ent.effectiveProductTier(rec, 'parasign', MONTH).tier, 'business');
});

(async () => {
  for (const run of pending) await run();
  console.log(`\n${passed} passed`);
})();

// ── The webhook half: a payment must buy a bounded period ────────────────────
const billing = require('../lib/billing');

function payment(over) {
  return Object.assign({
    id: 'tr_demo', status: 'paid', amount: { value: '18.15', currency: 'EUR' },
    metadata: { accountId: 'acct_demo', product: 'parasend', plan: 'pro', interval: 'monthly' },
  }, over || {});
}

test('a paid webhook grants a tier AND an end date', async () => {
  let got = null;
  const out = await billing.processPayment(payment(), {
    now: new Date('2026-09-15T10:00:00Z'),
    setProductPlan: (a, p, t, until) => { got = { a, p, t, until }; return { ok: true }; },
  });
  assert.strictEqual(out.result, 'granted');
  assert.strictEqual(got.t, 'pro');
  assert.strictEqual(got.until.toISOString(), '2026-10-15T10:00:00.000Z');
});

// 29 February exists only in a leap year, so the start date here must be a real
// one: 2024. Renewing lands on 28 February 2025, the last day of that month,
// never 1 March.
test('yearly buys twelve months and clamps a leap day to the month end', async () => {
  let got = null;
  await billing.processPayment(payment({
    amount: { value: '181.50', currency: 'EUR' },
    metadata: { accountId: 'acct_demo', product: 'parasend', plan: 'pro', interval: 'yearly' },
  }), {
    now: new Date('2024-02-29T00:00:00Z'),
    setProductPlan: (a, p, t, until) => { got = until; return { ok: true }; },
  });
  assert.strictEqual(got.toISOString().slice(0, 10), '2025-02-28');
});

test('renewing early extends from the end of the period, not from today', async () => {
  let got = null;
  await billing.processPayment(payment(), {
    now: new Date('2026-09-10T00:00:00Z'),
    currentPaidUntil: async () => '2026-09-15T00:00:00.000Z',
    setProductPlan: (a, p, t, until) => { got = until; return { ok: true }; },
  });
  assert.strictEqual(got.toISOString().slice(0, 10), '2026-10-15');
});

test('paying after a lapse starts from now, so a gap is not covered backwards', async () => {
  let got = null;
  await billing.processPayment(payment(), {
    now: new Date('2026-11-01T00:00:00Z'),
    currentPaidUntil: async () => '2026-09-15T00:00:00.000Z',
    setProductPlan: (a, p, t, until) => { got = until; return { ok: true }; },
  });
  assert.strictEqual(got.toISOString().slice(0, 10), '2026-12-01');
});

test('an interval with no period is refused, never granted open-ended', async () => {
  let called = false;
  const out = await billing.processPayment(payment({
    metadata: { accountId: 'acct_demo', product: 'parasend', plan: 'pro', interval: 'weekly' },
  }), { setProductPlan: () => { called = true; return { ok: true }; } });
  assert.strictEqual(out.result, 'refused');
  assert.strictEqual(called, false);
});

test('a chargeback clears the period along with the tier', async () => {
  let got = 'untouched';
  await billing.processPayment(payment({ status: 'chargeback' }), {
    setProductPlan: (a, p, t, until) => { got = { t, until }; return { ok: true }; },
  });
  assert.strictEqual(got.t, 'community');
  assert.strictEqual(got.until, null);
});

// ── The gate: getEntitlements must honour the period ─────────────────────────
// Writing the date on the record is not enough. Every quota and limit in the
// product comes out of getEntitlements, so if that function ignores the period,
// an expired subscription keeps working until somebody writes a downgrade.

test('an expired paid tier grants free-tier quotas at the gate', () => {
  const at = Date.parse('2026-10-01T00:00:00Z');
  const live = ent.getEntitlements({ plan_parasend: 'pro', paid_until_parasend: '2026-11-01T00:00:00.000Z' }, at);
  const dead = ent.getEntitlements({ plan_parasend: 'pro', paid_until_parasend: '2026-09-01T00:00:00.000Z' }, at);
  assert.strictEqual(live.parasend.tier, 'pro');
  assert.strictEqual(dead.parasend.tier, 'community');
  assert.ok(dead.parasend.quotas.transfers_month < live.parasend.quotas.transfers_month);
});

test('an account from before billing keeps its tier at the gate', () => {
  const at = Date.parse('2026-10-01T00:00:00Z');
  assert.strictEqual(ent.getEntitlements({ plan_parasend: 'pro' }, at).parasend.tier, 'pro');
  assert.strictEqual(ent.getEntitlements({ plan: 'pro' }, at).parasend.tier, 'pro');
});

test('expiry on one product leaves the other alone at the gate', () => {
  const at = Date.parse('2026-10-01T00:00:00Z');
  const e = ent.getEntitlements({
    plan_parasend: 'pro', paid_until_parasend: '2026-09-01T00:00:00.000Z',
    plan_parasign: 'business', paid_until_parasign: '2026-11-01T00:00:00.000Z',
  }, at);
  assert.strictEqual(e.parasend.tier, 'community');
  assert.strictEqual(e.parasign.tier, 'business');
});

test('the gate without a clock still answers, using now', () => {
  const e = ent.getEntitlements({ plan_parasign: 'pro' });
  assert.strictEqual(e.parasign.tier, 'pro');
});
