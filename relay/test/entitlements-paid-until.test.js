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
function test(name, fn) {
  try { fn(); passed++; console.log(`ok   ${name}`); }
  catch (e) { console.error(`FAIL ${name}\n     ${e.message}`); process.exitCode = 1; }
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

console.log(`\n${passed} passed`);
