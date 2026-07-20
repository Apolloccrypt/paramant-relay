'use strict';
// ParaSign Pro perk delivery. The pricing page (frontend/pricing.html, ParaSign
// Pro card) promises, per perk:
//   1. "100 signatures per month, then EUR 0.40 each, up to 1,000"
//   2. "Unlimited transfers - API access"
//
// These prove, per perk, what a per-product grant of parasign=pro (the exact
// effect of setProductPlan(account,'parasign','pro') and of a Mollie ParaSign
// Pro purchase) turns ON, using the REAL enforcement primitives:
//   - entitlements.getEntitlements  : the signs_month quota + overage policy
//   - quota.signGateDecision        : the real sign-gate 402 decision
//   - keysTable.accountHasParasignEntitlement : the real /v1-API entitlement gate
//   - entitlements.applyProductTier : the field mutation the grant applies
// and that plan_parasend + the unified plan stay untouched.
// All pure JS (crypto + entitlements + tiers); no relay boot / native core.
// Run: node --test relay/test/parasign-pro-perks.test.js

const { test } = require('node:test');
const assert = require('assert');
const ent = require('../lib/entitlements');
const quota = require('../lib/quota');
const keysTable = require('../lib/keys-table');

// A fresh free account: unified community, both products on their floor, no API.
function freeAccount() {
  return { key: 'pgp_perk', account_id: 'pgp_perk', plan: 'community', plan_parasend: 'community', plan_parasign: 'free', parasign: false };
}

// ── PERK 1: signatures quota + overage ────────────────────────────────────────
test('PERK signatures: parasign=pro raises the sign cap to 100 + EUR 0.40 overage up to 1,000', () => {
  const acct = freeAccount();

  // BEFORE: free = 2 signs, no metering (blocks at the included quota).
  const before = ent.getEntitlements(acct).parasign;
  assert.strictEqual(before.tier, 'free');
  assert.strictEqual(before.quotas.signs_month, 2, 'free includes 2 signatures');
  assert.strictEqual(before.overage.rate_eur, null, 'free does not meter');
  assert.strictEqual(quota.signGateDecision(2, before).allowed, false, 'free blocks at 2');

  // Grant.
  ent.applyProductTier(acct, 'parasign', 'pro');

  // AFTER: 100 included, EUR 0.40/sign overage, HARD cap 1,000.
  const after = ent.getEntitlements(acct).parasign;
  assert.strictEqual(after.tier, 'pro');
  assert.strictEqual(after.quotas.signs_month, 100, 'pro includes 100 signatures (matches the page)');
  assert.strictEqual(after.overage.rate_eur, 0.40, 'EUR 0.40 per sign past 100 (matches the page)');
  assert.strictEqual(after.overage.hard_cap, 1000, 'hard stop at 1,000 (matches the page on this main-based branch)');

  // Gate behaviour: allowed at 100 (metered), still allowed at 999, blocked at 1,000.
  assert.strictEqual(quota.signGateDecision(100, after).allowed, true, 'metered past the included 100');
  assert.strictEqual(quota.signGateDecision(999, after).allowed, true, 'metered up to the cap');
  const capped = quota.signGateDecision(1000, after);
  assert.strictEqual(capped.allowed, false, 'hard stop at 1,000');
  assert.strictEqual(capped.reason, 'hard_cap');
  assert.strictEqual(capped.limit, 1000);
});

// ── PERK 2: API access (the /v1 developer API) ────────────────────────────────
test('PERK API access: parasign=pro flips the parasign flag so the /v1 API gate admits the account', () => {
  const acct = freeAccount();

  // BEFORE: no parasign flag, community plan -> /v1 gate refuses.
  assert.strictEqual(keysTable.accountHasParasignEntitlement([acct], acct.plan), false, '/v1 refused before grant');

  const r = ent.applyProductTier(acct, 'parasign', 'pro');
  assert.strictEqual(r.parasignGranted, true, 'grant flips the API access flag');
  assert.strictEqual(acct.parasign, true);

  // AFTER: the real /v1 entitlement gate (accountHasParasignEntitlement) admits
  // purely on the parasign flag, independent of the unified plan.
  assert.strictEqual(keysTable.accountHasParasignEntitlement([acct], acct.plan), true, '/v1 admitted after grant');
});

// ── Isolation: unified plan + ParaSend stay untouched by a ParaSign grant ──────
test('parasign=pro leaves the unified plan and ParaSend entitlement untouched', () => {
  const acct = freeAccount();
  const sendBefore = ent.getEntitlements(acct).parasend;
  assert.strictEqual(sendBefore.tier, 'community');
  assert.strictEqual(sendBefore.quotas.transfers_month, 10, 'community transfers cap');

  ent.applyProductTier(acct, 'parasign', 'pro');

  assert.strictEqual(acct.plan, 'community', 'unified plan untouched');
  assert.strictEqual(acct.plan_parasend, 'community', 'plan_parasend untouched');
  const sendAfter = ent.getEntitlements(acct).parasend;
  assert.strictEqual(sendAfter.tier, 'community', 'ParaSend entitlement unchanged');
  assert.strictEqual(sendAfter.quotas.transfers_month, 10, 'ParaSend transfers cap unchanged');
});

// ── FINDING (regression-locked): "Unlimited transfers" is NOT delivered ───────
// The page's ParaSign Pro card lists "Unlimited transfers", but transfers are a
// ParaSEND capacity (plan_parasend), which a ParaSign grant deliberately does
// not touch. A ParaSign-Pro customer keeps their EXISTING ParaSend tier (10/mo
// for a free account). Moreover NO ParaSend tier is truly unlimited: even
// enterprise is capped at ENTERPRISE_MONTHLY_CEILING, not Infinity. This test
// pins that fact so a future "unlimited transfers" claim cannot slip in silently
// via a ParaSign grant. Mick decides: bundle a ParaSend entitlement into
// ParaSign Pro, or drop the line from the page.
test('FINDING: a parasign=pro grant does NOT grant unlimited transfers (page overclaim)', () => {
  const acct = freeAccount();
  ent.applyProductTier(acct, 'parasign', 'pro');
  const transfers = ent.getEntitlements(acct).parasend.quotas.transfers_month;
  assert.strictEqual(transfers, 10, 'ParaSign Pro grant leaves transfers at the free ParaSend cap, NOT unlimited');
  // And the highest ParaSend tier is finite, so "unlimited" is not a real tier.
  assert.strictEqual(ent.PARASEND.enterprise.quotas.transfers_month, ent.ENTERPRISE_MONTHLY_CEILING);
  assert.notStrictEqual(ent.PARASEND.enterprise.quotas.transfers_month, Infinity, 'no ParaSend tier is truly unlimited');
});
