'use strict';
// ParaSign Pro perk delivery. The pricing page (frontend/pricing.html, ParaSign
// Pro card) promises, per perk:
//   1. "100 signatures a month; after that signing waits for the new month"
//   2. "500 ParaSend transfers a month - API access"
//
// These prove, per perk, what a per-product grant of parasign=pro (the exact
// effect of setProductPlan(account,'parasign','pro') and of a Mollie ParaSign
// Pro purchase) turns ON, using the REAL enforcement primitives:
//   - entitlements.getEntitlements  : the signs_month quota
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

// ── PERK 1: signatures quota ──────────────────────────────────────────────────
test('PERK signatures: parasign=pro raises the sign cap to 100, and 100 is where it stops', () => {
  const acct = freeAccount();

  // BEFORE: free = 2 signs, blocking at the included quota.
  const before = ent.getEntitlements(acct).parasign;
  assert.strictEqual(before.tier, 'free');
  assert.strictEqual(before.quotas.signs_month, 2, 'free includes 2 signatures');
  assert.strictEqual(before.overage, undefined, 'no tier carries a meter');
  assert.strictEqual(quota.signGateDecision(2, before).allowed, false, 'free blocks at 2');

  // Grant.
  ent.applyProductTier(acct, 'parasign', 'pro');

  // AFTER: 100 included, and the 101st is refused. The page used to promise
  // EUR 0.40 a signature past 100 up to 1,000; nothing ever charged for those,
  // so the included quota is the whole story on every tier now.
  const after = ent.getEntitlements(acct).parasign;
  assert.strictEqual(after.tier, 'pro');
  assert.strictEqual(after.quotas.signs_month, 100, 'pro includes 100 signatures (matches the page)');
  assert.strictEqual(after.overage, undefined, 'pro does not meter past its quota');

  // Gate behaviour: allowed at 99, blocked at 100 and past it.
  assert.strictEqual(quota.signGateDecision(99, after).allowed, true, 'the 100th signature is included');
  const capped = quota.signGateDecision(100, after);
  assert.strictEqual(capped.allowed, false, 'the 101st is refused');
  assert.strictEqual(capped.reason, 'quota');
  assert.strictEqual(capped.limit, 100);
  assert.strictEqual(quota.signGateDecision(999, after).allowed, false, 'no second, higher ceiling behind it');
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

// ── FINDING (regression-locked): the transfers line is NOT delivered ─────────
// The page's ParaSign Pro card lists a ParaSend transfers allowance, but
// transfers are a ParaSEND capacity (plan_parasend), which a ParaSign grant
// deliberately does not touch. A ParaSign-Pro customer keeps their EXISTING
// ParaSend tier (10/mo for a free account), so the card promises 500 that the
// grant does not hand over.
//
// The card no longer says "Unlimited transfers". That half was strictly false
// for everyone, because NO ParaSend tier is unbounded: even enterprise is
// capped at ENTERPRISE_MONTHLY_CEILING, not Infinity, and /pricing, /parasign,
// the dashboard and the 402 upgrade card now all quote the real 500 (see
// tests/ui-truthfulness.test.mjs, which bans the old wording site-wide). What
// this test still pins is the DELIVERY gap underneath the wording: a
// parasign=pro grant moves no ParaSend ceiling at all. Mick decides: bundle a
// ParaSend Pro entitlement into ParaSign Pro, or drop the line from the cards.
test('FINDING: a parasign=pro grant does NOT move the ParaSend transfers ceiling (page overclaim)', () => {
  const acct = freeAccount();
  ent.applyProductTier(acct, 'parasign', 'pro');
  const transfers = ent.getEntitlements(acct).parasend.quotas.transfers_month;
  assert.strictEqual(transfers, 10, 'ParaSign Pro grant leaves transfers at the free ParaSend cap, NOT at the 500 the card names');
  // And the highest ParaSend tier is finite, so no card may drop the ceiling.
  assert.strictEqual(ent.PARASEND.enterprise.quotas.transfers_month, ent.ENTERPRISE_MONTHLY_CEILING);
  assert.notStrictEqual(ent.PARASEND.enterprise.quotas.transfers_month, Infinity, 'no ParaSend tier is unbounded');
});
