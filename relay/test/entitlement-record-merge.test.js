'use strict';
// Regression for the paid-upgrade-invisible bug (field report 2026-07-21).
//
// An account lives in two places: the accounts summary ({account_id, plan,
// email, primary_api_key, label}) and the api-key records. A payment writes the
// per-product tier (plan_parasign) onto the KEY records, never onto the summary.
// The ParaSign web sign gate read the summary alone, so getEntitlements fell
// back to the legacy `plan` and a paying Pro account was told "you've used both
// signatures this month" -- the free wall -- with no way past it.
//
// mergeAccountRecord is the resolver both now share. These assert that a paid
// grant on any key of the account survives the merge, that a stale free key
// cannot drag a paid account down, and that nothing regresses for accounts that
// really are on the floor tier.

const assert = require('assert');
const ent = require('../lib/entitlements');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// THE bug: summary says legacy 'community', the key carries the paid ParaSign
// tier. Reading the summary alone yields free/2 signs; the merge yields pro.
{
  const acct = { account_id: 'acc_1', plan: 'community', email: 'x@example.com' };
  const key = { plan: 'community', plan_parasign: 'pro', parasign: true, account_id: 'acc_1' };

  assert.strictEqual(ent.getEntitlements(acct).parasign.tier, 'free',
    'precondition: the bare summary really does read as free');
  assert.strictEqual(ent.getEntitlements(acct).parasign.quotas.signs_month, 2);

  const merged = ent.mergeAccountRecord(acct, [key]);
  const e = ent.getEntitlements(merged).parasign;
  assert.strictEqual(e.tier, 'pro');
  assert.strictEqual(e.quotas.signs_month, 100);
  assert.strictEqual(e.overage.rate_eur, 0.40);
  ok('paid plan_parasign on a key beats a legacy community summary');
}

// A stale free key alongside a paid one must not win: highest tier per product.
{
  const merged = ent.mergeAccountRecord(
    { account_id: 'acc_2', plan: 'community' },
    [{ plan_parasign: 'free' }, { plan_parasign: 'pro', parasign: true }, { plan_parasign: 'free' }],
  );
  assert.strictEqual(ent.getEntitlements(merged).parasign.tier, 'pro');
  assert.strictEqual(merged.parasign, true);
  ok('highest ParaSign tier across the account wins, order-independent');
}

// The two products stay independent through the merge.
{
  const merged = ent.mergeAccountRecord(
    { account_id: 'acc_3', plan: 'community' },
    [{ plan_parasign: 'business' }, { plan_parasend: 'pro' }],
  );
  const e = ent.getEntitlements(merged);
  assert.strictEqual(e.parasign.tier, 'business');
  assert.strictEqual(e.parasend.tier, 'pro');
  ok('parasign and parasend merge independently');
}

// No paid grant anywhere: the account genuinely stays on the floor tier.
{
  const merged = ent.mergeAccountRecord({ account_id: 'acc_4', plan: 'community' }, [{ plan: 'community' }]);
  assert.strictEqual(ent.getEntitlements(merged).parasign.tier, 'free');
  assert.strictEqual(ent.getEntitlements(merged).parasign.quotas.signs_month, 2);
  ok('an unpaid account still reads as free (no accidental over-grant)');
}

// Garbage tiers must not be treated as higher than a real one.
{
  const merged = ent.mergeAccountRecord({ account_id: 'acc_5', plan: 'community' },
    [{ plan_parasign: 'pro' }, { plan_parasign: 'platinum' }]);
  assert.strictEqual(ent.getEntitlements(merged).parasign.tier, 'pro');
  ok('an unknown tier string never outranks a real one');
}

// Inputs are not mutated (the caller hands in live in-memory records).
{
  const acct = { account_id: 'acc_6', plan: 'community' };
  const key = { plan_parasign: 'pro' };
  ent.mergeAccountRecord(acct, [key]);
  assert.strictEqual(acct.plan_parasign, undefined);
  assert.strictEqual(key.parasign, undefined);
  ok('merge does not mutate the account or key records');
}

// Degenerate inputs.
{
  assert.strictEqual(ent.mergeAccountRecord(null, []), null);
  assert.strictEqual(ent.mergeAccountRecord(null, null), null);
  const keyOnly = ent.mergeAccountRecord(null, [{ plan_parasign: 'pro' }]);
  assert.strictEqual(ent.getEntitlements(keyOnly).parasign.tier, 'pro');
  ok('unknown account -> null; key-only account still resolves');
}

console.log(`\nentitlement-record-merge: ${passed} assertions passed`);
