'use strict';
// Fine-grained admin per-product grant: setting ONE product's tier must move only
// that product's field (plan_parasign OR plan_parasend) and leave the unified
// `plan` AND the other product untouched.
//
// These exercise the REAL primitives the relay endpoint
// (POST /v2/admin/keys/set-product-plan) and billing's setProductPlan share:
//   - entitlements.validateProductPlan : the 400 gate (reject unknown
//     product/tier, never silently floor)
//   - entitlements.applyProductTier    : the field-level mutation setProductPlan
//     applies to every account/key record
// asserted through the real entitlements.getEntitlements. No relay boot / native
// crypto core needed: entitlements.js is pure (only ./tiers).
// Run: node --test relay/test/admin-set-product-plan.test.js

const { test } = require('node:test');
const assert = require('assert');
const ent = require('../lib/entitlements');

// ── 1. parasign=pro moves ONLY plan_parasign ──────────────────────────────────
test('set-product-plan parasign=pro sets ONLY plan_parasign, leaves plan + plan_parasend', () => {
  // A community account: unified community, both products on their floor.
  const entry = { key: 'pgp_x', plan: 'community', plan_parasend: 'community', plan_parasign: 'free', parasign: false };
  const before = ent.getEntitlements(entry);
  assert.strictEqual(before.parasign.tier, 'free');
  assert.strictEqual(before.parasend.tier, 'community');

  const r = ent.applyProductTier(entry, 'parasign', 'pro');
  assert.strictEqual(r.field, 'plan_parasign');
  assert.strictEqual(r.tier, 'pro');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.parasignGranted, true, 'paid parasign tier flips the access flag');

  // Only plan_parasign moved.
  assert.strictEqual(entry.plan_parasign, 'pro');
  assert.strictEqual(entry.plan_parasend, 'community', 'parasend field must be UNTOUCHED');
  assert.strictEqual(entry.plan, 'community', 'unified plan must be UNTOUCHED');
  assert.strictEqual(entry.parasign, true, 'parasign access flag granted on paid parasign tier');

  // Entitlements: ParaSign now pro, ParaSend unchanged.
  const after = ent.getEntitlements(entry);
  assert.strictEqual(after.parasign.tier, 'pro', 'ParaSign entitlement is now pro');
  assert.strictEqual(after.parasend.tier, 'community', 'ParaSend entitlement unchanged');
});

// ── 2. parasend=pro moves ONLY plan_parasend and never touches the parasign flag ─
test('set-product-plan parasend=pro sets ONLY plan_parasend, leaves plan + plan_parasign', () => {
  const entry = { key: 'pgp_y', plan: 'community', plan_parasend: 'community', plan_parasign: 'free', parasign: false };
  const r = ent.applyProductTier(entry, 'parasend', 'pro');
  assert.strictEqual(r.field, 'plan_parasend');
  assert.strictEqual(r.parasignGranted, false, 'a parasend change never flips the parasign access flag');
  assert.strictEqual(entry.plan_parasend, 'pro');
  assert.strictEqual(entry.plan_parasign, 'free', 'parasign field must be UNTOUCHED');
  assert.strictEqual(entry.plan, 'community', 'unified plan must be UNTOUCHED');
  assert.strictEqual(entry.parasign, false, 'parasign access flag must stay off');

  const after = ent.getEntitlements(entry);
  assert.strictEqual(after.parasend.tier, 'pro');
  assert.strictEqual(after.parasign.tier, 'free', 'ParaSign entitlement unchanged');
});

// ── 3. a paid account keeps its other product when one product changes ────────
test('parasign business on a pro-parasend account leaves parasend at pro', () => {
  const entry = { key: 'pgp_z', plan: 'pro', plan_parasend: 'pro', plan_parasign: 'pro', parasign: true };
  ent.applyProductTier(entry, 'parasign', 'business');
  assert.strictEqual(entry.plan_parasign, 'business');
  assert.strictEqual(entry.plan_parasend, 'pro', 'other product stays put');
  assert.strictEqual(entry.plan, 'pro', 'unified plan stays put');
  const after = ent.getEntitlements(entry);
  assert.strictEqual(after.parasign.tier, 'business');
  assert.strictEqual(after.parasend.tier, 'pro');
});

// ── 4. validateProductPlan accepts valid combinations ─────────────────────────
test('validateProductPlan accepts every real product+tier on its ladder', () => {
  assert.deepStrictEqual(ent.validateProductPlan('parasign', 'free'), { ok: true, product: 'parasign', tier: 'free' });
  assert.deepStrictEqual(ent.validateProductPlan('parasign', 'business'), { ok: true, product: 'parasign', tier: 'business' });
  assert.deepStrictEqual(ent.validateProductPlan('parasend', 'community'), { ok: true, product: 'parasend', tier: 'community' });
  assert.deepStrictEqual(ent.validateProductPlan('parasend', 'enterprise'), { ok: true, product: 'parasend', tier: 'enterprise' });
});

// ── 5. invalid product => 400 (invalid_product) ───────────────────────────────
test('validateProductPlan rejects an unknown product (=> 400 invalid_product)', () => {
  const r = ent.validateProductPlan('paraseng', 'pro');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.error, 'invalid_product');
  assert.strictEqual(ent.validateProductPlan(undefined, 'pro').error, 'invalid_product');
});

// ── 6. invalid tier => 400, never a silent floor to the base tier ─────────────
test('validateProductPlan rejects a tier not on the product ladder (=> 400 invalid_tier), no silent floor', () => {
  // 'business' is NOT a parasend tier: must reject, NOT floor to community.
  const r1 = ent.validateProductPlan('parasend', 'business');
  assert.strictEqual(r1.ok, false);
  assert.strictEqual(r1.error, 'invalid_tier');
  // 'community' is NOT a parasign tier (parasign floor is 'free'): must reject.
  const r2 = ent.validateProductPlan('parasign', 'community');
  assert.strictEqual(r2.ok, false);
  assert.strictEqual(r2.error, 'invalid_tier');
  // garbage / empty / wrong type all reject
  assert.strictEqual(ent.validateProductPlan('parasign', 'ultra').error, 'invalid_tier');
  assert.strictEqual(ent.validateProductPlan('parasign', '').error, 'invalid_tier');
  assert.strictEqual(ent.validateProductPlan('parasign', 42).error, 'invalid_tier');
});

// ── 7. applyProductTier is idempotent (matches setProductPlan's changed:0) ─────
test('applyProductTier re-applying the same tier reports changed:false and touches nothing', () => {
  const entry = { plan: 'pro', plan_parasend: 'pro', plan_parasign: 'pro', parasign: true };
  const r = ent.applyProductTier(entry, 'parasign', 'pro');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.parasignGranted, false, 'already-granted flag is not re-counted');
  assert.strictEqual(entry.plan_parasend, 'pro');
  assert.strictEqual(entry.plan_parasign, 'pro');
});

// ── 8. downgrade to free clears the tier but the access flag is not auto-revoked ─
test('parasign free does not raise the access flag (only paid tiers grant it)', () => {
  const entry = { plan: 'community', plan_parasend: 'community', plan_parasign: 'pro', parasign: true };
  const r = ent.applyProductTier(entry, 'parasign', 'free');
  assert.strictEqual(entry.plan_parasign, 'free');
  assert.strictEqual(r.parasignGranted, false, 'free never sets the access flag');
  assert.strictEqual(entry.plan_parasend, 'community', 'other product untouched');
  assert.strictEqual(entry.plan, 'community', 'unified plan untouched');
});
