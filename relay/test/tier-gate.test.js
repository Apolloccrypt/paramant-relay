'use strict';
// Billing-hardening tier gate + entitlement-flag honesty.
// Proves: the per-product Pro+/Business predicates deny the free floor and admit
// paid tiers (tasks 2/4/5/6 all gate through these); the `business` plan is now
// ParaSign-entitled on plan name alone (task 1); and the entitlement layer no
// longer advertises dead flags (task 3: api_access/priority_relay removed,
// audit_export kept because it now drives the audit-export gate).

const { test } = require('node:test');
const assert = require('assert');
const tg = require('../lib/tier-gate');
const keys = require('../lib/keys-table');
const ent = require('../lib/entitlements');

// ── ParaSend Pro+ (webhooks task 2, notifications task 6) ─────────────────────
test('ParaSend Pro+: community/free denied, pro/business/enterprise allowed', () => {
  assert.strictEqual(tg.isParasendProPlus({ plan: 'community' }), false);
  assert.strictEqual(tg.isParasendProPlus({ plan: 'free' }), false);
  assert.strictEqual(tg.isParasendProPlus({ plan: 'pro' }), true);
  assert.strictEqual(tg.isParasendProPlus({ plan: 'business' }), true);   // -> parasend enterprise
  assert.strictEqual(tg.isParasendProPlus({ plan: 'enterprise' }), true);
  assert.strictEqual(tg.isParasendProPlus(null), false);                  // malformed never over-grants
  assert.strictEqual(tg.isParasendProPlus({ plan_parasend: 'bogus' }), false);
});

// ── ParaSign Pro+ (history task 4 uses either product) ────────────────────────
test('ParaSign Pro+: free denied, pro/business/enterprise allowed', () => {
  assert.strictEqual(tg.isParasignProPlus({ plan: 'community' }), false); // -> parasign free
  assert.strictEqual(tg.isParasignProPlus({ plan: 'pro' }), true);
  assert.strictEqual(tg.isParasignProPlus({ plan: 'business' }), true);
  assert.strictEqual(tg.isParasignProPlus({ plan: 'enterprise' }), true);
});

// ── history: Pro+ on EITHER product ───────────────────────────────────────────
test('history allowed when Pro+ on either product, denied when free on both', () => {
  assert.strictEqual(tg.isHistoryAllowed({ plan_parasend: 'community', plan_parasign: 'free' }), false);
  assert.strictEqual(tg.isHistoryAllowed({ plan_parasend: 'pro', plan_parasign: 'free' }), true);
  assert.strictEqual(tg.isHistoryAllowed({ plan_parasend: 'community', plan_parasign: 'pro' }), true);
});

// ── audit export: Business+ only ──────────────────────────────────────────────
test('audit export gated Business+ (pro denied)', () => {
  assert.strictEqual(tg.isAuditExportAllowed({ plan: 'pro' }), false);
  assert.strictEqual(tg.isAuditExportAllowed({ plan_parasign: 'pro' }), false);
  assert.strictEqual(tg.isAuditExportAllowed({ plan: 'business' }), true);
  assert.strictEqual(tg.isAuditExportAllowed({ plan: 'enterprise' }), true);
});

// ── task 1: business is ParaSign-entitled on plan name alone ──────────────────
test('business plan carries the ParaSign entitlement without a per-key flag', () => {
  assert.strictEqual(keys.PARASIGN_ENTITLED_PLANS.has('business'), true);
  assert.strictEqual(keys.accountHasParasignEntitlement([], 'business'), true);
  assert.strictEqual(keys.accountHasParasignEntitlement([], 'community'), false); // control
});

// ── task 3: entitlement layer no longer advertises dead flags ─────────────────
test('dead entitlement flags removed; audit_export kept and live', () => {
  const proSign = ent.getEntitlements({ plan_parasign: 'pro' }).parasign.features;
  const bizSign = ent.getEntitlements({ plan_parasign: 'business' }).parasign.features;
  assert.strictEqual('api_access' in proSign, false, 'api_access removed (was never read)');
  assert.strictEqual(bizSign.audit_export, true, 'audit_export kept, now drives the export gate');
  assert.strictEqual(proSign.audit_export, false, 'audit_export false below business');
  const entSend = ent.getEntitlements({ plan_parasend: 'enterprise' }).parasend.features;
  assert.strictEqual('priority_relay' in entSend, false, 'priority_relay removed (no enforcement point)');
});
