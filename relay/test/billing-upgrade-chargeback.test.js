'use strict';
// Review #555, M2: Pro year (tr_A), then a Business month on top (tr_B,
// which pauses the Pro year), then a chargeback on tr_B. The pause was undone
// and then the floor path wiped every term: the customer lost the Pro year
// he paid for. A chargeback on the upgrade takes back only the upgrade.
// Run: node --test relay/test/billing-upgrade-chargeback.test.js
const { test } = require('node:test');
const assert = require('assert');
const billing = require('../lib/billing');
const ent = require('../lib/entitlements');
const cat = require('../lib/billing-catalog');
const vat = require('../lib/vat');

function harness() {
  const rec = {};
  const ledger = new Map();
  const setProductPlan = (a, p, t, u, b, o) => { ent.applyProductTier(rec, p, t, u, b, o); return { ok: true }; };
  const deps = {
    setProductPlan,
    currentTermEnd: async (a, p, t) => ent.termEndOf(rec, p, t),
    isProcessed: async (id) => (ledger.get(id) || {}).val || false,
    periodOf: async (id) => (ledger.get(id) || {}).grants || null,
    pauseLowerTerms: async (a, product, tier, span) => {
      const moved = []; const now = Date.now();
      for (const t of ent.termsOf(rec, product)) {
        if (t.until === null || t.tier === ent.floorTierOf(product)) continue;
        if (ent.termRelation(product, t.tier, tier) !== 'higher_running') continue;
        const end = new Date(t.until).getTime();
        if (!(end > now)) continue;
        setProductPlan(a, product, t.tier, new Date(end + span), t.bundle || null);
        moved.push({ tier: t.tier, by: span });
      }
      return moved;
    },
    markProcessed: async (id, val, extra) => { const prev = ledger.get(id); ledger.set(id, { val, grants: (extra && extra.grants) || (prev && prev.grants) }); },
  };
  return { rec, deps };
}
const pay = (id, plan, interval, status, extra = {}) => {
  const o = cat.resolveOrder({ product: 'parasign', plan, interval });
  return { id, status, amount: { value: vat.chargeAmount(o, vat.termsFromMetadata({})), currency: 'EUR' }, metadata: { accountId: 'acct_demo', product: 'parasign', plan, interval }, ...extra };
};

test('a chargeback on a Business month keeps the paid Pro year', async () => {
  const { rec, deps } = harness();
  assert.strictEqual((await billing.processPayment(pay('tr_A', 'pro', 'yearly', 'paid'), deps)).result, 'granted');
  const proEnd = ent.termEndOf(rec, 'parasign', 'pro');
  assert.strictEqual((await billing.processPayment(pay('tr_B', 'business', 'monthly', 'paid'), deps)).result, 'granted');
  const cb = pay('tr_B', 'business', 'monthly', 'charged_back', { amountChargedBack: { value: pay('tr_B', 'business', 'monthly').amount.value, currency: 'EUR' } });
  const r = await billing.processPayment(cb, deps);
  assert.strictEqual(r.result, 'revoked');
  const terms = ent.termsOf(rec, 'parasign');
  const pro = terms.find((t) => t.tier === 'pro');
  assert.ok(pro, 'the Pro year is still there: ' + JSON.stringify(terms));
  assert.strictEqual(new Date(pro.until).getTime(), new Date(proEnd).getTime(), 'with the end it had before the upgrade');
  assert.strictEqual(ent.effectiveProductTier(rec, 'parasign').tier, 'pro');
  assert.ok(!terms.some((t) => t.tier === 'business' && t.until > Date.now()), 'Business is gone');
});

test('a chargeback on a lone payment still drops to the floor', async () => {
  const { rec, deps } = harness();
  await billing.processPayment(pay('tr_C', 'pro', 'monthly', 'paid'), deps);
  const cb = pay('tr_C', 'pro', 'monthly', 'charged_back', { amountChargedBack: { value: pay('tr_C', 'pro', 'monthly').amount.value, currency: 'EUR' } });
  assert.strictEqual((await billing.processPayment(cb, deps)).result, 'revoked');
  assert.strictEqual(ent.effectiveProductTier(rec, 'parasign').tier, ent.floorTierOf('parasign'));
});
