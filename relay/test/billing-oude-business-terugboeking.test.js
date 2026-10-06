'use strict';
// Review #573, M2. Een Business-order levert sinds 3.1.1 ook ParaSend Pro mee
// (een inbegrepen grant). Een Business-betaling van voor die release kocht dat
// niet: het grootboek kent alleen de ParaSign-periode, of helemaal niets. Een
// refund of chargeback van zo'n oude betaling mag de ParaSend Pro-termijn van
// een betaald Firm-jaar niet wissen.
// Run: node --test relay/test/billing-oude-business-terugboeking.test.js
const { test } = require('node:test');
const assert = require('assert');
const billing = require('../lib/billing');
const ent = require('../lib/entitlements');
const cat = require('../lib/billing-catalog');
const vat = require('../lib/vat');

const DAY = 86400000;

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
  return { rec, ledger, deps };
}
const amount = (product, plan, interval) => vat.chargeAmount(cat.resolveOrder({ product, plan, interval }), vat.termsFromMetadata({}));
const pay = (id, product, plan, interval, status, extra = {}) => ({
  id, status, amount: { value: amount(product, plan, interval), currency: 'EUR' },
  metadata: { accountId: 'acct_demo', product, plan, interval }, ...extra,
});
const refund = (id) => pay(id, 'parasign', 'business', 'monthly', 'refunded', { amountRefunded: { value: amount('parasign', 'business', 'monthly'), currency: 'EUR' } });
const chargeback = (id) => pay(id, 'parasign', 'business', 'monthly', 'charged_back', { amountChargedBack: { value: amount('parasign', 'business', 'monthly'), currency: 'EUR' } });

async function firmYear(h) {
  assert.strictEqual((await billing.processPayment(pay('tr_firm', 'firm', 'firm', 'yearly', 'paid'), h.deps)).result, 'granted');
  const send = ent.termsOf(h.rec, 'parasend').find((t) => t.tier === 'pro');
  assert.ok(send, 'het Firm-jaar draagt ParaSend Pro');
  return send.until;
}

test('refund van een oude Business-betaling (grootboek zonder ParaSend) laat de ParaSend Pro van het Firm-jaar staan', async () => {
  const h = harness();
  const sendEnd = await firmYear(h);
  // De oude grant zoals de vorige release hem schreef: alleen ParaSign Business,
  // Pro gepauzeerd, grootboek zonder parasend.
  const now = Date.now(); const span = 30 * DAY; const until = new Date(now + span);
  ent.applyProductTier(h.rec, 'parasign', 'business', until, null);
  const pro = ent.termsOf(h.rec, 'parasign').find((t) => t.tier === 'pro');
  ent.applyProductTier(h.rec, 'parasign', 'pro', new Date(pro.until + span), 'firm');
  h.ledger.set('tr_old', { val: 'granted', grants: [{ product: 'parasign', tier: 'business', from: new Date(now).toISOString(), until: until.toISOString(), paused: [{ tier: 'pro', by: span }] }] });

  const r = await billing.processPayment(refund('tr_old'), h.deps);
  assert.strictEqual(r.result, 'revoked');
  const send = ent.termsOf(h.rec, 'parasend').find((t) => t.tier === 'pro');
  assert.ok(send, 'ParaSend Pro staat er nog: ' + JSON.stringify(ent.termsOf(h.rec, 'parasend')));
  assert.strictEqual(send.until, sendEnd, 'met dezelfde einddatum');
  assert.strictEqual(ent.effectiveProductTier(h.rec, 'parasend').tier, 'pro');
  assert.strictEqual(ent.effectiveProductTier(h.rec, 'parasign').tier, 'pro', 'ParaSign valt terug op het Firm-jaar');
});

test('chargeback van een Business-betaling zonder grootboek laat de ParaSend Pro van het Firm-jaar staan', async () => {
  const h = harness();
  const sendEnd = await firmYear(h);
  ent.applyProductTier(h.rec, 'parasign', 'business', new Date(Date.now() + 30 * DAY), null);
  const r = await billing.processPayment(chargeback('tr_pre'), h.deps);
  assert.strictEqual(r.result, 'revoked');
  const send = ent.termsOf(h.rec, 'parasend').find((t) => t.tier === 'pro');
  assert.ok(send, 'ParaSend Pro staat er nog: ' + JSON.stringify(ent.termsOf(h.rec, 'parasend')));
  assert.strictEqual(send.until, sendEnd);
});

test('refund van een nieuwe Business-betaling neemt de meegeleverde ParaSend Pro wel terug', async () => {
  const h = harness();
  assert.strictEqual((await billing.processPayment(pay('tr_new', 'parasign', 'business', 'monthly', 'paid'), h.deps)).result, 'granted');
  assert.strictEqual(ent.effectiveProductTier(h.rec, 'parasend').tier, 'pro');
  assert.strictEqual((await billing.processPayment(refund('tr_new'), h.deps)).result, 'revoked');
  assert.strictEqual(ent.effectiveProductTier(h.rec, 'parasend').tier, 'community');
  assert.strictEqual(ent.effectiveProductTier(h.rec, 'parasign').tier, 'free');
});
