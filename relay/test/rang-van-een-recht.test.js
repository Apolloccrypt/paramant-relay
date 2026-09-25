'use strict';
// Wat een tweede aankoop, een cadeaucode of een herstart met een lopend recht
// doet. Bevindingen R2, R3, R8 en R9 uit de betaaltest van 25-09-2026.
//
// R2  Een Firm-jaarklant die een maand Business kocht, kreeg dertien maanden
//     Business: de maand werd opgeteld bij de einddatum van het Firm-jaar.
// R3  Een Business-klant die Firm kocht, of een code inwisselde, stond daarna
//     op ParaSign Pro. Alleen op de relay die het verzoek deed: de andere
//     nemen uit redis geen lager recht over, dus de vloot werd het oneens.
// R8  De kassa verkocht de losse Pro-plannen die geen pagina meer verkoopt.
// R9  Na een herstart vergat de relay dat een termijn Firm was, en de klant
//     kreeg twee waarschuwingsmails over twee plannen die hij nooit kocht.
//
// Dit bestand pint de regels zelf, zonder relay. De weg van de koper over twee
// echte relays staat in tests/rang-en-kassa.test.mjs.
// Run: node --test relay/test/rang-van-een-recht.test.js

const test = require('node:test');
const assert = require('node:assert/strict');

const billing = require('../lib/billing');
const catalog = require('../lib/billing-catalog');
const entitlements = require('../lib/entitlements');
const keysTable = require('../lib/keys-table');
const planExpiry = require('../lib/plan-expiry');

const DAY = 86400000;
const NOW = new Date('2026-09-25T10:00:00.000Z');
const ACCOUNT = 'acct_rang';

// Wat de webhook op het account vindt en wat hij schrijft, per product. Het
// recht dat nu loopt komt uit dezelfde regel die elke poort leest.
function account(state) {
  const calls = [];
  const rec = () => {
    const r = {};
    for (const [product, v] of Object.entries(state)) {
      r[entitlements.PRODUCT_PLAN_FIELD[product]] = v.tier;
      if (v.paidUntil) r[entitlements.PRODUCT_PAID_UNTIL_FIELD[product]] = v.paidUntil;
    }
    return r;
  };
  return {
    calls,
    state,
    deps: {
      now: NOW,
      currentPaidUntil: async (_a, product) => (state[product] && state[product].paidUntil) || null,
      currentTier: async (_a, product) => entitlements.effectiveProductTier(rec(), product, NOW.getTime()).tier,
      setProductPlan: async (_a, product, tier, paidUntil, bundle) => {
        const iso = paidUntil ? new Date(paidUntil).toISOString() : null;
        calls.push({ product, tier, paidUntil: iso, bundle: bundle || null });
        state[product] = { tier, paidUntil: iso };
        return { ok: true, product, tier };
      },
    },
  };
}

function payment(product, plan, interval, id) {
  const order = catalog.resolveOrder({ product, plan, interval });
  return {
    id: id || `tr_${product}_${plan}_${interval}`,
    status: 'paid',
    amount: { currency: 'EUR', value: order.amount },
    metadata: { accountId: ACCOUNT, product, plan, interval },
  };
}

// ── R2 ───────────────────────────────────────────────────────────────────────

test('R2: een Business-maand na een Firm-jaar geeft een maand Business, geen dertien', async () => {
  const yearEnd = '2027-09-25T10:00:00.000Z';
  const a = account({
    parasign: { tier: 'pro', paidUntil: yearEnd },
    parasend: { tier: 'pro', paidUntil: yearEnd },
  });
  const out = await billing.processPayment(payment('parasign', 'business', 'monthly'), a.deps);
  assert.equal(out.result, 'granted');
  const sign = a.calls.find((c) => c.product === 'parasign');
  assert.ok(sign, 'Business werd niet toegekend');
  assert.equal(sign.tier, 'business');
  assert.equal(sign.paidUntil, '2026-10-25T10:00:00.000Z',
    'een betaalde Business-maand loopt een maand vanaf nu, niet een maand na het einde van het Firm-jaar');
  assert.equal(a.state.parasend.paidUntil, yearEnd, 'Versturen hoort bij Firm en blijft staan');
});

test('R2: dezelfde tier verlengen blijft tellen vanaf de bestaande einddatum', async () => {
  // De regel die R2 niet mocht breken: wie vroeg verlengt, verliest geen dag.
  const end = new Date(NOW.getTime() + 10 * DAY).toISOString();
  const a = account({
    parasign: { tier: 'pro', paidUntil: end },
    parasend: { tier: 'pro', paidUntil: end },
  });
  const out = await billing.processPayment(payment('firm', 'firm', 'monthly'), a.deps);
  assert.equal(out.result, 'granted');
  for (const product of ['parasign', 'parasend']) {
    assert.equal(a.state[product].tier, 'pro');
    assert.equal(a.state[product].paidUntil, '2026-11-05T10:00:00.000Z', `${product}: een maand na de lopende einddatum`);
  }
});

// ── R3 ───────────────────────────────────────────────────────────────────────

test('R3: een Firm-betaling zet een lopende Business-termijn niet terug naar Pro', async () => {
  const bizEnd = '2026-10-25T10:00:00.000Z';
  const a = account({
    parasign: { tier: 'business', paidUntil: bizEnd },
    parasend: { tier: 'community' },
  });
  const out = await billing.processPayment(payment('firm', 'firm', 'monthly'), a.deps);
  assert.equal(out.result, 'granted', 'het geld is binnen, de betaling blijft een toekenning met factuur');
  assert.deepEqual(a.state.parasign, { tier: 'business', paidUntil: bizEnd },
    'de lopende Business-termijn blijft precies wat hij was');
  assert.ok(!a.calls.some((c) => c.product === 'parasign'), 'er wordt niets over Business heen geschreven');
  assert.equal(a.state.parasend.tier, 'pro', 'wat Firm er wel bij geeft, komt er wel bij');
  assert.equal(a.state.parasend.paidUntil, '2026-10-25T10:00:00.000Z');
  assert.deepEqual((out.kept || []).map((k) => `${k.product}:${k.tier}`), ['parasign:business']);
});

test('R3: een verlopen Business-termijn telt niet meer als hoger recht', async () => {
  const a = account({
    parasign: { tier: 'business', paidUntil: new Date(NOW.getTime() - DAY).toISOString() },
    parasend: { tier: 'community' },
  });
  await billing.processPayment(payment('firm', 'firm', 'monthly'), a.deps);
  assert.equal(a.state.parasign.tier, 'pro');
  assert.equal(a.state.parasign.paidUntil, '2026-10-25T10:00:00.000Z');
});

test('R3: de regel zelf, per product', () => {
  // Wat er loopt tegenover wat er binnenkomt.
  assert.equal(entitlements.termRelation('parasign', 'pro', 'free'), 'none');
  assert.equal(entitlements.termRelation('parasign', 'pro', 'pro'), 'same');
  assert.equal(entitlements.termRelation('parasign', 'pro', 'business'), 'higher_running');
  assert.equal(entitlements.termRelation('parasign', 'pro', 'enterprise'), 'higher_running');
  assert.equal(entitlements.termRelation('parasign', 'business', 'pro'), 'lower_running');
  assert.equal(entitlements.termRelation('parasend', 'pro', 'community'), 'none');
  assert.equal(entitlements.termRelation('parasend', 'pro', 'enterprise'), 'higher_running');
  // Een verlopen termijn is de vloer, ook als er nog business in het veld staat.
  const lapsed = { plan_parasign: 'business', paid_until_parasign: new Date(NOW.getTime() - DAY).toISOString() };
  assert.equal(entitlements.termRelationOf(lapsed, 'parasign', 'pro', NOW.getTime()), 'none');
  // En een termijn zonder einddatum loopt.
  assert.equal(entitlements.termRelationOf({ plan_parasign: 'business' }, 'parasign', 'pro', NOW.getTime()), 'higher_running');
});

// ── R8 ───────────────────────────────────────────────────────────────────────

test('R8: de kassa verkoopt alleen wat de site verkoopt', () => {
  for (const { product, plan } of catalog.ON_SALE) {
    for (const interval of catalog.INTERVALS) {
      const sale = catalog.resolveSale({ product, plan, interval });
      assert.ok(!sale.error, `${product}/${plan}/${interval} staat op de site en moet te koop zijn`);
      assert.equal(sale.amount, catalog.priceOf(product, plan, interval));
    }
  }
  for (const [product, plan] of [['parasign', 'pro'], ['parasend', 'pro']]) {
    assert.equal(catalog.resolveSale({ product, plan, interval: 'monthly' }).error, 'not_on_sale',
      `${product}/${plan} staat op geen enkele pagina`);
    // Maar een betaling die al binnen is, of een abonnement van voor Firm, moet
    // de webhook nog steeds kunnen toekennen.
    assert.ok(!catalog.resolveOrder({ product, plan, interval: 'monthly' }).error);
  }
  assert.equal(catalog.resolveSale({ product: 'parasign', plan: 'enterprise', interval: 'monthly' }).error, 'unknown_plan');
});

// ── R9 ───────────────────────────────────────────────────────────────────────

// Genoeg van redis voor de index en de veegronde van lib/plan-expiry.
function fakeRedis() {
  const strings = new Map();
  const zsets = new Map();
  const hashes = new Map();
  const zset = (k) => { if (!zsets.has(k)) zsets.set(k, new Map()); return zsets.get(k); };
  const hash = (k) => { if (!hashes.has(k)) hashes.set(k, new Map()); return hashes.get(k); };
  return {
    isReady: true,
    async set(k, v, opts) {
      if (opts && opts.NX && strings.has(k)) return null;
      strings.set(k, String(v));
      return 'OK';
    },
    async get(k) { return strings.has(k) ? strings.get(k) : null; },
    async del(k) { return strings.delete(k) ? 1 : 0; },
    async zAdd(k, { score, value }) { zset(k).set(value, score); return 1; },
    async zRem(k, member) { return zset(k).delete(member) ? 1 : 0; },
    async zRangeByScore(k, min, max) {
      return [...zset(k).entries()].filter(([, s]) => s >= min && s <= max).sort((a, b) => a[1] - b[1]).map(([m]) => m);
    },
    async hSet(k, f, v) { hash(k).set(f, String(v)); return 1; },
    async hGet(k, f) { const v = hash(k).get(f); return v === undefined ? null : v; },
    async hDel(k, f) { return hash(k).delete(f) ? 1 : 0; },
  };
}

test('R9: na een herstart weet de relay nog dat de termijn Firm was, en er gaat één mail', async () => {
  const ends = new Date(NOW.getTime() + 6 * DAY).toISOString();
  // Precies wat setProductPlan voor een Firm-betaling in users.json zet.
  const raw = {
    key: 'pgp_rang_firm', account_id: 'acct_rang_firm', email: 'firm@example.test', plan: 'community', active: true,
    plan_parasign: 'pro', paid_until_parasign: ends, bundle_parasign: 'firm',
    plan_parasend: 'pro', paid_until_parasend: ends, bundle_parasend: 'firm',
  };
  // En zo leest relay.js dat bestand in bij het opstarten, dus na elke deploy.
  const apiKeys = new Map([[raw.key, { plan: raw.plan, email: raw.email, active: true, ...keysTable.parseAccountFields(raw) }]]);
  const accounts = new Map();
  keysTable.rebuildKeyIndexes(apiKeys, accounts, new Map(), new Map(), () => {});
  const merged = entitlements.mergeAccountRecord(accounts.get(raw.account_id), [apiKeys.get(raw.key)], NOW.getTime());
  assert.equal(merged.bundle_parasign, 'firm', 'de bundel moet een herstart overleven, net als de einddatum');
  assert.equal(merged.bundle_parasend, 'firm');

  const redis = fakeRedis();
  await planExpiry.seedIndex(redis, [{ accountId: raw.account_id, record: { ...merged, email: raw.email } }]);
  const sent = [];
  await planExpiry.runSweep({ redis, now: NOW.getTime(), sendEmail: async (m) => { sent.push(m); return true; } });
  assert.equal(sent.length, 1, `één termijn, één waarschuwing; kwam: ${sent.map((m) => m.subject).join(' | ')}`);
  assert.match(sent[0].subject, /Firm/, 'de mail noemt het plan dat de klant kocht');
});
