'use strict';
// The Firm plan: one price, one payment, TWO entitlements.
//
// Firm exists because the two Pro plans sold apart came to 64 euro a month
// excl. btw (ParaSign Pro 49 plus ParaSend Pro 15) while PKIsigning sells
// signing and sharing together from 14 with ISO 27001 behind it. Firm is 29 a
// month excl. btw, 290 a year, and it grants ParaSign Pro AND ParaSend Pro.
//
// What is pinned here, in the order it matters:
//   1. the amounts, and that the VAT split lands on the cent
//   2. one paid webhook sets BOTH entitlements, with one paid_until
//   3. a chargeback puts BOTH back on their floor tier
//   4. an existing ParaSign Pro or ParaSend Pro customer loses nothing:
//      his plan still resolves, and a Firm purchase never shortens a term he
//      has already paid for
//   5. the invoice line, the credit note and the expiry mail all name Firm and
//      say which products it covers
// Run: node relay/test/billing-firm.test.js (exits non-zero on failure).

const assert = require('assert');
const catalog = require('../lib/billing-catalog');
const billing = require('../lib/billing');
const entitlements = require('../lib/entitlements');
const invoice = require('../lib/invoice');
const creditNote = require('../lib/credit-note');
const planExpiry = require('../lib/plan-expiry');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

// Records every (account, product, tier, paidUntil, bundle) the state machine set.
function spySetter(current) {
  const calls = [];
  const state = current || {};
  const fn = async (accountId, product, tier, paidUntil, bundle) => {
    calls.push({ accountId, product, tier, paidUntil: paidUntil ? new Date(paidUntil).toISOString() : null, bundle: bundle || null });
    state[product] = { tier, paidUntil: paidUntil ? new Date(paidUntil).toISOString() : null };
    return { ok: true, product, tier };
  };
  fn.calls = calls;
  fn.state = state;
  return fn;
}

function firmPayment(over = {}) {
  return Object.assign({
    id: 'tr_FIRM1',
    status: 'paid',
    amount: { currency: 'EUR', value: '35.09' },
    metadata: { accountId: 'acct_firm', product: 'firm', plan: 'firm', interval: 'monthly' },
  }, over);
}

// A tiny redis stand-in: enough of the v4 surface for issueDocument and the
// credit-note path. Same pattern the invoice unit tests use.
function fakeRedis() {
  const m = new Map();
  const lists = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v, opts) {
      if (opts && opts.NX && m.has(k)) return null;
      m.set(k, String(v));
      return 'OK';
    },
    async incr(k) { const n = (parseInt(m.get(k) || '0', 10) || 0) + 1; m.set(k, String(n)); return n; },
    async rPush(k, v) { const l = lists.get(k) || []; l.push(v); lists.set(k, l); return l.length; },
    async lRange(k, a, b) {
      const l = lists.get(k) || [];
      const end = b === -1 ? l.length : b + 1;
      return l.slice(a < 0 ? Math.max(0, l.length + a) : a, end);
    },
    async del(k) { return m.delete(k) ? 1 : 0; },
    _map: m,
  };
}

async function main() {
  // ── 1. the amounts, and the VAT split ──────────────────────────────────────
  {
    const monthly = catalog.resolveOrder({ product: 'firm', plan: 'firm', interval: 'monthly' });
    const yearly = catalog.resolveOrder({ product: 'firm', plan: 'firm', interval: 'yearly' });
    assert.strictEqual(monthly.amount, '35.09');
    assert.strictEqual(yearly.amount, '350.90');
    assert.strictEqual(monthly.currency, 'EUR');
    assert.strictEqual(monthly.bundle, 'firm');
    ok('catalog sells firm at 35.09 a month and 350.90 a year, incl. 21% btw');

    // 29 and 290 excl. btw, exactly. An invoice whose net plus VAT is not the
    // amount collected is a wrong invoice, so this has to land on the cent.
    const m = invoice.splitVat(monthly.amount, invoice.CATALOG_VAT_RATE);
    assert.deepStrictEqual(m, { rate: 21, gross_cents: 3509, net_cents: 2900, vat_cents: 609 });
    assert.strictEqual(invoice.money(m.net_cents), '29.00');
    assert.strictEqual(invoice.money(m.vat_cents), '6.09');
    assert.strictEqual(m.net_cents + m.vat_cents, m.gross_cents);
    const y = invoice.splitVat(yearly.amount, invoice.CATALOG_VAT_RATE);
    assert.deepStrictEqual(y, { rate: 21, gross_cents: 35090, net_cents: 29000, vat_cents: 6090 });
    assert.strictEqual(invoice.money(y.net_cents), '290.00');
    assert.strictEqual(invoice.money(y.vat_cents), '60.90');
    assert.strictEqual(y.net_cents + y.vat_cents, y.gross_cents);
    ok('the VAT split is exact: 29.00 + 6.09 = 35.09 and 290.00 + 60.90 = 350.90');

    // Two months free, stated as the percentage the page prints.
    const pct = (1 - (35090 / (3509 * 12))) * 100;
    assert.strictEqual(pct.toFixed(1), '16.7');
    ok('the yearly price is two months free (16.7% off), the figure /pricing prints');
  }

  // ── the bundle is not a third entitlement product ──────────────────────────
  {
    assert.deepStrictEqual(catalog.PRODUCTS.slice(), ['parasend', 'parasign']);
    assert.deepStrictEqual(entitlements.PRODUCTS.slice(), ['parasend', 'parasign']);
    assert.deepStrictEqual(
      catalog.grantsOf('firm', 'firm').map((g) => `${g.product}:${g.tier}`),
      ['parasign:pro', 'parasend:pro'],
    );
    assert.strictEqual(catalog.grantsOf('firm', 'pro'), null);
    assert.strictEqual(catalog.resolveOrder({ product: 'firm', plan: 'pro', interval: 'monthly' }).error, 'unknown_plan');
    ok('firm is a bundle over the two real products, not a product of its own');
  }

  // ── what /pricing sells, and what it still honours ─────────────────────────
  {
    assert.ok(catalog.isOnSale('firm', 'firm'));
    assert.ok(catalog.isOnSale('parasign', 'business'));
    assert.ok(!catalog.isOnSale('parasign', 'pro'));
    assert.ok(!catalog.isOnSale('parasend', 'pro'));
    // Off the page, still in the catalog: an outstanding renewal link and a
    // Mollie subscription created before Firm carry {parasign, pro} metadata,
    // and refusing those would take the money and grant nothing.
    assert.strictEqual(catalog.resolveOrder({ product: 'parasign', plan: 'pro', interval: 'monthly' }).amount, '59.29');
    assert.strictEqual(catalog.resolveOrder({ product: 'parasend', plan: 'pro', interval: 'yearly' }).amount, '181.50');
    ok('the two Pro rows are off sale but still resolve, so old links and subscriptions still grant');
  }

  // ── 2. one payment, two entitlements, one paid_until ───────────────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(firmPayment(), {
      setProductPlan: set,
      now: new Date('2026-09-06T10:00:00.000Z'),
      currentPaidUntil: async () => null,
    });
    assert.strictEqual(r.result, 'granted');
    assert.strictEqual(r.bundle, 'firm');
    assert.strictEqual(set.calls.length, 2);
    assert.deepStrictEqual(set.calls.map((c) => `${c.product}:${c.tier}`), ['parasign:pro', 'parasend:pro']);
    assert.strictEqual(set.calls[0].paidUntil, '2026-10-06T10:00:00.000Z');
    assert.strictEqual(set.calls[1].paidUntil, set.calls[0].paidUntil, 'both products get the SAME paid_until');
    assert.strictEqual(set.calls[0].bundle, 'firm');
    assert.strictEqual(set.calls[1].bundle, 'firm');
    ok('one paid Firm webhook sets parasign pro AND parasend pro with one paid_until');
  }

  // ── the amount still comes from the catalog, never from the body ───────────
  {
    const set = spySetter();
    const r = await billing.processPayment(firmPayment({ amount: { currency: 'EUR', value: '1.00' } }), { setProductPlan: set });
    assert.strictEqual(r.result, 'refused');
    assert.strictEqual(r.level, 'error');
    assert.match(r.reason, /amount_mismatch/);
    assert.strictEqual(set.calls.length, 0, 'nothing was granted');
    ok('a Firm payment for the wrong amount grants nothing');
  }

  // ── a yearly Firm payment buys twelve months on both ───────────────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(firmPayment({
      id: 'tr_FIRMY', amount: { currency: 'EUR', value: '350.90' },
      metadata: { accountId: 'acct_firm', product: 'firm', plan: 'firm', interval: 'yearly' },
    }), { setProductPlan: set, now: new Date('2026-09-06T10:00:00.000Z'), currentPaidUntil: async () => null });
    assert.strictEqual(r.result, 'granted');
    assert.strictEqual(r.paidUntil, '2027-09-06T10:00:00.000Z');
    assert.ok(set.calls.every((c) => c.paidUntil === '2027-09-06T10:00:00.000Z'));
    ok('a yearly Firm payment carries both products a calendar year forward');
  }

  // ── 3. chargeback puts BOTH products back on their floor ───────────────────
  {
    const set = spySetter();
    const r = await billing.processPayment(firmPayment({ status: 'chargeback' }), { setProductPlan: set });
    assert.strictEqual(r.result, 'revoked');
    assert.strictEqual(set.calls.length, 2);
    assert.deepStrictEqual(set.calls.map((c) => `${c.product}:${c.tier}`), ['parasign:free', 'parasend:community']);
    assert.ok(set.calls.every((c) => c.paidUntil === null), 'the paid period is cleared with the tier');
    ok('a Firm chargeback drops parasign to free AND parasend to community');
  }
  {
    const set = spySetter();
    const r = await billing.processPayment(firmPayment({ status: 'charged_back' }), { setProductPlan: set });
    assert.strictEqual(r.result, 'revoked');
    assert.strictEqual(set.calls.length, 2);
    ok("Mollie's other spelling, charged_back, revokes both as well");
  }

  // ── a refund is money back, and money back takes the bundle back ───────────
  // Until 2026-09-06 this asserted the opposite: 'ignored', nothing moved. That
  // was the policy the 2026-09-05 review filed as a revenue leak, and it did not
  // survive being looked at. A refund reaches the webhook on the same tr_ id as
  // the payment; whether it arrives as the status string or as a counter on a
  // still-'paid' payment is a Mollie detail, not a decision about who keeps a
  // plan. Both spellings are asserted, because the counter shape is the one the
  // repo's own fake Mollie produces and it used to fall into the GRANT branch.
  {
    const set = spySetter();
    const r = await billing.processPayment(firmPayment({ status: 'refunded' }), { setProductPlan: set });
    assert.strictEqual(r.result, 'revoked');
    assert.strictEqual(r.reason, 'refund');
    assert.strictEqual(set.calls.length, 2);
    ok('a refunded Firm payment takes BOTH halves of the bundle back to their floor');
  }
  {
    const set = spySetter();
    const paid = firmPayment({ status: 'paid' });
    const r = await billing.processPayment(
      firmPayment({ status: 'paid', amountRefunded: { currency: 'EUR', value: paid.amount.value } }),
      { setProductPlan: set },
    );
    assert.strictEqual(r.result, 'revoked');
    assert.strictEqual(set.calls.length, 2);
    ok('a full refund reported as a counter on a still-paid payment revokes just the same');
  }
  {
    // The other side of the same rule: a part-refund is not a cancelled sale.
    const set = spySetter();
    const r = await billing.processPayment(
      firmPayment({ status: 'paid', amountRefunded: { currency: 'EUR', value: '1.00' } }),
      { setProductPlan: set },
    );
    assert.strictEqual(r.result, 'ignored');
    assert.match(r.reason, /^partial_refund:100_of_/);
    assert.strictEqual(set.calls.length, 0);
    ok('a part-refund on a Firm bundle grants nothing and revokes nothing');
  }

  // ── 4. nobody who already pays loses anything ──────────────────────────────
  {
    // An account bought ParaSign Pro yearly before Firm existed.
    const rec = {};
    entitlements.applyProductTier(rec, 'parasign', 'pro', new Date('2027-06-01T00:00:00.000Z'));
    assert.strictEqual(rec.plan_parasign, 'pro');
    assert.strictEqual(rec.paid_until_parasign, '2027-06-01T00:00:00.000Z');
    const ent = entitlements.getEntitlements(rec, Date.parse('2026-09-06T00:00:00.000Z'));
    assert.strictEqual(ent.parasign.tier, 'pro');
    assert.strictEqual(ent.parasign.quotas.signs_month, 100);
    ok('an existing ParaSign Pro customer keeps his tier, his quota and his paid_until');

    // He now buys one month of Firm. The month is added to the product with the
    // least time left (ParaSend, which has none), and his June on ParaSign is
    // untouched: no day he has paid for is ever taken away.
    const set = spySetter();
    const r = await billing.processPayment(firmPayment({ id: 'tr_FIRM2' }), {
      setProductPlan: set,
      now: new Date('2026-09-06T10:00:00.000Z'),
      currentPaidUntil: async (_a, product) => rec[entitlements.PRODUCT_PAID_UNTIL_FIELD[product]] || null,
    });
    assert.strictEqual(r.result, 'granted');
    const bySign = set.calls.find((c) => c.product === 'parasign');
    const bySend = set.calls.find((c) => c.product === 'parasend');
    assert.strictEqual(bySend.paidUntil, '2026-10-06T10:00:00.000Z', 'ParaSend gets the month that was bought');
    assert.strictEqual(bySign.paidUntil, '2027-06-01T00:00:00.000Z', 'ParaSign keeps the longer term it already had');
    ok('buying Firm never shortens a term an existing customer already paid for');
  }
  {
    // And a ParaSend Pro customer who renews on his old link still gets exactly
    // what he always got: one product, one tier, nothing else moved.
    const set = spySetter();
    const r = await billing.processPayment({
      id: 'tr_LEGACY', status: 'paid',
      amount: { currency: 'EUR', value: '18.15' },
      metadata: { accountId: 'acct_old', product: 'parasend', plan: 'pro', interval: 'monthly' },
    }, { setProductPlan: set, now: new Date('2026-09-06T10:00:00.000Z'), currentPaidUntil: async () => null });
    assert.strictEqual(r.result, 'granted');
    assert.strictEqual(r.bundle, null);
    assert.strictEqual(set.calls.length, 1);
    assert.deepStrictEqual(set.calls[0], {
      accountId: 'acct_old', product: 'parasend', tier: 'pro',
      paidUntil: '2026-10-06T10:00:00.000Z', bundle: null,
    });
    ok('a legacy ParaSend Pro renewal still grants exactly one product');
  }

  // ── 5a. the invoice line names both products ───────────────────────────────
  {
    const order = catalog.resolveOrder({ product: 'firm', plan: 'firm', interval: 'monthly' });
    assert.strictEqual(invoice.describe(order), 'Paramant Firm (ParaSign Pro and ParaSend Pro), monthly plan');
    assert.strictEqual(
      invoice.describe(catalog.resolveOrder({ product: 'firm', plan: 'firm', interval: 'yearly' })),
      'Paramant Firm (ParaSign Pro and ParaSend Pro), yearly plan',
    );
    // The plans that are still honoured keep the description they always had.
    assert.strictEqual(invoice.describe(catalog.resolveOrder({ product: 'parasign', plan: 'pro', interval: 'yearly' })),
      'Paramant ParaSign Pro, yearly plan');
    ok('the Firm invoice line states the supply: both products, by name');
  }

  // ── 5b. a real Firm document, and the credit note that reverses it ─────────
  {
    const redis = fakeRedis();
    const order = Object.assign(
      { accountId: 'acct_firm' },
      catalog.resolveOrder({ product: 'firm', plan: 'firm', interval: 'yearly' }),
    );
    const pay = {
      id: 'tr_FIRMDOC', method: 'ideal',
      amount: { currency: 'EUR', value: '350.90' },
      paidAt: '2026-09-06T10:00:00.000Z',
    };
    const seller = invoice.sellerFromEnv({ BILLING_SELLER_VAT: 'NL861234567B01', BILLING_SELLER_ADDRESS: 'Harderwijk' });
    const out = await invoice.issueDocument({
      payment: pay, order, seller,
      buyer: { email: 'a@b.nl', company: 'Kantoor B.V.', address: 'Harderwijk' },
      now: new Date('2026-09-06T10:00:00.000Z'),
      periodEnd: '2027-09-06T10:00:00.000Z',
    }, redis);
    assert.strictEqual(out.result, 'issued');
    assert.strictEqual(out.record.kind, 'invoice');
    assert.strictEqual(out.record.description, 'Paramant Firm (ParaSign Pro and ParaSend Pro), yearly plan');
    assert.strictEqual(out.record.amount_net, '290.00');
    assert.strictEqual(out.record.amount_vat, '60.90');
    assert.strictEqual(out.record.amount_gross, '350.90');
    assert.deepStrictEqual(out.record.grants, [
      { product: 'parasign', tier: 'pro' },
      { product: 'parasend', tier: 'pro' },
    ]);
    ok('a Firm invoice carries the right number, the right split and both grants');

    const credit = await creditNote.issueCreditNote({
      payment: Object.assign({}, pay, { amountRefunded: { currency: 'EUR', value: '350.90' } }),
      now: new Date('2026-09-07T10:00:00.000Z'),
    }, redis);
    assert.strictEqual(credit.result, 'issued');
    assert.ok(credit.record.number.startsWith('CN-'), 'money back gets its own series');
    assert.strictEqual(credit.record.credit_for, out.number);
    assert.strictEqual(credit.record.amount_gross, '-350.90');
    assert.strictEqual(credit.record.amount_net, '-290.00');
    assert.strictEqual(credit.record.amount_vat, '-60.90');
    ok('a Firm invoice can be credited in full, on the cent');
  }

  // ── 5c. the expiry mail says what is ending ────────────────────────────────
  {
    const at = Date.parse('2026-10-06T10:00:00.000Z');
    const warn = planExpiry.expiryMail({ product: 'parasign', tier: 'pro', paidUntil: at, kind: 'warn', bundle: 'firm' });
    assert.strictEqual(warn.subject, 'Your Paramant Firm plan (ParaSign Pro and ParaSend Pro) ends on 6 October 2026');
    assert.ok(warn.text.includes('nothing is charged automatically'));
    const ended = planExpiry.expiryMail({ product: 'parasend', tier: 'pro', paidUntil: at, kind: 'ended', bundle: 'firm' });
    assert.strictEqual(ended.subject, 'Your Paramant Firm plan (ParaSign Pro and ParaSend Pro) has ended');
    assert.ok(ended.text.includes('now on Community'));
    // Without a bundle the mail is exactly the one it has always been.
    assert.strictEqual(
      planExpiry.expiryMail({ product: 'parasign', tier: 'pro', paidUntil: at, kind: 'ended' }).subject,
      'Your ParaSign Pro has ended',
    );
    ok('the expiry mail names Firm and both products, and is unchanged for everyone else');

    // Both index entries of one Firm term share a notice key, so the customer
    // gets ONE mail about it and not two.
    const a = planExpiry.noticeKey('warn', 'acct_firm', 'firm', '2026-10-06T10:00:00.000Z');
    const b = planExpiry.noticeKey('warn', 'acct_firm', 'firm', '2026-10-06T10:00:00.000Z');
    assert.strictEqual(a, b);
    assert.notStrictEqual(a, planExpiry.noticeKey('warn', 'acct_firm', 'parasign', '2026-10-06T10:00:00.000Z'));
    ok('one Firm term produces one notice key, so one mail and not two');
  }

  // ── the bundle marker travels with the period it was written with ──────────
  {
    const rec = {};
    entitlements.applyProductTier(rec, 'parasend', 'pro', new Date('2026-10-06T10:00:00.000Z'), 'firm');
    assert.strictEqual(rec[entitlements.PRODUCT_BUNDLE_FIELD.parasend], 'firm');
    // Back to the floor: tier, period and marker all go.
    entitlements.applyProductTier(rec, 'parasend', 'community', null, null);
    assert.strictEqual(rec.plan_parasend, 'community');
    assert.strictEqual(rec.paid_until_parasend, undefined);
    assert.strictEqual(rec[entitlements.PRODUCT_BUNDLE_FIELD.parasend], undefined);
    ok('the bundle marker is written with the term and cleared with it');
  }

  // ── 5d. the billing history reads a bundle invoice as two terms ───────────
  {
    const history = require('../lib/billing-history');
    const rec = {
      number: 'PS-2026-0007', kind: 'invoice', account_id: 'acct_firm',
      product: 'firm', plan: 'firm', interval: 'monthly',
      grants: [{ product: 'parasign', tier: 'pro' }, { product: 'parasend', tier: 'pro' }],
      description: 'Paramant Firm (ParaSign Pro and ParaSend Pro), monthly plan',
      issued_at: '2026-09-06T10:00:00.000Z',
      service_period_end: '2026-10-06T10:00:00.000Z',
      amount_gross: '35.09',
    };
    const ends = history.termEndsFromDocuments([rec], Date.parse('2026-11-01T00:00:00.000Z'));
    assert.deepStrictEqual(
      ends.map((e) => `${e.product}:${e.tier}`).sort(),
      ['parasend:pro', 'parasign:pro'],
      'one Firm invoice ends one term on each product it bought, not one term on a product called firm',
    );
    assert.ok(ends.every((e) => e.iso === '2026-10-06T10:00:00.000Z'));
    // A row the customer reads: the payment line quotes the invoice description.
    assert.strictEqual(history.productName('parasign'), 'ParaSign');
    ok('the billing history reads a Firm invoice as a term on each product');
  }

  // ── a gift code that covers both products still works beside Firm ─────────
  {
    const coupon = require('../lib/coupon');
    assert.deepStrictEqual(
      coupon.DEFAULT_GRANTS.map((g) => `${g.product}:${g.tier}`),
      ['parasign:pro', 'parasend:pro'],
      'the default gift is still both products at the tier Firm sells',
    );
    assert.strictEqual(coupon.describeGrants(coupon.DEFAULT_GRANTS),
      '3 months of ParaSign Pro and ParaSend Pro');
    // A coupon is not a sale and never becomes one: it names the products, and
    // the tiers it grants are the same tiers Firm grants, so the two paths land
    // on one entitlement layer and cannot disagree.
    const firmGrants = catalog.grantsOf('firm', 'firm').map((g) => `${g.product}:${g.tier}`);
    assert.deepStrictEqual(coupon.DEFAULT_GRANTS.map((g) => `${g.product}:${g.tier}`), firmGrants);
    ok('a gift code for both products still resolves, and grants what Firm grants');
  }

  console.log(`\n${passed} assertions passed (billing-firm)`);
}

main().catch((e) => { console.error('FAIL:', e && e.stack || e); process.exit(1); });
