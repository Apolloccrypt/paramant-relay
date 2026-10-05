'use strict';
// Server-side ParaSend / ParaSign billing catalog. THE source of truth for what a
// plan costs and which entitlement tier it grants. The checkout endpoint reads the
// amount from HERE (never from the request body), and the webhook re-checks the
// amount actually paid against HERE before granting anything. Amounts are Mollie
// decimal strings in EUR incl. 21% VAT, matching the hosted payment links.
//
// TWO SHAPES OF LINE ITEM LIVE HERE.
//
// A PRODUCT plan sells one product: parasign business, and the two `pro` rows
// that are no longer on /pricing but are still honoured for everyone who holds
// one and still resolvable for a renewal link that is already out there.
//
// A BUNDLE sells one price that grants MORE THAN ONE product. `firm` is the
// first: 29 euro a month excl. btw for ParaSign Pro AND ParaSend Pro together.
// It exists because the two Pro plans priced apart came to 64 euro a month
// excl. btw, against a competitor selling signing and sharing together from 14.
// A bundle is deliberately NOT a third entitlement product: entitlements stay
// per product (plan_parasign / plan_parasend), and a bundle simply produces two
// grants from one payment. Everything downstream that asks "what did this buy"
// reads order.grants, which a single-product order fills with exactly one entry,
// so there is one code path and not two.

const CATALOG = Object.freeze({
  parasend: {
    pro: { monthly: '18.15', yearly: '181.50' },
  },
  parasign: {
    pro:      { monthly: '59.29',  yearly: '603.79'  },
    business: { monthly: '361.79', yearly: '3617.90' },
  },
  // Firm: 29 excl. btw a month -> 35.09 incl.; 290 excl. a year -> 350.90 incl.
  // Both split on the cent: 3509 / 1.21 = 2900 and 35090 / 1.21 = 29000, so the
  // net and the VAT on the invoice add up to the amount Mollie actually took.
  firm: {
    firm: { monthly: '35.09', yearly: '350.90' },
  },
});

// The entitlement products. NOT the sellable keys: `firm` is sold but is not a
// product anything is entitled to.
const PRODUCTS = Object.freeze(['parasend', 'parasign']);
// What a checkout may name. A bundle key is legal here and nowhere else.
const SELLABLE = Object.freeze(['parasend', 'parasign', 'firm']);
const INTERVALS = Object.freeze(['monthly', 'yearly']);

// A bundle: one price, several product grants. The order of `grants` is the
// order the invoice description lists them in.
const BUNDLES = Object.freeze({
  firm: Object.freeze({
    plan: 'firm',
    label: 'Firm',
    grants: Object.freeze([
      Object.freeze({ product: 'parasign', tier: 'pro' }),
      Object.freeze({ product: 'parasend', tier: 'pro' }),
    ]),
  }),
  // Business is more than Firm (besluit 05-10-2026). It is sold under its old
  // key, product 'parasign' plan 'business', because that is what every button,
  // payment link and Mollie metadata already carries. Until 05-10 it granted
  // ParaSign alone: a Business customer kept ParaSend Community (one recipient,
  // one hour, 50 a month), /parashare then told him "with Firm you send to 30",
  // and buying Firm was refused because Business was running (betaaltest 05-10,
  // row 1). Now it also carries the ParaSend half of Firm. That half is
  // `included`: it is not what the price is for, so it never moves the anchor
  // of the term (lib/billing.processPayment), it rides on it.
  business: Object.freeze({
    plan: 'business',
    sold_as: 'parasign',
    label: 'Business',
    grants: Object.freeze([
      Object.freeze({ product: 'parasign', tier: 'business' }),
      Object.freeze({ product: 'parasend', tier: 'pro', included: true }),
    ]),
  }),
});

// The bundle a sold (product, plan) is, or null. Firm is sold under its own
// key; Business under the ParaSign key it has always had.
function bundleKeyOf(product, plan) {
  if (product === 'firm' && plan === 'firm') return 'firm';
  if (product === 'parasign' && plan === 'business') return 'business';
  return null;
}

// The name a customer sees for what he bought: on the Mollie statement, on the
// invoice line and in his billing history. One function, so those three can
// never drift into three different names for one payment.
const PRODUCT_LABEL = Object.freeze({ parasend: 'ParaSend', parasign: 'ParaSign' });
const TIER_LABEL = Object.freeze({ pro: 'Pro', business: 'Business', enterprise: 'Enterprise' });

function planLabel(product, tier) {
  return `${PRODUCT_LABEL[product] || product} ${TIER_LABEL[tier] || tier}`;
}

// "ParaSign Pro", "ParaSign Business", or for a bundle the name plus what is in
// it: "Firm (ParaSign Pro and ParaSend Pro)". The contents are spelled out
// because an invoice that says only "Firm" tells a bookkeeper nothing about
// what was supplied, and Wet OB art. 35a asks for a description of the supply.
function orderLabel(order) {
  if (!order) return '';
  const bundle = BUNDLES[order.bundle || order.product];
  if (bundle) {
    const parts = bundle.grants.map((g) => planLabel(g.product, g.tier));
    const list = parts.length > 1
      ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`
      : parts[0];
    return `${bundle.label} (${list})`;
  }
  return planLabel(order.product, order.tier || order.plan);
}

// The Dutch name for what was bought, on the Mollie statement and the invoice
// of a buyer who bought in Dutch: "Firm (versturen en ondertekenen)". The
// English orderLabel above stays the name of the record (acceptatie 3.1.1,
// betalen punt 5; taal #4: no "ParaSign Pro and ParaSend Pro" for a Dutch
// buyer). A single-product term names the product by what it does.
const PRODUCT_LABEL_NL = Object.freeze({ parasend: 'versturen', parasign: 'ondertekenen' });
const TIER_LABEL_NL = Object.freeze({ pro: 'Firm', business: 'Business', enterprise: 'Enterprise' });
function orderLabelNl(order) {
  if (!order) return '';
  const bundle = BUNDLES[order.bundle || order.product];
  if (bundle) {
    const what = [...new Set(bundle.grants.map((g) => PRODUCT_LABEL_NL[g.product]))];
    const list = what.length > 1 ? 'versturen en ondertekenen' : what[0];
    return `${bundle.label} (${list})`;
  }
  const tier = order.tier || order.plan;
  return `${TIER_LABEL_NL[tier] || tier} voor ${PRODUCT_LABEL_NL[order.product] || order.product}`;
}

// The English name on the Mollie statement of a buyer who bought in English:
// the bundle and what it is for, "Firm (sending and signing)", the words the
// site uses.
const PRODUCT_LABEL_MAIL = Object.freeze({ parasend: 'sending', parasign: 'signing' });
function orderLabelEn(order) {
  if (!order) return '';
  const bundle = BUNDLES[order.bundle || order.product];
  if (bundle) {
    const what = [...new Set(bundle.grants.map((g) => PRODUCT_LABEL_MAIL[g.product]))];
    return `${bundle.label} (${what.length > 1 ? 'sending and signing' : what[0]})`;
  }
  const tier = order.tier || order.plan;
  return `${TIER_LABEL_NL[tier] || tier} for ${PRODUCT_LABEL_MAIL[order.product] || order.product}`;
}

// What the site sells today (the buttons on /pricing and /en/pricing, pinned
// to this list by relay/test/pricing-page.test.js), and therefore the only
// thing the checkout sells (resolveSale). The two `pro` rows are NOT here and
// are still in CATALOG on purpose: an existing ParaSign Pro or ParaSend Pro customer
// keeps his entitlement and his paid_until, an outstanding renewal link still
// resolves, and a Mollie subscription created before Firm carries
// {product:'parasign', plan:'pro'} in its metadata and must still grant when it
// collects. Taking a price out of the catalog would refuse that payment with
// 'unknown_plan' after the money had already moved.
const ON_SALE = Object.freeze([
  Object.freeze({ product: 'firm', plan: 'firm' }),
  Object.freeze({ product: 'parasign', plan: 'business' }),
]);

function isOnSale(product, plan) {
  return ON_SALE.some((o) => o.product === product && o.plan === plan);
}

// What the CHECKOUT may sell: a resolvable order that is also on sale. Until
// 2026-09-25 the checkout asked resolveOrder alone, so anyone calling the API,
// or editing a button attribute in the browser, could still buy ParaSign Pro
// or ParaSend Pro on its own: plans no page sells, that the docs say are no
// longer sold, and that every screen then called Firm while the other product
// stayed free (betaaltest 25-09, R8). The webhook keeps asking resolveOrder:
// money that has already moved for a legacy plan must still grant.
function resolveSale(req) {
  const order = resolveOrder(req);
  if (order.error) return order;
  if (!isOnSale(order.product, order.plan)) return { error: 'not_on_sale' };
  return order;
}

function isBundle(product) {
  return product === 'firm';
}

// The entitlement tier a (product, plan) grants. Here the sold plan name equals
// the entitlement tier name (pro -> pro, business -> business). Returns null for
// a plan the product does not sell.
function grantedTier(product, plan) {
  if (product === 'parasend') return plan === 'pro' ? 'pro' : null;
  if (product === 'parasign') return (plan === 'pro' || plan === 'business') ? plan : null;
  return null;
}

// Everything one (product, plan) entitles the buyer to, as [{ product, tier }].
// One entry for a product plan, two for the Firm bundle. null when the plan is
// not sold.
function grantsOf(product, plan) {
  const key = bundleKeyOf(product, plan);
  if (key) return BUNDLES[key].grants;
  if (BUNDLES[product]) return null;
  const tier = grantedTier(product, plan);
  return tier ? Object.freeze([Object.freeze({ product, tier })]) : null;
}

// The floor tier a product drops to on revocation (chargeback).
function floorTier(product) {
  return product === 'parasign' ? 'free' : 'community';
}

// Price for a (product, plan, interval), or null if unknown.
function priceOf(product, plan, interval) {
  const p = CATALOG[product];
  if (!p || !p[plan]) return null;
  return p[plan][interval] || null;
}

// Validate + resolve a checkout request into a billable line, or { error }.
// NOTE: the request never supplies an amount; it is looked up here.
//
// `tier` is kept for the single-product callers that have always read it; for a
// bundle it is the tier of the FIRST grant, and `grants` is the complete answer.
function resolveOrder({ product, plan, interval } = {}) {
  if (!SELLABLE.includes(product)) return { error: 'unknown_product' };
  if (!INTERVALS.includes(interval)) return { error: 'unknown_interval' };
  const amount = priceOf(product, plan, interval);
  const grants = grantsOf(product, plan);
  if (!amount || !grants) return { error: 'unknown_plan' };
  return {
    amount, currency: 'EUR', tier: grants[0].tier, grants,
    bundle: bundleKeyOf(product, plan),
    product, plan, interval,
  };
}

// Amount equality by integer cents, so '18.15' == '18.150' and formatting noise
// never lets a mismatched amount through. NaN (unparseable) is never equal.
// Digits past the cents are accepted only when they are zeros: '35.091' is not
// 35.09, and reading it as such would grant a plan for an amount nobody set.
function amountsEqual(a, b) {
  const cents = (s) => {
    const m = /^(\d+)\.(\d{2})0*$/.exec(String(s).trim());
    return m ? (parseInt(m[1], 10) * 100 + parseInt(m[2], 10)) : NaN;
  };
  const ca = cents(a), cb = cents(b);
  return Number.isFinite(ca) && ca === cb;
}

module.exports = {
  CATALOG, PRODUCTS, SELLABLE, INTERVALS, BUNDLES, ON_SALE, isOnSale, resolveSale,
  PRODUCT_LABEL, TIER_LABEL, planLabel, orderLabel, orderLabelNl, orderLabelEn,
  isBundle, bundleKeyOf, grantedTier, grantsOf, floorTier, priceOf, resolveOrder, amountsEqual,
};
