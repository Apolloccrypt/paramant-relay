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
});

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

// What /pricing actually sells today. The two `pro` rows are NOT here and are
// still in CATALOG on purpose: an existing ParaSign Pro or ParaSend Pro customer
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

function isBundle(product) {
  return Object.prototype.hasOwnProperty.call(BUNDLES, product);
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
  const bundle = BUNDLES[product];
  if (bundle) return bundle.plan === plan ? bundle.grants : null;
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
    bundle: isBundle(product) ? product : null,
    product, plan, interval,
  };
}

// Amount equality by integer cents, so '18.15' == '18.150' and formatting noise
// never lets a mismatched amount through. NaN (unparseable) is never equal.
function amountsEqual(a, b) {
  const cents = (s) => {
    const m = /^(\d+)\.(\d{2})\d*$/.exec(String(s).trim());
    return m ? (parseInt(m[1], 10) * 100 + parseInt(m[2], 10)) : NaN;
  };
  const ca = cents(a), cb = cents(b);
  return Number.isFinite(ca) && ca === cb;
}

module.exports = {
  CATALOG, PRODUCTS, SELLABLE, INTERVALS, BUNDLES, ON_SALE, isOnSale,
  PRODUCT_LABEL, TIER_LABEL, planLabel, orderLabel,
  isBundle, grantedTier, grantsOf, floorTier, priceOf, resolveOrder, amountsEqual,
};
