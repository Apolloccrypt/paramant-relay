'use strict';
// Server-side ParaSend / ParaSign billing catalog. THE source of truth for what a
// plan costs and which entitlement tier it grants. The checkout endpoint reads the
// amount from HERE (never from the request body), and the webhook re-checks the
// amount actually paid against HERE before granting anything. Amounts are Mollie
// decimal strings in EUR incl. 21% VAT, matching the hosted payment links.

const CATALOG = Object.freeze({
  parasend: {
    pro: { monthly: '18.15', yearly: '181.50' },
  },
  parasign: {
    pro:      { monthly: '59.29',  yearly: '603.79'  },
    business: { monthly: '361.79', yearly: '3617.90' },
  },
});

const PRODUCTS = Object.freeze(['parasend', 'parasign']);
const INTERVALS = Object.freeze(['monthly', 'yearly']);

// The entitlement tier a (product, plan) grants. Here the sold plan name equals
// the entitlement tier name (pro -> pro, business -> business). Returns null for
// a plan the product does not sell.
function grantedTier(product, plan) {
  if (product === 'parasend') return plan === 'pro' ? 'pro' : null;
  if (product === 'parasign') return (plan === 'pro' || plan === 'business') ? plan : null;
  return null;
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
function resolveOrder({ product, plan, interval } = {}) {
  if (!PRODUCTS.includes(product)) return { error: 'unknown_product' };
  if (!INTERVALS.includes(interval)) return { error: 'unknown_interval' };
  const amount = priceOf(product, plan, interval);
  const tier = grantedTier(product, plan);
  if (!amount || !tier) return { error: 'unknown_plan' };
  return { amount, currency: 'EUR', tier, product, plan, interval };
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
  CATALOG, PRODUCTS, INTERVALS,
  grantedTier, floorTier, priceOf, resolveOrder, amountsEqual,
};
