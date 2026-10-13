'use strict';
// The public plan list (GET /api/user/billing/plans), derived from the one
// catalog the checkout sells from (relay/lib/billing-catalog.js) and the one
// limit table the relay enforces (relay/lib/tiers.js).
//
// WHY. This list was a hand-kept array in admin/server.js with 'Pro' at 9/89
// euro and 5 MB files, and no Firm at all, while /pricing and the checkout sold
// Firm at 29/290 euro excl. VAT with 500 MB files (PLAN-46-A). Two lists drift;
// one list read twice cannot.
const catalog = require('../../relay/lib/billing-catalog');
const tiers = require('../../relay/lib/tiers');

const VAT = 1.21;
const exVat = (incl) => Math.round((Number(incl) / VAT) * 100) / 100;
const lim = (v) => (tiers.UNLIMITED === v || v === Infinity ? null : v);

function limitsOf(tier) {
  const t = tiers.TIER_LIMITS[tiers.normalisePlan(tier)];
  return {
    file_size_mb: lim(t.file_mb),
    link_ttl_hours: Math.round(t.view_ttl_ms / 3600000),
    reads_per_link: lim(t.max_views),
    registered_devices: lim(t.devices),
    signatures_per_month: lim(t.signs_month),
    transfers_per_month: lim(t.transfers_month),
    recipients_per_send: lim(t.max_recipients),
  };
}

function plans() {
  const out = [{
    id: 'community', name: 'Community', on_sale: true,
    price_monthly_eur: 0, price_yearly_eur: 0, price_monthly_eur_incl_vat: 0, price_yearly_eur_incl_vat: 0,
    includes: [], limits: limitsOf('community'),
  }];
  for (const o of catalog.ON_SALE) {
    const order = catalog.resolveSale({ product: o.product, plan: o.plan, interval: 'monthly' });
    const yearly = catalog.resolveSale({ product: o.product, plan: o.plan, interval: 'yearly' });
    if (order.error || yearly.error) continue;
    const grants = catalog.grantsOf(o.product, o.plan) || [];
    const id = o.product === o.plan ? o.plan : `${o.product}_${o.plan}`;
    const top = grants.reduce((a, g) => (g.tier === 'business' ? 'business' : a), 'pro');
    out.push({
      id, product: o.product, plan: o.plan, on_sale: true,
      name: catalog.BUNDLES[o.product] ? catalog.BUNDLES[o.product].label : catalog.planLabel(o.product, o.plan),
      price_monthly_eur: exVat(order.amount), price_yearly_eur: exVat(yearly.amount),
      price_monthly_eur_incl_vat: Number(order.amount), price_yearly_eur_incl_vat: Number(yearly.amount),
      includes: grants.map((g) => ({ product: g.product, tier: g.tier, name: catalog.planLabel(g.product, g.tier) })),
      limits: limitsOf(top),
    });
  }
  out.push({
    id: 'enterprise', name: 'Enterprise', on_sale: false, contact: 'privacy@paramant.app',
    price_monthly_eur: null, price_yearly_eur: null, price_monthly_eur_incl_vat: null, price_yearly_eur_incl_vat: null,
    includes: [], limits: limitsOf('enterprise'),
  });
  return out;
}

// Display name for a plan id in mails; legacy ids keep their old names.
const LEGACY = { pro: 'Pro', business: 'Business', community: 'Community', enterprise: 'Enterprise', free: 'Community' };
function planName(id) {
  const p = plans().find((x) => x.id === id);
  return p ? p.name : (LEGACY[id] || id);
}

module.exports = { plans, planName };
