'use strict';
// The pricing page shows the four ParaSign tiers (Free / Pro / Business /
// Enterprise) with the agreed copy, keeps all six paid checkout links wired
// for the API-first billing flow (data-billing-* attributes resolvable in the
// server catalog, no-JS href pointing at sign-in), states that checkout
// charges incl. 21% btw, shows the incl-btw amount up-front on every paid card,
// keeps one primary monthly CTA per tier with the yearly option demoted to a
// secondary link, and no longer claims a 5 MB file limit. It also checks the
// dead billing/checkout.html stub now redirects to /pricing with no "no charge"
// copy. Run: node relay/test/pricing-page.test.js (exits non-zero on failure).

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const catalog = require('../lib/billing-catalog');

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'pricing.html'), 'utf8');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

// The six paid variants and the excl-btw amounts behind the buttons.
const VARIANTS = [
  { product: 'parasend', plan: 'pro',      interval: 'monthly', excl: 15 },
  { product: 'parasend', plan: 'pro',      interval: 'yearly',  excl: 150 },
  { product: 'parasign', plan: 'pro',      interval: 'monthly', excl: 49 },
  { product: 'parasign', plan: 'pro',      interval: 'yearly',  excl: 499 },
  { product: 'parasign', plan: 'business', interval: 'monthly', excl: 299 },
  { product: 'parasign', plan: 'business', interval: 'yearly',  excl: 2990 },
];

// One annotated checkout button per variant. The href is the no-JS fallback and
// must NOT be a static Mollie payment link: those carry no metadata, so the
// webhook cannot attribute the payment and the buyer gets nothing, which is what
// happened to the first paying customer on 2026-07-21. All six were 404 by
// 2026-08-08 as well. The fallback is sign-in, because an account is what makes
// a payment attributable. This regex used to require the Mollie URL, so it kept
// the bug in place instead of the rule.
const btnRe = /<a\s+href="([^"]+)"\s+data-billing-product="([a-z]+)"\s+data-billing-plan="([a-z]+)"\s+data-billing-interval="([a-z]+)"/g;
const buttons = [];
for (let m; (m = btnRe.exec(html)); ) buttons.push({ href: m[1], product: m[2], plan: m[3], interval: m[4] });
assert.strictEqual(buttons.length, 6, 'expected 6 annotated checkout buttons, got ' + buttons.length);
ok('6 checkout buttons with data-billing-*');

for (const b of buttons) {
  assert(!/payment-links\.mollie\.com/.test(b.href),
    'checkout button falls back to a static Mollie link (no metadata, unattributable): ' + b.href);
  assert(b.href.startsWith('/auth/login'),
    'no-JS fallback must be sign-in, got ' + b.href + ' for ' + b.product + '/' + b.plan + '/' + b.interval);
}
ok('no-JS fallback on every button is sign-in, never a metadata-less payment link');

for (const v of VARIANTS) {
  const btn = buttons.find(b => b.product === v.product && b.plan === v.plan && b.interval === v.interval);
  assert(btn, 'missing button for ' + v.product + '/' + v.plan + '/' + v.interval);

  // The triple must resolve in the server-side catalog...
  const order = catalog.resolveOrder(btn);
  assert(!order.error, 'catalog rejects ' + v.product + '/' + v.plan + '/' + v.interval + ': ' + order.error);

  // ...and the catalog (= link) amount must be exactly the shown price + 21% btw.
  const incl = (v.excl * 1.21).toFixed(2);
  assert(catalog.amountsEqual(order.amount, incl),
    v.product + '/' + v.plan + '/' + v.interval + ': catalog charges ' + order.amount + ', page shows ' + v.excl + ' excl (incl would be ' + incl + ')');
  ok(v.product + ' ' + v.plan + ' ' + v.interval + ': shown ' + v.excl + ' excl = ' + order.amount + ' incl 21%');
}

// The four ParaSign tier cards carry the agreed copy, verbatim.
const PARASIGN_COPY = [
  // FREE - EUR 0
  '>&euro;0<',
  '2 signatures per month',
  'Unlimited receiving',
  'Full post-quantum crypto - Public verification log',
  'No card required',
  // PRO - EUR 49/month
  '&euro;49<',
  '100 signatures per month, then &euro;0.40 each, up to 1,000',
  'Past 1,000 a month, Business is cheaper anyway',
  'Unlimited transfers - API access',
  'Annual: &euro;499 excl. &middot; 15.1% off',
  // BUSINESS - EUR 299/month
  '&euro;299<',
  '1,000 signatures per month',
  'Named support, response within one business day',
  "We help you answer your customers' security questionnaires",
  'Exportable audit log with CT tree head (CSV or JSON)',
  'Annual: &euro;2,990 excl. &middot; 16.7% off',
  // ENTERPRISE - Let's talk
  "Let's talk",
  'Dedicated relay instance - Sector relay (health, legal, finance)',
  'SLA with service credits - Self-hosting licence - Audit support',
];
for (const s of PARASIGN_COPY) {
  assert(html.includes(s), 'missing ParaSign card copy: ' + s);
}
ok('four ParaSign tier cards carry the agreed copy verbatim');

// The line under the cards, verbatim.
assert(html.includes('Every plan gets the same encryption, the same post-quantum signatures and the same public proof log. Pay for volume, never for security. And pay per organisation, not per user.'),
  'missing the security/volume line under the ParaSign cards');
ok('security/volume line present under the cards');

// The FAQ names the Business exportable audit log, matching the card.
assert(html.includes('with named support and an exportable audit log'),
  'FAQ must state the Business exportable audit log');
ok('FAQ names the Business exportable audit log');

// The false "No cap, no block" claim never appears on the pricing page.
assert(!/No cap, no block/i.test(html), 'pricing page must not carry the No cap, no block claim');
ok('no "No cap, no block" claim on the pricing page');

// ParaSend keeps its displayed excl-btw amounts.
for (const s of ['&euro;15<', 'Annual &euro;150 excl.']) {
  assert(html.includes(s), 'missing displayed ParaSend price fragment: ' + s);
}
ok('ParaSend excl-btw amounts visible in the markup');

// Excl-btw framing plus the incl-21% checkout notice.
assert(/excl\. btw/.test(html), 'missing "excl. btw" mention');
assert(/incl\. 21% btw/.test(html), 'missing "incl. 21% btw" checkout notice');
ok('page states excl. btw and that checkout charges incl. 21% btw');

// The outdated 5 MB file-limit claim is gone.
assert(!/5\s?MB/i.test(html), 'pricing page still claims a 5 MB limit');
ok('no 5 MB claim left on the pricing page');

// Every paid card shows the incl-btw amount up-front, next to the excl price,
// so the amount on Mollie's page does not surprise the buyer.
const INCL_ONCARD = ['&euro;18.15/mo incl', '&euro;59.29/mo incl', '&euro;361.79/mo incl'];
for (const s of INCL_ONCARD) {
  assert(html.includes(s), 'paid card must show its btw-incl amount up-front: ' + s);
}
ok('every paid card shows the incl-btw amount next to the excl price');

// One primary monthly CTA per paid tier; the yearly variant is a secondary link,
// not an equal button. All six data-billing-* links stay wired for pricing-billing.js.
const monthlyPrimary = (html.match(/data-billing-interval="monthly"\s+class="btn btn-primary/g) || []).length;
assert.strictEqual(monthlyPrimary, 3, 'expected 3 primary monthly CTAs, got ' + monthlyPrimary);
const yearlyAlts = (html.match(/data-billing-interval="yearly"\s+class="yearly-alt"/g) || []).length;
assert.strictEqual(yearlyAlts, 3, 'expected 3 yearly options demoted to secondary links, got ' + yearlyAlts);
assert(!/data-billing-interval="yearly"\s+class="btn/.test(html), 'no yearly variant may still be an equal btn');
ok('one primary monthly CTA per tier, yearly demoted to a secondary link');

// The dead stub checkout page no longer serves the "no charge" lie; it redirects.
const checkoutHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'billing', 'checkout.html'), 'utf8');
assert(!/no charge/i.test(checkoutHtml), 'checkout.html must not claim "no charge"');
assert(!/activates immediately/i.test(checkoutHtml), 'checkout.html must not claim "activates immediately"');
assert(!/stub checkout/i.test(checkoutHtml), 'checkout.html must not carry the STUB CHECKOUT banner');
assert(/<meta[^>]+http-equiv="refresh"[^>]+url=\/pricing/i.test(checkoutHtml), 'checkout.html must redirect to /pricing');
ok('billing/checkout.html redirects to /pricing with no stub-payment copy');

// ---------------------------------------------------------------------------
// The page against the catalog. Everything below recomputes from
// relay/lib/billing-catalog.js, so a price edited on the page alone goes red.
//
// Why this exists: on 2026-08-30 the board found the page contradicting itself.
// Monthly prices were listed excl. btw (15 / 49 / 299) next to a yearly price
// listed incl. btw (3617,90). Side by side that reads as paying yearly costing
// more than paying monthly, which is the opposite of the truth. On one basis it
// is a 16.7% discount. The page also carried "two months free" on ParaSign Pro,
// where the real discount is 15.1%, and wrote the same amount four ways
// (EUR 3.617,90 / &euro;3,617.90 / EUR 361,79 / &euro;361.79).
//
// Comments are stripped first: the WHY comments in pricing.html quote the old
// wrong strings on purpose, and they must not satisfy or trip these checks.
// ---------------------------------------------------------------------------
const VISIBLE = html.replace(/<!--[\s\S]*?-->/g, '');
const VAT = 1.21;

// Every checkout amount, and the excl-btw price it is derived from. The catalog
// charges incl. btw, so the listed price is the amount divided by 1.21; if that
// does not land back on the catalog amount, the catalog holds a price that
// cannot be listed cleanly and we want to hear about it here.
const centsOf = (n) => Math.round(n * 100);
const money = new Map(); // euros -> label, everything the page is allowed to print
money.set(0, 'free tier');
// Per-signature overage. Metered on top of a plan, never a checkout amount, so
// it is not in the catalog; listed here so the sweep below stays exhaustive.
money.set(0.4, 'ParaSign overage per signature');

const pctByPlan = new Map();
for (const product of catalog.PRODUCTS) {
  for (const plan of Object.keys(catalog.CATALOG[product])) {
    const perInterval = {};
    for (const interval of catalog.INTERVALS) {
      const incl = Number(catalog.priceOf(product, plan, interval));
      const excl = Math.round(centsOf(incl) / VAT) / 100;
      assert(catalog.amountsEqual((excl * VAT).toFixed(2), incl.toFixed(2)),
        product + '/' + plan + '/' + interval + ': catalog ' + incl + ' is not a clean excl-btw price');
      money.set(incl, product + ' ' + plan + ' ' + interval + ' charged incl. btw');
      money.set(excl, product + ' ' + plan + ' ' + interval + ' listed excl. btw');
      perInterval[interval] = excl;
    }
    // btw is proportional, so the yearly discount is the same on either basis.
    const pct = (1 - perInterval.yearly / (perInterval.monthly * 12)) * 100;
    pctByPlan.set(product + '/' + plan, pct.toFixed(1));
  }
}
ok('catalog amounts all divide cleanly by 21% btw');

// One currency sign. The page used to mix "EUR 49" and "&euro;49".
assert(!/\bEUR\b/.test(VISIBLE), 'pricing page must write the euro sign as &euro;, never the string EUR');
assert(!/€/.test(VISIBLE), 'pricing page must use the &euro; entity, not a literal euro character');
ok('one currency sign on the page (&euro; only)');

// One number format: dot decimal, comma thousands, matching the rest of the
// English copy ("1,000 signatures"). The page had &euro;18,15 and &euro;18.15
// for the same amount.
const tokens = [...VISIBLE.matchAll(/&euro;([\d][\d.,]*)/g)].map(m => m[1]);
assert(tokens.length > 0, 'no money amounts found on the pricing page at all');
for (const t of tokens) {
  assert(/^\d{1,3}(?:,\d{3})*(?:\.\d{2})?$/.test(t),
    'money amount is not in the page number format (dot decimal, comma thousands): &euro;' + t);
}
ok(tokens.length + ' money amounts share one number format');

// Every amount printed on the page traces back to the catalog.
for (const t of tokens) {
  const v = Number(t.replace(/,/g, ''));
  assert(money.has(v), 'page shows &euro;' + t + ', which is not a catalog price (nor btw-derived from one)');
}
ok('every amount on the page traces back to billing-catalog.js');

// ...and every catalog amount, plus its excl-btw price, is actually printed. A
// price silently dropped from the page is as bad as a wrong one.
const printed = new Set(tokens.map(t => Number(t.replace(/,/g, ''))));
for (const [v, label] of money) {
  assert(printed.has(v), 'catalog price &euro;' + v.toFixed(2) + ' (' + label + ') is not shown on the page');
}
ok('every catalog price appears on the page, on both bases');

// The yearly discount is stated as the real percentage. "Two months free" is
// 16.7%: true for ParaSend Pro and ParaSign Business, false for ParaSign Pro.
assert(!/two months free/i.test(VISIBLE), 'the page must state the real discount, not "two months free"');
const shownPcts = [...VISIBLE.matchAll(/(\d+\.\d)% off/g)].map(m => m[1]);
const expectedPcts = [...pctByPlan.values()];
for (const p of shownPcts) {
  assert(expectedPcts.includes(p), 'page claims a ' + p + '% yearly discount, catalog gives ' + expectedPcts.join(' / '));
}
for (const [key, p] of pctByPlan) {
  assert(shownPcts.includes(p), 'missing the yearly discount for ' + key + ' (catalog says ' + p + '% off)');
}
assert.strictEqual(shownPcts.length, pctByPlan.size,
  'expected one stated discount per paid plan, got ' + shownPcts.length + ' for ' + pctByPlan.size + ' plans');
ok('yearly discount stated per plan and matches the catalog (' + expectedPcts.join(' / ') + '%)');

// One promise about starting for free. The page carried "30 days, no credit
// card, full relay access" next to Free cards saying "Forever, no card
// required" and a FAQ saying there is no separate trial.
assert(!/30 days/i.test(VISIBLE), 'pricing page must not promise a 30-day trial next to a forever-free tier');
assert(!/credit card/i.test(VISIBLE), 'pricing page must not carry the "no credit card" trial copy');
assert(!/full relay access/i.test(VISIBLE), 'the free tier is not full relay access');
assert(VISIBLE.includes('There is no separate trial'), 'FAQ must keep saying there is no separate trial');
assert(VISIBLE.includes('Forever &middot; no card required'), 'Free card must keep the forever/no-card promise');
ok('one starting-for-free promise: forever-free tier, no trial clock');

console.log('pricing-page: ' + passed + ' checks passed');
