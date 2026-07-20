'use strict';
// The pricing page shows the four ParaSign tiers (Free / Pro / Business /
// Enterprise) with the agreed copy, keeps all six paid checkout links wired
// for the API-first billing flow (data-billing-* attributes resolvable in the
// server catalog, static Mollie link as fallback), states that checkout
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

// One annotated checkout button per variant, static Mollie link as fallback.
const btnRe = /<a\s+href="(https:\/\/payment-links\.mollie\.com\/payment\/[A-Za-z0-9]+)"\s+data-billing-product="([a-z]+)"\s+data-billing-plan="([a-z]+)"\s+data-billing-interval="([a-z]+)"/g;
const buttons = [];
for (let m; (m = btnRe.exec(html)); ) buttons.push({ href: m[1], product: m[2], plan: m[3], interval: m[4] });
assert.strictEqual(buttons.length, 6, 'expected 6 annotated checkout buttons, got ' + buttons.length);
ok('6 checkout buttons with data-billing-* and a static Mollie fallback href');

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
  '>EUR 0<',
  '2 signatures per month',
  'Unlimited receiving',
  'Full post-quantum crypto - Public verification log',
  'No card required',
  // PRO - EUR 49/month
  'EUR 49<',
  '100 signatures per month, then EUR 0.40 each, up to 1,000',
  'Past 1,000 a month, Business is cheaper anyway',
  'Unlimited transfers - API access',
  'Annual: EUR 499 (two months free)',
  // BUSINESS - EUR 299/month
  'EUR 299<',
  '1,000 signatures per month',
  'Named support, response within one business day',
  "We help you answer your customers' security questionnaires",
  'Exportable audit log with CT tree head (CSV or JSON)',
  'Annual: EUR 2,990 (two months free)',
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
for (const s of ['&euro;15<', 'or &euro;150/yr']) {
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
const INCL_ONCARD = ['&euro;18,15/mo incl', 'EUR 59,29/mo incl', 'EUR 361,79/mo incl'];
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

console.log('pricing-page: ' + passed + ' checks passed');
