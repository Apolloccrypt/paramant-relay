'use strict';
// T1.3: the pricing page shows all six paid variants (3 product-tiers x
// monthly/yearly) with the right excl-btw amounts, states that checkout
// charges incl. 21% btw, keeps every checkout button wired for the API-first
// billing flow (data-billing-* attributes resolvable in the server catalog),
// and no longer claims a 5 MB file limit.
// Run: node relay/test/pricing-page.test.js (exits non-zero on failure).

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const catalog = require('../lib/billing-catalog');

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'pricing.html'), 'utf8');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

// The six variants and the excl-btw amounts the page must show.
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
  ok(v.product + ' ' + v.plan + ' ' + v.interval + ': shown €' + v.excl + ' excl = ' + order.amount + ' incl 21%');
}

// The shown amounts themselves (excl btw) are in the markup.
for (const s of ['&euro;15<', 'or &euro;150/yr', '&euro;49<', 'or &euro;499/yr', '&euro;299<', 'or &euro;2,990/yr']) {
  assert(html.includes(s), 'missing displayed price fragment: ' + s);
}
ok('all six excl-btw amounts visible in the markup');

// Excl-btw framing plus the incl-21% checkout notice.
assert(/excl\. btw/.test(html), 'missing "excl. btw" mention');
assert(/incl\. 21% btw/.test(html), 'missing "incl. 21% btw" checkout notice');
ok('page states excl. btw and that checkout charges incl. 21% btw');

// The outdated 5 MB file-limit claim is gone.
assert(!/5\s?MB/i.test(html), 'pricing page still claims a 5 MB limit');
ok('no 5 MB claim left on the pricing page');

console.log('pricing-page: ' + passed + ' checks passed');
