'use strict';
// The pricing page shows the four ParaSign tiers (Community / Pro / Business /
// Enterprise) with the agreed copy, keeps all six paid checkout links wired
// for the API-first billing flow (data-billing-* attributes resolvable in the
// server catalog, no-JS href pointing at sign-in), states that checkout
// charges incl. 21% btw, shows the incl-btw amount up-front on every paid card,
// keeps one primary monthly CTA per tier with the yearly option demoted to a
// secondary link, and states the Community limits the relay actually enforces
// (transfers_month and file_mb out of relay/lib/tiers.js). It also checks the
// dead billing/checkout.html stub now redirects to /pricing with no "no charge"
// copy. Run: node relay/test/pricing-page.test.js (exits non-zero on failure).

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const catalog = require('../lib/billing-catalog');
const entitlements = require('../lib/entitlements');
const tiers = require('../lib/tiers');

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
  '2 signatures a month',
  'No limit on receiving',
  'Full post-quantum crypto - Public verification log',
  'No card required',
  // PRO - EUR 49/month
  '&euro;49<',
  '100 signatures a month, then &euro;0.40 each, up to 1,000',
  'Past 1,000 a month, Business is cheaper anyway',
  'Unlimited transfers - API access',
  'Annual: &euro;499 excl. &middot; 15.1% off',
  // BUSINESS - EUR 299/month
  '&euro;299<',
  '1,000 signatures a month',
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

// The Community limits on the page are the ones the relay actually enforces.
//
// This block used to say the opposite: "the outdated 5 MB file-limit claim is
// gone", asserting that "5 MB" appears nowhere on the page. That rule outlived
// its reason. relay/relay.js refuses a larger blob with 413 `Max 5MB` against
// MAX_BLOB (default 5242880), and relay/lib/tiers.js gives every tier
// file_mb 5. The limit is real, so a test forbidding the page to name it was
// holding a true sentence off the page.
//
// What the page said instead was worse than silence: "10 uploads per hour per
// IP" is ANON_RATE_PER_HOUR on /v2/anon-inbound, which relay.js deprecated on
// 2026-05-28 and advertises with Sunset 2026-12-31. A visitor read a rate limit
// on a dying anonymous endpoint as the allowance on the account they were about
// to create, and never saw the monthly cap that actually stops them (402
// monthly_transfer_quota_reached, transfers_month from the plan).
//
// Both figures are read out of tiers.js here, so the page cannot drift from the
// relay without this test going red.
// Comments stripped: the WHY-note in pricing.html quotes the very wording this
// block forbids, which is exactly how it stays forbidden for the next reader.
const htmlVisible = html.replace(/<!--[\s\S]*?-->/g, '');
const communityTransfers = tiers.tierLimit('community', 'transfers_month');
const communityFileMb = tiers.tierLimit('community', 'file_mb');
const proTransfers = tiers.tierLimit('pro', 'transfers_month');

// Two different failures, kept apart on purpose.
//
// The site used to say "10 transfers a month" on / and /docs and "10 transfers
// per month" on /pricing, /parasend and /parasign: one limit, two spellings,
// and a reader who compares two pages cannot tell whether that is one number or
// two. The site's form is now "a month" everywhere.
//
// So the NUMBER checks accept either spelling. If tiers.js moves from 10 to 20
// they go red on the number, whatever the wording is that day. The WORDING is
// pinned once, further down (MONTHLY_FORM), so a page that drifts back to "per
// month" fails on wording and not on a limit that is still perfectly correct.
// Declared as functions, not consts: two parallel PRs each adding a top-level
// `const` under one name is exactly what stopped this file parsing on main, and
// a function declaration tolerates being declared twice where a const throws.
function aMonth(n, noun) { return new RegExp(`${n} ${noun} (?:a|per) month`); }
function statesLine(pageHtml, line) { return line instanceof RegExp ? line.test(pageHtml) : pageHtml.includes(line); }

assert(new RegExp(`<li>${communityTransfers} transfers (?:a|per) month</li>`).test(html),
  `the Community card must name the transfers_month limit from tiers.js (${communityTransfers})`);
assert(new RegExp(`<li>${communityFileMb} MB per file</li>`).test(html),
  `the Community card must name the file_mb limit from tiers.js (${communityFileMb} MB)`);
assert(new RegExp(`${communityTransfers} transfers (?:a|per) month, ${communityFileMb} MB per file`).test(html),
  'the lead must carry the same two Community limits as the card');
assert(new RegExp(`<li>${proTransfers} transfers (?:a|per) month</li>`).test(html),
  `the ParaSend Pro card must name its transfers_month limit from tiers.js (${proTransfers})`);
assert(!/uploads per hour/i.test(htmlVisible),
  'the page must not sell the anonymous per-IP rate of a deprecated endpoint as an account limit');
ok('Community and Pro transfer limits on the page come from relay/lib/tiers.js');

// ParaShare has no signature algorithm of its own. frontend/crypto-agility.html
// lists it with Default SIG "n/a" on a pre-v1 hybrid wire format, so the claim
// that its receipts are ML-DSA-65 signed was contradicted by our own register.
assert(!/ParaShare use ML-KEM-768 plus ECDH P-256 hybrid key exchange with ML-DSA-65 signed receipts/.test(html),
  'the page must not claim ML-DSA-65 signed receipts for ParaShare; the crypto register says n/a');
const agility = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'crypto-agility.html'), 'utf8');
assert(/<td>ParaShare \(webapp\)<\/td>\s*<td>ML-KEM-768 \+ ECDH P-256<\/td>\s*<td>n\/a<\/td>/.test(agility),
  'crypto-agility.html is the source for ParaShare\'s algorithms and must still list SIG as n/a');
ok('the ParaShare crypto claim matches the register on /crypto-agility');

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

// An amount ends where it says it ends. A bare includes('&euro;49') is satisfied
// by the annual "&euro;499 excl." on the same card, so the two Pro monthly
// prices, the ones a buyer clicks, were pinned by nothing at all. Verified by
// sabotage: &euro;49 -> &euro;59 and &euro;15 -> &euro;19 both stayed green
// before this, and both go red after it.
function esc(v) { return v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function showsAmount(pageHtml, amount) {
  return new RegExp(esc(amount) + '(?![\\d.,])').test(pageHtml);
}
// The excl-btw price has to sit on the card of the plan it belongs to. A page
// may mention "from &euro;49 a month" in its opening line as well, and that
// sentence must not be able to stand in for the tier itself.
function showsAmountOnCard(pageHtml, amount, interval) {
  const re = interval === 'monthly'
    ? new RegExp('<div class="tier-price">' + esc(amount) + '(?![\\d.,])')
    : new RegExp('Annual:?\\s*' + esc(amount) + '(?![\\d.,])');
  return re.test(pageHtml);
}

// /parasign is the product page and quotes the ParaSign prices a second time.
// relay/test/pricing-page.test.js is the only thing that ties a listed price to
// the catalog, so the product page is held to the same numbers here: an edit
// to one page without the other turns this suite red instead of leaving two
// prices on the site.
const parasignHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'parasign.html'), 'utf8');
for (const s of ['2 signatures a month', '100 signatures a month, then &euro;0.40 each, up to 1,000', '1,000 signatures a month']) {
  assert(parasignHtml.includes(s), 'parasign.html lost the quota line: ' + s);
}
assert(/excl\. btw/.test(parasignHtml) && /incl\. 21% btw/.test(parasignHtml), 'parasign.html must state excl. btw and the incl. 21% btw checkout amount');
ok('parasign.html carries the same quota lines and the btw convention');

// The free plan is called Community, full stop: on /parasign, on /pricing, on
// the homepage and on the dashboard badge. It used to need a bridge sentence
// ("this plan is the tier named Free") because /pricing disagreed with every
// other page; PR #328 renamed the tier instead, so the bridge is gone and the
// gate checks the thing that actually has to hold. A visitor who reads
// "Community" and goes looking for it on the pricing page must find it there.
assert(/<div class="tier-name">Community<\/div>/.test(html),
  '/pricing must carry a tier named Community');
assert(!/<div class="tier-name">Free<\/div>/.test(html),
  '/pricing must not name a tier Free any more; the plan is called Community');
assert(!/tier named <strong>Free<\/strong>|tier is called Free/.test(parasignHtml),
  'parasign.html must not explain Community away as Free; one name, one page');
ok('Community is the one name for the free plan on /pricing and /parasign');

// Every tier name the product page prints must be a tier /pricing sells, so the
// two pages cannot drift into different product line-ups.
const parasignTiers = [...parasignHtml.matchAll(/<div class="tier-name">([^<]+)<\/div>/g)].map(m => m[1].trim());
assert(parasignTiers.length >= 3, 'expected the business tiers on parasign.html, found ' + parasignTiers.length);
for (const name of parasignTiers) {
  assert(new RegExp('>\\s*' + name + '\\s*<').test(html),
    'parasign.html shows the tier "' + name + '", but /pricing does not sell it');
}
ok('parasign.html only names tiers /pricing sells (' + parasignTiers.join(', ') + ')');

// A biography is the easiest thing on a sales page to embellish and the hardest
// for a reader to check. The founder line may say what /about already says and
// nothing more, and naming him obliges the page to name the accountable company.
const aboutHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'about.html'), 'utf8');
for (const claim of ['Mick Beer', 'privacy and security researcher', 'Paramantis Solutions B.V.']) {
  if (parasignHtml.includes(claim)) {
    assert(aboutHtml.includes(claim),
      'parasign.html claims "' + claim + '" about the founder, but /about does not say it');
  }
}
assert(!/\bMick Beer\b/.test(parasignHtml) || /KvK 42115132/.test(parasignHtml),
  'if parasign.html names the founder it must also name the accountable company registration');
ok('the founder line on parasign.html matches /about and carries the registration');

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
// card, full relay access" next to Community cards saying "Forever, no card
// required" and a FAQ saying there is no separate trial.
assert(!/30 days/i.test(VISIBLE), 'pricing page must not promise a 30-day trial next to a forever-free tier');
assert(!/credit card/i.test(VISIBLE), 'pricing page must not carry the "no credit card" trial copy');
assert(!/full relay access/i.test(VISIBLE), 'the free tier is not full relay access');
assert(VISIBLE.includes('There is no separate trial'), 'FAQ must keep saying there is no separate trial');
assert(VISIBLE.includes('Forever &middot; no card required'), 'Community card must keep the forever/no-card promise');
ok('one starting-for-free promise: forever-free tier, no trial clock');


// ── Every amount belongs to the card it stands in ────────────────────────────
//
// The catalog sweep above asks two questions: is every amount on the page a
// catalog amount, and does every catalog amount appear somewhere. Both are true
// of a page where two cards have swapped prices, so a ParaSend Pro button
// reading EUR 59.29/mo passes: that is ParaSign Pro's real price, just on the
// wrong card. Same for a swapped yearly link, and same for a discount figure
// that is genuine for another plan.
//
// That is not a hypothetical. A wrong number next to the right plan is exactly
// the class of bug this page had, so the check has to bind an amount to the card
// it is printed in, not to the page as a whole.
const cards = html.split(/<div class="tier-card/).slice(1);
assert(cards.length >= 5, 'expected at least 5 tier cards, found ' + cards.length);

const cardMoney = /&euro;([\d,]+\.?\d*)/g;
  // Only a percentage presented as a discount, so an SLA figure ("99.9%") in a
  // paid card is not read as a price claim. The page writes discounts as
  // "16.7% off"; anything else is left alone.
  const cardPct = /(\d+\.\d)%\s*off/g;
let bound = 0;

for (const raw of cards) {
  // Strip HTML comments first: the WHY-notes above quote the old wrong figures
  // on purpose, and a test that reads them would fail on its own documentation.
  const card = raw.replace(/<!--[\s\S]*?-->/g, '');
  const btn = /data-billing-product="([a-z]+)"\s+data-billing-plan="([a-z]+)"/.exec(card);
  if (!btn) continue;                       // free card: nothing is charged there
  const [, product, plan] = btn;

  // Every price this card is allowed to print: its own, in both intervals, each
  // excl and incl btw. Anything else in this card is a number from another plan.
  const allowed = new Set();
  for (const interval of ['monthly', 'yearly']) {
    const order = catalog.resolveOrder({ product, plan, interval });
    assert(!order.error, product + '/' + plan + '/' + interval + ': ' + order.error);
    const incl = Number(order.amount);
    const excl = Math.round((incl / 1.21) * 100) / 100;
    allowed.add(incl.toFixed(2));
    allowed.add(excl.toFixed(2));
    allowed.add(String(Math.round(excl)));  // "15" as well as "15.00"
    allowed.add(Math.round(excl).toLocaleString('en-US'));
  }

  // The per-signature overage rate is a real amount on this card and it does not
  // come from the subscription catalog; it hangs off the tier itself. Read it
  // from there rather than allowing any stray number through, so a wrong overage
  // rate is still caught.
  const ent = entitlements.getEntitlements(
    product === 'parasign' ? { plan_parasign: plan } : { plan_parasend: plan },
  )[product];
  const rate = ent && ent.overage && ent.overage.rate_eur;
  if (rate != null) {
    allowed.add(Number(rate).toFixed(2));
    allowed.add(String(Number(rate)));
  }

  for (let m; (m = cardMoney.exec(card)); ) {
    const raw = m[1].replace(/,/g, '');
    const norm = new Set([raw, Number(raw).toFixed(2), String(Number(raw))]);
    const ok_ = [...norm].some((n) => allowed.has(n));
    assert(ok_, product + '/' + plan + ' card shows &euro;' + m[1] +
      ', which belongs to another plan (allowed here: ' + [...allowed].sort().join(', ') + ')');
    bound++;
  }
  cardMoney.lastIndex = 0;

  // The yearly discount printed on this card must be this plan's own discount.
  const mo = Number(catalog.resolveOrder({ product, plan, interval: 'monthly' }).amount);
  const yr = Number(catalog.resolveOrder({ product, plan, interval: 'yearly' }).amount);
  const own = Math.round((1 - yr / (mo * 12)) * 1000) / 10;
  for (let m; (m = cardPct.exec(card)); ) {
    assert.strictEqual(Number(m[1]), own,
      product + '/' + plan + ' card claims a ' + m[1] + '% yearly discount; its own is ' + own + '%');
  }
  cardPct.lastIndex = 0;
}
assert(bound >= 8, 'expected to bind at least 8 amounts to a card, bound ' + bound);
ok('every amount and discount sits on the card of the plan it belongs to (' + bound + ' amounts bound)');

// ── The product pages quote the same prices a second time ────────────────────
//
// /parasign and /parasend sell one product each and repeat its tiers. This file
// is the only thing that ties a listed price to relay/lib/billing-catalog.js,
// so both product pages are held to the same numbers here: an edit to one page
// without the other turns this suite red instead of leaving two prices on the
// site for the same plan. The pages carry no checkout button of their own; they
// send the buyer to /pricing, which is where the data-billing-* buttons live.
const PRODUCT_PAGES = [
  { product: 'parasign', file: 'parasign.html' },
  { product: 'parasend', file: 'parasend.html' },
];
const productHtml = {};
for (const page of PRODUCT_PAGES) {
  const pageHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', page.file), 'utf8');
  productHtml[page.product] = pageHtml;
  for (const v of VARIANTS.filter(x => x.product === page.product)) {
    const order = catalog.resolveOrder({ product: v.product, plan: v.plan, interval: v.interval });
    assert(!order.error, 'catalog rejects ' + v.plan + '/' + v.interval + ': ' + order.error);
    const excl = '&euro;' + v.excl.toLocaleString('en-US');
    assert(showsAmountOnCard(pageHtml, excl, v.interval),
      page.file + ' no longer shows ' + excl + ' on the ' + v.plan + ' card for ' + v.interval);
    const incl = '&euro;' + Number(order.amount).toLocaleString('en-US', { minimumFractionDigits: 2 });
    assert(showsAmount(pageHtml, incl), page.file + ' no longer shows the catalog amount ' + incl + ' incl. btw for ' + v.plan + '/' + v.interval);
    ok(page.file + ' ' + v.plan + ' ' + v.interval + ': shows ' + excl + ' excl and ' + incl + ' incl');
  }
  assert(/excl\. btw/.test(pageHtml) && /incl\. 21% btw/.test(pageHtml),
    page.file + ' must state excl. btw and the incl. 21% btw checkout amount');
}
ok('both product pages carry the btw convention and the catalog amounts');

// ── The free number, pinned to the code that enforces it ─────────────────────
//
// /parasend said "10 uploads per hour per IP". That figure is real, but it is
// ANON_RATE_PER_HOUR on POST /v2/anon-inbound (relay.js), an endpoint deprecated
// on 2026-05-28 that answers with Deprecation and Sunset headers and retires on
// 2026-12-31. It is not what a Community ACCOUNT gets. The account limits live
// in relay/lib/tiers.js and are enforced in relay.js: transfers_month with a 402
// (monthly_transfer_quota_reached), file_mb with a 413 (Max 5MB), view_ttl_ms
// and max_views on the link itself.
//
// So the page is pinned to tiers.js rather than to the wording on /pricing.
// Pinning one page to another only proves the two agree; it cannot catch both
// being wrong together, which is exactly what happened here: /pricing and
// index.html carry the same upload figure and are corrected in their own PRs.
const hours = (ms) => ms / 3_600_000;

// The transfer lines are matched on the number and accept either spelling of
// the period, so tiers.js drift fails here and wording drift fails in the
// MONTHLY_FORM block instead. Same split as the /pricing checks above.
const COMMUNITY_LINES = [
  [aMonth(tiers.tierLimit('community', 'transfers_month'), 'transfers'), 'transfers_month'],
  [tiers.tierLimit('community', 'file_mb') + ' MB per file', 'file_mb'],
  [hours(tiers.tierLimit('community', 'view_ttl_ms')) + ' hour link expiry', 'view_ttl_ms'],
  ['Up to ' + tiers.tierLimit('community', 'outbound_per_hour') + ' retrievals an hour', 'outbound_per_hour'],
  [tiers.tierLimit('community', 'devices') + ' registered devices', 'devices'],
];
for (const [line, dim] of COMMUNITY_LINES) {
  assert(statesLine(productHtml.parasend, line),
    'parasend.html no longer states the Community ' + dim + ' that tiers.js enforces: "' + line + '"');
}
assert(tiers.tierLimit('community', 'max_views') === 1 && /Burn on first read/.test(productHtml.parasend),
  'tiers.js gives Community one view, so parasend.html must say the link burns on first read');

const PRO_LINES = [
  [aMonth(tiers.tierLimit('pro', 'transfers_month'), 'transfers'), 'transfers_month'],
  [hours(tiers.tierLimit('pro', 'view_ttl_ms')) + ' hour link expiry', 'view_ttl_ms'],
  ['Up to ' + tiers.tierLimit('pro', 'max_views') + ' reads per link', 'max_views'],
  ['Up to ' + tiers.tierLimit('pro', 'outbound_per_hour') + ' retrievals an hour', 'outbound_per_hour'],
  ['Up to ' + tiers.tierLimit('pro', 'devices') + ' registered devices', 'devices'],
];
for (const [line, dim] of PRO_LINES) {
  assert(statesLine(productHtml.parasend, line),
    'parasend.html no longer states the ParaSend Pro ' + dim + ' that tiers.js enforces: "' + line + '"');
}
// The anon endpoint's figure may not come back on either product page under any
// wording. It describes a keyless path that is being retired, not a plan.
for (const [name, pageHtml] of [['parasign.html', productHtml.parasign], ['parasend.html', productHtml.parasend]]) {
  assert(!/uploads per hour|uploads an hour/i.test(pageHtml),
    name + ' states an uploads-per-hour figure; that is ANON_RATE_PER_HOUR on the deprecated /v2/anon-inbound, not a plan limit');
}
// No metered tier is unbounded: relay/lib/entitlements.js gives even enterprise
// a finite ceiling. A page may not promise unlimited transfers to anyone.
for (const [name, pageHtml] of [['parasign.html', productHtml.parasign], ['parasend.html', productHtml.parasend]]) {
  assert(!/Unlimited transfers/i.test(pageHtml),
    name + ' promises unlimited transfers, which entitlements.js forbids for every metered tier');
}
// ── The hourly ceiling the relay enforces and no page stated ─────────────────
//
// outbound_per_hour has been enforced since the rate-limit finding (relay.js,
// outboundRateOk, applied on GET /v2/outbound/:hash) and appeared on no page at
// all: a Community account that scripts its own downloads hit a 429 it had
// never been told about. It is now on /parasend per tier and on the /parasign
// Pro card, and it is pinned here like every other tiers.js number.
//
// What the page may NOT do is call it a send limit or a recipient limit. It
// counts the account's own retrievals through GET /v2/outbound with its own key;
// the browser recipient path is GET /v2/dl/:token/get, which has no rate limit,
// so a recipient opening a link never spends the sender's hour.
//
// In its own scope, like every block added below it: nothing this PR introduces
// reaches the top level, so a parallel PR cannot collide with it.
(function hourlyCeiling() {
  assert(tiers.isUnlimited(tiers.tierLimit('enterprise', 'outbound_per_hour')),
    'tiers.js now caps enterprise outbound_per_hour, so parasend.html may not say there is no hourly cap');
  assert(/No hourly cap on API retrievals/.test(productHtml.parasend),
    'parasend.html must state the Enterprise hourly position tiers.js gives it (unlimited)');
  for (const [name, pageHtml] of [['parasign.html', productHtml.parasign], ['parasend.html', productHtml.parasend]]) {
    assert(!/(sends|uploads) an hour/i.test(pageHtml),
      name + ' calls the hourly figure a send rate; outbound_per_hour counts retrievals through GET /v2/outbound, not sends');
  }
  assert(new RegExp('Up to ' + tiers.tierLimit('pro', 'outbound_per_hour') + ' ParaSend retrievals an hour').test(productHtml.parasign),
    'parasign.html must quote the hourly retrieval ceiling a ParaSign Pro account derives (' +
    tiers.tierLimit('pro', 'outbound_per_hour') + ')');
  ok('the hourly retrieval ceiling on /parasend and /parasign comes from tiers.js (' +
     tiers.tierLimit('community', 'outbound_per_hour') + '/' + tiers.tierLimit('pro', 'outbound_per_hour') + ' an hour)');
})();

// ── "No limit on receiving", pinned negatively ───────────────────────────────
//
// Every other limit on these pages points at a field. This one points at the
// absence of one: /parasign, /pricing and the homepage say receiving is not
// metered, and that is only true as long as no receiving dimension exists to
// meter it with. Nothing in tiers.js or in the entitlement quotas may name one,
// and the day something does, this fails and the pages have to state the real
// ceiling instead of a promise the code stopped keeping.
(function receivingIsNotMetered() {
  const receivingDim = (obj) => Object.keys(obj).find((k) => /receiv|inbound/i.test(k));
  for (const [tier, row] of Object.entries(tiers.TIER_LIMITS)) {
    const dim = receivingDim(row);
    assert(!dim, 'tiers.js gives ' + tier + ' a receiving dimension (' + dim + '), so "No limit on receiving" is no longer true');
  }
  const account = { key: 'k_demo', account_id: 'acct_demo', plan: 'community' };
  for (const [product, block] of Object.entries(entitlements.getEntitlements(account))) {
    if (!block || !block.quotas) continue;
    const dim = receivingDim(block.quotas);
    assert(!dim, 'entitlements.js meters receiving for ' + product + ' (' + dim + '), so "No limit on receiving" is no longer true');
  }
  for (const [name, pageHtml] of [['pricing.html', html], ['parasign.html', productHtml.parasign]]) {
    assert(pageHtml.includes('No limit on receiving'),
      name + ' dropped the receiving line; it is the one claim on these pages backed by a field that does not exist');
  }
  assert(/Receiving is not metered\./.test(productHtml.parasign),
    '/parasign must say what "no limit on receiving" rests on, and that signing what you receive is still counted');
  ok('"No limit on receiving" holds: no receiving dimension in tiers.js or in the entitlement quotas');
})();

// A ParaSign plan derives its ParaSend tier (entitlements.js derivePlanParasend),
// so where /parasign quotes a transfer number it must be that tier's number.
assert(aMonth(tiers.tierLimit('pro', 'transfers_month'), 'ParaSend transfers').test(productHtml.parasign),
  'parasign.html must quote the ParaSend transfer ceiling a ParaSign Pro account actually derives');
ok('the ParaSend limits on both product pages come from relay/lib/tiers.js (' +
   tiers.tierLimit('community', 'transfers_month') + '/' + tiers.tierLimit('pro', 'transfers_month') + ' transfers, ' +
   tiers.tierLimit('community', 'file_mb') + ' MB)');

// A feature bullet quoted from /pricing has to stay a quote. This one names a
// subprocessor, so dropping "via Resend" would quietly remove a disclosure the
// EU claim depends on being made in the same breath.
for (const line of ['Email notifications via Resend']) {
  assert(html.includes(line), '/pricing lost the feature line: ' + line);
  assert(productHtml.parasend.includes(line), 'parasend.html lost the feature line /pricing carries: ' + line);
}
ok('the ParaSend Pro feature bullets quoted from /pricing are still quotes');

// The signature quota lines stay pinned to the words /pricing uses: those three
// are billing copy (the overage rate and the hard cap), not a tiers.js row.
for (const line of ['2 signatures a month', '100 signatures a month, then &euro;0.40 each, up to 1,000', '1,000 signatures a month']) {
  assert(productHtml.parasign.includes(line), 'parasign.html lost the quota line: ' + line);
}
assert(tiers.tierLimit('community', 'signs_month') === 2,
  'tiers.js no longer gives the free plan 2 signatures a month, so the pages that say so are stale');
ok('parasign.html carries the signature quota lines, and tiers.js still backs the free one');

// ── The service promises in a tier bullet are pinned too ─────────────────────
//
// The quota lines above were pinned, the service lines were not, and that is
// exactly how "SLA 99.9%" reached parasend.html while /pricing and /sla both
// published 99.95%. A number in a tier card is a promise whether it is priced
// in euros or in uptime, so the uptime figure is now read from /sla, the page
// that defines it, and every page that repeats it has to match.
const slaHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'sla.html'), 'utf8');
// /sla states two targets, one per tier, so read the Enterprise cell by name
// rather than the first .uptime on the page: the Community figure (99.5%) is
// a real number too and would silently become the thing under test.
const slaTarget = /<div class="tier">Enterprise<\/div>\s*<div class="uptime">([\d.]+)%<\/div>/.exec(slaHtml);
assert(slaTarget, 'sla.html no longer states an Enterprise uptime target');
const SLA_TARGET = slaTarget[1];
const SLA_LINE = 'SLA ' + SLA_TARGET + '%, priority incident response';
const straySla = new RegExp('SLA (?!' + SLA_TARGET.replace('.', '\\.') + '%)\\d+\\.?\\d*%');
for (const [name, pageHtml] of [['pricing.html', html], ['parasend.html', productHtml.parasend]]) {
  assert(pageHtml.includes(SLA_LINE), name + ' must state "' + SLA_LINE + '", the target /sla publishes');
  assert(!straySla.test(pageHtml), name + ' states an SLA figure that is not the one on /sla');
}
ok('the SLA figure on /pricing and /parasend is the one /sla publishes (' + SLA_TARGET + '%)');

// A compliance framework named in a tier bullet carries its own limit in that
// bullet. The nuance used to live thousands of pixels below the bullet, which
// on a phone reads as a certification claim.
assert(productHtml.parasend.includes('IEC 62443 / NIS2 / NEN 7510 documentation as input for your own compliance process, not third-party certification'),
  'parasend.html must qualify the compliance bullet where the bullet stands');
ok('the compliance bullet on /parasend carries its own limit');

// ── One spelling for the monthly period ──────────────────────────────────────
//
// The same Community limit shipped as "10 transfers a month" on / and /docs and
// as "10 transfers per month" on /pricing, /parasend and /parasign. Both are
// true, which is what makes it a problem: a buyer comparing two pages has to
// work out whether that is one allowance or two, and every page that repeats a
// limit multiplies the chance of a real drift hiding inside a wording drift.
//
// The site's form is "a month". The number checks above accept both spellings
// on purpose, so a tiers.js change fails on the number; this is the only place
// the wording is pinned, so a page that reverts fails here and says so plainly.
(function oneMonthlyForm() {
  const MONTHLY_FORM = /([\d,]+) (signatures|transfers|ParaSend transfers) per month/;
  const PAGES = ['pricing.html', 'parasend.html', 'parasign.html', 'index.html', 'signup.html', 'help/index.html'];
  for (const rel of PAGES) {
    const pageHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', ...rel.split('/')), 'utf8');
    const stray = MONTHLY_FORM.exec(pageHtml);
    assert(!stray, rel + ' says "' + (stray ? stray[0] : '') + '"; the site says "' +
      (stray ? stray[1] + ' ' + stray[2] : 'N noun') + ' a month" and one limit gets one spelling');
    assert(/(signatures|transfers) a month/.test(pageHtml),
      rel + ' no longer states a monthly allowance at all, so this gate is guarding nothing');
  }
  ok('every page that repeats a monthly limit uses one spelling ("a month")');
})();

console.log('pricing-page: ' + passed + ' checks passed');
