// What /pricing sells after Firm, measured on a rendered page.
//
// Firm replaced two separately sold plans (ParaSign Pro at 49 excl. btw a month
// and ParaSend Pro at 15) with ONE plan at 29 that grants both. That is a
// pricing decision, and the page is where a buyer meets it, so the table is
// checked the way a buyer reads it: rendered, in order, with the amounts and
// the buttons that will actually be clicked.
//
// Read against the server-side catalog rather than against literals typed here,
// so a price that moves in relay/lib/billing-catalog.js and not on the page
// turns this red. relay/test/pricing-page.test.js holds the same chain on the
// markup; this file holds it on the pixels, which is the half that catches a
// card the layout has hidden or an amount that never rendered.
//
// The backend is mocked: nothing here talks to a relay, and the only network
// call the page makes on load is the session check, which is answered
// signed-out.
//
// Run: node --test tests/pricing-firm.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.join(HERE, '..', 'frontend');
const CHROME = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const TYPES = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };
const ROUTE_ALIAS = { '/pricing': '/pricing.html', '/signup': '/signup.html' };

const catalog = createRequire(import.meta.url)('../relay/lib/billing-catalog.js');

// The excl-btw price a buyer reads, derived from the incl-btw amount checkout
// charges. Same direction as invoice.splitVat: the catalog amount is the truth
// and the listed price follows from it.
const exclOf = (product, plan, interval) => {
  const incl = Number(catalog.priceOf(product, plan, interval));
  return Math.round((incl / 1.21) * 100) / 100;
};
const euros = (n) => (Number.isInteger(n) ? n.toLocaleString('en-US') : n.toLocaleString('en-US', { minimumFractionDigits: 2 }));

const web = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  pathname = ROUTE_ALIAS[pathname] || pathname;
  const file = path.join(WEB_ROOT, pathname);
  if (!file.startsWith(WEB_ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => web.listen(0, '127.0.0.1', resolve));
const BASE = `http://localhost:${web.address().port}`;
const chrome = await chromium.launch({ headless: true, ...(CHROME ? { executablePath: CHROME } : {}) });

async function openPricing() {
  const page = await chrome.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route('**/api/user/session/verify', (route) => route.fulfill({
    status: 401, contentType: 'application/json', body: '{"authenticated":false}',
  }));
  // Nothing else may be reached. A checkout call on load would mean the page
  // asks for a credential before anybody has clicked anything.
  await page.route('**/v2/billing/**', (route) => route.fulfill({
    status: 500, contentType: 'application/json', body: '{"error":"not_expected_on_load"}',
  }));
  await page.goto(`${BASE}/pricing`, { waitUntil: 'networkidle' });
  return page;
}

// Every plan card the page renders, in document order, per product section.
const readCards = (page) => page.evaluate(() => {
  const sections = [...document.querySelectorAll('section')].filter((s) => s.querySelector('.tier-card'));
  return sections.map((s) => ({
    heading: (s.querySelector('h3') || {}).textContent?.replace(/\s+/g, ' ').trim() || '',
    cards: [...s.querySelectorAll('.tier-card')].map((c) => ({
      name: (c.querySelector('.tier-name') || {}).textContent?.trim() || '',
      price: (c.querySelector('.tier-price') || {}).textContent?.replace(/\s+/g, ' ').trim() || '',
      note: (c.querySelector('.tier-price-note') || {}).textContent?.replace(/\s+/g, ' ').trim() || '',
      text: c.textContent.replace(/\s+/g, ' ').trim(),
      visible: c.getBoundingClientRect().width > 0,
      buys: [...c.querySelectorAll('a[data-billing-product]')].map((a) => ({
        product: a.getAttribute('data-billing-product'),
        plan: a.getAttribute('data-billing-plan'),
        interval: a.getAttribute('data-billing-interval'),
        href: a.getAttribute('href'),
        label: a.textContent.replace(/\s+/g, ' ').trim(),
      })),
    })),
  }));
});

test('the rendered plan table is Community, Firm, ParaSign Business and Enterprise', async () => {
  const page = await openPricing();
  const sections = await readCards(page);
  await page.close();

  assert.equal(sections.length, 2, 'the page keeps one plan table per product');
  const [signing, sending] = sections;
  assert.match(signing.heading, /ParaSign/);
  assert.match(sending.heading, /ParaSend/);

  assert.deepEqual(signing.cards.map((c) => c.name), ['Community', 'Firm', 'Business', 'Enterprise']);
  assert.deepEqual(sending.cards.map((c) => c.name), ['Community', 'Firm', 'Enterprise']);
  for (const s of sections) {
    for (const c of s.cards) assert.ok(c.visible, `${s.heading}: the ${c.name} card did not render`);
  }

  // The two Pro cards are gone from the sale. The tier names they granted are
  // untouched in the code; what is gone is a card a visitor can buy.
  const everyCard = sections.flatMap((s) => s.cards);
  assert.ok(!everyCard.some((c) => c.name === 'Pro'), 'no card named Pro may still be on sale');
  assert.ok(!everyCard.some((c) => c.buys.some((b) => b.plan === 'pro')), 'no button may still sell a plan called pro');
});

test('the Firm card shows 29 excl. btw, 35.09 incl., and the same in both sections', async () => {
  const page = await openPricing();
  const sections = await readCards(page);
  await page.close();

  const monthlyExcl = exclOf('firm', 'firm', 'monthly');
  const yearlyExcl = exclOf('firm', 'firm', 'yearly');
  const monthlyIncl = catalog.priceOf('firm', 'firm', 'monthly');
  const yearlyIncl = catalog.priceOf('firm', 'firm', 'yearly');
  assert.equal(monthlyExcl, 29);
  assert.equal(yearlyExcl, 290);
  assert.equal(monthlyIncl, '35.09');
  assert.equal(yearlyIncl, '350.90');

  const firmCards = sections.flatMap((s) => s.cards).filter((c) => c.name === 'Firm');
  assert.equal(firmCards.length, 2, 'Firm covers both products, so its card stands in both tables');
  for (const card of firmCards) {
    assert.ok(card.price.includes(`€${euros(monthlyExcl)}`), `Firm card shows "${card.price}", expected the monthly excl-btw price`);
    assert.ok(card.note.includes(`charged €${monthlyIncl}/mo incl. 21% btw`), `Firm card note is "${card.note}"`);
    assert.ok(card.text.includes(`€${euros(yearlyExcl)} excl.`), 'the Firm card states the yearly excl-btw price');
    // Two months free on the yearly term, stated as the percentage.
    assert.ok(card.text.includes('16.7% off'), 'the Firm card states its yearly discount');
  }
  // Both printings are the same offer, so the amounts cannot disagree. Only the
  // period is abbreviated differently, which is the house style of each table.
  const amountOf = (c) => /€([\d,]+(?:\.\d{2})?)/.exec(c.price)[1];
  assert.equal(amountOf(firmCards[0]), amountOf(firmCards[1]));
});

test('the Firm buttons check out the bundle, and the no-JS fallback is sign-in', async () => {
  const page = await openPricing();
  const sections = await readCards(page);
  await page.close();

  const buys = sections.flatMap((s) => s.cards).flatMap((c) => c.buys);
  const firm = buys.filter((b) => b.product === 'firm');
  assert.equal(firm.length, 4, 'the Firm card carries a monthly and a yearly button in each table');
  for (const b of firm) {
    assert.equal(b.plan, 'firm');
    assert.ok(['monthly', 'yearly'].includes(b.interval));
    const order = catalog.resolveOrder(b);
    assert.ok(!order.error, `the catalog refuses a button the page renders: ${order.error}`);
    assert.equal(order.amount, catalog.priceOf('firm', 'firm', b.interval));
    // One payment, two entitlements. This is the whole point of the plan.
    assert.deepEqual(order.grants.map((g) => `${g.product}:${g.tier}`), ['parasign:pro', 'parasend:pro']);
    // The href is the no-JS fallback and must never be a metadata-less payment
    // link: an unattributable payment is money in with nothing granted.
    assert.ok(b.href.startsWith('/auth/login'), `Firm button falls back to ${b.href}`);
    assert.ok(!/mollie\.com/.test(b.href));
  }
  assert.ok(firm.some((b) => /35\.09\/mo incl/.test(b.label)), 'the monthly Firm button names the amount that will be charged');

  // ParaSign Business is untouched and still sold on its own.
  const business = buys.filter((b) => b.plan === 'business');
  assert.equal(business.length, 2);
  for (const b of business) {
    assert.equal(b.product, 'parasign');
    const order = catalog.resolveOrder(b);
    assert.deepEqual(order.grants.map((g) => `${g.product}:${g.tier}`), ['parasign:business']);
  }
});

test('every amount rendered on the page is a price the catalog can charge', async () => {
  const page = await openPricing();
  const text = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
  await page.close();

  // What the page is allowed to print: zero, and both bases of every plan that
  // is on sale. Nothing else. EUR 0.40 used to sit in this set as the metered
  // per-signature rate; it was the one amount here that no catalog line could
  // charge, which is precisely why it should never have been waved through.
  const allowed = new Set(['0']);
  for (const { product, plan } of catalog.ON_SALE) {
    for (const interval of catalog.INTERVALS) {
      allowed.add(euros(Number(catalog.priceOf(product, plan, interval))));
      allowed.add(euros(exclOf(product, plan, interval)));
    }
  }
  const printed = [...new Set([...text.matchAll(/€([\d][\d,]*(?:\.\d{2})?)/g)].map((m) => m[1]))];
  assert.ok(printed.length >= 6, `expected the page to print several amounts, found ${printed.length}`);
  const stray = printed.filter((amount) => !allowed.has(amount));
  assert.deepEqual(stray, [], `the page renders ${stray.join(', ')}, which the catalog cannot charge`);

  // And the amounts of the plans that are off sale must be gone from the page.
  for (const legacy of [['parasign', 'pro'], ['parasend', 'pro']]) {
    assert.ok(!catalog.isOnSale(legacy[0], legacy[1]));
    for (const interval of catalog.INTERVALS) {
      const incl = euros(Number(catalog.priceOf(legacy[0], legacy[1], interval)));
      assert.ok(!printed.includes(incl), `${legacy.join('/')} is off sale but /pricing still prints €${incl}`);
    }
  }
});

test.after(async () => { await chrome.close(); web.close(); });
