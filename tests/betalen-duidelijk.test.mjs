// What the customer reads around paying, in a real browser on the real pages
// with the APIs stubbed. Rows 2 to 6 and 8 of the betaaltest of 05-10-2026:
// paying works and the rights are right, but the words around it were not.
//
//   row 4  back from Mollie after cancelling, failing or letting the payment
//          expire, the dashboard said "being confirmed" and then "you get the
//          plan by itself". It now says what happened and offers to pay again.
//   row 3  "Plan opzeggen" on a one-off payment, under "subscription and
//          history". A one-off payment has nothing to cancel.
//   row 8  after Firm then Business, /account showed two end dates with
//          nothing to say what they were. One line per product now.
//   row 6  a signed-out buyer on /en/pricing landed on the Dutch sign-in page,
//          and came back from paying on the Dutch dashboard.
//   row 5  the 101st signature said "all 100 transfers" and named no Business.
//
// The shape of tests/plan-term-visible.test.mjs: a static server on a free
// port and page.route() for every /api call. Nothing here needs a relay; the
// relay half (the status Mollie reports, the language of the redirect, the
// ParaSend half of Business) is relay/test/route-betalen-duidelijk.test.js.
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const aliases = { '/dashboard': '/dashboard.html', '/account': '/account.html', '/pricing': '/pricing.html',
  '/en/dashboard': '/en/dashboard.html', '/en/account': '/en/account.html', '/en/pricing': '/en/pricing.html',
  '/auth/login': '/auth/login.html', '/en/auth/login': '/en/auth/login.html' };

const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  pathname = aliases[pathname] || pathname;
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }
const json = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const DAY = 86400000;
const iso = (days) => new Date(Date.now() + days * DAY).toISOString();

const visible = (page, sel) => page.evaluate((s) => {
  const el = document.querySelector(s);
  if (!el || el.hidden) return null;
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0 ? el.textContent.replace(/\s+/g, ' ').trim() : null;
}, sel);

// ── row 4: the dashboard after Mollie sends the buyer back ───────────────────
async function dashboardReturn(prefix, me, payment) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/me', (route) => json(route, Object.assign({
    email: 'demo@example.com', label: null, plan: 'community', plan_parasign: 'free', plan_parasend: 'community',
    paid_until_parasign: null, paid_until_parasend: null, created_at: '2026-01-01T00:00:00.000Z',
    api_key_masked: 'pgp_demo...abcd', backup_codes_remaining: 3,
    session_expires_at: new Date(Date.now() + 3600000).toISOString(), usage_purpose: 'other',
  }, me)));
  await page.route('**/api/user/billing/last-payment', (route) => json(route, { ok: true, payment }));
  await page.route('**/api/user/documents**', (route) => json(route, { documents: [] }));
  await page.goto(`${ORIGIN}${prefix}/dashboard?billing=return`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const k = document.querySelector('[data-dh="return-kicker"]');
    return k && k.textContent.trim() !== '--';
  }, null, { timeout: 10000 });
  const state = {
    kicker: await visible(page, '[data-dh="return-kicker"]'),
    lede: await visible(page, '[data-dh="return-lede"]'),
    retry: await visible(page, '[data-dh="return-retry"]'),
    retryHref: await page.evaluate(() => { const a = document.querySelector('[data-dh="return-retry"]'); return a ? a.getAttribute('href') : null; }),
  };
  if (state.retry) {
    await page.click('[data-dh="return-retry"]');
    await page.waitForLoadState('domcontentloaded');
    state.landed = new URL(page.url()).pathname;
  }
  await page.close();
  return state;
}

const NOT_PAID = {
  nl: { canceled: 'Betaling geannuleerd', failed: 'Betaling mislukt', expired: 'Betaling verlopen', nothing: /Er is niets afgeschreven en uw plan is niet veranderd\./, retry: 'Opnieuw betalen', pricing: '/pricing', confirming: /wordt bevestigd|vanzelf/ },
  en: { canceled: 'Payment cancelled', failed: 'Payment failed', expired: 'Payment expired', nothing: /Nothing has been charged and your plan has not changed\./, retry: 'Pay again', pricing: '/en/pricing', confirming: /Confirming|by itself/ },
};
for (const [lang, prefix] of [['nl', ''], ['en', '/en']]) {
  const c = NOT_PAID[lang];
  for (const status of ['canceled', 'failed', 'expired']) {
    const s = await dashboardReturn(prefix, {}, { status, product: 'firm', plan: 'firm', interval: 'monthly', lang });
    ok(`${lang} dashboard, ${status}: says so`, s.kicker === c[status], JSON.stringify(s));
    ok(`${lang} dashboard, ${status}: nothing charged, plan unchanged`, c.nothing.test(s.lede || ''), s.lede);
    ok(`${lang} dashboard, ${status}: never "being confirmed" or "by itself"`, !c.confirming.test(`${s.kicker} ${s.lede}`), s.lede);
    ok(`${lang} dashboard, ${status}: a button to pay again, to the pricing page`, s.retry === c.retry && s.landed === c.pricing, JSON.stringify(s));
  }
  // Also for a customer who already pays: a cancelled renewal is not "received".
  const paying = await dashboardReturn(prefix, { plan_parasign: 'pro', plan_parasend: 'pro', paid_until_parasign: iso(20), paid_until_parasend: iso(20) },
    { status: 'canceled', product: 'firm', plan: 'firm', interval: 'yearly', lang });
  ok(`${lang} dashboard: a cancelled renewal on a paying account is not "payment received"`, paying.kicker === c.canceled, JSON.stringify(paying));
  const paid = await dashboardReturn(prefix, { plan_parasign: 'pro', plan_parasend: 'pro', paid_until_parasign: iso(31), paid_until_parasend: iso(31) },
    { status: 'paid', product: 'firm', plan: 'firm', interval: 'monthly', lang });
  ok(`${lang} dashboard: a paid payment with the plan on the account is received, without a retry`,
    /Betaling ontvangen|Payment received/.test(paid.kicker || '') && paid.retry === null, JSON.stringify(paid));
}

// ── rows 3 and 8: /account on a one-off payment, after Firm then Business ────
async function account(prefix, status) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/billing/status', (route) => json(route, status));
  await page.route('**/api/user/billing/history', (route) => json(route, { history: [] }));
  await page.route('**/api/user/account', (route) => json(route, {
    email: 'demo@example.com', plan: 'pro', api_key_masked: 'pgp_demo...abcd',
    created_at: '2026-01-01T00:00:00.000Z', sessions: [], backup_codes_remaining: 0,
  }));
  await page.goto(`${ORIGIN}${prefix}/account`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const el = document.getElementById('billing-content');
    return el && !el.classList.contains('hidden');
  }, null, { timeout: 10000 });
  const state = await page.evaluate(() => {
    const txt = (el) => (el ? el.textContent.replace(/\s+/g, ' ').trim() : '');
    const shown = (el) => !!(el && !el.hidden && !el.classList.contains('hidden') && el.getBoundingClientRect().height > 0);
    const section = document.getElementById('billing-section');
    return {
      kicker: txt(section.querySelector('.acct-kicker')),
      cancel: shown(document.getElementById('billing-cancel-btn')),
      line: shown(document.getElementById('billing-term-line')) ? txt(document.getElementById('billing-term-line')) : null,
      products: [...document.querySelectorAll('#billing-products li')].map(txt),
      productsShown: shown(document.getElementById('billing-products')),
      sectionText: txt(section),
    };
  });
  await page.close();
  return state;
}
const day = (when, lang) => new Date(when).toLocaleDateString(lang === 'nl' ? 'nl-NL' : 'en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
const BIZ_END = iso(31); const FIRM_END = iso(62);
const upgraded = {
  current_plan: 'business', plan_name: 'Business',
  plan_parasign: 'business', plan_parasend: 'pro',
  paid_until_parasign: FIRM_END, paid_until_parasend: FIRM_END,
  terms_parasign: [{ tier: 'business', until: BIZ_END, bundle: 'business' }, { tier: 'pro', until: FIRM_END, bundle: 'firm' }],
  terms_parasend: [{ tier: 'pro', until: FIRM_END, bundle: 'firm' }],
  access_until: FIRM_END, next_billing_date: null, auto_renews: false, cancellation_scheduled_at: null,
};
for (const [lang, prefix] of [['nl', ''], ['en', '/en']]) {
  const s = await account(prefix, upgraded);
  ok(`${lang} account: no cancel button on a one-off payment`, s.cancel === false, JSON.stringify(s));
  ok(`${lang} account: no "subscription" in the heading`, !/abonnement|subscription/i.test(s.kicker), s.kicker);
  ok(`${lang} account: "paid until <date>, renewing possible from today"`,
    s.line === (lang === 'nl'
      ? `Betaald tot ${day(FIRM_END, 'nl')}, verlengen kan vanaf vandaag: de nieuwe periode sluit aan op ${day(FIRM_END, 'nl')}. Er wordt niets automatisch verlengd.`
      : `Paid until ${day(FIRM_END, 'en')}, renewing is possible from today: the new term starts on ${day(FIRM_END, 'en')}. Nothing renews automatically.`), s.line);
  ok(`${lang} account: one line per product, with what takes over after Business`,
    s.productsShown && JSON.stringify(s.products) === JSON.stringify(lang === 'nl'
      ? [`Ondertekenen: Business tot ${day(BIZ_END, 'nl')}, daarna Firm tot ${day(FIRM_END, 'nl')}.`, `Versturen: Firm tot ${day(FIRM_END, 'nl')}.`]
      : [`ParaSign: Business until ${day(BIZ_END, 'en')}, then Firm until ${day(FIRM_END, 'en')}.`, `ParaSend: Firm until ${day(FIRM_END, 'en')}.`]),
    JSON.stringify(s.products));
  ok(`${lang} account: no second "access until" date row`, !/Toegang tot|Access until/.test(s.sectionText), s.sectionText.slice(0, 400));
  // With a subscription standing behind it (BILLING_MODE set), the button is there.
  const renews = await account(prefix, { ...upgraded, auto_renews: true });
  ok(`${lang} account: a plan that renews keeps its cancel button`, renews.cancel === true, JSON.stringify(renews));
  // Bought as Business alone: ParaSend is named after Business.
  const biz = await account(prefix, { ...upgraded, terms_parasign: [{ tier: 'business', until: BIZ_END, bundle: 'business' }],
    terms_parasend: [{ tier: 'pro', until: BIZ_END, bundle: 'business' }], paid_until_parasign: BIZ_END, paid_until_parasend: BIZ_END, access_until: BIZ_END });
  ok(`${lang} account: Business alone names its ParaSend half after Business`,
    (biz.products[1] || '') === (lang === 'nl' ? `Versturen: inbegrepen bij Business tot ${day(BIZ_END, 'nl')}.` : `ParaSend: included with Business until ${day(BIZ_END, 'en')}.`),
    JSON.stringify(biz.products));
}

// ── row 6: the English buyer stays English through the whole checkout ───────
for (const [lang, from, login] of [['en', '/en/pricing', '/en/auth/login'], ['nl', '/pricing', '/auth/login']]) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/app/token', (route) => json(route, { error: 'unauthorized' }, 401));
  await page.goto(ORIGIN + from, { waitUntil: 'domcontentloaded' });
  await page.click('a[data-billing-product="firm"][data-billing-interval="monthly"] >> nth=0');
  await page.waitForURL((u) => u.pathname.includes('/auth/login'), { timeout: 10000 }).catch(() => {});
  const u = new URL(page.url());
  ok(`${lang} pricing, signed out: the sign-in page in the same language`, u.pathname === login, page.url());
  ok(`${lang} pricing, signed out: and straight back to the same pricing page`, u.searchParams.get('next') === from, page.url());
  await page.close();

  // Signed in: the checkout tells the relay which dashboard to come back to.
  const p2 = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  let sent = null;
  await p2.route('**/api/**', (route) => json(route, {}));
  await p2.route('**/api/user/app/token', (route) => json(route, { token: 'pst_demo', expires_in: 900 }));
  await p2.route('**/v2/billing/checkout', (route) => { sent = JSON.parse(route.request().postData() || '{}'); return json(route, { ok: true, checkout_url: `${ORIGIN}${from}#paid` }); });
  await p2.goto(ORIGIN + from, { waitUntil: 'domcontentloaded' });
  await p2.click('a[data-billing-product="firm"][data-billing-interval="monthly"] >> nth=0');
  await p2.waitForFunction(() => location.hash === '#paid', null, { timeout: 10000 }).catch(() => {});
  ok(`${lang} pricing: the checkout carries the language`, sent && sent.lang === lang, JSON.stringify(sent));
  await p2.close();
}

// ── row 5: the 402 at the 101st signature, on a Dutch page ──────────────────
{
  const page = await browser.newPage();
  await page.goto(`${ORIGIN}/dashboard.html`, { waitUntil: 'domcontentloaded' }).catch(() => {});
  await page.setContent('<!DOCTYPE html><html lang="nl"><head></head><body></body></html>');
  await page.addScriptTag({ path: path.join(ROOT, 'js', 'quota-upgrade.js') });
  const card = await page.evaluate(() => window.paQuotaUpgrade.html({ error: 'monthly_sign_quota_reached', plan: 'pro', limit: 100, used: 100, reset_date: '2026-11-01' }));
  ok('nl 402 at 101: counts signatures', card.includes('U heeft alle 100 handtekeningen van uw plan voor deze maand gebruikt.'), card);
  ok('nl 402 at 101: never transfers', !/verzendingen/.test(card), card);
  ok('nl 402 at 101: names Business and the way to it on a Dutch page', /Business \(EUR 299\/maand excl\. btw\) voor 1\.000 handtekeningen/.test(card) && card.includes('mailto:privacy@paramant.app'), card);
  ok('nl 402 at 101: no button to a Dutch /pricing that sells no Business', !/href="\/pricing"/.test(card), card);
  await page.close();
}

await browser.close();
server.close();

for (const c of checks) console.log(`${c.pass ? 'ok' : 'FAIL'} - ${c.name}${c.pass ? '' : ` :: ${c.detail}`}`);
const failed = checks.filter((c) => !c.pass);
console.log(`${checks.length} checks, ${failed.length} failed`);
if (failed.length) process.exit(1);
