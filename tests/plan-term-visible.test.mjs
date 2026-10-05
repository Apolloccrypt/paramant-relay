// Does the customer actually SEE when his term runs out.
//
// The relay has carried paid_until_<product> since the betaalpad fixes and the
// entitlement layer has always floored an expired tier at read time, so the
// account has been quietly dropping to Community on a date nothing on the site
// ever mentioned. The reminder mail is one half of the fix; this is the other,
// and it is the half a customer looks at on the day he wonders.
//
// Driven against the real pages with the two APIs mocked, in the shape
// tests/navigation-shell.test.mjs uses: a static file server on a free port and
// page.route() for every /api call. Nothing here needs a relay.
//
// Three moments per page, and the third is the one that used to be invisible:
//   far    a term 40 days out    -> the date, no warning band
//   close  a term 3 days out     -> the date AND the amber band with Renew
//   ended  a term that has gone  -> "Ended on ..., now on Community"

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const aliases = { '/': '/index.html', '/dashboard': '/dashboard.html', '/account': '/account.html', '/pricing': '/pricing.html',
  '/en/dashboard': '/en/dashboard.html', '/en/account': '/en/account.html' };

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

const DAY = 86400000;
const json = (route, body, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

// The three terms under test, as an ISO paid_until the pages have to read.
function term(days) { return new Date(Date.now() + days * DAY).toISOString(); }
// The one notation the site shows, mirrored from frontend/js/format-date.js:
// day, month in full, year, in UTC, and never a slash.
// The Dutch pages write the month in Dutch (format-date.js reads <html lang>),
// the English copies under /en in English. Same shape either way.
function readable(iso, lang = 'en') {
  return new Date(iso).toLocaleDateString(lang === 'nl' ? 'nl-NL' : 'en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
}

// ── /account ─────────────────────────────────────────────────────────────────
// Its billing block hangs on one call. Everything else on the page is stubbed
// to something harmless so nothing else can fail the run.
async function account(paidUntil, prefix = '') {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  // Playwright tries the most recently added route first, so the catch-all is
  // registered before the two that matter, not after.
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/billing/status', (route) => json(route, {
    current_plan: 'pro',
    plan_parasign: 'pro',
    plan_parasend: 'community',
    paid_until_parasign: paidUntil,
    paid_until_parasend: null,
    period: 'monthly',
    amount_eur: null,
    access_until: Date.parse(paidUntil) > Date.now() ? paidUntil : null,
    next_billing_date: null,
    auto_renews: false,
    cancellation_scheduled_at: null,
  }));
  await page.route('**/api/user/billing/history', (route) => json(route, { history: [] }));
  await page.route('**/api/user/account', (route) => json(route, {
    email: 'demo@example.com', plan: 'pro', api_key_masked: 'pgp_demo...abcd',
    created_at: '2026-01-01T00:00:00.000Z', sessions: [], backup_codes_remaining: 0,
  }));
  await page.goto(ORIGIN + prefix + '/account', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const el = document.getElementById('billing-content');
    return el && !el.classList.contains('hidden');
  }, null, { timeout: 10000 });
  const state = await page.evaluate(() => {
    const line = document.getElementById('billing-term-line');
    const warn = document.getElementById('billing-term-warn');
    const cta = warn && warn.querySelector('a.plan-term-warn-cta');
    return {
      line: line && !line.hidden ? line.textContent.trim() : null,
      warn: warn && !warn.hidden ? warn.querySelector('[data-term="text"]').textContent.trim() : null,
      cta: cta ? { text: cta.textContent.trim(), href: cta.getAttribute('href') } : null,
      warnVisible: !!(warn && !warn.hidden && warn.getBoundingClientRect().height > 0),
    };
  });
  await page.close();
  return state;
}

// ── /dashboard ───────────────────────────────────────────────────────────────
async function dashboard(paidUntil, prefix = '') {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/me', (route) => json(route, {
    email: 'demo@example.com',
    label: null,
    plan: 'pro',
    plan_parasign: 'pro',
    plan_parasend: 'community',
    paid_until_parasign: paidUntil,
    paid_until_parasend: null,
    created_at: '2026-01-01T00:00:00.000Z',
    api_key_masked: 'pgp_demo...abcd',
    backup_codes_remaining: 3,
    session_expires_at: new Date(Date.now() + 3600000).toISOString(),
    usage_purpose: 'other',
  }));
  await page.route('**/api/user/documents**', (route) => json(route, { documents: [] }));
  await page.route('**/api/user/dashboard/overview', (route) => json(route, {}));
  await page.goto(ORIGIN + prefix + '/dashboard', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const el = document.getElementById('dh-term-line');
    return el && !el.hidden;
  }, null, { timeout: 10000 });
  const state = await page.evaluate(() => {
    const line = document.getElementById('dh-term-line');
    const warn = document.getElementById('dh-term-warn');
    const cta = warn && warn.querySelector('a.plan-term-warn-cta');
    return {
      line: line && !line.hidden ? line.textContent.trim() : null,
      warn: warn && !warn.hidden ? warn.querySelector('[data-dh="term-warn"]').textContent.trim() : null,
      cta: cta ? { text: cta.textContent.trim(), href: cta.getAttribute('href') } : null,
      warnVisible: !!(warn && !warn.hidden && warn.getBoundingClientRect().height > 0),
    };
  });
  await page.close();
  return state;
}

// Both pages are Dutch since 23 September 2026, with an English copy under /en/
// on the same script. The same four states are held in both languages.
const COPY = {
  nl: {
    lang: 'nl',
    ends: (d) => `Loopt af op ${d}, er wordt niets automatisch verlengd.`,
    ended: (d) => `Afgelopen op ${d}, nu op Community.`,
    noCharge: /Er wordt niets automatisch afgeschreven\./, renew: 'Verlengen', pricing: '/pricing',
  },
  en: {
    lang: 'en',
    ends: (d) => `Ends on ${d}, nothing renews automatically.`,
    ended: (d) => `Ended on ${d}, now on Community.`,
    noCharge: /Nothing is charged automatically\./, renew: 'Renew', pricing: /^\/(en\/)?pricing$/,
  },
};
const samePricing = (want, href) => (typeof want === 'string' ? href === want : want.test(href || ''));
for (const [name, run, prefix, copy] of [['account', account, '', COPY.nl], ['dashboard', dashboard, '', COPY.nl],
  ['en/account', account, '/en', COPY.en], ['en/dashboard', dashboard, '/en', COPY.en]]) {
  // Far out: the date is stated, and nothing shouts. A warning band on a term
  // with six weeks left is noise, and noise is what makes the real one invisible.
  const far = term(40);
  const farState = await run(far, prefix);
  ok(`${name}: a term far out shows the date and says nothing renews`,
    farState.line === copy.ends(readable(far, copy.lang)), JSON.stringify(farState));
  ok(`${name}: a term far out carries no warning band`, farState.warn === null, JSON.stringify(farState));

  // Inside the last seven days: the same date, plus one calm amber line with the
  // one action that changes anything.
  const close = term(3);
  const closeState = await run(close, prefix);
  ok(`${name}: a term inside seven days still states the date`,
    closeState.line === copy.ends(readable(close, copy.lang)), JSON.stringify(closeState));
  ok(`${name}: a term inside seven days raises the warning`,
    closeState.warnVisible && closeState.warn.includes(readable(close, copy.lang)), JSON.stringify(closeState));
  ok(`${name}: the warning says nothing is charged automatically`,
    copy.noCharge.test(closeState.warn || ''), closeState.warn || '');
  ok(`${name}: the warning offers Renew, and it goes to /pricing`,
    closeState.cta && closeState.cta.text === copy.renew && samePricing(copy.pricing, closeState.cta.href),
    JSON.stringify(closeState.cta));

  // After the term. This is the case the page used to render as "Pro plan,
  // active" while every gate answered 402.
  const gone = term(-2);
  const goneState = await run(gone, prefix);
  ok(`${name}: an ended term says so, and says where the account landed`,
    goneState.line === copy.ended(readable(gone, copy.lang)), JSON.stringify(goneState));
  ok(`${name}: an ended term drops the warning band`, goneState.warn === null, JSON.stringify(goneState));

  // House style. An em-dash in customer copy is a style failure everywhere in
  // this repo, and this text is generated rather than written into the HTML.
  ok(`${name}: no em-dash in the term copy`,
    ![farState.line, closeState.line, closeState.warn, goneState.line].some((s) => s && s.includes('\u2014')), '');
}

await browser.close();
server.close();

for (const c of checks) console.log(`${c.pass ? 'ok' : 'FAIL'} - ${c.name}${c.pass ? '' : ` :: ${c.detail}`}`);
const failed = checks.filter((c) => !c.pass);
console.log(`${checks.length} checks, ${failed.length} failed`);
if (failed.length) process.exit(1);
