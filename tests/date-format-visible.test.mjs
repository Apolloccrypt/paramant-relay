// One date notation, everywhere a customer looks.
//
// WHAT WENT WRONG
//
// A buyer read /account on 3 September 2026 and counted three notations on one
// screen:
//
//   INVOICES AND CREDIT NOTES   PM-2026-0413 · 8/9/2026
//   PLAN                        Ends on 8 September
//   ACCESS UNTIL                9/8/2026
//
// The two slashed dates are the same two digits in opposite orders. Both came
// from toLocaleDateString() with no locale, which follows the VISITOR's
// machine: a Dutch browser writes day/month, an American one month/day, and
// neither matches the sentence ten lines above it. An accountant reading
// 8/9/2026 as 8 September and 9/8/2026 as 9 August, on one page, about one
// term, is a mistake the page invited. The session list added a fourth shape,
// "3/17/2026, 8:48:55 PM".
//
// WHAT IS PINNED
//
//   1. No slashed date anywhere in the rendered text of /account or /dashboard.
//   2. Every date the page shows reads "8 September 2026": day, month in full,
//      year. One notation, no exceptions, from frontend/js/format-date.js.
//   3. The three dates the buyer had side by side are all in that one shape.
//
// Driven against the real pages with the APIs mocked, in the shape
// tests/navigation-shell.test.mjs uses: a static file server on a free port and
// page.route() for every /api call. Nothing here needs a relay.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const aliases = { '/': '/index.html', '/dashboard': '/dashboard.html', '/account': '/account.html', '/pricing': '/pricing.html' };

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

const json = (route, body, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

// The one shape: "8 September 2026". Anchored on both ends of the match so a
// two-digit year or a trailing slash cannot slip through.
const MONTH = '(?:January|February|March|April|May|June|July|August|September|October|November|December)';
const ONE_SHAPE = new RegExp(`^\\d{1,2} ${MONTH} \\d{4}$`);
const ANY_DATE_LIKE = new RegExp(`\\b\\d{1,2} ${MONTH} \\d{4}\\b`);

// A slashed date, and nothing else: "8/9/2026", "3/17/2026", "9/8/26". Written
// tightly so "24/7" and "and/or" are not dragged in.
const SLASHED = /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/;

// The mocked account. Deliberately the buyer's own situation: a bought term
// that ends on a day whose number is below 13, so a month/day reading of it is
// a different real date rather than an obvious impossibility.
const PAID_UNTIL = '2026-09-08T00:00:00.000Z';

async function open(url, ready) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  // Playwright tries the most recently added route first, so the catch-all is
  // registered before the ones that matter, not after.
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/session/verify', (route) => json(route, { authenticated: true }));
  await page.route('**/api/user/account', (route) => json(route, {
    email: 'demo@example.com', plan: 'pro', api_key_masked: 'pgp_demo...abcd',
    created_at: '2026-01-31T00:00:00.000Z', backup_codes_remaining: 4,
    session_expires_at: '2026-09-20T00:00:00.000Z',
    sessions: [{ ip_masked: '198.51.100.x', user_agent_short: 'Firefox on Linux', current: true, last_seen: '2026-03-17T20:48:55.000Z' }],
  }));
  await page.route('**/api/user/billing/status', (route) => json(route, {
    current_plan: 'pro', plan_parasign: 'pro', plan_parasend: 'community',
    paid_until_parasign: PAID_UNTIL, paid_until_parasend: null,
    period: 'monthly', amount_eur: null,
    access_until: PAID_UNTIL, next_billing_date: null, auto_renews: false,
    cancellation_scheduled_at: '2026-12-03T00:00:00.000Z',
  }));
  await page.route('**/api/user/billing/invoices', (route) => json(route, {
    invoices: [{ number: 'PM-2026-0413', date: '2026-09-08T00:00:00.000Z', kind: 'invoice',
      total: '18.15', currency: 'EUR', pdf_url: '/v2/billing/invoices/PM-2026-0413.pdf' }],
  }));
  await page.route('**/api/user/billing/history', (route) => json(route, {
    history: [{ ts: '2026-09-08T12:00:00.000Z', type: 'invoice', event_type: 'invoice',
      label: 'Paramant ParaSign Pro, monthly plan', detail: 'Paid',
      amount: '18.15', currency: 'EUR', document: 'PM-2026-0413' }],
  }));
  // /dashboard reads its own endpoint, and its document rows are the other
  // place a date used to be written a second way ("Created Aug 31, 2026").
  await page.route('**/api/user/me', (route) => json(route, {
    email: 'demo@example.com', label: null, plan: 'pro',
    plan_parasign: 'pro', plan_parasend: 'community',
    paid_until_parasign: PAID_UNTIL, paid_until_parasend: null,
    created_at: '2026-01-31T00:00:00.000Z', api_key_masked: 'pgp_demo...abcd',
    backup_codes_remaining: 3, session_expires_at: '2026-09-20T00:00:00.000Z',
    usage_purpose: 'other',
  }));
  await page.route('**/api/user/documents**', (route) => json(route, {
    documents: [{ id: 'doc_1', title: 'Payslip August', status: 'signed',
      created_at: '2026-08-31T09:00:00.000Z', expires_at: '2026-11-30T09:00:00.000Z' }],
  }));
  await page.route('**/api/user/dashboard/**', (route) => json(route, {}));
  await page.goto(ORIGIN + url, { waitUntil: 'domcontentloaded' });
  try { await page.waitForFunction(ready, null, { timeout: 10000 }); } catch { /* asserted below */ }
  return page;
}

// ── /account ─────────────────────────────────────────────────────────────────
const account = await open('/account', () => {
  const el = document.getElementById('billing-content');
  const inv = document.getElementById('billing-invoices');
  return el && !el.classList.contains('hidden') && inv && /PM-2026/.test(inv.textContent || '');
});

const shown = await account.evaluate(() => {
  const text = (el) => ((el && el.textContent) || '').trim();
  const invoiceRow = document.querySelector('#billing-invoices .info-row .info-label');
  const historyRow = document.querySelector('#billing-history .info-row .info-label');
  return {
    body: document.body.innerText,
    term: text(document.getElementById('billing-term-line')),
    accessUntil: text(document.getElementById('billing-next')),
    invoice: text(invoiceRow),
    history: text(historyRow),
    created: text(document.getElementById('created')),
    cancel: text(document.getElementById('billing-cancel-date')),
    session: text(document.querySelector('#sessions-list .info-value')),
  };
});
await account.close();

// 1. The slash is gone from the whole page, not only from the three rows.
const accountSlash = shown.body.split('\n').filter((line) => SLASHED.test(line));
ok('/account shows no slashed date anywhere on the page', accountSlash.length === 0, accountSlash.join(' | '));

// 2. The three dates that sat side by side now read the same way.
const pick = (s) => (s.match(ANY_DATE_LIKE) || [''])[0];
const trio = { 'the term line': pick(shown.term), 'access until': pick(shown.accessUntil), 'the invoice row': pick(shown.invoice) };
for (const [where, value] of Object.entries(trio)) {
  ok(`${where} carries a date in the one shape, day month year`, ONE_SHAPE.test(value), `${where}: "${value}" from "${shown[Object.keys(trio).indexOf(where) === 0 ? 'term' : 'accessUntil']}"`);
}
ok('the three dates on one screen are the same date, written one way',
  trio['the term line'] === '8 September 2026'
  && trio['access until'] === '8 September 2026'
  && trio['the invoice row'] === '8 September 2026',
  JSON.stringify(trio));

// 3. Every other date the page renders is in the same shape.
for (const [where, value] of Object.entries({
  'the billing history row': shown.history,
  'the account creation date': shown.created,
  'the scheduled downgrade': shown.cancel,
  'the session list': shown.session,
})) {
  ok(`${where} uses the one shape too`, ONE_SHAPE.test(pick(value)), `${where}: "${value}"`);
}

// A moment, not a day, still says which day and which zone.
ok('a session says the day and names the clock it is on',
  /8:48/.test(shown.session) === false && /20:48 UTC/.test(shown.session), shown.session);

// ── /dashboard ───────────────────────────────────────────────────────────────
// "Created Aug 31, 2026" sat one card away from "Ends on 8 September". Same
// page, same kind of fact, two notations.
const dashboard = await open('/dashboard', () => {
  const line = document.getElementById('dh-term-line');
  return line && !line.hidden;
});
const dash = await dashboard.evaluate(() => ({
  body: document.body.innerText,
  term: ((document.getElementById('dh-term-line') || {}).textContent || '').trim(),
}));
await dashboard.close();

const dashSlash = dash.body.split('\n').filter((line) => SLASHED.test(line));
ok('/dashboard shows no slashed date anywhere on the page', dashSlash.length === 0, dashSlash.join(' | '));
ok('/dashboard writes the term date exactly as /account does',
  pick(dash.term) === '8 September 2026', dash.term);
// The document row is where "Created Aug 31, 2026" stood, a third notation on a
// screen that already had two.
ok('a document row writes its date the same way the term line does',
  /Created 31 August 2026/.test(dash.body), (dash.body.match(/Created [^\n]*/) || ['no document row'])[0]);

// ── report ───────────────────────────────────────────────────────────────────
await browser.close();
server.close();
for (const c of checks) console.log(`${c.pass ? 'ok' : 'FAIL'} - ${c.name}${c.pass ? '' : `\n      ${c.detail}`}`);
const failed = checks.filter((c) => !c.pass).length;
console.log(`\n${checks.length} checks, ${failed} failed`);
process.exit(failed ? 1 : 0);
