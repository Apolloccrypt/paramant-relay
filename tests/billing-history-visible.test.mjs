// Does the customer actually SEE his billing history.
//
// /account has had a "Billing history" block since the account page existed and
// it said "No billing events yet" to a customer who had paid, been invoiced and
// watched his term run out: the only feed behind it was the admin audit log,
// which knows nothing about a self-serve Mollie payment. The relay now derives
// the list from the invoice and credit-note records it already holds; this is
// the half a customer looks at.
//
// Driven against the real page with the APIs mocked, in the shape
// tests/navigation-shell.test.mjs and tests/plan-term-visible.test.mjs use: a
// static file server on a free port and page.route() for every /api call.
// Nothing here needs a relay.
//
// Three states, and the first is the bug this replaces:
//   empty     nothing has happened      -> "No billing events yet."
//   paid      an invoice, a credit note, a term that ended
//   unreachable  the API is down        -> says so, does not lie about nothing

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const aliases = { '/': '/index.html', '/account': '/account.html' };

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

// Exactly the rows /api/user/billing/history answers for an account that paid,
// was partly refunded, and then let the term run out.
const HISTORY = [
  {
    ts: '2027-09-03T12:00:00.000Z', type: 'term_ended',
    label: 'ParaSign Pro term ended', detail: 'Account back on Community',
    amount: null, currency: null, document: null, notified_at: '2027-09-03T18:00:00.000Z',
  },
  {
    ts: '2026-10-01T09:00:00.000Z', type: 'credit_note',
    label: 'Credit note for invoice PS-2026-0001 (partial)', detail: 'Refunded',
    amount: '-100.00', currency: 'EUR', document: 'CN-2026-0001',
    credit_for: 'PS-2026-0001', pdf_url: '/v2/billing/invoices/CN-2026-0001.pdf',
  },
  {
    ts: '2026-09-03T12:00:00.000Z', type: 'invoice',
    label: 'Paramant ParaSign Pro, yearly plan', detail: 'Paid',
    amount: '603.79', currency: 'EUR', document: 'PS-2026-0001',
    pdf_url: '/v2/billing/invoices/PS-2026-0001.pdf',
  },
  {
    ts: '2026-08-01T08:00:00.000Z', type: 'plan_changed',
    label: 'Plan changed from community to pro', detail: null,
    amount: null, currency: null, document: null,
    event_type: 'plan_changed', metadata: { from: 'community', to: 'pro' },
  },
];

async function account({ history, status = 200 }) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/billing/status', (route) => json(route, {
    current_plan: 'pro', plan_parasign: 'pro', plan_parasend: 'community',
    access_until: null, next_billing_date: null, auto_renews: false,
    cancellation_scheduled_at: null,
  }));
  await page.route('**/api/user/billing/invoices', (route) => json(route, { invoices: [] }));
  await page.route('**/api/user/billing/history', (route) =>
    (status === 200 ? json(route, { history }) : json(route, { error: 'relay_unreachable' }, status)));
  await page.route('**/api/user/account', (route) => json(route, {
    email: 'demo@example.com', plan: 'pro', api_key_masked: 'pgp_demo...abcd',
    created_at: '2026-01-01T00:00:00.000Z', sessions: [], backup_codes_remaining: 0,
  }));
  await page.goto(ORIGIN + '/account', { waitUntil: 'domcontentloaded' });
  // The block starts on a loading line, so "done" is when that line is gone.
  await page.waitForFunction(() => {
    const el = document.getElementById('billing-history');
    return el && !/Loading/i.test(el.textContent || '');
  }, null, { timeout: 10000 });
  const state = await page.evaluate(() => {
    const el = document.getElementById('billing-history');
    const rows = Array.from(el.querySelectorAll('.info-row')).map((row) => ({
      left: (row.querySelector('.info-label') || {}).textContent || '',
      right: (row.querySelector('.info-value') || {}).textContent || '',
      href: (row.querySelector('a') || {}).getAttribute ? row.querySelector('a').getAttribute('href') : null,
    }));
    return { text: (el.textContent || '').trim(), rows, html: el.innerHTML };
  });
  await page.close();
  return state;
}

// ── an account that has never paid ───────────────────────────────────────────
const empty = await account({ history: [] });
ok('nothing has happened: the block says so and says nothing else',
  empty.text === 'No billing events yet.', empty.text);

// ── an account that paid, was refunded, and ran out ──────────────────────────
const full = await account({ history: HISTORY });
ok('every event is a row', full.rows.length === HISTORY.length, `${full.rows.length} rows`);
ok('the block is no longer empty', !full.text.includes('No billing events yet'), full.text);

ok('the payment is there, with its invoice number and its total',
  full.rows.some((r) => r.left.includes('PS-2026-0001')
    && r.left.includes('Paramant ParaSign Pro, yearly plan')
    && r.right.includes('EUR 603.79')),
  JSON.stringify(full.rows[2]));

ok('the credit note is there, negative, naming the invoice it credits',
  full.rows.some((r) => r.left.includes('CN-2026-0001')
    && r.left.includes('Credit note for invoice PS-2026-0001')
    && r.right.includes('EUR -100.00')),
  JSON.stringify(full.rows[1]));

ok('the term that ended is there, and says where the account landed',
  full.rows.some((r) => r.left.includes('ParaSign Pro term ended')
    && r.right.includes('Account back on Community')),
  JSON.stringify(full.rows[0]));

ok('the plan change from the audit log is in the same list',
  full.rows.some((r) => r.left.includes('Plan changed from community to pro')),
  JSON.stringify(full.rows[3]));

ok('every document row offers its PDF, and only document rows do',
  full.rows.filter((r) => r.href).length === 2
  && full.rows.filter((r) => r.href).every((r) => /\/api\/user\/billing\/invoices\/(PS|CN)-2026-0001\.pdf$/.test(r.href)),
  JSON.stringify(full.rows.map((r) => r.href)));

ok('the newest event is first',
  full.rows[0].left.includes('term ended') && full.rows[3].left.includes('Plan changed'),
  `${full.rows[0].left} | ${full.rows[3].left}`);

// House style, on copy this page generates rather than carries.
ok('no em-dash anywhere in the history',
  !full.text.includes('\u2014'), full.text);

// The server sends text; the page must put it in the document as text. A label
// that arrived as markup and rendered as markup would be a hole straight into
// the account page.
const injected = await account({
  history: [{
    ts: '2026-09-03T12:00:00.000Z', type: 'invoice',
    label: '<img src=x onerror=1>', detail: 'Paid', amount: '1.00',
    currency: 'EUR', document: 'PS-2026-0001',
  }],
});
ok('a label is rendered as text and never as markup',
  !injected.html.includes('<img') && injected.text.includes('<img src=x onerror=1>'),
  injected.html.slice(0, 200));

// ── the API is down ──────────────────────────────────────────────────────────
const down = await account({ history: [], status: 502 });
ok('an unreachable API says so rather than claiming nothing ever happened',
  down.text.includes('unavailable') && !down.text.includes('No billing events yet'), down.text);

await browser.close();
server.close();

for (const c of checks) console.log(`${c.pass ? 'ok' : 'FAIL'} - ${c.name}${c.pass ? '' : ` :: ${c.detail}`}`);
const failed = checks.filter((c) => !c.pass);
console.log(`${checks.length} checks, ${failed.length} failed`);
if (failed.length) process.exit(1);
