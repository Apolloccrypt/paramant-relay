/* What a Dutch customer reads after a refusal, a code, a cancellation, and when
 * his signing quota runs low. In a real browser, APIs mocked.
 *
 * Fase 1 found these pages answering the Dutch customer in English, or not at
 * all:
 *   PLAN-07  a second plan next to a running one: the relay refused with a 409
 *            and an explanation, the page threw the body away and printed
 *            "Afrekenen lukte niet... Probeer het opnieuw".
 *   PLAN-28/29/31  "Your code is redeemed", "We do not know that code" on the
 *            Dutch /pricing, /account and /redeem.
 *   PLAN-19  the Dutch billing history in English ("Credit note for invoice",
 *            "Cancellation scheduled", "Gift: ...").
 *   DASH-27-N  the 80% usage warning with an upgrade link lived in dead code
 *            on /dashboard and was shown to nobody.
 *
 * What the relay answers is pinned in relay/test/route-coupon.test.js and
 * relay/test/billing-history.test.js; this asks what the browser does with it.
 * Run: node --test tests/klant-nl-meldingen.test.mjs
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2',
};
const aliases = {
  '/': '/index.html', '/account': '/account.html', '/en/account': '/en/account.html',
  '/pricing': '/pricing.html', '/en/pricing': '/en/pricing.html', '/developer': '/developer.html',
};

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
test.after(async () => { await browser.close(); server.close(); });

const json = (route, body, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function stub(page, extra = {}) {
  // The catch-all first: Playwright tries the most recently added route first.
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/account', (route) => json(route, {
    email: 'demo@example.com', plan: 'pro', api_key_masked: 'pgp_demo...abcd',
    created_at: '2026-01-01T00:00:00.000Z', sessions: [], backup_codes_remaining: 0,
  }));
  await page.route('**/api/user/billing/status', (route) => json(route, {
    current_plan: 'business', plan_parasign: 'business', plan_parasend: 'community',
    access_until: null, next_billing_date: null, auto_renews: false, cancellation_scheduled_at: null,
  }));
  await page.route('**/api/user/billing/invoices', (route) => json(route, { invoices: [] }));
  await page.route('**/api/user/billing/history', (route) => json(route, { history: extra.history || [] }));
  await page.route('**/api/user/app/token', (route) => json(route, { ok: true, token: 'pst_stub_token', expires_in_s: 900 }));
  if (extra.checkout) await page.route('**/v2/billing/checkout', extra.checkout);
  if (extra.redeem) await page.route('**/v2/billing/redeem', extra.redeem);
  if (extra.snapshot) await page.route('**/api/user/developer/snapshot', (route) => json(route, extra.snapshot));
  if (extra.snapshot) await page.route('**/api/user/developer/parasign-keys', (route) => json(route, { keys: [] }));
}

async function open(slug, extra) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await stub(page, extra);
  await page.goto(ORIGIN + slug, { waitUntil: 'domcontentloaded' });
  return page;
}

// ── PLAN-07: the refused second plan ─────────────────────────────────────────
const REFUSED = {
  error: 'other_plan_running', product: 'parasign', running: 'business',
  paid_until: '2026-11-05T00:00:00.000Z',
  message: 'You already have ParaSign Business until 5 November 2026. Paramant Firm (ParaSign Pro and ParaSend Pro) would run alongside it and you would pay twice for the same weeks, so no payment was started. To change plans, mail privacy@paramant.app.',
};

async function refusedText(slug) {
  const page = await open(slug, { checkout: (route) => json(route, REFUSED, 409) });
  const btn = page.locator('a[data-billing-product="firm"][data-billing-interval="monthly"]').first();
  await btn.click();
  const box = page.locator('[id^="billing-error-firm"]').first();
  await box.waitFor({ timeout: 10000 });
  const text = (await box.innerText()).replace(/\s+/g, ' ').trim();
  await page.close();
  return text;
}

test('/pricing explains a refused second plan in Dutch and does not invite a retry', async () => {
  const text = await refusedText('/pricing');
  assert.match(text, /^U heeft al ParaSign Business tot 5 november 2026\./, text);
  assert.match(text, /twee keer/, text);
  assert.match(text, /privacy@paramant\.app/, text);
  assert.doesNotMatch(text, /lukte niet|Probeer het opnieuw/i, text);
});

test('/en/pricing shows the relay\'s own explanation', async () => {
  const text = await refusedText('/en/pricing');
  assert.equal(text, REFUSED.message);
});

// ── PLAN-28/31: the code answers ─────────────────────────────────────────────
const GRANTED = {
  ok: true, code: 'COFFEE',
  granted: [{ product: 'parasign', tier: 'pro', days: 90, ends: '2026-12-03T00:00:00.000Z' }],
  message: 'Your code is redeemed. You now have ParaSign Pro until 3 December 2026. Nothing was charged.',
  message_nl: 'Uw code is ingewisseld. U heeft nu ParaSign Pro tot 3 december 2026. Er is niets afgeschreven.',
};
const UNKNOWN = {
  error: 'unknown',
  message: 'We do not know that code. Check the spelling and try again.',
  message_nl: 'Deze code kennen we niet. Controleer de spelling en probeer het opnieuw.',
};

async function redeemSays(slug, body, status) {
  const page = await open(slug, { redeem: (route) => json(route, body, status) });
  await page.waitForSelector('[data-redeem-form]', { timeout: 10000 });
  await page.fill('[data-redeem-form] [data-redeem-input]', 'COFFEE');
  await page.click('[data-redeem-form] [data-redeem-submit]');
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-redeem-form] [data-redeem-message]');
    return el && !el.hidden && el.textContent && !/Checking your code|We controleren uw code/.test(el.textContent);
  }, null, { timeout: 10000 });
  const text = (await page.textContent('[data-redeem-form] [data-redeem-message]')).trim();
  await page.close();
  return text;
}

for (const slug of ['/pricing', '/account']) {
  test(`${slug}: a redeemed code and a refused one are told in Dutch`, async () => {
    assert.equal(await redeemSays(slug, GRANTED, 200), GRANTED.message_nl);
    assert.equal(await redeemSays(slug, UNKNOWN, 404), UNKNOWN.message_nl);
  });
}

test('/en/pricing keeps the English sentences', async () => {
  assert.equal(await redeemSays('/en/pricing', GRANTED, 200), GRANTED.message);
  assert.equal(await redeemSays('/en/pricing', UNKNOWN, 404), UNKNOWN.message);
});

// ── PLAN-19: the billing history ─────────────────────────────────────────────
const HISTORY = [
  { ts: '2026-10-05T10:00:00.000Z', type: 'plan_cancellation_scheduled', label: 'Cancellation scheduled', label_nl: 'Opzegging gepland', detail: null, amount: null, document: null },
  { ts: '2026-10-05T09:00:00.000Z', type: 'credit_note', label: 'Credit note for invoice PS-2026-0001', label_nl: 'Creditnota voor factuur PS-2026-0001', detail: 'Refunded', detail_nl: 'Terugbetaald', amount: '-35.09', currency: 'EUR', document: 'CN-2026-0001' },
  { ts: '2026-10-01T09:00:00.000Z', type: 'gift', label: 'Gift: 3 months of ParaSign Pro, code COFFEE', label_nl: 'Cadeau: 3 maanden ParaSign Pro, code COFFEE', detail: 'No payment, no invoice', detail_nl: 'Geen betaling, geen factuur', amount: null, document: null },
];

async function historyRows(slug) {
  const page = await open(slug, { history: HISTORY });
  await page.waitForFunction(() => document.querySelectorAll('#billing-history .info-row').length === 3, null, { timeout: 10000 });
  const rows = await page.$$eval('#billing-history .info-row', (els) => els.map((e) => e.textContent.replace(/\s+/g, ' ').trim()));
  await page.close();
  return rows;
}

test('/account prints the Dutch labels, the cancellation on top', async () => {
  const rows = await historyRows('/account');
  assert.match(rows[0], /Opzegging gepland/, rows[0]);
  assert.match(rows[1], /Creditnota voor factuur PS-2026-0001/, rows[1]);
  assert.match(rows[2], /Cadeau: 3 maanden ParaSign Pro, code COFFEE.*Geen betaling, geen factuur/, rows[2]);
  assert.ok(!rows.join(' ').match(/Credit note|Cancellation|Gift:|No payment/), rows.join(' | '));
});

test('/en/account keeps the English labels', async () => {
  const rows = await historyRows('/en/account');
  assert.match(rows[0], /Cancellation scheduled/);
  assert.match(rows[2], /Gift: 3 months of ParaSign Pro, code COFFEE.*No payment, no invoice/);
});

// ── DASH-27-N: the usage warning ─────────────────────────────────────────────
async function usage(signs, cap) {
  const page = await open('/developer', {
    snapshot: { email: 'demo@example.com', tiers: { parasign: 'pro' }, quota: { signs, caps: { signs: cap } }, audit: [] },
  });
  await page.waitForFunction(() => !/geladen/.test(document.getElementById('usage-note').textContent), null, { timeout: 10000 });
  const note = (await page.textContent('#usage-note')).trim();
  const href = (await page.locator('#usage-upgrade').count()) ? await page.locator('#usage-upgrade').getAttribute('href') : null;
  await page.close();
  return { note, href };
}

test('/developer warns at 80% of the signing quota and names the way up', async () => {
  const high = await usage(85, 100);
  assert.match(high.note, /Nog 15 handtekeningen over deze maand\. Bijna op\. Meer nodig\? Bekijk een groter plan/, high.note);
  assert.equal(high.href, '/pricing');
  const low = await usage(10, 100);
  assert.equal(low.href, null, 'no warning below 80%');
  assert.equal(low.note, 'Nog 90 handtekeningen over deze maand.');
});

test('/dashboard carries no dead usage panel any more', () => {
  const src = fs.readFileSync(path.join(ROOT, 'js', 'dashboard.js'), 'utf8');
  assert.doesNotMatch(src, /dh-ops-usage|loadOperations|function renderOps/,
    'the panel drew into #dh-ops, which /dashboard does not have: the warning reached nobody');
});
