/* Het beheerscherm (admin/public) in een echte browser, desktop en telefoon.
 *
 * WAAR DIT VOOR IS. admin/test/beheer.test.js bewijst dat de routes de goede
 * getallen en zinnen teruggeven en nooit een volle sleutel. Dit bewijst wat de
 * eigenaar ervan ziet, op zijn iPhone en op zijn laptop:
 *   1. het overzicht staat op één scherm en elk getal is een knop naar zijn details;
 *   2. de audit zegt wanneer (lokaal en relatief), wat (in het Nederlands), wie
 *      (het e-mailadres, de sleutel ingeklapt) en vat de details samen, met een
 *      uitklapper die een lijst toont en geen {};
 *   3. de CSV heeft elke kolom gevuld;
 *   4. een klant openen geeft één infopagina met plannen, sleutels, betalingen
 *      en audit;
 *   5. geen hoofdletterlinks, raakvlakken van minstens 44 px op de telefoon, en
 *      op 390 px schuift geen enkel tabblad zijwaarts.
 *
 * De API is nagebootst: dit gaat over wat de browser met een antwoord doet.
 *
 * Draaien: node --test tests/admin-beheer.test.mjs
 *          ~/bin/pw-webkit.sh tests/admin-beheer.test.mjs   (WebKit, iPhone 13)
 * Met PW_SHOT_DIR gezet komen er schermafdrukken bij.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium, devices } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'admin', 'public');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const SHOTS = process.env.PW_SHOT_DIR || '';
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html' };

const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (!p.startsWith('/admin/')) { res.writeHead(404); return res.end(); }
  p = p.slice('/admin'.length);
  if (p === '/' || p === '') p = '/index.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, body) => {
    if (err) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
test.after(async () => { await browser.close(); server.close(); });

const NOW = Date.now();
const KID = 'k_a1b2c3d4e5f6';
const ROW = {
  ts: NOW - 5 * 60000, iso: new Date(NOW - 5 * 60000).toISOString(), event_type: 'admin_plan_changed',
  label: 'Plan gewijzigd door jou', summary: 'van community naar pro', who: 'jan@bakkerij-jansen.nl',
  who_kind: 'klant', kid: KID, key_masked: 'pgp_1a2b...9f0e', user_id: 'pgp_1a2b...9f0e',
  metadata: { from: 'community', to: 'pro', admin_ip: '10.0.x.x' },
};
const ROW2 = { ...ROW, ts: NOW - 3600000, iso: new Date(NOW - 3600000).toISOString(), event_type: 'webauthn_login', label: 'Ingelogd met passkey', summary: 'via passkey', metadata: {} };
const DOC = { number: 'PS-2026-0002', date: new Date(NOW).toISOString().slice(0, 10), kind: 'invoice', kind_nl: 'Factuur', customer: 'jan@bakkerij-jansen.nl', email: 'jan@bakkerij-jansen.nl', description: 'ParaSign Business, jaarplan', amount_net: '1188.00', amount_gross: '1437.48', currency: 'EUR', status: 'loopt', status_nl: 'Betaald, loopt tot 2027-10-05', kid: KID };
const FIX = {
  '/auth/check': { ok: true },
  '/admin/overview': {
    stats: { signups_today: 2, active_sessions: 3, pro_upgrades_today: 0, revenue_mrr: 9900 },
    customers: { total: 12, active: 11, on_paid_plan: 4, paying: 3 },
    revenue: { month: '2026-10', net_cents: 118800, gross_cents: 143748, documents: 1, mrr_cents: 9900, mrr_basis: 1 },
    relays: ['main', 'health', 'legal', 'finance', 'iot'].map((s) => ({ sector: s, ok: true, version: '3.1.0', uptime_s: 90000 })),
    problems: [
      { id: 'relays', level: 'goed', tab: 'relay', title: 'Relays', text: 'Alle 5 relays antwoorden.' },
      { id: 'mails', level: 'let_op', tab: 'audit', title: 'Mislukte mails', text: '2 mails konden de laatste 24 uur niet weg vanaf de beheerkant.' },
      { id: 'http429', level: 'goed', tab: 'overview', title: 'Te veel verzoeken (429)', text: '0 keer.' },
      { id: 'ctlog', level: 'goed', tab: 'relay', title: 'Transparantielogboek', text: 'groei laatste 24 uur: main +4.' },
      { id: 'redis', level: 'goed', tab: 'relay', title: 'Geheugen van de opslag (redis)', text: '2 MB in gebruik.' },
    ],
    recent_signups: [{ name: 'jan@bakkerij-jansen.nl', kid: KID, created: new Date(NOW - 86400000).toISOString(), plan_parasign: 'business', plan_parasend: 'community', active: true }],
    recent_payments: [DOC],
    recent_activity: [ROW, ROW2],
    plan_distribution: { community: 8, pro: 3, enterprise: 1 },
  },
  '/admin/overview/failures': { mails: [{ ts: NOW - 600000, reason: 'http_502', provider: 'resend', subject_fp: 'a1b2c3d4' }], http429: [] },
  '/admin/users': {
    users: [{ key: 'pgp_1a2b...9f0e', key_id: KID, email: 'jan@bakkerij-jansen.nl', label: 'jansen', plan: 'pro', plan_parasign: 'business', plan_parasend: 'community', paid_until_parasign: new Date(NOW + 300 * 86400000).toISOString(), active: true, created: new Date(NOW - 86400000).toISOString(), totp_status: 'active', last_activity: { ts: NOW - 3600000, label: 'Ingelogd met passkey' }, usage_month: { transfers: 4, signs: 2 } }],
    counts: { total: 1, active: 1 }, pagination: { page: 1, page_size: 50, total_items: 1, total_pages: 1, has_next: false, has_prev: false },
  },
  '/admin/audit': { events: [ROW, ROW2], total: 2, event_types: ['admin_plan_changed', 'webauthn_login'], event_labels: { admin_plan_changed: 'Plan gewijzigd door jou', webauthn_login: 'Ingelogd met passkey' } },
  '/admin/billing': {
    total_customers: 12, plan_distribution: {}, recent_checkouts: [ROW],
    revenue: { this_month: { month: '2026-10', net_cents: 118800, gross_cents: 143748, documents: 1 }, last_month: { month: '2026-09', net_cents: 0, gross_cents: 0, documents: 0 }, mrr_cents: 9900, mrr_basis: 1, paying_accounts: 1 },
    documents: [DOC], payments: [DOC], refunds: [], subscriptions: [],
    terms: [{ who: 'jan@bakkerij-jansen.nl', kid: KID, product: 'parasign', tier: 'business', until: new Date(NOW + 300 * 86400000).toISOString(), running: true, status_nl: 'Loopt tot 2027-08-01, stopt daarna' }],
    collection_failed: 0,
  },
  '/admin/coupons': { ok: true, coupons: [] },
  '/admin/relay-detail': { sectors: Object.fromEntries(['main', 'health', 'legal', 'finance', 'iot'].map((s) => [s, { version: '3.1.0', uptime_s: 90000, stats: {}, metrics: { ct_log: 40 } }])), ct: [] },
  [`/admin/user-details/${KID}`]: {
    key_id: KID, key_masked: 'pgp_1a2b...9f0e', email: 'jan@bakkerij-jansen.nl', label: 'jansen', plan: 'pro', plan_parasign: 'business', plan_parasend: 'community',
    paid_until_parasign: new Date(NOW + 300 * 86400000).toISOString(), auto_renews: false, parasign: true, active: true, created: new Date(NOW - 86400000).toISOString(),
    totp_status: 'active', active_sessions: 1,
    keys: [{ kid: KID, key_masked: 'pgp_1a2b...9f0e', kind: 'Accountsleutel', active: true, primary: true }],
    usage: { month: '2026-10', transfers: 4, signs: 2, limits: { transfers_month: 500, signs_month: 100 } },
    envelopes: { total: 1, recent: [{ id: 'abc…', status_nl: 'Wacht op ondertekening', created: new Date(NOW).toISOString(), parties: 2, signed: 1 }] },
    payments: [DOC], audit: [ROW], audit_events: [],
  },
};

async function openPanel(ctxOpts, tag) {
  const ctx = await browser.newContext({ ...ctxOpts, acceptDownloads: true });
  await ctx.addInitScript(() => sessionStorage.setItem('adm_session', 'a'.repeat(64)));
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('dialog', (d) => d.dismiss());
  await page.route('**/admin/api/**', (route) => {
    const u = new URL(route.request().url());
    const p = u.pathname.replace('/admin/api', '');
    const body = FIX[p];
    return route.fulfill({ status: body ? 200 : 404, contentType: 'application/json', body: JSON.stringify(body || { error: 'nope' }) });
  });
  await page.goto(ORIGIN + '/admin/');
  await page.waitForSelector('#tab-overview .sc', { timeout: 15000 });
  return { ctx, page, errors, shot: async (n) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/test-${tag}-${n}.png` }); } };
}

const VIEWS = [
  ['desktop', { viewport: { width: 1366, height: 900 } }],
  ['iphone', { ...devices['iPhone 13'] }],
];

for (const [tag, opts] of VIEWS) {
  test(`${tag}: het overzicht is één scherm en elk getal is een knop naar de details`, async () => {
    const { ctx, page, errors, shot } = await openPanel(opts, tag);
    const cards = await page.$$eval('#tab-overview .sc', (els) => els.map((e) => ({ tag: e.tagName, text: e.innerText })));
    assert.strictEqual(cards.length, 4);
    assert.ok(cards.every((c) => c.tag === 'BUTTON'), 'elk getal is een knop');
    assert.match(cards[2].text, /€ 1\.188,00/);
    assert.match(cards[2].text, /MRR € 99,00/);
    assert.strictEqual(await page.locator('#tab-overview .ri').count(), 5);
    assert.match(await page.innerText('#tab-overview'), /Mislukte mails/);
    await shot('overzicht');
    await page.click('#ov-betalend');
    assert.strictEqual(await page.getAttribute('#tabBtn-billing', 'aria-selected'), 'true');
    await page.click('#tabBtn-overview');
    await page.click('.pr[data-id="mails"]');
    await page.waitForSelector('#mo-info-body table', { timeout: 5000 });
    assert.match(await page.innerText('#mo-info-body'), /a1b2c3d4/);
    assert.deepStrictEqual(errors, []);
    await ctx.close();
  });

  test(`${tag}: de audit zegt wanneer, wat, wie en vat samen; CSV met elke kolom gevuld`, async () => {
    const { ctx, page, errors, shot } = await openPanel(opts, tag);
    await page.click('#tabBtn-audit');
    await page.waitForSelector('#a-results tbody tr', { timeout: 5000 });
    const row = await page.innerText('#a-results tbody tr:first-child');
    assert.match(row, /Plan gewijzigd door jou/);
    assert.match(row, /jan@bakkerij-jansen\.nl/);
    assert.match(row, /van community naar pro/);
    assert.match(row, /geleden/);
    assert.doesNotMatch(row, /\{\}/);
    const opts2 = await page.$$eval('#a-event option', (o) => o.map((x) => x.textContent));
    assert.deepStrictEqual(opts2, ['Alle gebeurtenissen', 'Plan gewijzigd door jou', 'Ingelogd met passkey']);
    await page.click('#a-results tbody tr:first-child details.det summary');
    assert.match(await page.innerText('#a-results tbody tr:first-child details.det'), /Van\s+community/);
    await shot('audit');
    const [dl] = await Promise.all([page.waitForEvent('download'), page.click('button[data-click=exportAuditCSV]')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8').replace(/^﻿/, '');
    const lines = csv.trim().split('\r\n');
    assert.strictEqual(lines.length, 3);
    for (const l of lines) {
      const cells = l.slice(1, -1).split('";"');
      assert.strictEqual(cells.length, 8, l);
      assert.ok(cells.every((c) => c.trim() !== ''), 'lege kolom in: ' + l);
    }
    assert.match(dl.suggestedFilename(), /^paramant-audit-\d{4}-\d{2}-\d{2}\.csv$/);
    assert.deepStrictEqual(errors, []);
    await ctx.close();
  });

  test(`${tag}: een klant openen geeft één infopagina`, async () => {
    const { ctx, page, errors, shot } = await openPanel(opts, tag);
    await page.click('#tabBtn-users');
    await page.waitForSelector('#tab-users tbody tr');
    assert.match(await page.innerText('#tab-users tbody tr'), /ParaSign: Business/);
    await page.click('#tab-users [data-click="openKlant"]');
    await page.waitForSelector('#mo-details-body .g2');
    const t = await page.innerText('#mo-details-body');
    for (const want of [/Tweestapsverificatie aan/, /Business/, /pgp_1a2b\.\.\.9f0e/, /Wacht op ondertekening/, /PS-2026-0002/, /Plan gewijzigd door jou/, /4 van 500/]) assert.match(t, want);
    await shot('klant');
    assert.deepStrictEqual(errors, []);
    await ctx.close();
  });

  test(`${tag}: gewone letters, grote raakvlakken, niets schuift zijwaarts`, async () => {
    const { ctx, page, errors } = await openPanel(opts, tag);
    for (const t of ['overview', 'users', 'audit', 'billing', 'relay']) {
      await page.click('#tabBtn-' + t);
      await page.waitForTimeout(400);
      const wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      assert.ok(wide <= 1, `${t}: ${wide}px zijwaarts`);
      const caps = await page.$$eval('button, a', (els) => els.filter((e) => e.offsetParent && getComputedStyle(e).textTransform === 'uppercase').map((e) => e.textContent.trim()));
      assert.deepStrictEqual(caps, [], `${t}: hoofdletterknoppen`);
    }
    if (tag === 'iphone') {
      const small = await page.$$eval('.tabs button, .btn, .amb, .more summary', (els) => els.filter((e) => e.offsetParent).map((e) => [e.textContent.trim(), e.getBoundingClientRect().height]).filter(([, h]) => h < 43.5));
      assert.deepStrictEqual(small, [], 'raakvlakken kleiner dan 44 px');
    }
    assert.deepStrictEqual(errors, []);
    await ctx.close();
  });
}
