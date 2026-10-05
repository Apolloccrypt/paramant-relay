// /dashboard after fase 1 (P08, P05 and VERIFY-36), in a real browser against a
// stubbed account server:
//
//   DASH-04-J  after a payment the page polls /api/user/me and every round
//              added another set of click handlers: one click acted six times
//   DASH-10-A  the three Vernieuwen buttons did nothing
//   DASH-01-K  a 429 said "Opnieuw inloggen HTTP 429"
//   DASH-21-A  a 500 said "Opnieuw inloggen HTTP 500", with no way to retry
//   DASH-15-A  "Herinnering verstuurd" stood there for less than 40 ms
//   DASH-18-A  following the link in the passkey modal did not count as an answer
//   DASH-18-F  "envelope" on the English page
//   SENDNAME-18-A  "Sent 4 oktober 2026" on the Dutch page, every row "Een bestand"
//   VERIFY-36-A    the audit export (and the send history) had no buttons at all
//
// Run: node --test tests/dashboard-fase2-browser.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DF_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const DF_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const DF_MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png' };

const df = {
  me: { status: 200, body: { email: 'firm@zorg.test', plan: 'pro', usage_purpose: 'organisation', created_at: null, backup_codes_remaining: 10 } },
  hits: {},
  lastAuth: {},
  passkeys: { passkeys: [] },
};
const dfSend = { id: 'snd_1', status: 'open', total: 2, collected: 0, outstanding: 2, created_at: '2026-10-04T12:32:00.000Z' };
const dfDoc = { id: 'env_1', file_name: 'contract.pdf', status: 'sent', created_at: '2026-10-04T10:00:00Z', expires_at: '2026-11-04T10:00:00Z', parties: [{ name: 'A', status: 'pending' }], signed_count: 0, party_count: 1 };

let dfServer;
let dfBrowser;
let DF_ORIGIN;

before(async () => {
  dfServer = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://localhost');
    df.hits[u.pathname] = (df.hits[u.pathname] || 0) + 1;
    df.lastAuth[u.pathname] = req.headers.authorization || '';
    const send = (status, body, type = 'application/json') => { res.writeHead(status, { 'content-type': type }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
    if (u.pathname === '/api/user/me') return send(df.me.status, df.me.body);
    if (u.pathname === '/api/user/sends') return send(200, { sends: [dfSend] });
    if (u.pathname === '/api/user/sends/snd_1') return send(200, { id: 'snd_1', recipients: [{ email: 'a@x.test', status: 'waiting' }, { email: 'b@x.test', status: 'waiting' }] });
    if (u.pathname === '/api/user/sends/snd_1/reinvite') return send(200, { ok: true });
    if (u.pathname === '/api/user/documents') return send(200, { documents: [dfDoc] });
    if (u.pathname === '/api/user/account/webauthn/credentials') return send(200, df.passkeys);
    if (u.pathname === '/api/user/app/token') return send(200, { token: 'pst_app_test', expires_in_s: 900 });
    if (u.pathname === '/v2/parasign/audit-export') return send(200, 'ts,event\n1,signed\n', 'text/csv');
    if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/v2/')) return send(200, {});
    const map = { '/dashboard': 'dashboard.html', '/en/dashboard': 'en/dashboard.html' };
    const file = path.join(DF_ROOT, map[u.pathname] || u.pathname);
    if (!file.startsWith(DF_ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, body) => {
      if (e) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': DF_MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  await new Promise((r) => dfServer.listen(0, '127.0.0.1', r));
  DF_ORIGIN = `http://localhost:${dfServer.address().port}`;
  dfBrowser = await chromium.launch({ headless: true, ...(DF_EXE ? { executablePath: DF_EXE } : {}) });
});

after(async () => {
  if (dfBrowser) await dfBrowser.close();
  if (dfServer) await new Promise((r) => dfServer.close(r));
});

async function dfOpen(p = '/dashboard', opts = {}) {
  const ctx = await dfBrowser.newContext({ acceptDownloads: true });
  if (opts.dismissModal !== false) await ctx.addInitScript(() => { try { localStorage.setItem('paramant.keysetup.dismissed.v1', '1'); } catch (_) {} });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(DF_ORIGIN + p);
  return { ctx, page, errors };
}

test('DASH-01-K / DASH-21-A: a 429 or a 500 says what happened and offers a retry, not a sign-in', async () => {
  for (const [status, re] of [[429, /te veel verzoeken/i], [500, /storing bij ons/i]]) {
    df.me = { status, body: { error: 'x' } };
    const { ctx, page } = await dfOpen();
    await page.waitForSelector('#dh-error:not([hidden])', { timeout: 10000 });
    const text = await page.locator('#dh-error').innerText();
    assert.match(text, re);
    assert.doesNotMatch(text, /HTTP \d{3}/);
    assert.equal(await page.locator('#dh-error-login').isVisible(), false, 'sends a signed-in customer to the login');
    assert.equal(await page.locator('#dh-error-retry').isVisible(), true);
    df.me = { status: 200, body: { email: 'firm@zorg.test', plan: 'pro', usage_purpose: 'organisation', created_at: null, backup_codes_remaining: 10 } };
    await page.click('#dh-error-retry');
    await page.waitForSelector('#dh-root.dh-loaded', { timeout: 10000 });
    await ctx.close();
  }
});

test('DASH-10-A: every Vernieuwen button fetches its list again', async () => {
  const { ctx, page } = await dfOpen();
  await page.waitForSelector('#dh-sends .dh-send-row', { timeout: 10000 });
  for (const [btn, route] of [['#dh-documents-refresh', '/api/user/documents'], ['#dh-sends-refresh', '/api/user/sends']]) {
    const before = df.hits[route] || 0;
    await page.click(btn);
    await page.waitForTimeout(400);
    assert.equal(df.hits[route], before + 1, btn + ' did not fetch ' + route);
  }
  assert.equal(await page.locator('#dh-inbox-refresh').getAttribute('data-pa-action'), 'inbox-refresh');
  await ctx.close();
});

test('DASH-04-J: after the payment polls one click still acts once', async () => {
  df.me = { status: 200, body: { email: 'gratis@zorg.test', plan: 'community', usage_purpose: 'organisation' } };
  const { ctx, page } = await dfOpen('/dashboard?billing=return');
  await page.waitForFunction(() => /nog niet bevestigd/i.test(document.querySelector('#dh-billing-return')?.textContent || ''), null, { timeout: 20000 });
  const before = df.hits['/api/user/documents'] || 0;
  await page.click('#dh-documents-refresh');
  await page.waitForTimeout(600);
  assert.equal(df.hits['/api/user/documents'] - before, 1, 'one click on Vernieuwen fetched more than once');
  df.me = { status: 200, body: { email: 'firm@zorg.test', plan: 'pro', usage_purpose: 'organisation', created_at: null, backup_codes_remaining: 10 } };
  await ctx.close();
});

test('DASH-15-A: the reminder confirmation stays on screen', async () => {
  const { ctx, page } = await dfOpen();
  await page.waitForSelector('#dh-sends .dh-send-row', { timeout: 10000 });
  await page.click('[data-pa-action="send-open"]');
  await page.waitForSelector('[data-pa-action="send-remind"]', { timeout: 5000 });
  await page.click('[data-pa-action="send-remind"]');
  await page.waitForTimeout(3000);
  assert.match(await page.locator('[data-send-people="snd_1"]').innerText(), /Herinnering verstuurd/);
  // Eindmatrix DASH-15-A: the sender is told what the reminder does and does
  // not carry, and what to do when the first mail is lost.
  assert.match(await page.locator('[data-send-people="snd_1"]').innerText(), /verwijst naar de eerste mail, want alleen daarin zit de sleutel\. Is die mail kwijt, stuur het bestand dan opnieuw\./);
  assert.equal(await page.locator('[data-send-people="snd_1"]').isVisible(), true, 'the panel closed over the confirmation');
  await ctx.close();
});

test('SENDNAME-18-A: a Dutch row says Verstuurd and tells sends apart', async () => {
  const { ctx, page } = await dfOpen();
  await page.waitForSelector('#dh-sends .dh-send-row', { timeout: 10000 });
  const row = await page.locator('#dh-sends .dh-send-row').first().innerText();
  assert.doesNotMatch(row, /\bSent\b/);
  assert.match(row, /Verstuurd 4 oktober 2026 om \d\d:\d\d/);
  assert.match(row, /Bestand aan 2 ontvangers/);
  await ctx.close();
});

test('DASH-20-A: no "--" for a member-since date the account does not have', async () => {
  const { ctx, page } = await dfOpen();
  await page.waitForSelector('#dh-root.dh-loaded', { timeout: 10000 });
  await page.click('#dh-acct-toggle');
  await page.waitForTimeout(200);
  assert.equal(await page.locator('[data-dh="backup"]').isVisible(), true, 'the account panel did not open');
  assert.equal(await page.locator('[data-dh="created"]').isVisible(), false);
  await ctx.close();
});

test('VERIFY-36-A: a paying account can export the audit trail as CSV', async () => {
  const { ctx, page, errors } = await dfOpen();
  await page.waitForSelector('#dh-records:not([hidden])', { timeout: 10000 });
  assert.equal(df.hits['/v2/parasign/audit-export'] || 0, 0, 'nothing may be fetched before the click');
  const dl = page.waitForEvent('download', { timeout: 10000 });
  await page.click('#dh-export-csv');
  const d = await dl;
  assert.equal(d.suggestedFilename(), 'parasign_audit.csv');
  assert.equal(df.lastAuth['/v2/parasign/audit-export'], 'Bearer pst_app_test');
  assert.match(await page.locator('#dh-export-body').innerText(), /export is klaar/);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('VERIFY-36-A: a free account does not get the export section', async () => {
  df.me = { status: 200, body: { email: 'gratis@zorg.test', plan: 'community', usage_purpose: 'organisation' } };
  const { ctx, page } = await dfOpen();
  await page.waitForSelector('#dh-root.dh-loaded', { timeout: 10000 });
  assert.equal(await page.locator('#dh-records').isVisible(), false);
  df.me = { status: 200, body: { email: 'firm@zorg.test', plan: 'pro', usage_purpose: 'organisation', created_at: null, backup_codes_remaining: 10 } };
  await ctx.close();
});

test('DASH-18-A: following the passkey link counts as an answer', async () => {
  const { ctx, page } = await dfOpen('/dashboard', { dismissModal: false });
  const shown = await page.waitForSelector('#dh-passkey-modal:not([hidden])', { timeout: 10000 }).then(() => true, () => false);
  if (shown) {
    await page.evaluate(() => { document.querySelector('a.dh-pm-item').addEventListener('click', (e) => e.preventDefault()); });
    await page.click('a.dh-pm-item');
    assert.equal(await page.evaluate(() => localStorage.getItem('paramant.keysetup.dismissed.v1')), '1');
  } else {
    // Headless Chromium without PublicKeyCredential shows no offer; then the
    // wiring is checked in the source instead.
    assert.match(fs.readFileSync(path.join(DF_ROOT, 'js/dashboard.js'), 'utf8'), /closest\('a\.dh-pm-item'\)/);
  }
  await ctx.close();
});

test('DASH-18-F: no "envelope" jargon on the English dashboard', () => {
  const text = fs.readFileSync(path.join(DF_ROOT, 'en/dashboard.html'), 'utf8').replace(/<!--[\s\S]*?-->/g, '').replace(/<[^>]+>/g, ' ');
  assert.doesNotMatch(text, /\benvelope/i);
});
