// Acceptatie r5, drie voorbehouden op /co-sign:
//   A. "Maak er gratis een" ging naar /signup zonder bewaard adres; na het
//      instellen van het account was er geen weg terug naar het document.
//      Nu staat de nieuwe gebruiker na "Alles staat klaar" vanzelf weer op
//      het document, ook als de mails in een nieuw tabblad openden.
//   B. Het uitnodigingstoken reisde in de query van elke relay- en
//      documentaanvraag, en kwam zo in access-logs. Nu in een header: in de
//      HAR staat het in geen enkele request-URL meer, behalve de maillink.
//   C. Na een verlopen sessie wees de notitie naar "de knop voor het origineel
//      hierboven" terwijl die knop er niet stond.
// Echte pagina's, echte WebCrypto; alleen het netwerk is nagebootst.
// Draait in Chromium; in WebKit via ~/bin/pw-webkit.sh.
// Run: node --test tests/cosign-r5-terugweg-en-token.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.woff2': 'font/woff2', '.ttf': 'font/ttf' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/__proof') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>proof</title>'); }
  if (p === '/co-sign' || p === '/signup') p += '.html';
  if (p === '/en/co-sign' || p === '/en/signup') p += '.html';
  if (/^\/auth\/setup\/[A-Za-z0-9_-]+$/.test(p)) p = '/auth/setup.html';
  if (/^\/en\/auth\/setup\/[A-Za-z0-9_-]+$/.test(p)) p = '/en/auth/setup.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cosign-r5-'));
after(async () => { await browser.close(); server.close(); fs.rmSync(TMP, { recursive: true, force: true }); });

const ENV_ID = 'env_demo_r5terugwegabcdef';
const TOKEN = ('R5invitetoken' + 'x'.repeat(43)).slice(0, 43);
const SETUP = 'setup_demo_r5abcdefghijklmnop';

async function capsuleFor(page, bytes) {
  await page.goto(ORIGIN + '/__proof');
  return page.evaluate(async ({ arr, envelopeId }) => {
    const pqc = await import('/vendor/paramant-pqc.js');
    const delivery = await import('/js/parasign-document-capsule.js?v=2');
    const b = new Uint8Array(arr);
    const docHash = Array.from(pqc.sha3_256(b)).map((x) => x.toString(16).padStart(2, '0')).join('');
    const out = await delivery.encryptDocumentCapsule({ bytes: b, filename: 'contract.pdf', mime: 'application/pdf', envelopeId, docHash });
    return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash };
  }, { arr: Array.from(bytes), envelopeId: ENV_ID });
}

async function makePdf(page) {
  await page.goto(ORIGIN + '/__proof');
  await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
  const arr = await page.evaluate(async () => {
    const { PDFDocument, StandardFonts } = window.PDFLib;
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const pg = doc.addPage([595.28, 841.89]);
    pg.drawText('Artikel 1. Partijen komen overeen.', { x: 72, y: 760, size: 11, font });
    return Array.from(await doc.save());
  });
  return new Uint8Array(arr);
}

let FX = null;
async function fixture() {
  if (FX) return FX;
  const p = await browser.newPage();
  const bytes = await makePdf(p);
  FX = await capsuleFor(p, bytes);
  await p.close();
  return FX;
}

// One browser context with every request logged and a HAR on disk. state.account
// decides whether a session exists; state.document the status of the document read.
async function context(label, state) {
  const fx = await fixture();
  const har = path.join(TMP, label + '.har');
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true, ...(state.har ? { recordHar: { path: har, content: 'omit' } } : {}) });
  const reqs = [];
  ctx.on('request', (r) => reqs.push({ url: r.url(), headers: r.headers() }));
  // Nothing leaves the machine: a request to the outside world stays open in a
  // sandbox, and the HAR waits for it on close.
  await ctx.route('https://**/**', (route) => route.abort());
  await ctx.route('https://health.paramant.app/v2/envelopes/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/view')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
    const complete = state.status === 'complete';
    return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: JSON.stringify({ envelope: {
      id: ENV_ID, doc_hash: fx.docHash, original_filename: 'contract.pdf', recipe_version: 5,
      created_at: '2026-10-04T12:00:00.000Z', expires_at: '2026-11-03T12:00:00.000Z', sign_expires_at: '2026-10-11T12:00:00.000Z',
      status: complete ? 'complete' : 'sent', signed_count: complete ? 2 : 1, party_count: 2,
      parties: [{ index: 0, label: 'Afzender Demo', status: 'signed' }, { index: 1, label: 'Signer Demo', status: complete ? 'signed' : 'pending' }],
    } }) });
  });
  await ctx.route(`**/api/user/envelopes/${ENV_ID}/document*`, (route) => (state.document === 401
    ? route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"unauthorized"}' })
    : route.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fx.capsule) })));
  await ctx.route(`**/api/user/envelopes/${ENV_ID}/receipt*`, (route) => route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Content-Disposition': 'attachment; filename="contract.psign"' }, body: '{"psign":"demo"}' }));
  await ctx.route('**/api/user/account/webauthn/credentials', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"passkeys":[]}' }));
  await ctx.route('**/api/user/account', (route) => route.fulfill({ status: state.account, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' },
    body: state.account === 200 ? '{"email":"signer@example.com"}' : '{"error":"x"}' }));
  await ctx.route(`**/api/user/setup/${SETUP}`, (route) => route.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ otpauth: 'otpauth://totp/Paramant:signer@example.com?secret=JBSWY3DPEHPK3PXP', email: 'signer@example.com', secret: 'JBSWY3DPEHPK3PXP' }) }));
  await ctx.route(`**/api/user/setup/${SETUP}/confirm`, (route) => { state.account = 200; return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ backup_codes: ['aaaa-bbbb', 'cccc-dddd'] }) }); });
  await ctx.route('**/api/**', (route) => route.fallback());
  const link = `${ORIGIN}/co-sign?env=${ENV_ID}&p=1&t=${TOKEN}${fx.fragment}`;
  return { ctx, reqs, har, link, fx };
}

// Every request URL that carries the token, apart from the mailed link itself.
// A request never carries the #fragment, so the mailed link is compared without it.
function tokenUrls(urls, link) {
  const mail = link.split('#')[0];
  return urls.filter((u) => u.split('#')[0] !== mail && (u.includes(TOKEN) || u.includes(encodeURIComponent(TOKEN))));
}
function harUrls(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8')).log.entries.map((e) => e.request.url);
}

// The setup link comes from a mail: a new tab, without the sessionStorage of
// the tab with the invitation.
async function setupInNewTab(ctx) {
  const tab = await ctx.newPage();
  await tab.goto(`${ORIGIN}/auth/setup/${SETUP}`, { waitUntil: 'domcontentloaded' });
  const start = tab.locator('#start-btn');
  if (await start.isVisible().catch(() => false)) await start.click();
  await tab.locator('#verify-code').waitFor({ state: 'visible', timeout: 15000 });
  await tab.fill('#verify-code', '123456');
  await tab.click('#verify-btn');
  await tab.locator('#saved-confirm').check();
  await tab.click('#finish-btn');
  await tab.locator('#welcome-doc-return:not([hidden])').waitFor({ timeout: 5000 });
  assert.match(await tab.locator('#state-welcome').innerText(), /Alles staat klaar/);
  await tab.waitForURL((u) => u.pathname === '/co-sign', { timeout: 15000 });
  return tab;
}

// "Maak er gratis een" opens /signup in a new tab; the invitation stays.
async function clickSignup(ctx, page) {
  const signup = page.locator('#cs-signup-link');
  await signup.waitFor({ state: 'visible', timeout: 30000 });
  assert.match(await page.locator('#sign-cta').innerText(), /vanzelf hier terug/, 'de notitie belooft geen "open de link opnieuw" meer');
  const [popup] = await Promise.all([ctx.waitForEvent('page'), signup.click()]);
  await popup.waitForURL(/\/signup$/, { timeout: 15000 });
  assert.equal(page.url().split('#')[0], (await page.evaluate(() => location.href)).split('#')[0]);
  return popup;
}

test('A: na "Maak er gratis een" en het instellen staat de nieuwe gebruiker vanzelf weer op het document', async () => {
  const state = { account: 401, status: 'sent' };
  const { ctx, reqs, link, fx } = await context('A', state);
  const page = await ctx.newPage();
  await page.goto(link, { waitUntil: 'domcontentloaded' });
  const popup = await clickSignup(ctx, page);
  // Review #566: only which request and party, with an expiry; no token, no key.
  const raw = await page.evaluate(() => localStorage.getItem('paramant:signup-return'));
  const stash = JSON.parse(raw || 'null');
  assert.ok(stash, 'de terugweg wacht in deze browser');
  assert.deepEqual(Object.keys(stash).sort(), ['env', 'exp', 'p', 'path']);
  assert.equal(stash.env, ENV_ID); assert.equal(stash.p, 1); assert.equal(stash.path, '/co-sign');
  assert.ok(stash.exp > Date.now() && stash.exp <= Date.now() + 24 * 3600e3, 'vervalt binnen 24 uur');
  assert.ok(!raw.includes(TOKEN) && !raw.includes(fx.fragment.slice(4, 30)), 'geen token en geen sleutel in localStorage');
  await popup.close();

  const tab = await setupInNewTab(ctx);
  await tab.locator('#document-delivery-status').filter({ hasText: /geopend/ }).waitFor({ timeout: 30000 });
  assert.equal(tab.url(), link, 'terug op precies het document uit de uitnodiging (van het tabblad met de uitnodiging)');
  assert.equal(await tab.evaluate(() => localStorage.getItem('paramant:signup-return')), null, 'de terugweg is na gebruik weg');
  await ctx.close();
  const leaked = tokenUrls(reqs.map((r) => r.url), link);
  assert.deepEqual(leaked, [], 'het token stond in geen enkele request-URL, ook niet in /signup of de terugweg');
});

test('A: is het tabblad met de uitnodiging dicht, dan zegt de pagina eerlijk dat de maillink het document opent', async () => {
  const state = { account: 401, status: 'sent' };
  const { ctx, reqs, link } = await context('A-dicht', state);
  const page = await ctx.newPage();
  await page.goto(link, { waitUntil: 'domcontentloaded' });
  const popup = await clickSignup(ctx, page);
  await popup.close();
  await page.close();
  const tab = await setupInNewTab(ctx);
  await tab.locator('#step-error.active').waitFor({ timeout: 15000 });
  const text = (await tab.locator('#step-error').innerText()).replace(/\s+/g, ' ');
  assert.match(text, /Uw account staat klaar/);
  assert.match(text, /Open de link uit de uitnodigingsmail nog een keer/);
  const u = new URL(tab.url());
  assert.equal(u.searchParams.get('env'), ENV_ID);
  assert.equal(u.searchParams.get('p'), '1');
  assert.equal(u.searchParams.get('t'), null);
  assert.equal(u.hash, '');
  assert.equal(await tab.evaluate(() => localStorage.getItem('paramant:signup-return')), null);
  await ctx.close();
  assert.deepEqual(tokenUrls(reqs.map((r) => r.url), link), []);
});

test('A: ook na een passkey brengt "Verder" de nieuwe gebruiker naar het document, niet naar het dashboard', async () => {
  const state = { account: 401, status: 'sent' };
  const { ctx, link } = await context('A-passkey', state);
  const page = await ctx.newPage();
  await page.goto(link, { waitUntil: 'domcontentloaded' });
  const popup = await clickSignup(ctx, page);
  await popup.goto(`${ORIGIN}/auth/setup/${SETUP}`, { waitUntil: 'domcontentloaded' });
  await popup.waitForTimeout(500);
  state.account = 200;
  // The passkey route's own success screen, as passkey.js shows it.
  await popup.evaluate(() => {
    document.querySelectorAll('section[id^="state-"]').forEach((s) => s.classList.add('hidden'));
    document.getElementById('state-passkey-success').classList.remove('hidden');
  });
  assert.match(await popup.locator('#passkey-finish-btn').innerText(), /document/);
  await popup.click('#passkey-finish-btn');
  await popup.locator('#welcome-doc-return:not([hidden])').waitFor({ timeout: 5000 });
  await popup.waitForURL((u) => u.pathname === '/co-sign' && u.searchParams.get('t') !== null, { timeout: 15000 });
  assert.equal(popup.url(), link);
  await ctx.close();
});

// Review #566: the record expires, is checked on every page and goes on sign-out.
test('A: de terugweg vervalt, een oud record met de link verdwijnt bij de eerstvolgende pagina, uitloggen wist hem', async () => {
  const lr = await import(path.join(ROOT, 'js', 'login-return.js'));
  const mem = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m }; };
  const loc = { pathname: '/co-sign', search: `?env=${ENV_ID}&p=1&t=${TOKEN}`, hash: '#ks=v1.secret' };
  const st = mem();
  const now = Date.parse('2026-10-05T12:00:00Z');
  assert.equal(lr.stashSignupReturn(st, loc, now), true);
  const rec = JSON.parse(st.getItem(lr.SIGNUP_KEY));
  assert.deepEqual(rec, { path: '/co-sign', env: ENV_ID, p: 1, exp: now + lr.SIGNUP_MAX_AGE_MS });
  assert.equal(lr.signupReturnPath(st, now + 1000), `/co-sign?env=${ENV_ID}&p=1&resume=1`);
  assert.equal(lr.signupReturnPath(st, now + lr.SIGNUP_MAX_AGE_MS + 1), null, 'na 24 uur niet meer');
  assert.equal(st.getItem(lr.SIGNUP_KEY), null, 'en weg');
  assert.equal(lr.stashSignupReturn(st, { pathname: '/elders', search: '?env=x', hash: '' }, now), false, 'alleen vanaf /co-sign met een verzoek');
  st.setItem(lr.SIGNUP_KEY, JSON.stringify({ path: '/co-sign', url: '/co-sign?env=' + ENV_ID + '&p=1&t=' + TOKEN, at: now }));
  assert.equal(lr.signupReturnPath(st, now), null, 'een oud record met de link telt niet');
  assert.equal(st.getItem(lr.SIGNUP_KEY), null);

  const state = { account: 200, status: 'sent' };
  const { ctx } = await context('A-sweep', state);
  const page = await ctx.newPage();
  await page.goto(`${ORIGIN}/signup`, { waitUntil: 'domcontentloaded' });
  await page.evaluate(({ e, t }) => localStorage.setItem('paramant:signup-return', JSON.stringify({ path: '/co-sign', url: `/co-sign?env=${e}&p=1&t=${t}#ks=v1.x`, at: Date.now() })), { e: ENV_ID, t: TOKEN });
  await page.reload({ waitUntil: 'load' });
  await page.waitForTimeout(300);
  assert.equal(await page.evaluate(() => localStorage.getItem('paramant:signup-return')), null, 'een oud record met token en sleutel gaat bij de volgende pagina');
  await page.evaluate(({ e }) => localStorage.setItem('paramant:signup-return', JSON.stringify({ path: '/co-sign', env: e, p: 1, exp: Date.now() - 1 })), { e: ENV_ID });
  await page.reload({ waitUntil: 'load' });
  await page.waitForTimeout(300);
  assert.equal(await page.evaluate(() => localStorage.getItem('paramant:signup-return')), null, 'een verlopen record gaat bij de volgende pagina');
  const src = fs.readFileSync(path.join(ROOT, 'js', 'nav-auth.js'), 'utf8');
  const signout = src.slice(src.indexOf("signout.addEventListener('click'"), src.indexOf("signout.addEventListener('click'") + 600);
  assert.match(signout, /localStorage\.removeItem\(SIGNUP_RETURN\)/, 'uitloggen wist de terugweg');
  await ctx.close();
});

test('A: zonder uitnodiging blijft het welkomstscherm zoals het was', async () => {
  const state = { account: 401, status: 'sent' };
  const { ctx } = await context('A-plain', state);
  const page = await ctx.newPage();
  await page.goto(`${ORIGIN}/auth/setup/${SETUP}`, { waitUntil: 'domcontentloaded' });
  const start = page.locator('#start-btn');
  if (await start.isVisible().catch(() => false)) await start.click();
  await page.locator('#verify-code').waitFor({ state: 'visible', timeout: 15000 });
  await page.fill('#verify-code', '123456');
  await page.click('#verify-btn');
  await page.locator('#saved-confirm').check();
  await page.click('#finish-btn');
  await page.waitForTimeout(3500);
  assert.match(new URL(page.url()).pathname, /^\/auth\/setup\//, 'geen sprong naar een document');
  assert.equal(await page.locator('#welcome-default').isVisible(), true);
  assert.equal(await page.locator('#welcome-doc-return').isVisible(), false);
  await ctx.close();
});

test('B: het uitnodigingstoken staat in geen enkele request-URL meer, behalve de maillink (HAR)', async () => {
  const state = { account: 200, status: 'complete', har: true };
  const { ctx, reqs, har, link } = await context('B', state);
  const page = await ctx.newPage();
  await page.goto(link, { waitUntil: 'domcontentloaded' });
  await page.locator('#result-download-proof:not([hidden])').waitFor({ timeout: 30000 });
  const dl = page.waitForEvent('download', { timeout: 15000 });
  await page.click('#result-download-proof');
  const download = await dl;
  assert.equal(download.suggestedFilename(), 'contract.psign');
  await ctx.close();
  const urls = harUrls(har);
  assert.ok(urls.some((u) => u.split('#')[0] === link.split('#')[0]), 'de HAR bevat de maillink zelf');
  const doc = reqs.find((r) => r.url.includes(`/api/user/envelopes/${ENV_ID}/document`));
  const relay = reqs.find((r) => r.url.startsWith(`https://health.paramant.app/v2/envelopes/${ENV_ID}?`));
  const receipt = reqs.find((r) => r.url.includes(`/api/user/envelopes/${ENV_ID}/receipt`));
  for (const [name, r] of [['document', doc], ['relay', relay], ['bewijs', receipt]]) {
    assert.ok(r, `de ${name}-aanvraag is gedaan`);
    assert.equal(r.headers['x-parasign-invite-token'], TOKEN, `de ${name}-aanvraag draagt het token in de header`);
  }
  assert.deepEqual(tokenUrls(urls, link), [], 'HAR: geen request-URL met het token');
  assert.deepEqual(tokenUrls(reqs.map((r) => r.url), link), []);
});

test('B: co-sign.js bouwt nergens meer een URL met &t=', () => {
  const src = fs.readFileSync(path.join(ROOT, 'co-sign.js'), 'utf8');
  assert.doesNotMatch(src, /['"]&t=['"]|&t=' \+|\?t=' \+/, 'geen token in een query');
});

test('C: zonder geopend document wijst de notitie niet naar een knop die er niet staat', async () => {
  const state = { account: 200, status: 'complete', document: 401 };
  const { ctx, link } = await context('C', state);
  const page = await ctx.newPage();
  await page.goto(link, { waitUntil: 'domcontentloaded' });
  await page.locator('#result-note:not([hidden])').waitFor({ timeout: 30000 });
  const r = await page.evaluate(() => ({
    note: document.getElementById('result-note').textContent,
    original: !document.getElementById('result-download-original').hidden,
    pdf: !document.getElementById('result-download-pdf').hidden,
  }));
  await ctx.close();
  assert.equal(r.original, false, 'de knop voor het origineel staat er niet');
  assert.equal(r.pdf, false);
  assert.doesNotMatch(r.note, /knop voor het origineel hierboven/);
  assert.match(r.note, /zodra het document op deze pagina is geopend/);
});

test('C: met geopend document noemt de notitie de knop, en die staat er', async () => {
  const state = { account: 200, status: 'complete' };
  const { ctx, link } = await context('C-ok', state);
  const page = await ctx.newPage();
  await page.goto(link, { waitUntil: 'domcontentloaded' });
  await page.locator('#result-download-original:not([hidden])').waitFor({ timeout: 30000 });
  const note = await page.locator('#result-note').textContent();
  await ctx.close();
  // Since acceptance 3.1.1 (16) the note names the original by its file name
  // and says to keep it with the proof; the button stands right above it.
  assert.match(note, /Bewaar het origineel \(/);
});
