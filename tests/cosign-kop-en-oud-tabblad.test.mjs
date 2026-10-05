// Acceptatie 3.1.1, twee punten op /co-sign:
//   10. De kop zei altijd "Lees het document en zet uw handtekening", ook
//       boven "Door iedereen getekend" en op de resultaatpagina van de
//       afzender. De kop volgt nu de status (js/cosign-heading.js).
//    5. Na een account maken via de uitnodiging opende het document in het
//       nieuwe tabblad, en bleef het oude op "Inloggen om verder te gaan"
//       staan. Het oude tabblad luistert nu (BroadcastChannel, met een
//       storage-event als terugval, en terugkomen in het tabblad) en gaat
//       vanzelf door zodra er in deze browser is ingelogd.
// Echte pagina's; alleen het netwerk is nagebootst.
// Run: node --test tests/cosign-kop-en-oud-tabblad.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', 'frontend');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const { cosignHeading } = await import(path.join(ROOT, 'js/cosign-heading.js'));
const NL = (nl) => nl;
const EN = (_nl, en) => en;

test('kop per status: alleen een open verzoek vraagt om te tekenen', () => {
  const asks = /zet uw handtekening/;
  assert.match(cosignHeading({ state: 'open' }, NL).sub, asks);
  for (const s of [
    { state: 'complete' }, { state: 'complete', owner: true }, { state: 'complete', signedByMe: true },
    { state: 'open', owner: true }, { state: 'open', signedByMe: true },
    { state: 'declined' }, { state: 'cancelled' }, { state: 'expired' },
  ]) {
    const h = cosignHeading(s, NL);
    assert.doesNotMatch(h.title + ' ' + h.sub, asks, JSON.stringify(s));
    const e = cosignHeading(s, EN);
    assert.doesNotMatch(e.title + ' ' + e.sub, /add your signature/, JSON.stringify(s));
  }
  assert.equal(cosignHeading({ state: 'complete' }, NL).title, 'Door iedereen getekend');
  assert.equal(cosignHeading({ state: 'open', owner: true }, NL).title, 'Uw verzoek');
  assert.equal(cosignHeading({ state: 'open', signedByMe: true }, NL).title, 'U heeft getekend');
  assert.equal(cosignHeading({ state: 'cancelled' }, EN).title, 'This request was withdrawn');
});

test('de pagina zet de kop vanuit de status, in beide talen', () => {
  for (const f of ['co-sign.html', 'en/co-sign.html']) {
    assert.match(read(f), /<h1 id="cosign-title">/, f);
    assert.match(read(f), /<p class="sub" id="cosign-sub">/, f);
  }
  const js = read('co-sign.js');
  assert.match(js, /import \{ cosignHeading \} from '\/js\/cosign-heading\.js\?v=\d+'/);
  const render = js.slice(js.indexOf('function renderEnvelope()'), js.indexOf("const list = $('parties-list')"));
  assert.match(render, /cosignHeading\(\{ state, signedByMe: .*owner: __ownerMode \}, L\)/);
});

const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.woff2': 'font/woff2', '.ttf': 'font/ttf' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/__proof') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>proof</title>'); }
  if (p === '/co-sign' || p === '/en/co-sign') p += '.html';
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
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

const ENV_ID = 'env_demo_oudtabbladabcdefgh';
const TOKEN = ('Oudtabbladtoken' + 'x'.repeat(43)).slice(0, 43);

let FX = null;
async function fixture() {
  if (FX) return FX;
  const page = await browser.newPage();
  await page.goto(ORIGIN + '/__proof');
  await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
  FX = await page.evaluate(async (envelopeId) => {
    const { PDFDocument, StandardFonts } = window.PDFLib;
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    doc.addPage([595.28, 841.89]).drawText('Artikel 1. Partijen komen overeen.', { x: 72, y: 760, size: 11, font });
    const b = new Uint8Array(await doc.save());
    const pqc = await import('/vendor/paramant-pqc.js');
    const delivery = await import('/js/parasign-document-capsule.js?v=2');
    const docHash = Array.from(pqc.sha3_256(b)).map((x) => x.toString(16).padStart(2, '0')).join('');
    const out = await delivery.encryptDocumentCapsule({ bytes: b, filename: 'contract.pdf', mime: 'application/pdf', envelopeId, docHash });
    return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash };
  }, ENV_ID);
  await page.close();
  return FX;
}

// One browser context; state.account decides whether this browser has a
// session, and can change while the tabs are open.
async function context(state) {
  const fx = await fixture();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  // Playwright tries the last registered route first: the catch-alls go first.
  await ctx.route('https://**/**', (route) => route.abort());
  await ctx.route('**/api/**', (route) => route.fulfill({ status: 404, contentType: 'application/json', body: '{}' }));
  await ctx.route('https://health.paramant.app/v2/envelopes/**', (route) => {
    if (new URL(route.request().url()).pathname.endsWith('/view')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
    const complete = state.status === 'complete';
    return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: JSON.stringify({ envelope: {
      id: ENV_ID, doc_hash: fx.docHash, original_filename: 'contract.pdf', recipe_version: 5,
      created_at: '2026-10-04T12:00:00.000Z', expires_at: '2099-11-03T12:00:00.000Z', sign_expires_at: '2099-10-11T12:00:00.000Z',
      status: complete ? 'complete' : 'sent', signed_count: complete ? 2 : 1, party_count: 2,
      parties: [{ index: 0, label: 'Afzender Demo', status: 'signed' }, { index: 1, label: 'Signer Demo', status: complete ? 'signed' : 'pending' }],
    } }) });
  });
  await ctx.route(`**/api/user/envelopes/${ENV_ID}/document*`, (route) => route.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fx.capsule) }));
  await ctx.route('**/api/user/account/webauthn/credentials', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"passkeys":[]}' }));
  await ctx.route('**/api/user/account', (route) => route.fulfill({ status: state.account, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' },
    body: state.account === 200 ? '{"email":"signer@example.com"}' : '{"error":"x"}' }));
  return { ctx, link: `${ORIGIN}/co-sign?env=${ENV_ID}&p=1&t=${TOKEN}${fx.fragment}` };
}

const waitLoginButton = (page) => page.locator('#sign-cta a.btn[href^="/auth/login"]').waitFor({ timeout: 30000 });
const waitDocumentOpen = (page) => page.waitForFunction(() => !document.body.classList.contains('needs-login')
  && /klopt met dit verzoek/.test(document.getElementById('document-delivery-status')?.textContent || ''), null, { timeout: 30000 });

test('oud tabblad: ingelogd in een nieuw tabblad, het oude gaat vanzelf door', async () => {
  const state = { account: 401 };
  const { ctx, link } = await context(state);
  const oud = await ctx.newPage();
  await oud.goto(link, { waitUntil: 'domcontentloaded' });
  await waitLoginButton(oud);
  assert.equal(await oud.locator('#cosign-title').textContent(), 'Document ondertekenen');
  // The account is made in another tab; that tab lands on /co-sign signed in.
  state.account = 200;
  const nieuw = await ctx.newPage();
  await nieuw.goto(link, { waitUntil: 'domcontentloaded' });
  await waitDocumentOpen(nieuw);
  // The old tab was not touched: the message from the new tab moved it on.
  await waitDocumentOpen(oud);
  await ctx.close();
});

test('oud tabblad: zonder BroadcastChannel brengt het storage-event het door', async () => {
  const state = { account: 401 };
  const { ctx, link } = await context(state);
  await ctx.addInitScript(() => { try { delete window.BroadcastChannel; window.BroadcastChannel = undefined; } catch { /* read-only */ } });
  const oud = await ctx.newPage();
  await oud.goto(link, { waitUntil: 'domcontentloaded' });
  await waitLoginButton(oud);
  state.account = 200;
  const nieuw = await ctx.newPage();
  await nieuw.goto(link, { waitUntil: 'domcontentloaded' });
  await waitDocumentOpen(nieuw);
  await waitDocumentOpen(oud);
  // The ping key is gone again: nothing stays in the browser.
  assert.equal(await oud.evaluate(() => localStorage.getItem('paramant:signed-in-ping')), null);
  await ctx.close();
});

test('oud tabblad: ingelogd op een andere pagina, terugkomen in het tabblad gaat door', async () => {
  const state = { account: 401 };
  const { ctx, link } = await context(state);
  const oud = await ctx.newPage();
  await oud.goto(link, { waitUntil: 'domcontentloaded' });
  await waitLoginButton(oud);
  state.account = 200;
  await oud.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await waitDocumentOpen(oud);
  await ctx.close();
});

test('kop boven een afgerond verzoek vraagt niet om te tekenen', async () => {
  const state = { account: 200, status: 'complete' };
  const { ctx, link } = await context(state);
  const page = await ctx.newPage();
  await page.goto(link, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => document.getElementById('cosign-title')?.textContent === 'Door iedereen getekend', null, { timeout: 30000 });
  assert.doesNotMatch(await page.locator('#cosign-sub').textContent(), /zet uw handtekening/);
  await ctx.close();
});
