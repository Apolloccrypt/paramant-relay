// /co-sign zegt wat er echt aan de hand is (matrix P02 en PDF-sweep, 2026-10-04):
//   - een link zonder sleutel (COSIGN-46, b.v. "stuur mij de link opnieuw"):
//     uitleg en een herstelweg, niet alleen "geen sleutel";
//   - een storing bij /api/user/account (COSIGN-24-C) is geen "log in";
//   - de afzender heette "<naam> (you)", ook op een Nederlandse pagina en
//     voor de andere partijen (COSIGN-02);
//   - een beveiligde pdf beloofde een paraaf en gaf geen pdf (sweep B8);
//   - een pdf met een eerdere digitale handtekening werd stil ongeldig (B3);
//   - een paraaf zonder vrije marge stond stil over de tekst (B1).
// Echte pagina, echte WebCrypto; alleen het netwerk is nagebootst.
// Draait in Chromium; in WebKit via ~/bin/pw-webkit.sh.
// Run: node --test tests/cosign-randgevallen-eerlijk.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.woff2': 'font/woff2', '.ttf': 'font/ttf' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/__proof') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>proof</title>'); }
  if (p === '/co-sign') p = '/co-sign.html';
  if (p === '/en/co-sign') p = '/en/co-sign.html';
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
after(async () => { await browser.close(); server.close(); });

const ENV_ID = 'env_demo_abcdefghijklmnop';
const TOKEN = 't'.repeat(43);

// Encrypt `bytes` in a page the way /sign does, so /co-sign can open it.
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

// A pdf made with the page's own pdf-lib. full: text from edge to edge.
async function makePdf(page, { pages = 2, full = false } = {}) {
  await page.goto(ORIGIN + '/__proof');
  await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
  const arr = await page.evaluate(async ({ pages, full }) => {
    const { PDFDocument, StandardFonts } = window.PDFLib;
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    for (let i = 0; i < pages; i++) {
      const pg = doc.addPage([595.28, 841.89]);
      const x0 = full ? 4 : 72, top = full ? 836 : 760, bottom = full ? 4 : 90;
      for (let y = top; y >= bottom; y -= 9) pg.drawText('Artikel ' + i + '. Huurder en verhuurder komen overeen dat de woning wordt opgeleverd zoals afgesproken.'.repeat(full ? 2 : 1), { x: x0, y, size: 8, font });
    }
    return Array.from(await doc.save());
  }, { pages, full });
  return new Uint8Array(arr);
}

async function openCosign({ bytes, fragment = 'auto', account = 200, envelope = {}, lang = 'nl' }) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const fx = bytes ? await capsuleFor(page, bytes) : { capsule: [], fragment: '', docHash: 'a'.repeat(64) };
  await page.route('https://health.paramant.app/v2/envelopes/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/view')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ envelope: {
      id: ENV_ID, doc_hash: fx.docHash, original_filename: 'contract.pdf', recipe_version: 5,
      created_at: '2026-10-04T12:00:00.000Z', expires_at: '2026-11-03T12:00:00.000Z', sign_expires_at: '2026-10-11T12:00:00.000Z',
      status: 'sent', signed_count: 1, party_count: 2,
      parties: [{ index: 0, label: 'Afzender Zelf (you)', status: 'signed' }, { index: 1, label: 'Ayşe Yılmaz', status: 'pending' }],
      ...envelope,
    } }) });
  });
  await page.route(`**/api/user/envelopes/${ENV_ID}/document*`, (route) => route.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fx.capsule) }));
  await page.route('**/api/user/account/webauthn/credentials', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"passkeys":[]}' }));
  await page.route('**/api/user/account', (route) => route.fulfill({ status: account, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' },
    body: account === 200 ? '{"email":"ayse@example.com"}' : '{"error":"x"}' }));
  const frag = fragment === 'auto' ? fx.fragment : fragment;
  await page.goto(`${ORIGIN}/${lang === 'en' ? 'en/' : ''}co-sign?env=${ENV_ID}&p=1&t=${TOKEN}${frag}`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const s = document.getElementById('sign-status');
    const d = document.getElementById('document-delivery-status');
    return (s && !s.hidden && /storing/i.test(s.textContent)) || (d && !d.hidden && d.textContent && !/wordt gedownload|wordt opgehaald|Downloading|Fetching the document/.test(d.textContent)) /* Mick 05-10: taalronde */;
  }, null, { timeout: 30000 });
  await page.waitForTimeout(800);
  return { page, ctx, errors };
}

const read = (page) => page.evaluate(() => ({
  delivery: (document.getElementById('document-delivery-status') || {}).textContent || '',
  manual: !(document.getElementById('verify-file-cta') || { hidden: true }).hidden,
  status: (document.getElementById('sign-status') || {}).textContent || '',
  cta: (document.getElementById('sign-cta') || {}).innerHTML || '',
  ctaHidden: !!(document.getElementById('sign-cta') || {}).hidden,
  parties: [...document.querySelectorAll('#parties-list .party-label')].map((e) => e.textContent),
  note: (() => { const n = document.getElementById('pdf-note'); return n && !n.hidden ? n.textContent : ''; })(),
  editor: !(document.getElementById('appearance-editor') || { hidden: true }).hidden,
  overText: document.querySelectorAll('.appearance-field.over-text').length,
}));

test('COSIGN-46: link zonder sleutel legt uit wat er mis is en wat werkt', async () => {
  const proof = await browser.newPage();
  const bytes = await makePdf(proof);
  await proof.close();
  const { page, ctx, errors } = await openCosign({ bytes, fragment: '' });
  const r = await read(page);
  await ctx.close();
  assert.match(r.delivery, /eerste uitnodigingsmail/);
  assert.match(r.delivery, /Vraag de afzender dan om de link opnieuw te sturen/);
  assert.equal(r.manual, true, 'het document zelf kiezen staat klaar');
  assert.deepEqual(errors, []);
});

test('COSIGN-24-C: storing bij het account is geen "log in"', async () => {
  const proof = await browser.newPage();
  const bytes = await makePdf(proof);
  await proof.close();
  const { page, ctx } = await openCosign({ bytes, account: 503 });
  const r = await read(page);
  await ctx.close();
  assert.match(r.status, /storing bij ons/);
  assert.doesNotMatch(r.status, /Log in als de ontvanger/);
  assert.doesNotMatch(r.cta, /auth\/login/);
  assert.match(r.cta, /Opnieuw proberen/);
});

test('COSIGN-02: de afzender heet niet "(you)", ook niet op de Nederlandse pagina', async () => {
  const proof = await browser.newPage();
  const bytes = await makePdf(proof);
  await proof.close();
  const { page, ctx } = await openCosign({ bytes });
  const r = await read(page);
  await ctx.close();
  assert.equal(r.parties[0], 'Afzender Zelf');
  assert.equal(r.parties[1], 'Ayşe Yılmaz (u)');
});

test('B8: beveiligde pdf belooft geen paraaf en geen pdf-kopie', async () => {
  const bytes = new Uint8Array(fs.readFileSync(path.join(HERE, 'fixtures', 'sign', 'encrypted-owneronly.pdf')));
  const { page, ctx, errors } = await openCosign({ bytes });
  const r = await read(page);
  const built = await page.evaluate(async () => {
    const mod = await import(document.querySelector('script[src*="co-sign.js"]').getAttribute('src'));
    return (await mod.buildSignedPdf({ appearance: { version: 1, fields: [] }, signed_at: '2026-10-04T12:00:00.000Z' })) === null;
  });
  await ctx.close();
  assert.match(r.note, /beveiligd/);
  assert.equal(r.editor, false, 'geen velden plaatsen die nooit in een pdf komen');
  assert.equal(built, true, 'geen pdf-kopie');
  assert.deepEqual(errors, []);
});

test('B3: een eerdere digitale handtekening wordt gemeld', async () => {
  const bytes = new Uint8Array(fs.readFileSync(path.join(HERE, 'fixtures', 'cosign', 'signed-visible.pdf')));
  const { page, ctx } = await openCosign({ bytes });
  const r = await read(page);
  await ctx.close();
  assert.match(r.note, /digitale handtekening/);
  assert.equal(r.editor, true, 'tekenen met zichtbare velden kan nog steeds');
});

test('B1: paraaf zonder vrije marge wordt gemeld en rood omlijnd', async () => {
  const proof = await browser.newPage();
  const bytes = await makePdf(proof, { pages: 2, full: true });
  await proof.close();
  const req = { version: 2, fields: [{ type: 'seal', page_index: 1, x: 0.5, y: 0.8, w: 0.3, h: 0.085 }, { type: 'seal', page_index: 0, x: 0.84, y: 0.95, w: 0.066, h: 0.021, all_pages: true }] };
  const { page, ctx } = await openCosign({ bytes, envelope: { requested_appearance: req, requested_for_party: true } });
  const r = await read(page);
  await ctx.close();
  assert.match(r.note, /pagina's 1 en 2/);
  assert.match(r.note, /over de tekst/);
  assert.ok(r.overText >= 2, 'de paraaf staat rood omlijnd op beide pagina\'s: ' + r.overText);
});
