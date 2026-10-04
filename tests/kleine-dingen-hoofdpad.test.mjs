// Kleine dingen in het hoofdpad (hertest 2026-10-04, T5-12a, b en c).
//
//   a. /auth/setup: "STAP 3 VAN 5 · Kies hoe u inlogt" bleef boven stap 4, 5 en
//      zelfs "Alles staat klaar" staan.
//   b. /co-sign: het verwijderkruisje dekte het eind van een getypte naam af
//      ("Pieter Partn[x]").
//   c. /sign op een iPhone: het document begon pas een vol scherm onder de
//      vouw, en naast "Pagina 1 van 3" stond een leeg invulveld.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, devices } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPdfLibs } from './helpers/sign-pdf-libs.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/__blank') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>leeg</title>'); }
  if (p.startsWith('/auth/setup/')) p = '/auth/setup.html';
  if (p === '/sign') p = '/sign.html';
  if (p === '/co-sign') p = '/co-sign.html';
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
const json = (route, status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

test('a. /auth/setup: "stap 3 van 5" staat alleen bij het kiezen', async () => {
  const page = await browser.newPage();
  await page.route('**/api/user/setup/**', (r) => json(r, 200, { otpauth: 'otpauth://totp/Paramant:s@example.com?secret=JBSWY3DPEHPK3PXP', email: 's@example.com', secret: 'JBSWY3DPEHPK3PXP', backup_codes: ['aaaa-bbbb'] }));
  await page.goto(ORIGIN + '/auth/setup/tok_demo_123', { waitUntil: 'domcontentloaded' });
  const visibleEyebrows = () => page.evaluate(() => [...document.querySelectorAll('.eyebrow')].filter((e) => e.offsetParent !== null).map((e) => e.textContent.trim()));
  const atStart = (await visibleEyebrows()).includes('stap 3 van 5');
  await page.locator('#start-btn').click();
  await page.locator('#state-active:not(.hidden)').waitFor({ timeout: 10000 });
  const eyebrows = await visibleEyebrows();
  await page.close();
  assert.ok(atStart, 'bij het kiezen staat de stap er wel');
  assert.deepEqual(eyebrows, ['stap 4 van 5'], `zichtbare stapkoppen: ${eyebrows.join(' | ')}`);
});

test('b+d. /co-sign: het kruisje dekt de getypte naam niet af, en de naam komt zoals getypt in de pdf', async () => {
  const ENV_ID = 'env_demo_kruisjexyzabcd';
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  await page.goto(ORIGIN + '/__blank');
  await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
  const fixture = await page.evaluate(async ({ envelopeId }) => {
    const pqc = await import('/vendor/paramant-pqc.js');
    const delivery = await import('/js/parasign-document-capsule.js?v=2');
    const pdf = await window.PDFLib.PDFDocument.create();
    pdf.addPage([595, 842]).drawText('Overeenkomst', { x: 56, y: 760, size: 14 });
    const bytes = new Uint8Array(await pdf.save());
    const docHash = Array.from(pqc.sha3_256(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
    const out = await delivery.encryptDocumentCapsule({ bytes, filename: 'o.pdf', mime: 'application/pdf', envelopeId, docHash });
    return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash };
  }, { envelopeId: ENV_ID });
  await page.route('**/api/**', (r) => json(r, 200, { ok: true }));
  await page.route('https://health.paramant.app/v2/envelopes/**', (route) => {
    if (new URL(route.request().url()).pathname.endsWith('/view')) return json(route, 200, { ok: true });
    return json(route, 200, { envelope: { id: ENV_ID, doc_hash: fixture.docHash, original_filename: 'o.pdf', recipe_version: 5,
      created_at: '2026-10-04T12:00:00.000Z', expires_at: '2026-11-03T12:00:00.000Z', status: 'sent', signed_count: 0, party_count: 1,
      parties: [{ index: 0, label: 'Pieter Partner', status: 'pending' }] } });
  });
  await page.route(`**/api/user/envelopes/${ENV_ID}/document*`, (r) => r.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fixture.capsule) }));
  await page.route('**/api/user/account', (r) => json(r, 200, { email: 'demo@example.com' }));
  await page.goto(`${ORIGIN}/co-sign?env=${ENV_ID}&p=0&t=${'t'.repeat(43)}${fixture.fragment}`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !document.querySelector('#sign-confirm')?.disabled, null, { timeout: 30000 });
  await page.locator('#ink-name').fill('Pieter Partner van den Broek');
  await page.locator('#ink-name').dispatchEvent('input');
  // Place the signature by hand, as the hertest did: then it is the signer's
  // own field, with its ×.
  await page.locator('#appearance-seal').click();
  const pg = page.locator('.doc-page[data-page-index="0"]');
  await pg.scrollIntoViewIfNeeded();
  const box = await pg.boundingBox();
  await page.mouse.click(box.x + box.width * 0.3, box.y + box.height * 0.6);
  await page.waitForTimeout(400);
  const r = await page.evaluate(() => {
    const field = [...document.querySelectorAll('.appearance-field.mine')].find((f) => !f.classList.contains('paraaf') && f.querySelector('.appearance-remove') && f.querySelector('.ink'));
    if (!field) return null;
    const x = field.querySelector('.appearance-remove').getBoundingClientRect();
    const ink = field.querySelector('.ink');
    const range = document.createRange(); range.selectNodeContents(ink);
    const t = range.getBoundingClientRect();
    const overlap = !(t.right <= x.left || x.right <= t.left || t.bottom <= x.top || x.bottom <= t.top);
    return { overlap, text: ink.textContent };
  });
  // D (acceptance test): a name outside WinAnsi reaches the PDF as written,
  // not as "Ay?e Y?lmaz".
  await page.locator('#ink-name').fill('Ayşe Yılmaz');
  await page.locator('#ink-name').dispatchEvent('input');
  // Acceptance r2, 7: the screen shows the name the way the pdf writes it
  // (upright Noto Sans for letters Times Italic does not have), not cursive serif.
  await page.waitForTimeout(200);
  const shown = await page.evaluate(() => {
    const ink = document.querySelector('.appearance-field .ink');
    return ink ? getComputedStyle(ink).fontStyle : null;
  });
  const pdfText = await page.evaluate(async () => {
    const mod = await import(document.querySelector('script[src*="co-sign.js"]').getAttribute('src'));
    const out = await mod.buildSignedPdf({ appearance: window.__cosignDebug.appearance(), signed_at: '2026-10-04T12:00:00.000Z' });
    const doc = await window.pdfjsLib.getDocument({ data: new Uint8Array(out) }).promise;
    let text = '';
    for (let i = 1; i <= doc.numPages; i++) text += (await (await doc.getPage(i)).getTextContent()).items.map((it) => it.str).join(' ') + ' ';
    return text;
  });
  await page.close();
  assert.match(pdfText, /Ayşe Yılmaz/, 'de naam staat zoals getypt in de pdf: ' + pdfText.slice(0, 200));
  assert.equal(shown, 'normal', 'op het scherm rechtop, zoals in de pdf (niet cursief)');
  assert.ok(r, 'er staat een handtekeningveld met een kruisje');
  assert.equal(r.overlap, false, `het kruisje ligt over "${r.text}"`);
});

test('c. /sign op een iPhone: het document begint op het eerste scherm, geen leeg veld', async () => {
  const d = { ...devices['iPhone 13'] }; delete d.defaultBrowserType;
  const ctx = await browser.newContext(d);
  const page = await ctx.newPage();
  await page.route('**/api/**', (r) => json(r, 200, { authenticated: true, email: 'demo@example.com' }));
  await page.goto(`${ORIGIN}/sign?mode=alone`, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    for (let i = 0; i < 3; i++) doc.addPage([595, 842]).drawText('Pagina ' + (i + 1), { x: 60, y: 760, size: 16 });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'drie.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap canvas').first().waitFor({ timeout: 30000 });
  await page.waitForTimeout(800);
  const r = await page.evaluate(() => ({
    top: Math.round(document.querySelector('#ds-pdf-canvas-list .ds-page-wrap').getBoundingClientRect().top + window.scrollY),
    vh: window.innerHeight,
    jump: document.getElementById('ds-page-nav-jump').placeholder,
  }));
  // The tools are one tap away.
  await page.locator('#ds-more-tools').click();
  const toolsVisible = await page.locator('#ds-add-text').isVisible();
  await ctx.close();
  assert.ok(r.top < r.vh, `het document begint op y ${r.top}, het scherm is ${r.vh} hoog`);
  assert.ok(r.jump.trim().length > 0, 'het paginaveld heeft een aanwijzing');
  assert.ok(toolsVisible, 'tekst, datum en meer zijn met één tik te openen');
});
