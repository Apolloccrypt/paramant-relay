// De eigen stempel van de afzender (alleen én "Samen ondertekenen") kon zonder
// waarschuwing over een afbeelding of over artikelen als beeld vallen: de
// controle keek op een pagina mét tekstlaag alleen naar de tekst. Nu kijkt hij,
// net als /co-sign bij een handtekeningvak, ook naar de pixels onder het vak,
// en zegt het naast de plaatsingshint (met een vrije plek of een
// handtekeningblad) en nogmaals op de controlestap.
// Run: node --test tests/sign-stempel-over-beeld.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPdfLibs } from './helpers/sign-pdf-libs.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/sign') p = '/sign.html';
  const f = path.join(ROOT, p);
  if (!f.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

async function placeOnImage(mode) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } });
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"a@example.nl"}' }));
  await page.goto(ORIGIN + '/sign?mode=' + mode, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await new Promise((r) => setTimeout(r, 20));
    const L = window.PDFLib;
    const doc = await L.PDFDocument.create();
    const font = await doc.embedFont(L.StandardFonts.Helvetica);
    const pg = doc.addPage([595, 842]);
    // A text layer exists (one heading), but the articles are an image:
    // a dark block from y=300 to y=700 with nothing readable in it.
    pg.drawText('Overeenkomst', { x: 56, y: 790, size: 14, font });
    for (let y = 690; y > 300; y -= 14) pg.drawRectangle({ x: 56, y, width: 480, height: 8, color: L.rgb(0.1, 0.1, 0.1) });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'contract-scan.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  const canvas = page.locator('#ds-pdf-canvas-list .ds-page-wrap canvas').first();
  await canvas.waitFor({ timeout: 30000 });
  await page.waitForTimeout(800);
  await canvas.scrollIntoViewIfNeeded();
  const box = await canvas.boundingBox();
  await canvas.click({ position: { x: box.width * 0.5, y: box.height * (1 - 500 / 842) } });
  await page.locator('#ds-stamp-over-text').waitFor({ timeout: 10000 }).catch(() => {});
  const onImage = {
    notice: await page.locator('#ds-stamp-over-text').count() ? await page.locator('#ds-stamp-over-text').innerText() : '',
    sheet: await page.locator('#ds-cover-sheet').count(),
  };
  // Below the block: the notice goes away.
  await canvas.click({ position: { x: box.width * 0.5, y: box.height * (1 - 150 / 842) } });
  await page.waitForTimeout(1200);
  const below = await page.locator('#ds-stamp-over-text').count();
  await page.close();
  return { onImage, below };
}

const alone = await placeOnImage('alone');
const samen = await placeOnImage('cosign');

for (const [name, r] of [['alleen', alone], ['samen ondertekenen', samen]]) {
  test(`${name}: stempel op een afbeelding geeft de waarschuwing met handtekeningblad`, () => {
    assert.match(r.onImage.notice, /pagina 1 over tekst of een afbeelding/, JSON.stringify(r.onImage));
    assert.equal(r.onImage.sheet, 1, 'knop voor een handtekeningblad');
  });
  test(`${name}: op een lege plek verdwijnt de waarschuwing`, () => {
    assert.equal(r.below, 0);
  });
}
