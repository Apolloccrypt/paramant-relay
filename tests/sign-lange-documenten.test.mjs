// Lange documenten op /sign (hertest 2026-10-04, T2-B1/T5-N3 en T1-12).
//
//   - De afzender zag maar 30 pagina's en kon geen plek op pagina 31 of later
//     aanwijzen. Nu toont de stap Plaatsen alle pagina's tot 300.
//   - Een document van 40 pagina's versprong tijdens het renderen: de laatste
//     pagina schoof van y 15570 naar y 34685, de eerste pagina's waren eerst
//     477 px hoog en daarna 1158. Nu heeft elke pagina haar maat voordat er
//     iets getekend wordt.
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
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/sign') p = '/sign.html';
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

const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' }));
await page.goto(`${ORIGIN}/sign?mode=alone`, { waitUntil: 'domcontentloaded' });
await loadPdfLibs(page);
const r = await page.evaluate(async () => {
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
  const doc = await window.PDFLib.PDFDocument.create();
  const font = await doc.embedFont(window.PDFLib.StandardFonts.Helvetica);
  for (let p = 0; p < 40; p++) {
    const pg = doc.addPage([595.28, 841.89]);
    pg.drawText('Pagina ' + (p + 1) + ' van 40', { x: 56, y: 780, size: 14, font });
    for (let y = 750; y >= 300; y -= 14) pg.drawText('Artikel ' + (p + 1) + '. Een regel tekst om het renderen werk te geven.', { x: 56, y, size: 10, font });
  }
  const t = new DataTransfer();
  t.items.add(new File([await doc.save()], 'veertig.pdf', { type: 'application/pdf' }));
  const input = document.getElementById('ds-doc-input');
  input.files = t.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  // The moment the first page is on screen: where does the last page sit?
  for (let i = 0; i < 600; i++) {
    const c = document.querySelector('#ds-pdf-canvas-list .ds-page-wrap canvas');
    if (!document.getElementById('step-place').hidden && c && c.getBoundingClientRect().height > 0) break;
    await sleep(10);
  }
  const lastBottom = () => { const w = [...document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap')].pop(); return w ? Math.round(w.getBoundingClientRect().bottom + window.scrollY) : 0; };
  const firstH = () => Math.round(document.querySelector('#ds-pdf-canvas-list .ds-page-wrap canvas').getBoundingClientRect().height);
  const early = { last: lastBottom(), first: firstH(), wraps: document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap').length };
  await sleep(2500);
  const late = { last: lastBottom(), first: firstH(), wraps: document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap').length };
  return { early, late };
});

test('de afzender ziet alle 40 pagina\'s', () => {
  assert.equal(r.late.wraps, 40, `${r.late.wraps} pagina's in de stap Plaatsen`);
});

test('niets verspringt terwijl de pagina\'s renderen', () => {
  assert.ok(Math.abs(r.early.first - r.late.first) <= 2, `eerste pagina ${r.early.first} -> ${r.late.first} px hoog`);
  // A pixel per page from rounding is not a jump; the retest saw 19 000 px.
  if (r.early.wraps === r.late.wraps) assert.ok(Math.abs(r.early.last - r.late.last) <= Math.max(4, 0.002 * r.late.last), `laatste pagina van y ${r.early.last} naar y ${r.late.last}`);
});

test('een plek op pagina 35 aanwijzen kan', async () => {
  const wrap = page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="34"]');
  await wrap.scrollIntoViewIfNeeded();
  await page.waitForTimeout(800);
  await wrap.click({ position: { x: 200, y: 600 } });
  const onPage = await page.evaluate(() => { const m = document.querySelector('.ds-stamp-marker'); return m ? m.closest('.ds-page-wrap').dataset.pageIndex : null; });
  const hint = await page.locator('#ds-place-hint').textContent();
  assert.equal(onPage, '34');
  assert.match(hint, /pagina 35/);
});
