// Fase 2 (2026-10-04), /sign solo, P01:
//  SIGN-10: de paginabalk plakte op 8px, onder de vaste sitebalk (56px); daar
//    lag een menulink over de knoppen. Nu plakt hij onder de sitebalk.
//  SIGN-18: na "+ Pagina's..." zette het her-renderen de standaardhint terug;
//    de melding met de bestandsnaam verdween.
//  SIGN-21: de datum was ISO in UTC (tussen 00:00 en 02:00 de dag van gisteren);
//    nu de eigen klok, op de NL-pagina als 4-10-2026.
//  SIGN-34: "SHA3-256 van het document" bij Controleren is de hash van het
//    origineel; het label zegt dat nu.
// Run: node --test tests/sign-fase2.test.mjs
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

async function openWithPdf(pages = 3) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' }));
  await page.goto(`${ORIGIN}/sign?mode=alone`, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async (n) => {
    const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    const font = await doc.embedFont(window.PDFLib.StandardFonts.Helvetica);
    for (let p = 0; p < n; p++) doc.addPage([595.28, 841.89]).drawText('Pagina ' + (p + 1), { x: 56, y: 780, size: 14, font });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'drie.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, pages);
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap canvas').first().waitFor({ timeout: 20000 });
  return page;
}

test('SIGN-10: de paginabalk plakt onder de vaste sitebalk', async () => {
  const page = await openWithPdf(3);
  const top = await page.evaluate(() => getComputedStyle(document.getElementById('ds-page-nav')).top);
  assert.equal(top, '64px');
  await page.close();
});

test('SIGN-18: de melding na pagina\'s toevoegen blijft staan', async () => {
  const page = await openWithPdf(3);
  const extra = await page.evaluate(async () => {
    const doc = await window.PDFLib.PDFDocument.create();
    doc.addPage([595.28, 841.89]); doc.addPage([595.28, 841.89]);
    return Array.from(await doc.save());
  });
  await page.locator('#ds-page-merge-file').setInputFiles({ name: 'bijlage-b.pdf', mimeType: 'application/pdf', buffer: Buffer.from(extra) });
  await page.waitForFunction(() => document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap').length === 5, null, { timeout: 20000 });
  await page.waitForTimeout(500);
  const hint = await page.locator('#ds-place-hint').textContent();
  assert.match(hint, /bijlage-b\.pdf/, hint);
  await page.close();
});

test('SIGN-21: de datum is vandaag op de eigen klok, Nederlands geschreven', async () => {
  const page = await openWithPdf(1);
  const c = page.locator('#ds-pdf-canvas-list .ds-page-wrap').first();
  const box = await c.boundingBox();
  await c.click({ position: { x: box.width * 0.5, y: box.height * 0.6 } });   // eerst de zegel
  await page.locator('#ds-add-date').click();
  await c.click({ position: { x: box.width * 0.3, y: box.height * 0.25 } });
  const txt = (await page.locator('.ds-anno[data-type="date"]').evaluate((el) => el.firstChild.textContent)).trim();
  const want = await page.evaluate(() => { const d = new Date(); return d.getDate() + '-' + (d.getMonth() + 1) + '-' + d.getFullYear(); });
  assert.ok(txt.startsWith(want), `datum "${txt}", verwacht ${want}`);
  await page.close();
});

test('SIGN-34: het label zegt dat de hash bij Controleren die van het origineel is', () => {
  const flow = fs.readFileSync(path.join(ROOT, 'sign-flow.js'), 'utf8');
  for (const f of ['sign.html', 'en/sign.html']) assert.match(fs.readFileSync(path.join(ROOT, f), 'utf8'), /id="ds-proof-doc-hash-label"/, f);
  assert.match(flow, /SHA3-256 van het origineel \(de handtekening komt op de versie met de zegel\)/);
});
