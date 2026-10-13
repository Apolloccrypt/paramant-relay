// Acceptatie ronde 2, punt 1: op /sign (alleen) kon de stempel op de
// contracttekst van de laatste pagina worden gezet zonder enige waarschuwing;
// de tekstcontrole bestond alleen in de uitnodigingsmodus. Nu zegt de hint het,
// met twee uitwegen zoals co-sign: een vrije plek of een handtekeningblad.
// Run: node --test tests/sign-solo-stempel-op-tekst.test.mjs
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

const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } });
await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"a@example.nl"}' }));
await page.goto(ORIGIN + '/sign?mode=alone', { waitUntil: 'domcontentloaded' });
await loadPdfLibs(page);
await page.evaluate(async () => {
  for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await new Promise((r) => setTimeout(r, 20));
  const L = window.PDFLib;
  const doc = await L.PDFDocument.create();
  const font = await doc.embedFont(L.StandardFonts.Helvetica);
  // One contract page: articles from the top down to y=300, free below.
  const pg = doc.addPage([595, 842]);
  for (let y = 780; y > 300; y -= 14) pg.drawText('Artikel ' + y + '. De partijen komen het volgende overeen over levering en betaling.', { x: 56, y, size: 10, font });
  const t = new DataTransfer();
  t.items.add(new File([await doc.save()], 'contract.pdf', { type: 'application/pdf' }));
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
// Middle of the articles (about y=560 pt from the bottom).
await canvas.click({ position: { x: box.width * 0.5, y: box.height * (1 - 560 / 842) } });
await page.locator('#ds-cover-sheet').waitFor({ timeout: 10000 }).catch(() => {});
const warned = await page.locator('#ds-place-hint').innerText();
const hasFree = await page.locator('#ds-cover-free').count();
if (hasFree) await page.locator('#ds-cover-free').click();
await page.waitForTimeout(300);
const after1 = await page.evaluate(() => ({ hint: document.getElementById('ds-place-hint').textContent }));
// Below the articles: no warning.
await canvas.click({ position: { x: box.width * 0.5, y: box.height * (1 - 150 / 842) } });
await page.waitForTimeout(900);
const freeHint = await page.locator('#ds-place-hint').innerText();
await page.close();

test('de stempel op de artikelen geeft een waarschuwing met twee uitwegen', () => {
  assert.match(warned, /staat op de tekst van pagina 1/, warned);
  assert.equal(hasFree, 1, 'een knop voor een vrije plek');
});

test('"vrije plek" zet hem op een plek zonder tekst', () => {
  assert.match(after1.hint, /op een vrije plek/, after1.hint);
});

test('onder de tekst: geen waarschuwing', () => {
  assert.doesNotMatch(freeHint, /staat op de tekst/, freeHint);
});
