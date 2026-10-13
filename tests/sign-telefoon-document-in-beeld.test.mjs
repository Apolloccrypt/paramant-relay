// Hertest r2 T5-12c: op een iPhone begon het document pas onderaan het eerste
// scherm. Gemeten op 1c000f03 met een iPhone 13 (390x664 zichtbaar): van
// pagina 1 stonden alleen de bovenste 36 px in beeld, onder de zoomknoppen, de
// vakknop, het paraafvinkje en de paginabalk. Nu: minstens de helft van
// pagina 1 staat in beeld zodra de stap Plaatsen opent, in beide modi.
// Run: node --test tests/sign-telefoon-document-in-beeld.test.mjs
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
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/sign') p = '/sign.html';
  if (p === '/en/sign') p = '/en/sign.html';
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

async function measure(route) {
  const ctx = await browser.newContext({ ...devices['iPhone 13'] });
  const page = await ctx.newPage();
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"a@example.nl"}' }));
  await page.goto(ORIGIN + route, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await new Promise((r) => setTimeout(r, 20));
    const doc = await window.PDFLib.PDFDocument.create();
    for (let i = 0; i < 3; i++) doc.addPage([595, 842]).drawText('Pagina ' + (i + 1), { x: 60, y: 760, size: 16 });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'contract.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap canvas').first().waitFor({ timeout: 30000 });
  await page.waitForTimeout(1500);
  const r = await page.evaluate(() => {
    const c = document.querySelector('#ds-pdf-canvas-list .ds-page-wrap canvas').getBoundingClientRect();
    const hint = document.getElementById('ds-place-hint').getBoundingClientRect();
    return { visible: Math.max(0, Math.min(innerHeight, c.bottom) - Math.max(0, c.top)) / c.height, hintTop: hint.top, hintBottom: hint.bottom, vh: innerHeight };
  });
  await ctx.close();
  return r;
}

for (const route of ['/sign?mode=invite', '/sign?mode=alone', '/en/sign?mode=invite']) {
  test(`${route}: pagina 1 staat op een iPhone direct grotendeels in beeld`, async () => {
    const r = await measure(route);
    assert.ok(r.visible >= 0.5, `maar ${Math.round(r.visible * 100)}% van pagina 1 in beeld`);
    assert.ok(r.hintTop >= 0 && r.hintBottom <= r.vh, 'en de aanwijzing "klik op een pagina" staat er nog boven');
  });
}
