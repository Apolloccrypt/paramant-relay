// Het zegel op /sign laat de tekst eronder leesbaar (hertest 2026-10-04, T1-10).
//
// De hertest mat het zegel op 40% van de A4-breedte (240 x 100 pt) met een
// massief witte binnenkant: wat eronder stond, was weg. Deze suite zet het
// zegel met een klik midden in een pagina vol tekst, laat de echte
// buildStampedPdf het bakken en rendert bron en resultaat met pdf.js. Ze eist:
//   - het standaardzegel is hooguit 30% van de paginabreedte;
//   - van de tekstpixels onder het zegel is in het resultaat nog minstens 85%
//     donker (een witte binnenkant liet er vrijwel niets van over);
//   - de getekende handtekening gaat als doorzichtige PNG mee (geen witte rand).
// Run: node --test tests/sign-seal-doorzichtig.test.mjs
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
  const p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
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

const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
const page = await context.newPage();
await page.route('**/api/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' }));
await page.goto(`${ORIGIN}/sign.html?mode=alone`, { waitUntil: 'domcontentloaded' });
await loadPdfLibs(page);

const r = await page.evaluate(async () => {
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  for (let i = 0; i < 400 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
  const { PDFDocument, StandardFonts } = window.PDFLib;
  const src = await PDFDocument.create();
  const font = await src.embedFont(StandardFonts.Helvetica);
  const pg = src.addPage([595.28, 841.89]);
  for (let y = 790; y >= 50; y -= 13) pg.drawText('Artikel 7. De partijen verklaren dat deze regel tekst leesbaar moet blijven onder het zegel.', { x: 40, y, size: 10.5, font });
  const bytes = await src.save();

  const input = document.getElementById('ds-doc-input');
  const dt = new DataTransfer();
  dt.items.add(new File([bytes], 'zegel-proef.pdf', { type: 'application/pdf' }));
  input.files = dt.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  for (let i = 0; i < 400 && (document.getElementById('step-place').hidden || !document.querySelector('#ds-pdf-canvas-list .ds-page-wrap canvas')); i++) await sleep(25);
  const wrap = document.querySelector('#ds-pdf-canvas-list .ds-page-wrap');
  const settled = () => wrap.querySelector('canvas').width > 400 && Math.abs(wrap.querySelector('canvas').getBoundingClientRect().width - parseFloat(wrap.style.width || '0')) < 2;
  for (let i = 0; i < 400 && !settled(); i++) await sleep(25);
  await sleep(200);
  const rect = wrap.querySelector('canvas').getBoundingClientRect();
  wrap.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: rect.left + rect.width / 2, clientY: rect.top + rect.height / 2 }));
  for (let i = 0; i < 100 && !wrap.querySelector('.ds-stamp-marker'); i++) await sleep(25);
  const marker = wrap.querySelector('.ds-stamp-marker');
  if (!marker) return { error: 'geen zegel geplaatst' };
  const ratio = 595.28 / rect.width;
  const mr = marker.getBoundingClientRect();
  const stamp = { pageIndex: 0, x: (mr.left - rect.left) * ratio, y: 841.89 - (mr.bottom - rect.top) * ratio, w: mr.width * ratio, h: mr.height * ratio };
  const markerBg = getComputedStyle(marker).backgroundColor;

  const mod = await import(document.querySelector('script[src*="sign-flow.js"]').getAttribute('src'));
  const out = await mod.buildStampedPdf(bytes, stamp, 'Sandeep G. Prasad', '2026-10-04T12:00:00Z', '0a1b2c3d4e5f6071');

  const SCALE = 2;
  const render = async (b) => {
    const doc = await window.pdfjsLib.getDocument({ data: new Uint8Array(b) }).promise;
    const p = await doc.getPage(1);
    const vp = p.getViewport({ scale: SCALE });
    const c = document.createElement('canvas');
    c.width = Math.round(vp.width); c.height = Math.round(vp.height);
    await p.render({ canvasContext: c.getContext('2d'), viewport: vp }).promise;
    return c.getContext('2d').getImageData(0, 0, c.width, c.height);
  };
  const a = await render(bytes), b = await render(out);
  // The inside of the seal, a band clear of its outline.
  const x0 = Math.ceil((stamp.x + 4) * SCALE), x1 = Math.floor((stamp.x + stamp.w - 4) * SCALE);
  const y0 = Math.ceil((841.89 - stamp.y - stamp.h + 4) * SCALE), y1 = Math.floor((841.89 - stamp.y - 4) * SCALE);
  let textPx = 0, stillDark = 0;
  for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) {
    const i = (y * a.width + x) * 4;
    if (a.data[i] < 110) { textPx++; if (b.data[i] < 200 || b.data[i + 2] < 200) stillDark++; }
  }
  return { stamp, markerBg, textPx, stillDark };
});

test('het standaardzegel is klein en laat de tekst eronder zien', () => {
  assert.ok(!r.error, r.error);
  assert.ok(r.stamp.w / 595.28 <= 0.3, `zegel ${r.stamp.w.toFixed(0)} pt breed is ${(100 * r.stamp.w / 595.28).toFixed(0)}% van de pagina`);
  assert.ok(r.textPx > 500, `er staat tekst onder het zegel (${r.textPx} px)`);
  const kept = r.stillDark / r.textPx;
  assert.ok(kept >= 0.85, `van de tekst onder het zegel is ${(100 * kept).toFixed(0)}% nog zichtbaar`);
});

test('het zegel op het scherm is net zo doorzichtig als in de pdf', () => {
  assert.match(r.markerBg, /rgba\(0, 0, 0, 0\)|transparent/, `achtergrond van het zegel op het scherm: ${r.markerBg}`);
});
