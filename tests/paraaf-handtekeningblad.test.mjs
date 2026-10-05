// Acceptatie r4, Nieuw 2: "Onderteken elke pagina" together with "Voeg een
// apart handtekeningblad toe" gave a pdf without a single paraaf, and nothing
// said so. Choosing the sheet switched "every page" off in silence and hid the
// box. The sheet is for the signature; the parafen still go on every page of
// the document. This suite walks /sign the way a person does (tick every page,
// choose the sheet), bakes through the page's own buildStampedPdf, and reads
// the pdf back.
// Run: node --test tests/paraaf-handtekeningblad.test.mjs
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
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.woff2':'font/woff2' };

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

const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
await page.route('**/api/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' }));
await page.goto(`${ORIGIN}/sign.html?mode=alone`, { waitUntil: 'domcontentloaded' });
await loadPdfLibs(page);

const r = await page.evaluate(async () => {
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  for (let i = 0; i < 400 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
  const { PDFDocument, StandardFonts } = window.PDFLib;
  const src = await PDFDocument.create();
  const font = await src.embedFont(StandardFonts.TimesRoman);
  for (let p = 0; p < 3; p++) {
    const pg = src.addPage([595.28, 841.89]);
    for (let y = 780; y >= 200; y -= 14) pg.drawText('Artikel ' + (p + 1) + '. De partijen komen het volgende overeen.', { x: 56, y, size: 10.5, font });
  }
  const bytes = await src.save();
  const input = document.getElementById('ds-doc-input');
  const dt = new DataTransfer();
  dt.items.add(new File([bytes], 'blad-proef.pdf', { type: 'application/pdf' }));
  input.files = dt.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  for (let i = 0; i < 400 && (document.getElementById('step-place').hidden || document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap').length < 3); i++) await sleep(25);
  if (document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap').length < 3) return { error: 'place step did not render three pages' };

  // The order a person takes: every page first, then the sheet.
  const cb = document.getElementById('ds-allpages');
  cb.checked = true;
  cb.dispatchEvent(new Event('change', { bubbles: true }));
  const sheet = document.getElementById('ds-seal-sheet');
  sheet.checked = true;
  sheet.dispatchEvent(new Event('change', { bubbles: true }));
  await sleep(300);
  const ui = {
    stillTicked: cb.checked,
    boxUsable: !cb.disabled && !document.getElementById('ds-allpages-label').hidden,
    tip: (document.getElementById('ds-seal-tip') || {}).textContent || '',
  };
  for (let i = 0; i < 200 && document.querySelectorAll('.ds-stamp-ghost.ds-paraaf').length < 3; i++) await sleep(25);
  ui.previewParafen = document.querySelectorAll('.ds-stamp-ghost.ds-paraaf').length;

  const mod = await import(document.querySelector('script[src*="sign-flow.js"]').getAttribute('src'));
  const out = await mod.buildStampedPdf(bytes, null, 'Sandeep G. Prasad', '2026-10-05T12:00:00Z', '0a1b2c3d4e5f6071');
  const doc = await window.pdfjsLib.getDocument({ data: new Uint8Array(out) }).promise;
  const texts = [];
  for (let i = 1; i <= doc.numPages; i++) texts.push((await (await doc.getPage(i)).getTextContent()).items.map((it) => it.str).join(' '));
  return { ui, numPages: doc.numPages, texts, plan: mod.lastParaafPlan() };
});

test('the flow reached the bake', () => {
  assert.equal(r.error, undefined, r.error);
});

test('choosing the sheet keeps "every page" on, usable, and says where the parafen go', () => {
  assert.equal(r.ui.stillTicked, true, 'the sheet must not switch "every page" off in silence');
  assert.equal(r.ui.boxUsable, true, 'the box stays visible and usable with a sheet');
  assert.match(r.ui.tip, /elke pagina van het document krijgt uw paraaf/, r.ui.tip);
  assert.equal(r.ui.previewParafen, 3, 'the place step shows a paraaf on each of the three pages');
});

test('the pdf has a paraaf on every page of the document and the signature on the sheet', () => {
  assert.equal(r.numPages, 4, 'three pages plus the signature sheet');
  for (const i of [0, 1, 2]) {
    assert.match(r.texts[i], /S\.G\.P\./, `page ${i + 1} has no paraaf`);
    assert.doesNotMatch(r.texts[i], /POST-QUANTUM|ML-DSA-65/, `page ${i + 1} carries a seal; the signature belongs on the sheet`);
  }
  assert.match(r.texts[3], /ParaSign-handtekeningblad/);
  assert.match(r.texts[3], /ML-DSA-65/, 'the signature is on the sheet');
  assert.doesNotMatch(r.texts[3], /S\.G\.P\./, 'the sheet itself gets no paraaf');
  assert.deepEqual((r.plan || []).map((b) => b.pageIndex), [0, 1, 2]);
});
