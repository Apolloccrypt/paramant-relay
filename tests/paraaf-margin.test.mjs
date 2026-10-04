// "Sign every page" on /sign, end to end in Chromium: the real buildStampedPdf
// on a real three-page PDF that is text from margin to margin on pages 1 and 2
// and has a free signature line on page 3.
//
// Customer report 2026-10-04: "Het plaatst de paraaf random op de tekst." The
// old code put the full seal on pages 1 and 2 at the same spot as on page 3,
// which is the middle of the body text there. This suite holds the baked PDF
// and the on-screen preview to the fix:
//   - page 3 keeps the seal where the signer put it;
//   - pages 1 and 2 get a paraaf (initials, no seal), smaller than the seal;
//   - the paraaf does not overlap any text of the source page;
//   - the preview shows the paraaf on exactly the spot that is baked.
//
// The pure placement is tests/paraaf-place.test.mjs.
// Run: node --test tests/paraaf-margin.test.mjs
// Local: PLAYWRIGHT_CHROMIUM_PATH=<chrome binary> node --test tests/paraaf-margin.test.mjs
// PARAMANT_PARAAF_SHOT_DIR=<dir> also writes the baked pages and the preview as PNG, for
// a look with your own eyes.
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
const PNG_DIR = process.env.PARAMANT_PARAAF_SHOT_DIR || '';
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

const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
const page = await context.newPage();
await page.route('**/api/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' }));
await page.goto(`${ORIGIN}/sign.html?mode=alone`, { waitUntil: 'domcontentloaded' });
await loadPdfLibs(page);

const SEAL = { pageIndex: 2, x: 300, y: 130, w: 240, h: 100 };

// Build the source, pick it, tick "sign every page", place the seal on page 3
// by clicking the free line, and bake through the module instance the page
// itself loaded.
const r = await page.evaluate(async ({ SEAL, wantPng }) => {
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  for (let i = 0; i < 400 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
  const { PDFDocument, StandardFonts } = window.PDFLib;
  const src = await PDFDocument.create();
  const font = await src.embedFont(StandardFonts.TimesRoman);
  const line = 'Artikel 4. Partijen komen overeen dat de dienstverlening wordt uitgevoerd volgens de voorwaarden.';
  for (let p = 0; p < 3; p++) {
    const pg = src.addPage([595.28, 841.89]);
    // Pages 1 and 2: body text from the top margin to the bottom margin.
    // Page 3: text in the top half, then a free signature line.
    const lowest = p < 2 ? 60 : 420;
    for (let y = 780; y >= lowest; y -= 14) pg.drawText(line, { x: 56, y, size: 10.5, font });
    if (p === 0) pg.drawText('Pagina 1 van 3', { x: 500, y: 30, size: 8, font });   // a page number bottom right
    if (p === 2) pg.drawText('Handtekening:', { x: 56, y: 180, size: 11, font });
  }
  const bytes = await src.save();

  const input = document.getElementById('ds-doc-input');
  const dt = new DataTransfer();
  dt.items.add(new File([bytes], 'paraaf-proef.pdf', { type: 'application/pdf' }));
  input.files = dt.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  for (let i = 0; i < 400 && (document.getElementById('step-place').hidden || document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap').length < 3); i++) await sleep(25);
  const wraps = document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap');
  if (wraps.length < 3) return { error: 'place step did not render three pages' };
  // Wait until every page is drawn at its final size: a click measured against
  // a canvas still at its 300x150 default lands somewhere else entirely.
  const settled = () => [...wraps].every((w) => w.querySelector('canvas').width > 400 && Math.abs(w.querySelector('canvas').getBoundingClientRect().width - parseFloat(w.style.width || '0')) < 2);
  for (let i = 0; i < 400 && !settled(); i++) await sleep(25);
  await sleep(200);

  const cb = document.getElementById('ds-allpages');
  cb.checked = true;
  cb.dispatchEvent(new Event('change', { bubbles: true }));
  // Click the centre of the seal box on page 3 (PDF points -> CSS px).
  const w3 = wraps[2];
  const rect = w3.querySelector('canvas').getBoundingClientRect();
  const ratio = 595.28 / rect.width;
  const cx = rect.left + (SEAL.x + SEAL.w / 2) / ratio;
  const cy = rect.top + (841.89 - SEAL.y - SEAL.h / 2) / ratio;
  w3.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: cx, clientY: cy }));
  for (let i = 0; i < 200 && document.querySelectorAll('.ds-paraaf').length < 2; i++) await sleep(25);

  // The seal the click produced, read back from its marker (CSS px -> points).
  const marker = w3.querySelector('.ds-stamp-marker');
  const mr = marker.getBoundingClientRect();
  const stamp = { pageIndex: 2, x: (mr.left - rect.left) * ratio, y: 841.89 - (mr.bottom - rect.top) * ratio, w: mr.width * ratio, h: mr.height * ratio };

  // The preview paraafs, CSS px -> points, per page.
  const preview = [];
  wraps.forEach((wrap, i) => {
    const cr = wrap.querySelector('canvas').getBoundingClientRect();
    const k = 595.28 / cr.width;
    for (const el of wrap.querySelectorAll('.ds-paraaf')) {
      const b = el.getBoundingClientRect();
      preview.push({ pageIndex: i, x: (b.left - cr.left) * k, y: 841.89 - (b.bottom - cr.top) * k, w: b.width * k, h: b.height * k, text: el.textContent });
    }
  });

  const mod = await import(document.querySelector('script[src*="sign-flow.js"]').getAttribute('src'));
  const out = await mod.buildStampedPdf(bytes, stamp, 'Sandeep G. Prasad', '2026-10-04T12:00:00Z', '0a1b2c3d4e5f6071');
  const plan = mod.lastParaafPlan();

  // Read both PDFs back with pdf.js: source text boxes, and what was drawn.
  const boxesOf = (items) => items.filter((it) => it.str.trim()).map((it) => {
    const [a, b, c, d, e, f] = it.transform; const fs = Math.hypot(c, d);
    return { x: e, y: f - 0.25 * fs, w: it.width, h: 1.25 * fs, str: it.str };
  });
  const srcDoc = await window.pdfjsLib.getDocument({ data: new Uint8Array(bytes) }).promise;
  const outDoc = await window.pdfjsLib.getDocument({ data: new Uint8Array(out) }).promise;
  const pages = [];
  const pngs = [];
  for (let i = 1; i <= 3; i++) {
    const sp = await srcDoc.getPage(i), op = await outDoc.getPage(i);
    const srcItems = (await sp.getTextContent()).items;
    const outItems = (await op.getTextContent()).items;
    const srcStrs = new Set(srcItems.map((it) => it.str));
    pages.push({
      srcBoxes: boxesOf(srcItems),
      added: boxesOf(outItems).filter((b) => !srcStrs.has(b.str)),
      text: outItems.map((it) => it.str).join(' '),
    });
    if (wantPng) {
      const vp = op.getViewport({ scale: 2 });
      const canvas = document.createElement('canvas');
      canvas.width = vp.width; canvas.height = vp.height;
      await op.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise;
      pngs.push(canvas.toDataURL('image/png'));
    }
  }
  return { stamp, preview, plan, pages, pngs };
}, { SEAL, wantPng: !!PNG_DIR });

if (PNG_DIR && r.pngs) {
  fs.mkdirSync(PNG_DIR, { recursive: true });
  r.pngs.forEach((u, i) => fs.writeFileSync(path.join(PNG_DIR, `gebakken-p${i + 1}.png`), Buffer.from(u.split(',')[1], 'base64')));
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap').nth(0).screenshot({ path: path.join(PNG_DIR, 'voorbeeld-p1.png') });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap').nth(2).screenshot({ path: path.join(PNG_DIR, 'voorbeeld-p3.png') });
}

// The review step: the last thing the signer sees before Sign. Walk there the
// way a person does (Continue, name, Continue) and read the paraafs back.
await page.click('#ds-place-continue');
await page.fill('#ds-signer-name', 'Sandeep G. Prasad');
await page.locator('#ds-signer-name').dispatchEvent('input');
await page.click('#ds-identity-continue', { timeout: 10000 }).catch(() => {});
const review = await page.evaluate(async () => {
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  for (let i = 0; i < 400 && document.querySelectorAll('.ds-mockup-paraaf').length < 2; i++) await sleep(25);
  const out = [];
  for (const el of document.querySelectorAll('.ds-mockup-paraaf')) {
    const wrap = el.parentElement;
    const cr = wrap.querySelector('canvas').getBoundingClientRect();
    const k = 595.28 / cr.width;
    const b = el.getBoundingClientRect();
    const idx = [...wrap.parentElement.children].filter((c) => c.querySelector && c.querySelector('canvas')).indexOf(wrap);
    out.push({ pageIndex: idx, x: (b.left - cr.left) * k, y: 841.89 - (b.bottom - cr.top) * k, w: b.width * k, h: b.height * k, text: el.textContent });
  }
  return out;
});
if (PNG_DIR) {
  const pane = page.locator('.ds-review-pane.has-pdf').first();
  if (await pane.count()) await pane.screenshot({ path: path.join(PNG_DIR, 'controle-stap.png') }).catch(() => {});
}

const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

test('the flow reached the bake', () => {
  assert.equal(r.error, undefined, r.error);
  assert.ok(Array.isArray(r.plan), 'buildStampedPdf left a paraaf plan');
});

test('the click put the seal on the free signature line of page 3', () => {
  for (const k of ['x', 'y']) assert.ok(Math.abs(r.stamp[k] - SEAL[k]) < 15, `seal ${k} ${r.stamp[k].toFixed(1)}, clicked for ${SEAL[k]}`);
  assert.ok(!r.pages[2].srcBoxes.some((t) => overlaps(t, r.stamp)), 'the seal sits on free space on its own page');
});

test('page 3 keeps the full seal, pages 1 and 2 get a paraaf and no seal', () => {
  assert.match(r.pages[2].text, /POST-QUANTUM SIGNED/, 'the seal is on the signing page');
  for (const i of [0, 1]) {
    assert.doesNotMatch(r.pages[i].text, /POST-QUANTUM|ML-DSA-65/, `page ${i + 1} carries a copy of the seal`);
    assert.match(r.pages[i].text, /S\.G\.P\./, `page ${i + 1} has no initials`);
    assert.match(r.pages[i].text, /2026-10-04 · PQ 0a1b2c3d/, `page ${i + 1} has no date and fingerprint line`);
  }
  assert.deepEqual(r.plan.map((b) => b.pageIndex), [0, 1]);
});

test('(a) the paraaf does not overlap any text of the page', () => {
  for (const b of r.plan) {
    const src = r.pages[b.pageIndex].srcBoxes;
    assert.ok(src.length > 10, 'precondition: the page is full of text');
    // The old spot (the seal's, copied) would have hit text: proves the test bites.
    assert.ok(src.some((t) => overlaps(t, r.stamp)), `precondition: the seal spot hits text on page ${b.pageIndex + 1}`);
    for (const t of src) assert.ok(!overlaps(b, t), `paraaf on page ${b.pageIndex + 1} overlaps "${t.str.slice(0, 30)}"`);
    // And what was actually drawn sits inside the planned box.
    for (const a of r.pages[b.pageIndex].added) {
      assert.ok(a.x >= b.x - 0.5 && a.x + a.w <= b.x + b.w + 0.5 && a.y >= b.y - 2 && a.y + a.h <= b.y + b.h + 2,
        `drawn "${a.str}" sits outside the paraaf box on page ${b.pageIndex + 1}`);
    }
  }
  assert.equal(r.plan[0].corner, 'linksonder', 'page 1 has a page number bottom right, so the paraaf moves');
  assert.equal(r.plan[1].corner, 'rechtsonder');
});

test('(b) the paraaf is smaller than the seal', () => {
  for (const b of r.plan) {
    assert.ok(b.w < r.stamp.w && b.h < r.stamp.h, `paraaf ${b.w.toFixed(0)}x${b.h.toFixed(0)} vs seal ${r.stamp.w.toFixed(0)}x${r.stamp.h.toFixed(0)}`);
    assert.ok(b.w / 595.28 < 0.21 && b.h / 841.89 < 0.05);
  }
});

test('WYSIWYS: the preview shows the paraaf on the spot that is baked', () => {
  assert.equal(r.preview.length, 2, 'one preview paraaf on each of the two other pages');
  for (const b of r.plan) {
    const p = r.preview.find((x) => x.pageIndex === b.pageIndex);
    assert.ok(p, `no preview paraaf on page ${b.pageIndex + 1}`);
    for (const k of ['x', 'y', 'w', 'h']) assert.ok(Math.abs(p[k] - b[k]) < 1.5, `page ${b.pageIndex + 1} ${k}: preview ${p[k].toFixed(1)} vs baked ${b[k].toFixed(1)}`);
    assert.match(p.text, /Paraaf/, 'before the identity step the preview says what goes there');
  }
});

test('WYSIWYS: the review step shows the same paraafs, with the initials', () => {
  assert.equal(review.length, 2, 'one paraaf on each of the two other pages in the review');
  for (const b of r.plan) {
    const p = review.find((x) => x.pageIndex === b.pageIndex);
    assert.ok(p, `no review paraaf on page ${b.pageIndex + 1}`);
    for (const k of ['x', 'y', 'w', 'h']) assert.ok(Math.abs(p[k] - b[k]) < 1.5, `page ${b.pageIndex + 1} ${k}: review ${p[k].toFixed(1)} vs baked ${b[k].toFixed(1)}`);
    assert.match(p.text, /S\.G\.P\./);
  }
});
