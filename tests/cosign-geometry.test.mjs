// WYSIWYS on /co-sign for pages that are turned or cropped: every party's
// signature, paraaf, date and drawn ink lands in the signed PDF on the spot the
// preview showed, upright, within 1% of the page.
//
// /sign got this in fix/sign-plaatsing-en-fouten (tests/sign-geometry.test.mjs):
// a spot is a fraction of the page as pdf.js SHOWS it (the visible box, turned
// by /Rotate), and the bake has to map that view onto the PDF's own space. The
// co-sign bake (buildSignedPdf) still drew in the unturned MediaBox, so on
// /Rotate 90/180/270 and on a CropBox not at 0,0 the marks landed elsewhere and
// sideways. The free-spot seed read the text layer in the PDF's own space too,
// against the view size, so on a turned page it judged the wrong axis.
//
// Real Chromium (or WebKit through ~/bin/pw-webkit.sh), the real co-sign.js,
// network stubbed; same harness as tests/cosign-paraaf-margin.test.mjs. The
// signed PDF is rendered with pdf.js and the pixels and text are measured.
// Run: node --test tests/cosign-geometry.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.woff2':'font/woff2','.ttf':'font/ttf' };
const TOL = 0.01;   // 1% of the page, in each direction

const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/__proof') { res.writeHead(200, { 'content-type':'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>proof</title>'); }
  if (p === '/co-sign') p = '/co-sign.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

const TOKEN = 't'.repeat(43);
const LABEL = 'Sandeep G. Prasad';
const SIGNED_AT = '2026-10-04T12:00:00.000Z';
let envSeq = 0;

// Build the PDF in the page, encrypt it as the sender would, and open /co-sign
// on it with the relay and the account stubbed.
async function openCosign(spec) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  const envelopeId = 'env_demo_cosigngeometry' + String(++envSeq).padStart(3, '0');
  await page.goto(ORIGIN + '/__proof');
  await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
  const fixture = await page.evaluate(async ({ envelopeId, spec }) => {
    const pqc = await import('/vendor/paramant-pqc.js');
    const delivery = await import('/js/parasign-document-capsule.js?v=2');
    const { PDFDocument, StandardFonts, degrees } = window.PDFLib;
    const pdf = await PDFDocument.create();
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    for (const p of spec.pages) {
      const pg = pdf.addPage(p.size || [595.28, 841.89]);
      if (p.mediaBox) pg.setMediaBox(...p.mediaBox);
      // Short lines on the right of the paper: on a page turned 90 clockwise
      // that is the BOTTOM of the page as it is shown.
      if (p.rightText) for (let y = 800; y >= 40; y -= 14) pg.drawText('Artikel 7. Partijen', { x: 470, y, size: 10, font });
      if (p.cropBox) pg.setCropBox(...p.cropBox);
      if (p.rotate) pg.setRotation(degrees(p.rotate));
    }
    const bytes = new Uint8Array(await pdf.save());
    const docHash = Array.from(pqc.sha3_256(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
    const out = await delivery.encryptDocumentCapsule({ bytes, filename: 'geometrie.pdf', mime: 'application/pdf', envelopeId, docHash });
    return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash };
  }, { envelopeId, spec });

  await page.route('https://health.paramant.app/v2/envelopes/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/view')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ envelope: {
      id: envelopeId, doc_hash: fixture.docHash, original_filename: 'geometrie.pdf', recipe_version: 5,
      created_at: '2026-10-04T12:00:00.000Z', expires_at: '2026-11-03T12:00:00.000Z',
      status: 'sent', signed_count: 0, party_count: 1, parties: [{ index: 0, label: LABEL, status: 'pending' }],
    } }) });
  });
  await page.route(`**/api/user/envelopes/${envelopeId}/document*`, (route) => route.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fixture.capsule) }));
  await page.route('**/api/user/account', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"email":"demo@example.com"}' }));
  await page.goto(`${ORIGIN}/co-sign?env=${envelopeId}&p=0&t=${TOKEN}${fixture.fragment}`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction((n) => document.querySelectorAll('.doc-page[data-page-index]').length === n && !document.querySelector('#sign-confirm')?.disabled, spec.pages.length, { timeout: 30000 });
  return page;
}

// Bake with a drawn signature, then render every signed page with pdf.js and
// measure: the bounding box of the blue ink, of everything that is not white,
// and the text items, all as fractions of the page AS SHOWN (y from the top).
async function bakeAndMeasure(page, appearance, inkRegion) {
  return page.evaluate(async ({ appearance, signedAt, inkRegion }) => {
    // A signature drawn on the pad: one stroke, wider than high.
    const pad = document.getElementById('ink-pad');
    const radio = document.querySelector('input[name="ink-style"][value="draw"]');
    if (radio) { radio.checked = true; radio.dispatchEvent(new Event('change', { bubbles: true })); }
    pad.__pad.drawStrokes([[{ x: 10, y: 60 }, { x: 60, y: 20 }, { x: 110, y: 80 }, { x: 160, y: 25 }, { x: 210, y: 70 }, { x: 260, y: 40 }]]);
    const mod = await import(document.querySelector('script[src*="co-sign.js"]').getAttribute('src'));
    const out = await mod.buildSignedPdf({ appearance, signed_at: signedAt });
    const doc = await window.pdfjsLib.getDocument({ data: out }).promise;
    const pages = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const pg = await doc.getPage(i);
      const vp1 = pg.getViewport({ scale: 1 });
      const vp = pg.getViewport({ scale: 2 });
      const c = document.createElement('canvas');
      c.width = Math.round(vp.width); c.height = Math.round(vp.height);
      const ctx = c.getContext('2d');
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, c.width, c.height);
      await pg.render({ canvasContext: ctx, viewport: vp }).promise;
      const d = ctx.getImageData(0, 0, c.width, c.height).data;
      const boxes = {};
      const grow = (k, x, y) => { const b = boxes[k]; if (!b) boxes[k] = { x0: x, y0: y, x1: x, y1: y }; else { if (x < b.x0) b.x0 = x; if (x > b.x1) b.x1 = x; if (y < b.y0) b.y0 = y; if (y > b.y1) b.y1 = y; } };
      for (let y = 0; y < c.height; y++) for (let x = 0; x < c.width; x++) {
        const o = (y * c.width + x) * 4, r = d[o], g = d[o + 1], b = d[o + 2];
        // The ink colour #1D4ED8 (29, 78, 216), antialiased towards white.
        const blue = b > 150 && b - r > 70 && b - g > 50;
        const fx = x / c.width, fy = y / c.height;
        const region = inkRegion.find((q) => fx >= q.x0 && fx <= q.x1 && fy >= q.y0 && fy <= q.y1);
        if (blue) grow(region ? 'blue_' + region.name : 'blue_elsewhere', x, y);
        if (r < 235 || g < 235 || b < 235) grow(region ? 'ink_' + region.name : 'ink_elsewhere', x, y);
      }
      const frac = (b) => b && { x: b.x0 / c.width, y: b.y0 / c.height, w: (b.x1 - b.x0 + 1) / c.width, h: (b.y1 - b.y0 + 1) / c.height };
      const out = {};
      for (const k of Object.keys(boxes)) out[k] = frac(boxes[k]);
      const texts = (await pg.getTextContent()).items.filter((it) => it.str.trim()).map((it) => {
        const m = window.pdfjsLib.Util.transform(vp1.transform, it.transform);
        return { str: it.str, x: m[4] / vp1.width, y: m[5] / vp1.height, dirX: m[0], dirY: m[1] };
      });
      pages.push({ view: { w: vp1.width, h: vp1.height }, rotate: pg.rotate, boxes: out, texts });
    }
    return pages;
  }, { appearance, signedAt: SIGNED_AT, inkRegion });
}

const near = (a, b, what) => assert.ok(Math.abs(a - b) <= TOL, `${what}: signed ${a.toFixed(4)} vs shown ${b.toFixed(4)} (off by ${(Math.abs(a - b) * 100).toFixed(2)}%)`);
const within = (box, f, what) => {
  assert.ok(box, `${what}: nothing found where it was shown`);
  assert.ok(box.x >= f.x - TOL && box.y >= f.y - TOL && box.x + box.w <= f.x + f.w + TOL && box.y + box.h <= f.y + f.h + TOL,
    `${what}: drawn at ${JSON.stringify(box)} outside the shown box ${JSON.stringify(f)}`);
};

// The spots, as the preview and the manifest hold them: fractions of the
// shown page, y from the top.
const SIG = { type: 'seal', page_index: 1, x: 0.12, y: 0.30, w: 0.34, h: 0.10 };
const PAR = { type: 'seal', page_index: 0, x: 0.76, y: 0.90, w: 0.16, h: 0.045, all_pages: true };
const DATE = { type: 'date', page_index: 1, x: 0.60, y: 0.32, w: 0.16, h: 0.03 };
const APPEARANCE = { version: 2, fields: [SIG, PAR, DATE] };
// Measuring regions: a margin of 3% round each shown box, so the blue of the
// signature and of the paraaf is told apart; anything outside is 'elsewhere'.
const pad = (f, name) => ({ name, x0: f.x - 0.03, y0: f.y - 0.03, x1: f.x + f.w + 0.03, y1: f.y + f.h + 0.03 });
const REGIONS = [pad(SIG, 'sig'), pad(PAR, 'par'), pad(DATE, 'date')];

function checkSigned(m, label) {
  assert.equal(m.length, 2, `${label}: two pages`);
  for (let i = 0; i < 2; i++) {
    const b = m[i].boxes;
    assert.equal(b.blue_elsewhere, undefined, `${label} p${i + 1}: ink drawn where nothing was shown: ${JSON.stringify(b.blue_elsewhere)}`);
    assert.equal(b.ink_elsewhere, undefined, `${label} p${i + 1}: marks drawn where nothing was shown: ${JSON.stringify(b.ink_elsewhere)}`);
    // The paraaf on every page: the drawn mark inside its box, centred, and
    // the hairline under it at 84% of the box height.
    within(b.blue_par, PAR, `${label} p${i + 1} paraaf ink`);
    near(b.blue_par.x + b.blue_par.w / 2, PAR.x + PAR.w / 2, `${label} p${i + 1} paraaf centre x`);
    within(b.ink_par, PAR, `${label} p${i + 1} paraaf`);
    near(b.ink_par.x + b.ink_par.w / 2, PAR.x + PAR.w / 2, `${label} p${i + 1} paraaf centre`);
    near(b.ink_par.y + b.ink_par.h, PAR.y + PAR.h * 0.84, `${label} p${i + 1} paraaf hairline`);
  }
  const p = m[1], b = p.boxes;
  // The signature: drawn ink in the top 60% of the box, centred; the line and
  // the caption span the whole width.
  within(b.blue_sig, { x: SIG.x, y: SIG.y, w: SIG.w, h: SIG.h * 0.62 }, `${label} signature ink`);
  near(b.blue_sig.x + b.blue_sig.w / 2, SIG.x + SIG.w / 2, `${label} signature centre x`);
  within(b.ink_sig, SIG, `${label} signature`);
  near(b.ink_sig.x, SIG.x, `${label} signature left edge`);
  near(b.ink_sig.x + b.ink_sig.w, SIG.x + SIG.w, `${label} signature right edge`);
  // Upright: the caption reads left to right, sits under the ink, at the left
  // edge of the box.
  const cap = p.texts.find((t) => t.str.startsWith(LABEL));
  assert.ok(cap, `${label}: the caption is in the signed PDF`);
  assert.ok(cap.dirX > 0 && Math.abs(cap.dirY) < 1e-6, `${label}: the caption runs sideways (${cap.dirX}, ${cap.dirY})`);
  near(cap.x, SIG.x, `${label} caption x`);
  assert.ok(cap.y > b.blue_sig.y + b.blue_sig.h && cap.y <= SIG.y + SIG.h + TOL, `${label}: the caption is not under the ink (caption ${cap.y.toFixed(3)}, ink bottom ${(b.blue_sig.y + b.blue_sig.h).toFixed(3)})`);
  // The date: its text at the left of its box, baseline in the box, upright.
  const date = p.texts.find((t) => t.str === SIGNED_AT.slice(0, 10));
  assert.ok(date, `${label}: the date is in the signed PDF`);
  assert.ok(date.dirX > 0 && Math.abs(date.dirY) < 1e-6, `${label}: the date runs sideways`);
  near(date.x, DATE.x + 2 / p.view.w, `${label} date x`);
  assert.ok(date.y >= DATE.y - TOL && date.y <= DATE.y + DATE.h + TOL, `${label}: date baseline ${date.y.toFixed(3)} outside its box`);
}

const A4 = [595.28, 841.89];
const cases = [
  ['rotate-0', { size: A4 }],
  ['rotate-90', { size: A4, rotate: 90 }],
  ['rotate-180', { size: A4, rotate: 180 }],
  ['rotate-270', { size: A4, rotate: 270 }],
  ['cropbox-offset', { size: A4, cropBox: [50, 80, 450, 650] }],
  ['mediabox-origin', { size: A4, mediaBox: [-100, -100, 595.28, 841.89] }],
  ['rotate-270-cropbox', { size: A4, cropBox: [40, 60, 500, 700], rotate: 270 }],
];
for (const [label, pg] of cases) {
  test(`${label}: signature, paraaf, date and drawn ink land where /co-sign showed them, upright`, async () => {
    const page = await openCosign({ pages: [pg, pg] });
    const m = await bakeAndMeasure(page, APPEARANCE, REGIONS);
    checkSigned(m, label);
    await page.close();
  });
}

test('mixed pages: a turned page between plain ones keeps every mark in place', async () => {
  const page = await openCosign({ pages: [{ size: A4, rotate: 90 }, { size: A4, rotate: 180, cropBox: [30, 40, 520, 760] }] });
  checkSigned(await bakeAndMeasure(page, APPEARANCE, REGIONS), 'mixed');
  await page.close();
});

test('the suggested spot on a turned page is judged on the page as shown: not on the text', async () => {
  // Text on the right of the paper is the BOTTOM of a page turned 90
  // clockwise. Read in the PDF's own space against the shown size, it looked
  // like a column in the middle, and the seed went to the bottom left: on it.
  const page = await openCosign({ pages: [{ size: A4, rotate: 90, rightText: true }] });
  await page.waitForFunction(() => document.querySelector('.doc-page[data-page-index="0"] .appearance-field.seal'), null, { timeout: 10000 });
  const r = await page.evaluate(async () => {
    const wrap = document.querySelector('.doc-page[data-page-index="0"]');
    const node = wrap.querySelector('.appearance-field.seal');
    const pct = (v) => parseFloat(v) / 100;
    const seed = { x: pct(node.style.left), y: pct(node.style.top), w: pct(node.style.width), h: pct(node.style.height) };
    const canvas = wrap.querySelector('canvas');
    const ratio = canvas.width / canvas.height;
    return { seed, ratio };
  });
  assert.ok(r.ratio > 1.3, `the turned page is shown wide (ratio ${r.ratio.toFixed(2)})`);
  // The text (x 470..~545 on the paper) runs from 79% to 92% of the shown
  // height, across the whole width, so the usual spot at the bottom left is
  // taken. The suggestion has to go above it.
  assert.ok(r.seed.y + r.seed.h <= 0.79 + TOL, `the suggested signature sits on the text at the bottom of the shown page: ${JSON.stringify(r.seed)}`);
  await page.close();
});
