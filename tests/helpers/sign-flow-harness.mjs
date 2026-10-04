// /sign end to end in Chromium with the server answers stubbed (TOTP path):
// pick a PDF, place, walk to Sign, enter a code, take the downloads. The bake
// is the real buildStampedPdf, so what comes out is what a customer gets.
// Shared by tests/sign-geometry.test.mjs and tests/sign-errors.test.mjs.
// Same stubs as tests/end-screen-calm.test.mjs.
import { chromium, devices } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPdfLibs } from './sign-pdf-libs.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'frontend');
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.wasm': 'application/wasm', '.json': 'application/json', '.ico': 'image/x-icon' };
const ALIAS = { '/sign': '/sign.html', '/en/sign': '/en/sign.html' };

export async function startServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const rel = ALIAS[url.pathname] || decodeURIComponent(url.pathname);
    const file = path.join(ROOT, rel);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, origin: `http://localhost:${server.address().port}` };
}

export async function launch() {
  const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
  return chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
}

const ENV_ID = 'env_demo_abcdefghijklmnop';
const TOKEN = 't'.repeat(43);

// overrides: { activation: (route) => ..., submit: (route) => ... } to make a
// server step fail the way a real relay does.
export async function stubSign(page, overrides = {}) {
  const j = (r, o, s = 200) => r.fulfill({ status: s, contentType: 'application/json', body: typeof o === 'string' ? o : JSON.stringify(o) });
  await page.route('**/api/**', (r) => j(r, '{"ok":true}'));
  await page.route('**/api/user/session/verify', (r) => j(r, { authenticated: true, email: 'demo@example.com' }));
  await page.route('**/api/user/me', (r) => overrides.me ? overrides.me(r, j) : j(r, { email: 'demo@example.com', plan: 'community', plan_parasign: null, plan_parasend: null, paid_until_parasign: null, paid_until_parasend: null }));
  await page.route('**/api/user/account/signing-key/step-up/options', (r) => j(r, '{"error":"no_passkey"}', 409));
  await page.route('**/api/user/account/signing-key', (r) => r.request().method() === 'POST' ? j(r, '{"ok":true,"totp_algorithm":"sha256"}') : j(r, '{"keys":[]}'));
  await page.route('**/api/user/envelopes', async (route) => {
    const b = route.request().postDataJSON();
    const n = (b.recipients || []).length + 1;
    await j(route, { ok: true, envelope: { id: ENV_ID, party_count: n, binding_mode: 'email', expires_at: '2026-10-20T12:00:00.000Z',
      party_links: Array.from({ length: n }, (_, party_index) => ({ party_index, sign_path: `/co-sign?env=${ENV_ID}&p=${party_index}&t=${TOKEN}`, invite_token: TOKEN })) } });
  });
  await page.route('**/api/user/sign/activation', (r) => overrides.activation ? overrides.activation(r, j) : j(r, { activation_id: 'act_demo_0001', email_hash: 'b'.repeat(64), recipe_version: 4 }));
  await page.route('**/api/user/sign/submit', (r) => overrides.submit ? overrides.submit(r, j) : j(r, { ok: true, signed_count: 1, party_count: 1, status: 'complete', appearance_hash: null }));
  for (const host of ['health', 'legal', 'finance', 'iot', 'relay']) await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
}

export async function newPage(browser, { mobile = false, overrides = {}, viewport } = {}) {
  const opts = mobile ? { ...devices['iPhone 13'] } : { viewport: viewport || { width: 1366, height: 900 } };
  delete opts.defaultBrowserType;
  const ctx = await browser.newContext({ ...opts, acceptDownloads: true });
  const page = await ctx.newPage();
  page._errors = [];
  page.on('pageerror', (e) => page._errors.push('pageerror: ' + e.message));
  await stubSign(page, overrides);
  return page;
}

export async function openSign(page, origin, lang = 'nl') {
  await page.goto(`${origin}/${lang === 'en' ? 'en/' : ''}sign?mode=alone`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ds-doc-input').waitFor({ state: 'attached', timeout: 20000 });
}

// A PDF built in the page with its own pdf-lib. spec: { pages: [{ size:[w,h],
// rotate, cropBox:[x,y,w,h], mediaBox:[x,y,w,h], lines: bool }] }.
export async function makePdf(page, spec) {
  await loadPdfLibs(page);
  const b64 = await page.evaluate(async (spec) => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 400 && !window.PDFLib; i++) await sleep(25);
    const { PDFDocument, StandardFonts, degrees, rgb } = window.PDFLib;
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    for (const p of spec.pages) {
      const [w, h] = p.size || [595.28, 841.89];
      const pg = doc.addPage([w, h]);
      if (p.mediaBox) pg.setMediaBox(...p.mediaBox);
      const mb = pg.getMediaBox();
      if (p.lines) {
        for (let y = mb.y + mb.height - 70; y >= mb.y + 70; y -= 14) {
          pg.drawText('Artikel ' + Math.round(y) + '. Partijen komen overeen dat de dienst wordt geleverd.', { x: mb.x + 56, y, size: 10, font, color: rgb(0, 0, 0) });
        }
      }
      if (p.cropBox) pg.setCropBox(...p.cropBox);
      if (p.rotate) pg.setRotation(degrees(p.rotate));
    }
    const bytes = await doc.save();
    let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }, spec);
  return Buffer.from(b64, 'base64');
}

export async function pickBytes(page, bytes, name = 'proef.pdf') {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sign-')), name);
  fs.writeFileSync(file, bytes);
  await page.setInputFiles('#ds-doc-input', file);
}

// Wait until the place step shows n pages, each drawn at its final size.
export async function waitPlaced(page, n) {
  await page.waitForFunction((n) => {
    const wraps = document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap');
    if (document.getElementById('step-place').hidden || wraps.length < n) return false;
    return [...wraps].every((w) => w.querySelector('canvas').width > 400 && Math.abs(w.querySelector('canvas').getBoundingClientRect().width - parseFloat(w.style.width || '0')) < 2);
  }, n, { timeout: 30000 });
  await page.waitForTimeout(200);
}

export async function clickPage(page, idx, fx, fy) {
  const canvas = page.locator(`#ds-pdf-canvas-list .ds-page-wrap[data-page-index="${idx}"] canvas`);
  await canvas.scrollIntoViewIfNeeded();
  let box = await canvas.boundingBox();
  const vh = page.viewportSize().height;
  await page.evaluate((dy) => window.scrollBy(0, dy), box.y + box.height * fy - vh * 0.45);
  await page.waitForTimeout(150);
  box = await canvas.boundingBox();
  await page.mouse.click(box.x + box.width * fx, box.y + box.height * fy);
}

// Every marker on the place step, as fractions of its page canvas.
export async function uiBoxes(page) {
  return page.evaluate(() => {
    const out = [];
    for (const el of document.querySelectorAll('.ds-stamp-marker, .ds-paraaf, .ds-anno')) {
      if (el.hidden) continue;
      const wrap = el.closest('.ds-page-wrap');
      if (!wrap) continue;
      const c = wrap.querySelector('canvas').getBoundingClientRect();
      const r = el.getBoundingClientRect();
      const kind = el.classList.contains('ds-paraaf') ? 'paraaf' : el.classList.contains('ds-anno') ? el.dataset.type : 'seal';
      out.push({ kind, page: Number(wrap.dataset.pageIndex), x: (r.left - c.left) / c.width, y: (r.top - c.top) / c.height, w: r.width / c.width, h: r.height / c.height, text: el.textContent });
    }
    return out;
  });
}

// From the place step to a downloaded PDF. Returns { pdf: Buffer } or { error }.
export async function signAndDownload(page, { name = 'Sandeep Test' } = {}) {
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-signer-name').fill(name);
  await page.locator('#ds-signer-name').dispatchEvent('input');
  await page.locator('#ds-identity-continue').click();
  await page.locator('#step-sign:not([hidden])').waitFor({ timeout: 20000 });
  return signNow(page);
}

export async function signNow(page) {
  await page.locator('#ds-sign-now').click();
  await page.locator('#ds-pass-panel:not([hidden]), #ds-sign-status.err').first().waitFor({ timeout: 60000 });
  if (await page.locator('#ds-pass-panel:not([hidden])').count()) {
    await page.locator('#ds-pass-input').fill('123456');
    await page.locator('#ds-pass-confirm').click();
  }
  const done = page.locator('#step-done:not([hidden])');
  const err = page.locator('#ds-sign-status.err');
  await Promise.race([done.waitFor({ timeout: 120000 }), err.waitFor({ timeout: 120000 })]);
  if (await err.count() && await err.isVisible()) return { error: (await err.textContent()).trim() };
  const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 60000 }), page.locator('#ds-dl-pdf').click()]);
  const p = await dl.path();
  return { pdf: fs.readFileSync(p) };
}

// Render a PDF in the page with pdf.js and measure, per page and as fractions
// of the page AS SHOWN (view space): the navy box (seal or paraaf), the
// highlight, the note edge, and where each added text item sits and which way
// it runs. pngScale > 0 also returns PNG data URLs.
export async function measurePdf(page, pdf, pngScale = 0) {
  await loadPdfLibs(page);
  return page.evaluate(async ({ b64, pngScale }) => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 400 && !window.pdfjsLib; i++) await sleep(25);
    const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const doc = await window.pdfjsLib.getDocument({ data: bin }).promise;
    const out = [];
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
      const boxes = { navy: null, highlight: null, noteEdge: null };
      const grow = (k, x, y) => { const b = boxes[k]; if (!b) boxes[k] = { x0: x, y0: y, x1: x, y1: y }; else { if (x < b.x0) b.x0 = x; if (x > b.x1) b.x1 = x; if (y < b.y0) b.y0 = y; if (y > b.y1) b.y1 = y; } };
      for (let y = 0; y < c.height; y++) for (let x = 0; x < c.width; x++) {
        const o = (y * c.width + x) * 4, r = d[o], g = d[o + 1], b = d[o + 2];
        if (Math.abs(r - 11) < 28 && Math.abs(g - 58) < 28 && Math.abs(b - 106) < 28) grow('navy', x, y);
        else if (r > 245 && g > 225 && g < 252 && b > 160 && b < 210) grow('highlight', x, y);
        else if (Math.abs(r - 212) < 20 && Math.abs(g - 179) < 20 && Math.abs(b - 51) < 25) grow('noteEdge', x, y);
      }
      const frac = (b) => b && { x: b.x0 / c.width, y: b.y0 / c.height, w: (b.x1 - b.x0 + 1) / c.width, h: (b.y1 - b.y0 + 1) / c.height };
      // Upright: the seal's band is navy on top, the body below it is mostly white.
      let bandTop = null;
      if (boxes.navy) {
        const b = boxes.navy, rows = (y0, y1) => { let n = 0, t = 0; for (let y = y0; y <= y1; y++) for (let x = b.x0; x <= b.x1; x++) { const o = (y * c.width + x) * 4; t++; if (Math.abs(d[o] - 11) < 28 && Math.abs(d[o + 1] - 58) < 28 && Math.abs(d[o + 2] - 106) < 28) n++; } return n / Math.max(1, t); };
        const hh = b.y1 - b.y0;
        bandTop = { top: rows(b.y0 + 2, b.y0 + Math.max(3, Math.floor(hh * 0.12))), bottom: rows(b.y1 - Math.max(3, Math.floor(hh * 0.12)), b.y1 - 2), left: 0 };
      }
      const texts = (await pg.getTextContent()).items.filter((it) => it.str.trim()).map((it) => {
        const m = window.pdfjsLib.Util.transform(vp1.transform, it.transform);
        return { str: it.str, x: m[4] / vp1.width, y: m[5] / vp1.height, dirX: m[0], dirY: m[1] };
      });
      out.push({ view: { w: vp1.width, h: vp1.height }, rotate: pg.rotate, navy: frac(boxes.navy), highlight: frac(boxes.highlight), noteEdge: frac(boxes.noteEdge), bandTop, texts, png: pngScale ? c.toDataURL('image/png') : null });
    }
    return out;
  }, { b64: pdf.toString('base64'), pngScale });
}

export function savePngs(dir, prefix, measured) {
  if (!dir) return;
  fs.mkdirSync(dir, { recursive: true });
  measured.forEach((m, i) => { if (m.png) fs.writeFileSync(path.join(dir, `${prefix}-p${i + 1}.png`), Buffer.from(m.png.split(',')[1], 'base64')); });
}
