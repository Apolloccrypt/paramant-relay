// /co-sign "Repeat on every page": ticking it puts the seal small in a free
// margin corner, so the repeated mark does not land on the text of the other
// pages (customer report 2026-10-04, see tests/paraaf-margin.test.mjs for /sign).
//
// The manifest keeps its meaning: one seal field with all_pages, the same
// normalised coordinates on every page. Only the default spot and size changed.
// Real Chromium, real co-sign.js, network stubbed; same harness as
// tests/cosign-document-delivery.test.mjs.
// Run: node --test tests/cosign-paraaf-margin.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.woff2':'font/woff2' };

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
const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });

const ENV_ID = 'env_demo_paraafmarginxyz';
const TOKEN = 't'.repeat(43);
await page.goto(ORIGIN + '/__proof');
await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
const fixture = await page.evaluate(async ({ envelopeId }) => {
  const pqc = await import('/vendor/paramant-pqc.js');
  const delivery = await import('/js/parasign-document-capsule.js?v=2');
  const pdf = await window.PDFLib.PDFDocument.create();
  for (let p = 0; p < 2; p++) {
    const pg = pdf.addPage([595, 842]);
    for (let y = 780; y >= 60; y -= 14) pg.drawText('Artikel 7. De opdrachtnemer levert de diensten volgens de overeenkomst.', { x: 56, y, size: 10.5 });
  }
  const bytes = new Uint8Array(await pdf.save());
  const docHash = Array.from(pqc.sha3_256(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
  const out = await delivery.encryptDocumentCapsule({ bytes, filename: 'paraaf-demo.pdf', mime: 'application/pdf', envelopeId, docHash });
  return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash, bytes: Array.from(bytes) };
}, { envelopeId: ENV_ID });

await page.route('https://health.paramant.app/v2/envelopes/**', (route) => {
  const url = new URL(route.request().url());
  if (url.pathname.endsWith('/view')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
  return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ envelope: {
    id: ENV_ID, doc_hash: fixture.docHash, original_filename: 'paraaf-demo.pdf', recipe_version: 5,
    created_at: '2026-10-04T12:00:00.000Z', expires_at: '2026-11-03T12:00:00.000Z',
    status: 'sent', signed_count: 0, party_count: 1, parties: [{ index: 0, label: 'Sandeep G. Prasad', status: 'pending' }],
  } }) });
});
await page.route(`**/api/user/envelopes/${ENV_ID}/document*`, (route) => route.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fixture.capsule) }));
await page.route('**/api/user/account', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"email":"demo@example.com"}' }));

await page.goto(`${ORIGIN}/co-sign?env=${ENV_ID}&p=0&t=${TOKEN}${fixture.fragment}`, { waitUntil: 'domcontentloaded' });
await page.waitForFunction(() => document.querySelectorAll('.doc-page[data-page-index]').length === 2 && !document.querySelector('#sign-confirm')?.disabled, null, { timeout: 20000 });
await page.locator('#appearance-allpages').check();
await page.waitForFunction(() => document.querySelectorAll('.appearance-field.seal.paraaf').length === 2, null, { timeout: 10000 });

const r = await page.evaluate(async (srcBytes) => {
  const raw = Array.from({ length: sessionStorage.length }, (_, i) => sessionStorage.getItem(sessionStorage.key(i))).find((v) => v && v.includes('"fields"'));
  const appearance = JSON.parse(raw);
  const mod = await import(document.querySelector('script[src*="co-sign.js"]').getAttribute('src'));
  const out = await mod.buildSignedPdf({ appearance, signed_at: '2026-10-04T12:00:00.000Z' });
  const boxes = async (bytes) => {
    const doc = await window.pdfjsLib.getDocument({ data: new Uint8Array(bytes) }).promise;
    const pages = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const items = (await (await doc.getPage(i)).getTextContent()).items.filter((it) => it.str.trim());
      pages.push(items.map((it) => { const fs = Math.hypot(it.transform[2], it.transform[3]); return { str: it.str, x: it.transform[4], y: it.transform[5] - 0.25 * fs, w: it.width, h: 1.25 * fs }; }));
    }
    return pages;
  };
  return { appearance, src: await boxes(srcBytes), out: await boxes(out) };
}, fixture.bytes);

const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

// Since 2026-10-04 the paraaf is ADDED next to the signature (a contract asks
// for initials on every sheet and a signature on the last), so the manifest
// holds two seals: the signature on one page and the repeated paraaf.
test('ticking the box adds one small repeated paraaf in the bottom-right margin, next to the signature', () => {
  const seals = r.appearance.fields.filter((f) => f.type === 'seal');
  assert.equal(seals.length, 2);
  assert.equal(seals.filter((f) => !f.all_pages).length, 1, 'the signature stays');
  const s = seals.find((f) => f.all_pages);
  assert.equal(s.all_pages, true);
  assert.equal(s.page_index, 0);
  assert.equal(r.appearance.version, 2);
  assert.ok(s.w <= 0.2 && s.h <= 0.05, `small: ${s.w} x ${s.h}`);
  assert.ok(s.w < 0.36 && s.h < 0.105, 'smaller than the default co-sign seal');
  assert.ok(s.x > 0.5 && s.y > 0.85, `bottom right: x ${s.x}, y ${s.y}`);
});

test('the baked repeated seal does not overlap the text on any page', () => {
  assert.equal(r.out.length, 2);
  for (let i = 0; i < 2; i++) {
    const srcStrs = new Set(r.src[i].map((b) => b.str));
    const added = r.out[i].filter((b) => !srcStrs.has(b.str));
    assert.ok(added.some((b) => /S\.G\.P\./.test(b.str)), `page ${i + 1} has the paraaf with initials`);
    assert.ok(!added.some((b) => /PARAMANT SIGNED/.test(b.str)), 'no English frame text any more');
    // The paraaf is what this suite is about. (The fixture is text from top to
    // bottom, so the suggested signature spot has no free place to go; it is a
    // suggestion the signer moves, and js/cosign-layout.js picks the least
    // covered spot, tested in tests/cosign-layout.test.mjs.)
    for (const a of added.filter((b) => /S\.G\.P\./.test(b.str))) for (const t of r.src[i]) assert.ok(!overlaps(a, t), `page ${i + 1}: "${a.str}" overlaps "${t.str.slice(0, 20)}"`);
  }
});
