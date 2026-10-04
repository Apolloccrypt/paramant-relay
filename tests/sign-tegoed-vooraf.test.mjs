// Acceptatie ronde 2, punt 6: een afzender zonder tegoed kon versturen zonder
// waarschuwing, en de ondertekenaar strandde. Nu kijkt /sign vooraf: is er
// minder tegoed dan het aantal ondertekenaars, dan zegt de pagina dat, en pas
// een tweede klik verstuurt. Met genoeg tegoed (of onbekend) gaat het meteen.
// Run: node --test tests/sign-tegoed-vooraf.test.mjs
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

async function run(quota) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  let creates = 0;
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"s@example.nl"}' }));
  await page.route('**/api/user/dashboard/overview', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ quota }) }));
  await page.route('**/api/user/envelopes', (r) => { creates++; return r.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"stop_here"}' }); });
  await page.goto(ORIGIN + '/sign?mode=invite', { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await new Promise((r) => setTimeout(r, 20));
    const doc = await window.PDFLib.PDFDocument.create();
    doc.addPage([595, 842]).drawText('Overeenkomst', { x: 60, y: 760, size: 16 });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'o.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 20000 });
  for (const [i, [label, email]] of [['Een', 'een@example.nl'], ['Twee', 'twee@example.nl']].entries()) {
    await page.locator('#ds-add-recipient').click();
    await page.locator('[data-field="label"]').nth(i).fill(label);
    await page.locator('[data-field="email"]').nth(i).fill(email);
  }
  await page.locator('#ds-recipients-continue').click();
  await page.waitForTimeout(1200);
  const first = { creates, hint: await page.locator('#ds-recipients-hint').innerText().catch(() => '') };
  await page.locator('#ds-recipients-continue').click();
  await page.waitForTimeout(1500);
  const second = { creates };
  await page.close();
  return { first, second };
}

test('te weinig tegoed: eerst een waarschuwing, pas de tweede klik verstuurt', async () => {
  const r = await run({ signs: 1, caps: { signs: 2 } });
  assert.equal(r.first.creates, 0, 'de eerste klik verstuurde al');
  assert.match(r.first.hint, /nog 1 handtekening over/);
  assert.match(r.first.hint, /vraagt er 2/);
  assert.equal(r.second.creates, 1, 'de tweede klik verstuurt');
});

test('genoeg tegoed: meteen versturen', async () => {
  const r = await run({ signs: 0, caps: { signs: 100 } });
  assert.equal(r.first.creates, 1);
});
