// Real Chromium coverage for encrypted document delivery on /co-sign.
// Self-contained: serves the real frontend, uses real WebCrypto and stubs only
// network APIs. No Redis, account, production request or persistent test data.

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
const page = await browser.newPage({ viewport: { width: 390, height: 844 } });

const ENV_ID = 'env_demo_abcdefghijklmnop';
const TOKEN = 't'.repeat(43);
await page.goto(ORIGIN + '/__proof');
await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
const fixture = await page.evaluate(async ({ envelopeId }) => {
  const pqc = await import('/vendor/paramant-pqc.js');
  const delivery = await import('/js/parasign-document-capsule.js?v=1');
  const pdf = await window.PDFLib.PDFDocument.create();
  const pdfPage = pdf.addPage([595, 842]);
  pdfPage.drawText('Generic agreement for recipient placement test', { x: 50, y: 780, size: 16 });
  const bytes = new Uint8Array(await pdf.save());
  const docHash = Array.from(pqc.sha3_256(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
  const out = await delivery.encryptDocumentCapsule({
    bytes, filename: 'agreement-demo.pdf', mime: 'application/pdf', envelopeId, docHash,
  });
  return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash };
}, { envelopeId: ENV_ID });

let accountOk = true;
let documentReads = 0;
await page.route('https://health.paramant.app/v2/envelopes/**', (route) => {
  const request = route.request();
  const url = new URL(request.url());
  if (url.pathname.endsWith('/view')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
  return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    envelope: {
      id: ENV_ID, doc_hash: fixture.docHash, original_filename: 'agreement-demo.pdf', recipe_version: 5,
      created_at: '2026-07-21T12:00:00.000Z', expires_at: '2026-08-20T12:00:00.000Z',
      status: 'sent', signed_count: 0, party_count: 1,
      parties: [{ index: 0, label: 'Signer Demo', status: 'pending' }],
    },
  }) });
});
await page.route(`**/api/user/envelopes/${ENV_ID}/document*`, (route) => {
  documentReads++;
  return route.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fixture.capsule) });
});
await page.route('**/api/user/account', (route) => route.fulfill({
  status: accountOk ? 200 : 401,
  contentType: 'application/json',
  headers: { 'Cache-Control': 'no-store' },
  body: accountOk ? '{"email":"demo@example.com"}' : '{"error":"unauthorized"}',
}));

const base = `${ORIGIN}/co-sign?env=${ENV_ID}&p=0&t=${TOKEN}`;
const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }
async function waitForDeliveryResult(target = page) {
  await target.waitForFunction(() => {
    const step = document.querySelector('.step.active')?.id;
    const text = document.querySelector('#document-delivery-status')?.textContent || '';
    return step === 'step-cosign' && text && !/^(Loading|Downloading)/i.test(text);
  }, null, { timeout: 15000 });
}

await page.goto(base + fixture.fragment, { waitUntil: 'domcontentloaded' });
await waitForDeliveryResult();
let state = await page.evaluate(() => ({
  step: document.querySelector('.step.active')?.id,
  delivery: document.querySelector('#document-delivery-status')?.textContent,
  result: document.querySelector('#verify-result')?.textContent,
  signDisabled: document.querySelector('#sign-confirm')?.disabled,
  overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
}));
ok('automatic delivery opens the co-sign step', state.step === 'step-cosign', state.step);
ok('automatic delivery reports decrypted + matched', /loaded, decrypted and matched/i.test(state.delivery), state.delivery);
ok('automatic delivery verifies the document hash', /Hash matches/i.test(state.result), state.result);
ok('verified delivered document enables signing', state.signDisabled === false, state.signDisabled);
ok('phone viewport has no horizontal overflow', state.overflow <= 1, state.overflow);
ok('document endpoint read once', documentReads === 1, documentReads);

await page.locator('#appearance-seal').click();
await page.locator('.doc-page[data-page-index="0"] .appearance-layer').click({ position: { x: 160, y: 90 } });
await page.locator('#appearance-date').click();
await page.locator('.doc-page[data-page-index="0"] .appearance-layer').click({ position: { x: 160, y: 170 } });
let appearanceState = await page.evaluate(() => ({
  fields: Array.from(document.querySelectorAll('.appearance-field:not(.prior)')).map((node) => ({ text: node.textContent, left: node.style.left, top: node.style.top })),
  draft: Array.from({ length: sessionStorage.length }, (_, i) => sessionStorage.getItem(sessionStorage.key(i))).find((value) => value && value.includes('"fields"')) || '',
}));
ok('recipient places a visible signature and date on the PDF', appearanceState.fields.length === 2 && appearanceState.fields.some((field) => /Paramant signed/i.test(field.text)) && appearanceState.fields.some((field) => /2026|2027/i.test(field.text)), JSON.stringify(appearanceState));
ok('placement draft stores coordinates only for refresh recovery', /"type":"seal"/.test(appearanceState.draft) && !/example\.com|agreement/i.test(appearanceState.draft), appearanceState.draft);
if (process.env.PARAMANT_COSIGN_SCREENSHOT_PATH) await page.screenshot({ path:process.env.PARAMANT_COSIGN_SCREENSHOT_PATH, fullPage:true });
const renderedPdf = await page.evaluate(async () => {
  const raw = Array.from({ length: sessionStorage.length }, (_, i) => sessionStorage.getItem(sessionStorage.key(i))).find((value) => value && value.includes('"fields"'));
  const mod = await import('/co-sign.js?v=19');
  const bytes = await mod.buildSignedPdf({ appearance: JSON.parse(raw), signed_at: '2026-07-21T12:00:00.000Z' });
  const pdf = await window.pdfjsLib.getDocument({ data: new Uint8Array(bytes) }).promise;
  const text = (await (await pdf.getPage(1)).getTextContent()).items.map((item) => item.str).join(' ');
  return { size: bytes.length, pages: pdf.numPages, text };
});
ok('download renderer bakes the signed seal and date into a PDF', renderedPdf.size > 500 && renderedPdf.pages === 1 && /PARAMANT SIGNED/.test(renderedPdf.text) && /2026-07-21/.test(renderedPdf.text), JSON.stringify(renderedPdf));

await page.reload({ waitUntil: 'domcontentloaded' });
await waitForDeliveryResult();
await page.waitForFunction(() => document.querySelectorAll('.appearance-field:not(.prior)').length === 2);
state = await page.evaluate(() => ({ delivery: document.querySelector('#document-delivery-status')?.textContent, signDisabled: document.querySelector('#sign-confirm')?.disabled, fields: document.querySelectorAll('.appearance-field:not(.prior)').length }));
ok('refresh retrieves the document and restores placed fields', documentReads === 2 && /matched/i.test(state.delivery) && state.signDisabled === false && state.fields === 2, JSON.stringify({ documentReads, ...state }));

const keyStart = '#doc=v1.'.length;
const badFragment = fixture.fragment.slice(0, keyStart) +
  (fixture.fragment[keyStart] === 'A' ? 'B' : 'A') + fixture.fragment.slice(keyStart + 1);
await page.goto(base + '&case=bad-key' + badFragment, { waitUntil: 'domcontentloaded' });
await waitForDeliveryResult();
state = await page.evaluate(() => ({ delivery: document.querySelector('#document-delivery-status')?.textContent, signDisabled: document.querySelector('#sign-confirm')?.disabled }));
ok('altered document key fails closed', /could not be decrypted|incomplete or altered/i.test(state.delivery) && state.signDisabled === true, JSON.stringify(state));

const readsBeforeNoKey = documentReads;
await page.goto(base, { waitUntil: 'domcontentloaded' });
await waitForDeliveryResult();
state = await page.evaluate(() => ({ delivery: document.querySelector('#document-delivery-status')?.textContent, manual: document.querySelector('#verify-file-cta')?.textContent }));
ok('older link without key gives an actionable manual fallback', /does not contain/i.test(state.delivery) && /manually/i.test(state.manual), JSON.stringify(state));
ok('missing fragment does not fetch undecryptable ciphertext', documentReads === readsBeforeNoKey, documentReads);

const anonPage = await browser.newPage({ viewport: { width: 390, height: 844 } });
let anonymousDocumentReads = 0;
await anonPage.route(`**/api/user/envelopes/${ENV_ID}/document*`, (route) => {
  anonymousDocumentReads++;
  return route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"unauthenticated"}' });
});
await anonPage.route('https://health.paramant.app/v2/envelopes/**', (route) => {
  const request = route.request();
  const url = new URL(request.url());
  if (url.pathname.endsWith('/view')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
  return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    envelope: {
      id: ENV_ID, doc_hash: fixture.docHash, original_filename: 'agreement-demo.pdf', recipe_version: 5,
      created_at: '2026-07-21T12:00:00.000Z', expires_at: '2026-08-20T12:00:00.000Z',
      status: 'sent', signed_count: 0, party_count: 1,
      parties: [{ index: 0, label: 'Signer Demo', status: 'pending' }],
    },
  }) });
});
await anonPage.route('**/api/user/account', (route) => route.fulfill({
  status: 401, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' }, body: '{"error":"unauthorized"}',
}));
await anonPage.goto(base + fixture.fragment, { waitUntil: 'domcontentloaded' });
await waitForDeliveryResult(anonPage);
const returnHref = await anonPage.locator('#sign-cta a').getAttribute('href');
ok('sign-in return preserves the document-key fragment', decodeURIComponent(returnHref || '').includes(fixture.fragment), returnHref);
ok('ciphertext is not requested before recipient sign-in', anonymousDocumentReads === 0, anonymousDocumentReads);
await anonPage.close();

for (const c of checks) console.log(`${c.pass ? 'PASS' : 'FAIL'} ${c.name}${c.detail ? ' :: ' + c.detail : ''}`);
await browser.close();
server.close();
if (checks.some((c) => !c.pass)) process.exit(1);
console.log(`\ncosign-document-delivery: ${checks.length} checks passed`);
