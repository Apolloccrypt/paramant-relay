// /en/sign is the English copy of /sign (23 September 2026). Both pages load
// the same sign-flow.js, which picks its words from <html lang>. This walks the
// English page far enough to see the script speak English in the places the
// Dutch suites pin in Dutch, and checks the Dutch page still gets Dutch.
//
// Real Chromium, the real page, same-origin APIs stubbed the way
// tests/sign-signed-out.test.mjs stubs them.

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
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/sign') pathname = '/sign.html';
  if (pathname === '/en/sign') pathname = '/en/sign.html';
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }

// The session answer, in the shape /api/user/session/verify actually returns:
// 200 with authenticated true or false. Everything else on the page is stubbed
// to a bland 200 so nothing else in the flow reaches the network.
async function openSign(authenticated, url = '/en/sign') {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  // Playwright matches routes last-registered-first, so the catch-all goes down
  // before the specific one or it swallows it.
  await page.route('**/api/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.route('**/api/user/session/verify', (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify(authenticated ? { authenticated: true, email: 'owner@example.com' } : { authenticated: false }),
  }));
  await page.goto(ORIGIN + url, { waitUntil: 'domcontentloaded' });
  return page;
}

// A real PDF, built in the page with the pdf-lib the page already loads, so the
// bytes that reach the picker are the bytes a browser would hand it.
async function pickPdf(page) {
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 400 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    doc.addPage([300, 400]).drawText('Lease agreement', { x: 30, y: 350, size: 14 });
    const transfer = new DataTransfer();
    transfer.items.add(new File([await doc.save()], 'lease.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

// The exact shape of the file the owner picked on his phone: JPEG magic bytes,
// and a MIME type that says image/jpeg. The page used to take it anyway.
async function pickJpeg(page) {
  await page.locator('#ds-doc-input').setInputFiles({
    name: 'IMG_4445.jpeg',
    mimeType: 'image/jpeg',
    buffer: Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(4096, 7)]),
  });
}

// ── /en/sign: the same page and the same script, in English ────────────────
const out = await openSign(false);
await out.locator('#ds-signedout:not([hidden])').waitFor({ timeout: 15000 });
ok('the English page says it is English', await out.evaluate(() => document.documentElement.lang) === 'en', 'lang');
ok('signed out, the bar speaks English',
  /You are not signed in\. You can prepare a document here; signing or sending it needs a free Community account\./.test(await out.locator('#ds-signedout').innerText()),
  await out.locator('#ds-signedout').innerText());
const barLinks = await out.locator('#ds-signedout a').evaluateAll((nodes) => nodes.map((n) => [n.textContent.trim(), n.getAttribute('href')]));
ok('the bar comes back to /en/sign afterwards',
  JSON.stringify(barLinks) === JSON.stringify([['Sign in', '/auth/login?next=/en/sign'], ['Create account', '/signup?next=/en/sign']]),
  JSON.stringify(barLinks));
await out.locator('.ds-mode-card[data-mode="invite"]').click();
ok('the script labels the invite stepper in English',
  (await out.locator('.ds-stepper li[data-step="sign"]').textContent()).trim() === 'Send',
  await out.locator('.ds-stepper').innerText());
await pickPdf(out);
await out.locator('#step-place:not([hidden])').waitFor({ timeout: 15000 });
ok('the placement hint the script writes is English',
  /Optional: you can continue without asking for a spot\./.test(await out.locator('#ds-place-hint').innerText()),
  await out.locator('#ds-place-hint').innerText());
await out.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 100 } });
await out.locator('#ds-place-continue').click();
await out.locator('#step-recipients:not([hidden])').waitFor({ timeout: 15000 });
ok('the send button asks for the session, in English',
  (await out.locator('#ds-recipients-continue').innerText()).trim() === 'Sign in to send',
  await out.locator('#ds-recipients-continue').innerText());
ok('the default subject is the English one',
  await out.locator('#ds-invite-subject').inputValue() === 'Signature requested',
  await out.locator('#ds-invite-subject').inputValue());
await out.locator('#ds-recipients-continue').click();
await out.waitForURL(/\/auth\/login/, { timeout: 15000 }).catch(() => {});
ok('pressing it comes back to the English page', /\/auth\/login\?next=(\/|%2F)en(\/|%2F)sign$/.test(out.url()), out.url());
await out.close();

const jpeg = await openSign(true);
await jpeg.locator('.ds-mode-card[data-mode="alone"]').click();
await pickJpeg(jpeg);
await jpeg.locator('#ds-doc-error:not([hidden])').waitFor({ timeout: 15000 });
ok('a JPEG is refused in English',
  (await jpeg.locator('#ds-doc-error').innerText()).trim()
    === 'This is a JPEG image, not a PDF. ParaSign signs PDF documents. Export or print your file to PDF first.',
  await jpeg.locator('#ds-doc-error').innerText());
await jpeg.close();

// And the Dutch page, from the same script, stays Dutch.
const nl = await openSign(false, '/sign');
await nl.locator('#ds-signedout:not([hidden])').waitFor({ timeout: 15000 });
await nl.locator('.ds-mode-card[data-mode="invite"]').click();
ok('the Dutch page gets the Dutch label from the same script',
  (await nl.locator('.ds-stepper li[data-step="sign"]').textContent()).trim() === 'Versturen',
  await nl.locator('.ds-stepper').innerText());
await nl.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nsign-en: ${checks.length} checks passed`);
