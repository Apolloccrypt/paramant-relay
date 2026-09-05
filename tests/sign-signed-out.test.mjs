// /sign told the truth about two things it used to be quiet about. The bar's
// sentence names both verbs now: 'sending' was true of the invite flow only,
// and the visitor who picked 'Sign it myself' was told about a step his
// workflow does not have. See tests/sign-signed-out-dead-end.test.mjs for the
// gate on the other two workflows.
//
// 1. A visitor with no session. The page is public, and the notice that says
//    so was a .ds-step, so setActive() hid it the moment a workflow was chosen.
//    The owner reached step 3 (Co-signers) on an iPhone with the nav still
//    reading "Create account / Sign in" and nothing on screen disagreeing.
//    #ds-signedout lives outside the steps and stays for every step, and the
//    send button becomes the sign-in rather than a guaranteed 401.
//
// 2. The file. accept="application/pdf,.pdf" is a hint iOS Safari ignores, and
//    the File object's MIME type comes from the same place, so a 6.5MB camera
//    JPEG was accepted as a "document". The check is on the magic bytes now.
//
// Real Chromium, the real page, same-origin APIs stubbed the way
// tests/navigation-shell.test.mjs stubs them.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.woff2':'font/woff2' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/sign') pathname = '/sign.html';
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
async function openSign(authenticated, url = '/sign') {
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

// ── signed out: the bar, and what it does not do ─────────────────────────────
const out = await openSign(false);
await out.locator('#ds-signedout:not([hidden])').waitFor({ timeout: 15000 });
ok('signed out, the flow carries a bar that says so',
  /You are not signed in\. You can prepare a document here; signing or sending it needs a free Community account\./.test(await out.locator('#ds-signedout').innerText()),
  await out.locator('#ds-signedout').innerText());
const barLinks = await out.locator('#ds-signedout a').evaluateAll((nodes) => nodes.map((n) => [n.textContent.trim(), n.getAttribute('href')]));
ok('the bar comes back to /sign afterwards',
  JSON.stringify(barLinks) === JSON.stringify([['Sign in', '/auth/login?next=/sign'], ['Create account', '/signup?next=/sign']]),
  JSON.stringify(barLinks));
ok('the bar cannot be dismissed', await out.locator('#ds-signedout button').count() === 0, String(await out.locator('#ds-signedout button').count()));

// The bug itself: it has to survive the steps, because the notice it replaces
// did not. Walk the same route the owner walked.
await out.locator('.ds-mode-card[data-mode="invite"]').click();
ok('the bar survives choosing a workflow', await out.locator('#ds-signedout').isVisible(), 'step-doc');
ok('the account notice is gone by then, as it always was', await out.locator('#step-anon').isHidden(), 'step-anon');
await pickPdf(out);
await out.locator('#step-place:not([hidden])').waitFor({ timeout: 15000 });
ok('the bar survives picking a document', await out.locator('#ds-signedout').isVisible(), 'step-place');
await out.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 100 } });
await out.locator('#ds-place-continue').click();
await out.locator('#step-recipients:not([hidden])').waitFor({ timeout: 15000 });
ok('the bar is still there on Co-signers, where it was missing', await out.locator('#ds-signedout').isVisible(), 'step-recipients');
ok('the send button asks for the session instead of promising to send',
  (await out.locator('#ds-recipients-continue').innerText()).trim() === 'Sign in to send',
  await out.locator('#ds-recipients-continue').innerText());
ok('and it says the prepared document does not survive signing in',
  /has not been uploaded/i.test(await out.locator('#ds-recipients-hint').innerText()),
  await out.locator('#ds-recipients-hint').innerText());
await out.locator('#ds-recipients-continue').click();
await out.waitForURL(/\/auth\/login\?next=%2Fsign|\/auth\/login\?next=\/sign/, { timeout: 15000 }).catch(() => {});
ok('pressing it goes to the sign-in and back to /sign', /\/auth\/login\?next=(\/|%2F)sign$/.test(out.url()), out.url());
await out.close();

// ── signed in: nothing of the above ──────────────────────────────────────────
const inn = await openSign(true);
await inn.waitForTimeout(600);
ok('signed in, there is no bar', await inn.locator('#ds-signedout').isHidden(), 'hidden');
ok('signed in, there is no account notice either', await inn.locator('#step-anon').isHidden(), 'hidden');
await inn.locator('.ds-mode-card[data-mode="invite"]').click();
await pickPdf(inn);
await inn.locator('#step-place:not([hidden])').waitFor({ timeout: 15000 });
await inn.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 100 } });
await inn.locator('#ds-place-continue').click();
await inn.locator('#step-recipients:not([hidden])').waitFor({ timeout: 15000 });
ok('signed in, the send button is the send button',
  (await inn.locator('#ds-recipients-continue').innerText()).trim() === 'Send for signature',
  await inn.locator('#ds-recipients-continue').innerText());
await inn.close();

// ── the file: a JPEG is not a document ───────────────────────────────────────
const jpeg = await openSign(true);
await jpeg.locator('.ds-mode-card[data-mode="invite"]').click();
await pickJpeg(jpeg);
await jpeg.locator('#ds-doc-error:not([hidden])').waitFor({ timeout: 15000 });
ok('a JPEG is refused, and named',
  (await jpeg.locator('#ds-doc-error').innerText()).trim()
    === 'This is a JPEG image, not a PDF. ParaSign signs PDF documents. Export or print your file to PDF first.',
  await jpeg.locator('#ds-doc-error').innerText());
ok('a refused file does not move the flow on',
  await jpeg.locator('#step-doc').isVisible()
  && await jpeg.locator('#step-place').isHidden()
  && await jpeg.locator('#step-hash-only').isHidden()
  && await jpeg.locator('#step-recipients').isHidden(),
  await jpeg.locator('main').innerText());
ok('a refused file is not named as the document under the flow',
  await jpeg.locator('#ds-doc-meta').isHidden(), 'ds-doc-meta');

// The picker also stops asking for a file it cannot use.
ok('the picker asks for a PDF',
  await jpeg.locator('#ds-doc-input').getAttribute('accept') === 'application/pdf,.pdf',
  await jpeg.locator('#ds-doc-input').getAttribute('accept'));
// The signature IMAGE is a different field and keeps taking images.
await jpeg.close();
const sig = await openSign(true, '/sign?mode=alone');
ok('the signature image field is untouched',
  await sig.locator('#ds-sig-image-input').getAttribute('accept') === 'image/png,image/jpeg',
  await sig.locator('#ds-sig-image-input').getAttribute('accept'));

// A real PDF still walks straight through the same door.
await pickPdf(sig);
await sig.locator('#step-place:not([hidden])').waitFor({ timeout: 15000 });
ok('a real PDF reaches the placement step', await sig.locator('#step-place').isVisible(), 'step-place');
ok('and it is named under the flow',
  /lease\.pdf/.test(await sig.locator('#ds-doc-meta').innerText()),
  await sig.locator('#ds-doc-meta').innerText());
ok('with no error left on screen', await sig.locator('#ds-doc-error').isHidden(), 'ds-doc-error');
await sig.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nsign-signed-out: ${checks.length} checks passed`);
