// The document under the signing flow must be named on every step that acts on
// it, in every mode.
//
// Why this suite exists. The file name and size were added to the Place step,
// which is the step the request-signatures flow never visits: onDocChosen()
// sends that mode straight from the file picker to the co-signers. So a
// customer who chose "Request signatures" picked a file, typed two email
// addresses and pressed "Send for signature" without one screen in between
// saying what he was sending. A koper review found it on the second pass, on a
// phone, where the only other place the name could have been (the collapsed
// step-1 panel) is off screen.
//
// It drives the real page in Chromium rather than reading the source, because
// what is under test is whether the name is VISIBLE at that moment: the element
// existed the whole time, in a section that was hidden.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.png':'image/png','.wasm':'application/wasm','.woff2':'font/woff2' };

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

// A phone, because that is where the finding was made: on a desktop a stray
// name higher up the page can still be in view, on 390x844 it cannot.
async function uploadIn(mode, filename) {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  // Signed in: the account notice must not be what fills the screen.
  await page.route('**/api/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"authenticated":true}' }));
  await page.goto(`${ORIGIN}/sign?mode=${mode}`, { waitUntil: 'networkidle' });
  await page.evaluate(async (name) => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    while (!window.PDFLib || !window.pdfjsLib) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    doc.addPage([595, 842]).drawText('Lease', { x: 40, y: 780, size: 14 });
    const bytes = await doc.save();
    const input = document.getElementById('ds-doc-input');
    const transfer = new DataTransfer();
    transfer.items.add(new File([bytes], name, { type: 'application/pdf' }));
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
    for (let i = 0; i < 300 && document.getElementById('step-doc').hidden === false; i++) await sleep(20);
    await sleep(300);
  }, filename);
  await page.waitForTimeout(300);
  return page;
}

// What the customer can actually see: the element is visible, it is inside the
// viewport, and it is not sitting in a section the flow has hidden.
async function documentLine(page) {
  return page.evaluate(() => {
    const el = document.getElementById('ds-doc-meta');
    if (!el) return { present: false };
    const box = el.getBoundingClientRect();
    const step = el.closest('.ds-step');
    return {
      present: true,
      visible: !el.hidden && box.height > 0 && getComputedStyle(el).display !== 'none',
      inViewport: box.top >= 0 && box.bottom <= window.innerHeight,
      insideHiddenStep: !!(step && step.hidden),
      text: el.innerText.replace(/\s+/g, ' ').trim(),
      activeStep: document.body.getAttribute('data-ds-step'),
    };
  });
}

// ── invite: the mode that had no Place step at all ───────────────────────────
const invite = await uploadIn('invite', 'huur.pdf');
const inviteLine = await documentLine(invite);
ok('request-signatures names the file on the co-signers step',
  inviteLine.activeStep === 'step-recipients' && inviteLine.visible && !inviteLine.insideHiddenStep &&
  inviteLine.inViewport && /huur\.pdf/.test(inviteLine.text) && /\d/.test(inviteLine.text),
  JSON.stringify(inviteLine));

// And it is still there at the moment that matters: the screen carrying the
// button that sends the document to other people.
await invite.locator('#ds-recipients-continue').waitFor();
const sendLabel = (await invite.locator('#ds-recipients-continue').innerText()).trim();
const beforeSend = await documentLine(invite);
ok('the file is named on the screen that sends it',
  sendLabel === 'Send for signature' && beforeSend.visible && beforeSend.inViewport && /huur\.pdf/.test(beforeSend.text),
  JSON.stringify({ sendLabel, ...beforeSend }));
await invite.close();

// ── sign it myself: the Place step, where the line started ───────────────────
const alone = await uploadIn('alone', 'huur.pdf');
const aloneLine = await documentLine(alone);
ok('signing it yourself names the file on the place step',
  aloneLine.activeStep === 'step-place' && aloneLine.visible && !aloneLine.insideHiddenStep && /huur\.pdf/.test(aloneLine.text),
  JSON.stringify(aloneLine));
await alone.close();

// ── sign together: place first, co-signers after ─────────────────────────────
const cosign = await uploadIn('cosign', 'huur.pdf');
const cosignPlace = await documentLine(cosign);
await cosign.locator('#ds-place-continue').waitFor();
ok('signing together names the file on the place step',
  cosignPlace.visible && !cosignPlace.insideHiddenStep && /huur\.pdf/.test(cosignPlace.text), JSON.stringify(cosignPlace));
await cosign.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nsign-document-identity: ${checks.length} checks passed`);
