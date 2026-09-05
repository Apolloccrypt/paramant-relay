// No workflow on /sign may run to its last request and fail there.
//
// The complaint this gate comes from: signed out, pick a file, walk the whole
// screen, and the first thing that says "you are not signed in" is a 401 on
// POST /api/user/account/signing-key/step-up/options. tests/sign-signed-out
// .test.mjs already pinned the fix for one of the three workflows: 'Request
// signatures' turns Send into the sign-in. 'Sign it myself' and 'Sign together'
// end at a different button, #ds-sign-now, and it kept its promise all the way
// into doSign().
//
// So this walks all three, signed out, and asserts two things per workflow:
//
//   1. The last button is the sign-in, and pressing it lands on
//      /auth/login?next=/sign, which auth-login.js honours (local paths only).
//   2. Nothing along that route asks /api/user/ anything except the one session
//      probe. A request that is answered with a 401 IS the dead end, whether or
//      not the page shows it; counting requests catches the next one too,
//      wherever a future step puts it.
//
// It also holds the two guarantees that must not be traded away for the fix:
// the page is served to a signed-out visitor with a 200 and no redirect (the
// nginx gate stays off, see the twenty-line note in the conf), and a signed-in
// visitor reaches the real Sign button with the real label.
//
// Real Chromium, the real page, same-origin APIs stubbed the way
// tests/sign-signed-out.test.mjs stubs them.

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

// Read an element that a broken page may not have at all. A gate that throws
// instead of reporting still fails the run, but it stops at the first problem
// and names a locator rather than the promise that was broken.
async function textOf(page, selector) {
  try {
    if (await page.locator(selector).count() === 0) return '(no ' + selector + ')';
    return await page.locator(selector).innerText({ timeout: 2000 });
  } catch { return '(' + selector + ' not visible)'; }
}

// Every /api/user/ path the page asked for, minus the session probe, which is
// the one call that is supposed to happen and the one that answers the
// question. Anything else on that prefix needs a session by definition.
function privileged(page) {
  const seen = [];
  page.on('request', (req) => {
    const p = new URL(req.url()).pathname;
    if (p.startsWith('/api/user/') && p !== '/api/user/session/verify') seen.push(req.method() + ' ' + p);
  });
  return seen;
}

// The session answer, in the shape /api/user/session/verify actually returns.
// Every other API is a bland 200, so a call that should not happen still
// shows up in the list above rather than dying of its own stub.
async function openSign(authenticated) {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await page.route('**/api/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.route('**/api/user/session/verify', (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify(authenticated ? { authenticated: true, email: 'owner@example.com' } : { authenticated: false }),
  }));
  const calls = privileged(page);
  const response = await page.goto(ORIGIN + '/sign', { waitUntil: 'domcontentloaded' });
  return { page, calls, response };
}

// A real PDF, built in the page with the pdf-lib the page already loads.
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

// Everything up to (not including) the last button, for one workflow.
async function walkToTheEnd(page, mode) {
  await page.locator(`.ds-mode-card[data-mode="${mode}"]`).click();
  await pickPdf(page);
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 15000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 100 } });
  await page.locator('#ds-place-continue').click();
  if (mode === 'invite') {
    await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 15000 });
    return '#ds-recipients-continue';
  }
  if (mode === 'cosign') {
    await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 15000 });
    await page.locator('#ds-recipients-continue').click();
  }
  // Identity: a typed name and a typed signature are all the step asks for.
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 15000 });
  await page.locator('#ds-signer-name').fill('Demo Signer');
  await page.locator('#ds-identity-continue:not([disabled])').waitFor({ timeout: 15000 });
  await page.locator('#ds-identity-continue').click();
  await page.locator('#step-sign:not([hidden])').waitFor({ timeout: 15000 });
  return '#ds-sign-now';
}

// ── the three workflows, signed out ──────────────────────────────────────────
for (const [mode, label] of [['alone', 'Sign in to sign'], ['cosign', 'Sign in to sign'], ['invite', 'Sign in to send']]) {
  const { page, calls } = await openSign(false);
  await page.locator('#ds-signedout:not([hidden])').waitFor({ timeout: 15000 });
  const button = await walkToTheEnd(page, mode);

  const buttonText = await textOf(page, button);
  ok(`${mode}: the last button asks for the session`, buttonText.trim() === label, buttonText);
  ok(`${mode}: the last button is not disabled`,
    !(await page.locator(button).isDisabled()), button);
  ok(`${mode}: the bar is still on screen at the last step`,
    await page.locator('#ds-signedout').isVisible(), '#ds-signedout');
  const hint = await textOf(page, mode === 'invite' ? '#ds-recipients-hint' : '#ds-sign-signin-hint');
  ok(`${mode}: and the last step says the prepared file does not travel`,
    /has not been uploaded/i.test(hint), hint);

  // The gate proper: nothing on the whole route asked for anything that needs
  // an account. No 401 was raised, because no request was made that could.
  ok(`${mode}: nothing on the route needs a session`,
    calls.length === 0, calls.join(', ') || 'none');

  await page.locator(button).click();
  await page.waitForURL(/\/auth\/login\?next=(%2F|\/)sign$/, { timeout: 15000 }).catch(() => {});
  ok(`${mode}: pressing it goes to the sign-in and back to /sign`,
    /\/auth\/login\?next=(%2F|\/)sign$/.test(page.url()), page.url());
  await page.close();
}

// ── the guarantees the fix may not trade away ────────────────────────────────
// /sign stays a public 200 with no redirect. The nginx auth_request was taken
// off this route on purpose (Googlebot was being handed a robots-disallowed
// sign-in page); a fix that puts a redirect back is the wrong fix.
{
  const { page, response } = await openSign(false);
  ok('signed out, /sign answers 200', response.status() === 200, String(response.status()));
  ok('signed out, /sign does not redirect',
    new URL(page.url()).pathname === '/sign' && response.request().redirectedFrom() === null,
    page.url());
  const robots = await page.locator('meta[name="robots"]').count();
  const content = robots ? await page.locator('meta[name="robots"]').first().getAttribute('content') : '';
  ok('signed out, /sign is not marked noindex', !/noindex/i.test(content || ''), content || '(no robots meta)');
  await page.close();
}

// ── signed in: none of the above ─────────────────────────────────────────────
for (const mode of ['alone', 'cosign', 'invite']) {
  const { page } = await openSign(true);
  await page.waitForTimeout(600);
  ok(`${mode}: signed in, there is no bar`, await page.locator('#ds-signedout').isHidden(), '#ds-signedout');
  const button = await walkToTheEnd(page, mode);
  const buttonText = await textOf(page, button);
  ok(`${mode}: signed in, the last button is the real one`,
    buttonText.trim() === (mode === 'invite' ? 'Send for signature' : 'Sign this document'), buttonText);
  if (mode !== 'invite') {
    ok(`${mode}: signed in, no sign-in hint on the last step`,
      await page.locator('#ds-sign-signin-hint').count() === 1
      && await page.locator('#ds-sign-signin-hint').isHidden(), '#ds-sign-signin-hint');
  }
  await page.close();
}

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nsign-signed-out-dead-end: ${checks.length} checks passed`);
