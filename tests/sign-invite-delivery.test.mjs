// Real Chromium coverage for the sender side of encrypted signing requests.
// Uses the real page and WebCrypto. Only same-origin APIs are stubbed.

import { chromium } from 'playwright';
import { stableScreenshot } from '../scripts/stable-screenshot.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.woff2':'font/woff2' };
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
const page = await browser.newPage({ viewport: { width: 390, height: 844 } });

const ENV_ID = 'env_demo_abcdefghijklmnop';
const TOKEN = 't'.repeat(43);
let envelopeCreates = [];
let documentUploads = [];
let invitationCalls = [];
let invitationAttempt = 0;
await page.route('**/api/user/envelopes', async (route) => {
  const body = route.request().postDataJSON();
  envelopeCreates.push(body);
  await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, envelope: {
    id: ENV_ID, party_count: body.recipients.length,
    expires_at: '2026-08-20T12:00:00.000Z',
    party_links: body.recipients.map((_, party_index) => ({ party_index, sign_path: `/co-sign?env=${ENV_ID}&p=${party_index}&t=${TOKEN}`, invite_token: TOKEN })),
  } }) });
});
await page.route(`**/api/user/envelopes/${ENV_ID}/document`, async (route) => {
  documentUploads.push({ headers: route.request().headers(), body: await route.request().postDataBuffer() });
  await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
});
await page.route(`**/api/user/envelopes/${ENV_ID}/invitations`, async (route) => {
  const body = route.request().postDataJSON();
  invitationCalls.push(body);
  invitationAttempt++;
  const failed = invitationAttempt === 1 ? [0] : [];
  await route.fulfill({
    status: failed.length ? 207 : 200,
    contentType: 'application/json',
    body: JSON.stringify({ ok: failed.length === 0, partial_failure: failed.length > 0, failed_party_indexes: failed, results: body.invitations.map((item) => ({ party_index: item.party_index, ok: !failed.includes(item.party_index) })) }),
  });
});

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }

const directPage = await browser.newPage({ viewport: { width: 390, height: 844 } });
await directPage.goto(ORIGIN + '/sign?mode=alone', { waitUntil: 'domcontentloaded' });
ok('dashboard deep link enters self-signing directly', await directPage.locator('#step-doc').isVisible() && await directPage.locator('.ds-stepper li[data-step="recipients"]').isHidden(), await directPage.locator('main').innerText());
await directPage.close();

// ── the session probe: three answers, three different things to say ──────────
// "Signing a document needs an account" is only true when the browser HAS no
// session. A koper review saw it while signed in, because the probe had failed
// rather than refused. A failure gets the shared service sentence instead, and
// a healthy answer gets neither.
async function probeSays(status, body) {
  const probe = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await probe.route('**/api/user/session/verify', (route) => route.fulfill({
    status, contentType: 'application/json', body: body || '{}',
  }));
  await probe.goto(ORIGIN + '/sign', { waitUntil: 'domcontentloaded' });
  await probe.waitForFunction(() => !!(self.paramantErrors), null, { timeout: 15000 });
  await probe.waitForTimeout(300);
  const seen = await probe.evaluate(() => ({
    anon: !document.getElementById('step-anon').hidden,
    bar: !document.getElementById('ds-signedout').hidden,
    service: !document.getElementById('ds-service-note').hidden,
    serviceText: document.getElementById('ds-service-note').textContent,
    support: self.paramantErrors.SUPPORT_FAILURE_MESSAGE,
  }));
  await probe.close();
  return seen;
}
const probeOut = await probeSays(200, '{"authenticated":false}');
ok('no session gets the account notice and the bar', probeOut.anon === true && probeOut.bar === true && probeOut.service === false, JSON.stringify(probeOut));
const probe503 = await probeSays(503, '{"error":"session_store_unavailable"}');
ok('a broken probe is a service failure, not a missing account',
  probe503.anon === false && probe503.bar === false && probe503.service === true && probe503.serviceText === probe503.support,
  JSON.stringify(probe503));
const probeIn = await probeSays(200, '{"authenticated":true,"email":"owner@example.com"}');
ok('a signed-in visitor is told nothing at all', probeIn.anon === false && probeIn.bar === false && probeIn.service === false, JSON.stringify(probeIn));

await page.goto(ORIGIN + '/sign', { waitUntil: 'domcontentloaded' });
ok('landing leads with the request-signatures workflow', await page.locator('.ds-mode-card').first().getAttribute('data-mode') === 'invite' && await page.locator('.ds-mode-card').first().getAttribute('class').then((value) => value.includes('primary')), await page.locator('.ds-mode-card').first().innerText());
ok('technical stepper stays hidden until a workflow is chosen', await page.locator('#ds-stepper').isHidden(), 'hidden');
ok('landing has no phone-width overflow', await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth) <= 1, await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
if (process.env.PARAMANT_SIGN_SCREENSHOT_PATH) await stableScreenshot(page, { path:process.env.PARAMANT_SIGN_SCREENSHOT_PATH, fullPage:true });
await page.locator('.ds-mode-card[data-mode="invite"]').click();
// A .txt used to go straight to the recipients through the hash-only path.
// /sign refuses anything that is not a PDF now (tests/sign-signed-out.test.mjs
// covers the refusal), so the delivery run takes the road a customer takes.
await page.evaluate(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  while (!window.PDFLib) await sleep(20);
  const source = await window.PDFLib.PDFDocument.create();
  source.addPage([300, 400]).drawText('Agreement', { x: 30, y: 350, size: 14 });
  const transfer = new DataTransfer();
  transfer.items.add(new File([await source.save()], 'agreement-demo.pdf', { type: 'application/pdf' }));
  const input = document.getElementById('ds-doc-input');
  input.files = transfer.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
});
await page.locator('#step-place:not([hidden])').waitFor({ timeout: 15000 });
await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"] canvas').waitFor();
await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 120 } });
await page.locator('#ds-place-continue').click();
await page.locator('#step-recipients:not([hidden])').waitFor();
await page.locator('#ds-add-recipient').click();
await page.locator('[data-field="label"]').fill('Signer Demo');
await page.locator('[data-field="email"]').fill('signer@example.com');
await page.locator('#ds-invite-message').fill('Reference ACME-001');
ok('email delivery is the visible default', await page.locator('input[name="ds-delivery-mode"][value="email"]').isChecked(), 'email');
ok('recipient identity requirement is shown before sending', /must sign in with the invited email address/i.test(await page.locator('#ds-invite-delivery').innerText()), await page.locator('#ds-invite-delivery').innerText());
await page.locator('#ds-recipients-continue').click();
await page.locator('#step-done:not([hidden])').waitFor({ timeout: 15000 });

const firstInvite = invitationCalls[0]?.invitations?.[0];
const firstUrl = firstInvite ? new URL(firstInvite.invite_url) : null;
ok('document is uploaded once as an encrypted capsule', documentUploads.length === 1 && documentUploads[0].body?.subarray(0, 4).toString() === 'PSDC', JSON.stringify({ count: documentUploads.length, magic: documentUploads[0]?.body?.subarray(0, 4).toString() }));
ok('email invitation carries a personal fragment key', firstUrl?.hash.match(/^#doc=v1\.[A-Za-z0-9_-]{43}$/), firstUrl?.hash);
ok('email invitation is bound to the intended party and address', firstInvite?.party_index === 0 && firstInvite?.email === 'signer@example.com', JSON.stringify(firstInvite));
ok('partial email failure is not shown as success', /not every email was delivered/i.test(await page.locator('#ds-success-banner').innerText()), await page.locator('#ds-success-banner').innerText());
ok('failed email offers a retry', await page.locator('#ds-invite-retry').isVisible(), await page.locator('#ds-invite-retry').innerText());
ok('sender still has a copy-link fallback', await page.locator('.ds-pl-copy').isVisible(), await page.locator('.ds-pl-copy').innerText());

await page.locator('#ds-invite-retry').click();
await page.waitForFunction(() => /all email invitations/i.test(document.querySelector('#ds-invite-delivery-result')?.textContent || ''));
ok('retry sends only failed parties', invitationCalls.length === 2 && invitationCalls[1].invitations.length === 1 && invitationCalls[1].invitations[0].party_index === 0, JSON.stringify(invitationCalls[1]?.invitations));
ok('successful retry clears the warning', /all email invitations/i.test(await page.locator('#ds-invite-delivery-result').innerText()) && !(await page.locator('#ds-invite-retry').isVisible()), await page.locator('#ds-invite-delivery-result').innerText());
ok('phone viewport has no horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth) <= 1, await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));

// ── PDF variant: the requester points at the spot where the other party signs ──
// The run above is the delivery half: what the email does, what a partial
// failure says, what a retry sends. Everything below is /sign's promise ("show
// them where to sign"), measured on the bytes that leave the browser.
ok('the delivery run created exactly one signing request', envelopeCreates.length === 1, JSON.stringify(envelopeCreates.map((e) => e.recipients?.length)));

const pdfCreates = [];
const pdfPage = await browser.newPage({ viewport: { width: 390, height: 844 } });
await pdfPage.route('**/api/user/envelopes', async (route) => {
  const body = route.request().postDataJSON();
  pdfCreates.push(body);
  await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, envelope: {
    id: ENV_ID, party_count: body.recipients.length,
    expires_at: '2026-08-20T12:00:00.000Z',
    party_links: body.recipients.map((_, party_index) => ({ party_index, sign_path: `/co-sign?env=${ENV_ID}&p=${party_index}&t=${TOKEN}`, invite_token: TOKEN })),
  } }) });
});
await pdfPage.route(`**/api/user/envelopes/${ENV_ID}/document`, async (route) => {
  await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
});
await pdfPage.route(`**/api/user/envelopes/${ENV_ID}/invitations`, async (route) => {
  const body = route.request().postDataJSON();
  await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, partial_failure: false, failed_party_indexes: [], results: body.invitations.map((item) => ({ party_index: item.party_index, ok: true })) }) });
});

await pdfPage.goto(ORIGIN + '/sign', { waitUntil: 'domcontentloaded' });
await pdfPage.locator('.ds-mode-card[data-mode="invite"]').click();
ok('the invite stepper shows the Place step', await pdfPage.locator('.ds-stepper li[data-step="place"]').isVisible(), await pdfPage.locator('.ds-stepper').innerText());
await pdfPage.evaluate(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  while (!window.PDFLib) await sleep(20);
  const source = await window.PDFLib.PDFDocument.create();
  source.addPage([300, 400]).drawText('Page one', { x: 30, y: 350, size: 14 });
  source.addPage([300, 400]).drawText('Signature page', { x: 30, y: 350, size: 14 });
  const transfer = new DataTransfer();
  transfer.items.add(new File([await source.save()], 'agreement-demo.pdf', { type: 'application/pdf' }));
  const input = document.getElementById('ds-doc-input');
  input.files = transfer.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
});
await pdfPage.locator('#step-place:not([hidden])').waitFor({ timeout: 15000 });
await pdfPage.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="1"] canvas').waitFor();

// The requester is not signing, so none of the signer's chrome belongs here.
// On a 390px phone that editor is 160px and the seal panel another 247px, which
// is exactly the difference between seeing the document and scrolling for it.
ok('invite Place shows one button, not the signer toolbars',
  await pdfPage.locator('#ds-invite-tools').isVisible()
  && await pdfPage.locator('#ds-edit-tools').isHidden()
  && await pdfPage.locator('#ds-seal-tools').isHidden(),
  await pdfPage.locator('#ds-invite-place').innerText());
const fold = await pdfPage.evaluate(() => ({
  canvasTop: Math.round(document.querySelector('#ds-pdf-canvas-list .ds-page-wrap').getBoundingClientRect().top),
  viewport: window.innerHeight,
  overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
}));
ok('the document is above the fold at 390', fold.canvasTop > 0 && fold.canvasTop < fold.viewport, JSON.stringify(fold));
ok('the Place step has no phone-width overflow', fold.overflow <= 1, JSON.stringify(fold));

await pdfPage.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="1"]').click({ position: { x: 170, y: 100 } });
ok('placing the box says who it is for', /asking for a signature on page 2/i.test(await pdfPage.locator('#ds-place-hint').innerText()), await pdfPage.locator('#ds-place-hint').innerText());
ok('the marker asks rather than signs', /SIGNATURE REQUESTED/.test(await pdfPage.locator('.ds-stamp-marker').innerText()), await pdfPage.locator('.ds-stamp-marker').innerText());

await pdfPage.locator('#ds-place-continue').click();
await pdfPage.locator('#step-recipients:not([hidden])').waitFor();
await pdfPage.locator('#ds-add-recipient').click();
await pdfPage.locator('[data-field="label"]').fill('Signer Demo');
await pdfPage.locator('[data-field="email"]').fill('signer@example.com');
await pdfPage.locator('#ds-recipients-continue').click();
await pdfPage.locator('#step-done:not([hidden])').waitFor({ timeout: 15000 });

const requested = pdfCreates[0]?.requested_appearance;
const seal = requested?.fields?.[0];
ok('the create call carries exactly one requested position',
  requested?.version === 1 && requested.fields.length === 1 && seal.type === 'seal',
  JSON.stringify(requested));
ok('the requested position names the page that was clicked', seal?.page_index === 1, JSON.stringify(seal));
ok('the requested position is fractions of the page, y from the top',
  seal && [seal.x, seal.y, seal.w, seal.h].every((n) => typeof n === 'number' && n >= 0 && n <= 1)
  && seal.x + seal.w <= 1.000001 && seal.y + seal.h <= 1.000001
  && seal.y < 0.4 && Math.abs(seal.w - 0.8) < 0.01 && Math.abs(seal.h - 0.25) < 0.01,
  JSON.stringify(seal));
await pdfPage.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nsign-invite-delivery: ${checks.length} checks passed`);
