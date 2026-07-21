// Real Chromium coverage for the sender side of encrypted signing requests.
// Uses the real page and WebCrypto. Only same-origin APIs are stubbed.

import { chromium } from 'playwright';
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
let documentUploads = [];
let invitationCalls = [];
let invitationAttempt = 0;
await page.route('**/api/user/envelopes', async (route) => {
  const body = route.request().postDataJSON();
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

await page.goto(ORIGIN + '/sign', { waitUntil: 'domcontentloaded' });
ok('landing leads with the request-signatures workflow', await page.locator('.ds-mode-card').first().getAttribute('data-mode') === 'invite' && await page.locator('.ds-mode-card').first().getAttribute('class').then((value) => value.includes('primary')), await page.locator('.ds-mode-card').first().innerText());
ok('technical stepper stays hidden until a workflow is chosen', await page.locator('#ds-stepper').isHidden(), 'hidden');
ok('landing has no phone-width overflow', await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth) <= 1, await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
if (process.env.PARAMANT_SIGN_SCREENSHOT_PATH) await page.screenshot({ path:process.env.PARAMANT_SIGN_SCREENSHOT_PATH, fullPage:true });
await page.locator('.ds-mode-card[data-mode="invite"]').click();
await page.locator('#ds-doc-input').setInputFiles({ name: 'agreement-demo.txt', mimeType: 'text/plain', buffer: Buffer.from('agreement document for invite delivery') });
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

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nsign-invite-delivery: ${checks.length} checks passed`);
