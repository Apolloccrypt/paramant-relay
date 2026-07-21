// Real Chromium coverage for the document-focused user dashboard.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/dashboard') pathname = '/dashboard.html';
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
const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });
const page = await browser.newPage({ viewport:{ width:390, height:844 } });

let overviewRequests = 0;
let documentRequests = 0;
let cancelRequests = 0;
await page.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await page.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({
  email:'demo@example.com', label:'Demo', plan:'pro', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:'2026-07-21T16:00:00.000Z', usage_purpose:'organisation'
}) }));
await page.route('**/api/user/dashboard/overview', (route) => { overviewRequests++; return route.fulfill({ status:500, body:'' }); });
await page.route('**/api/user/account/signing-key', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"keys":[{"label":"Signing key"}]}' }));
await page.route('**/api/user/account/webauthn/credentials', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"passkeys":[{"label":"Passkey"}]}' }));
await page.route('**/api/user/documents', (route) => {
  documentRequests++;
  return route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ documents:[
    { id:'env_waiting_abcdefghijklmnop', original_filename:'Lease agreement.pdf', status:'sent', created_at:'2026-07-21T10:00:00.000Z', party_count:2, signed_count:0 },
    { id:'env_progress_abcdefghijklmnop', original_filename:'Service order.pdf', status:'sent', created_at:'2026-07-20T10:00:00.000Z', party_count:3, signed_count:1 },
    { id:'env_complete_abcdefghijklmnop', original_filename:'Completed contract.pdf', status:'complete', created_at:'2026-07-19T10:00:00.000Z', party_count:2, signed_count:2 },
    { id:'env_void_abcdefghijklmnop', original_filename:'<img src=x onerror=window.dashboardInjected=1>', status:'void', created_at:'2026-07-18T10:00:00.000Z', party_count:1, signed_count:0 }
  ] }) });
});
await page.route('**/api/user/documents/env_waiting_abcdefghijklmnop/cancel', (route) => {
  cancelRequests++;
  return route.fulfill({ status:200, contentType:'application/json', body:'{"ok":true,"status":"void"}' });
});

const checks = [];
function ok(name, condition, detail='') { checks.push({ name, pass:!!condition, detail:String(detail) }); }

await page.goto(ORIGIN + '/dashboard', { waitUntil:'networkidle' });
await page.locator('#dh-root:not([hidden])').waitFor();
await page.waitForFunction(() => document.querySelectorAll('.dh-document').length === 2);
const mainText = await page.locator('main').innerText();
ok('mission is the first dashboard promise', /Important documents, under control/.test(mainText) && /Send, sign and prove important documents/.test(mainText), mainText.slice(0, 220));
ok('dashboard leads with three plain-language actions', await page.locator('.dh-start-card').count() === 3, await page.locator('.dh-start').innerText());
ok('signing actions enter the intended workflow', await page.locator('.dh-start-card').nth(0).getAttribute('href') === '/sign?mode=invite' && await page.locator('.dh-start-card').nth(1).getAttribute('href') === '/sign?mode=alone', await page.locator('.dh-start').innerText());
ok('open filter shows waiting and in-progress documents', await page.locator('.dh-document').count() === 2 && /Waiting for signatures/.test(await page.locator('#dh-documents').innerText()) && /In progress/.test(await page.locator('#dh-documents').innerText()), await page.locator('#dh-documents').innerText());
ok('relay document counts fill every filter', await page.locator('[data-doc-count="open"]').innerText() === '2' && await page.locator('[data-doc-count="completed"]').innerText() === '1' && await page.locator('[data-doc-count="cancelled"]').innerText() === '1' && await page.locator('[data-doc-count="all"]').innerText() === '4', await page.locator('.dh-filters').innerText());
ok('normal dashboard no longer loads developer operations', overviewRequests === 0 && !/API keys|More tools|Operations/.test(mainText), overviewRequests);
await page.locator('.dh-document').first().click();
ok('open document has actionable owner controls', await page.locator('#dh-document-dialog').isVisible() && await page.locator('[data-pa-action="document-cancel"]').isVisible() && /not recoverable from the relay dashboard/i.test(await page.locator('#dh-document-dialog-body').innerText()), await page.locator('#dh-document-dialog-body').innerText());
page.once('dialog', (dialog) => dialog.accept());
await page.locator('[data-pa-action="document-cancel"]').click();
await page.waitForFunction(() => document.querySelector('#dh-document-dialog-body')?.textContent.includes('closed'));
ok('cancel is owner action and updates measured status', cancelRequests === 1 && /Cancelled/.test(await page.locator('#dh-document-dialog-body').innerText()), await page.locator('#dh-document-dialog-body').innerText());
await page.locator('[data-pa-action="document-close"]').click();
if (process.env.PARAMANT_DASHBOARD_SCREENSHOT_PATH) await page.screenshot({ path:process.env.PARAMANT_DASHBOARD_SCREENSHOT_PATH, fullPage:true });

await page.locator('[data-doc-filter="completed"]').click();
ok('completed filter shows only completed work', await page.locator('.dh-document').count() === 1 && /Completed contract/.test(await page.locator('#dh-documents').innerText()), await page.locator('#dh-documents').innerText());
await page.locator('.dh-document').click();
const completedDialogMetrics = await page.locator('#dh-document-dialog').evaluate((node) => {
  const box = node.getBoundingClientRect();
  const style = getComputedStyle(node);
  const panel = node.querySelector('.dh-doc-dialog-panel');
  const panelStyle = panel ? getComputedStyle(panel) : null;
  return { hidden:node.hidden, display:style.display, position:style.position, zIndex:style.zIndex, background:style.backgroundColor, panelDisplay:panelStyle && panelStyle.display, panelBackground:panelStyle && panelStyle.backgroundColor, top:box.top, left:box.left, bottom:box.bottom, right:box.right, width:box.width, height:box.height, innerWidth, innerHeight };
});
const completedDialogInViewport = !completedDialogMetrics.hidden && completedDialogMetrics.top >= -5 && completedDialogMetrics.left >= -5 && completedDialogMetrics.bottom <= completedDialogMetrics.innerHeight + 5 && completedDialogMetrics.right <= completedDialogMetrics.innerWidth + 5;
ok('completed document exposes proof export with honest storage guidance', completedDialogInViewport && await page.locator('a[download]').getAttribute('href') === '/api/user/documents/env_complete_abcdefghijklmnop/receipt' && /not a plaintext copy/i.test(await page.locator('#dh-document-dialog-body').innerText()), JSON.stringify(completedDialogMetrics));
if (process.env.PARAMANT_DASHBOARD_DETAIL_SCREENSHOT_PATH) {
  await page.waitForTimeout(100);
  await page.locator('#dh-document-dialog').screenshot({ path:process.env.PARAMANT_DASHBOARD_DETAIL_SCREENSHOT_PATH });
}
await page.locator('[data-pa-action="document-close"]').click();
await page.locator('[data-doc-filter="cancelled"]').click();
ok('filenames are rendered as text', await page.locator('.dh-document img').count() === 0 && await page.evaluate(() => !window.dashboardInjected), await page.locator('#dh-documents').innerText());
ok('phone viewport has no horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth) <= 1, await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
ok('document status is fetched once on load', documentRequests === 1, documentRequests);
await page.setViewportSize({ width:1280, height:900 });
ok('desktop uses a three-action row without overflow', await page.evaluate(() => getComputedStyle(document.querySelector('.dh-start')).gridTemplateColumns.split(' ').length === 3 && document.documentElement.scrollWidth - document.documentElement.clientWidth <= 1), await page.evaluate(() => getComputedStyle(document.querySelector('.dh-start')).gridTemplateColumns));

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nuser-dashboard-documents: ${checks.length} checks passed`);
