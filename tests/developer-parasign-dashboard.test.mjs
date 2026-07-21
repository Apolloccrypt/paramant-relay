// Real Chromium coverage for the ParaSign-only developer dashboard.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/developer') pathname = '/developer.html';
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

let keyList = [{ kid:'psk_demo_1', key_masked:'psk_live_abc...1234', label:'Production service', mode:'live', active:true }];
let createBody = null;
let revokeBody = null;
let toolsRequests = 0;
await page.route('**/api/user/developer/snapshot', (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({
  email:'developer@example.com', plan:'pro', quota:{ signs:18, transfers:400, caps:{ signs:100, transfers:500 } },
  audit:[{ event_type:'envelope_created', ts:Date.now() }, { event_type:'transfer_sent', ts:Date.now() - 1000 }],
}) }));
await page.route('**/api/user/developer/tools', (route) => { toolsRequests++; return route.fulfill({ status:500, body:'' }); });
await page.route('**/api/user/developer/parasign-keys', async (route) => {
  const request = route.request();
  if (request.method() === 'POST') {
    createBody = request.postDataJSON();
    keyList.push({ kid:'psk_demo_2', key_masked:'psk_live_def...5678', label:createBody.label, mode:'live', active:true });
    return route.fulfill({ status:201, contentType:'application/json', body:JSON.stringify({ key:'psk_live_demo_secret', kid:'psk_demo_2', mode:'live', plan:'pro' }) });
  }
  if (request.method() === 'DELETE') {
    revokeBody = request.postDataJSON();
    keyList = keyList.map((key) => key.kid === revokeBody.kid ? { ...key, active:false } : key);
    return route.fulfill({ status:200, contentType:'application/json', body:'{"ok":true}' });
  }
  return route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ keys:keyList }) });
});

const checks = [];
function ok(name, condition, detail='') { checks.push({ name, pass:!!condition, detail:String(detail) }); }
await page.goto(ORIGIN + '/developer', { waitUntil:'networkidle' });
const bodyText = await page.locator('main').innerText();
ok('dashboard is ParaSign-only', /ParaSign API/.test(bodyText) && !/What happens to a transfer|Tools · status|S3|database backup/i.test(bodyText), bodyText.slice(0, 240));
ok('dashboard does not request the obsolete tool catalogue', toolsRequests === 0, toolsRequests);
ok('signing usage ignores transfer usage', await page.locator('#sign-used').innerText() === '18' && !/400/.test(await page.locator('[aria-labelledby="usage-title"]').innerText()), await page.locator('[aria-labelledby="usage-title"]').innerText());
ok('existing ParaSign key is visible', /psk_live_abc/.test(await page.locator('#psk-keys').innerText()), await page.locator('#psk-keys').innerText());
ok('phone viewport has no horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth) <= 1, await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
if (process.env.PARAMANT_SCREENSHOT_PATH) await page.screenshot({ path:process.env.PARAMANT_SCREENSHOT_PATH, fullPage:true });

await page.locator('#psk-new').click();
await page.locator('#psk-label').fill('Invoice integration');
await page.locator('#psk-generate').click();
await page.locator('[data-view="secret"]:not([hidden])').waitFor();
ok('key creation sends only the user label', createBody && createBody.label === 'Invoice integration' && Object.keys(createBody).length === 1, JSON.stringify(createBody));
ok('new secret is shown once in the modal', await page.locator('#psk-secret').innerText() === 'psk_live_demo_secret', await page.locator('#psk-secret').innerText());
ok('new secret is not persisted in browser storage', await page.evaluate(() => !JSON.stringify(localStorage).includes('psk_live_demo_secret') && !JSON.stringify(sessionStorage).includes('psk_live_demo_secret')), 'storage clean');
await page.locator('[data-view="secret"] [data-close]').click();
ok('closing the modal clears the secret from the DOM', await page.locator('#psk-secret').innerText() === '', await page.locator('#psk-secret').innerText());

page.on('dialog', (dialog) => dialog.accept());
await page.locator('[data-revoke="psk_demo_1"]').click();
await page.waitForFunction(() => document.querySelector('[data-revoke="psk_demo_1"]') === null);
ok('revoke is scoped to the selected ParaSign key', revokeBody && revokeBody.kid === 'psk_demo_1', JSON.stringify(revokeBody));

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\ndeveloper-parasign-dashboard: ${checks.length} checks passed`);
