// Real browser coverage for two P10 cells of the fase-1 matrix.
//
// API-01-A: the /docs sidebar. Clicking a link must light THAT link. It used
// to compare window.scrollY with h2.offsetTop, which is relative to the offset
// parent and not the page, and it ignored the h3 headings and span anchors the
// sidebar also links to: 17 of the 37 links never lit up, on /docs and /en/docs.
//
// API-05-A: the developer dashboard put the unified legacy plan ("community")
// next to a fresh ParaSign key on a Pro account. It now shows the key's
// ParaSign tier (plan_parasign from the mint), and a 403 on the key list is
// said in words instead of "could not be loaded".
//
// Runs in Chromium; ~/bin/pw-webkit.sh runs the same file in WebKit.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };
const ROUTES = { '/docs': '/docs.html', '/en/docs': '/en/docs.html', '/developer': '/developer.html' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (ROUTES[pathname]) pathname = ROUTES[pathname];
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

for (const pth of ['/docs', '/en/docs']) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route((u) => !u.href.startsWith(ORIGIN), (route) => route.abort());
  await page.goto(ORIGIN + pth, { waitUntil: 'load' });
  const hrefs = await page.$$eval('.sidebar a[href^="#"]', (as) => as.map((a) => a.getAttribute('href')));
  const wrong = [];
  for (const href of hrefs) {
    await page.locator(`.sidebar a[href="${href}"]`).first().click();
    await page.waitForTimeout(250);
    const r = await page.evaluate((h) => ({
      exists: !!document.getElementById(h.slice(1)),
      active: [...document.querySelectorAll('.sidebar a.active')].map((a) => a.getAttribute('href')),
    }), href);
    if (!r.exists || !r.active.includes(href)) wrong.push(`${href} (active: ${r.active.join(',') || 'none'})`);
  }
  ok(`${pth}: every sidebar link lights up when clicked (${hrefs.length} links)`, hrefs.length > 20 && wrong.length === 0, wrong.slice(0, 6).join(' | '));
  // Scrolling by hand afterwards follows the page again.
  await page.mouse.move(700, 450);
  for (let i = 0; i < 40; i++) { await page.mouse.wheel(0, -5000); await page.waitForTimeout(20); }
  await page.waitForTimeout(400);
  const top = await page.evaluate(() => [...document.querySelectorAll('.sidebar a.active')].map((a) => a.getAttribute('href')));
  ok(`${pth}: back at the top the first section is lit`, top.length >= 1 && top[0] === (await page.$eval('.sidebar a[href^="#"]', (a) => a.getAttribute('href'))), top.join(','));
  await page.close();
}

{
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route((u) => !u.href.startsWith(ORIGIN), (route) => route.abort());
  await page.route('**/api/user/developer/snapshot', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    email: 'developer@example.com', tiers: { parasend: 'free', parasign: 'pro' }, quota: { signs: 1, transfers: 0, caps: { signs: 100, transfers: 50 } }, audit: [],
  }) }));
  let listStatus = 200;
  await page.route('**/api/user/developer/parasign-keys', (route) => {
    if (route.request().method() === 'POST') {
      // What the relay answers for a Pro ParaSign key on an account whose
      // legacy plan is community (relay.js mintParasignKey).
      return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ ok: true, key: 'psk_live_demo', kid: 'k_demo', mode: 'live', plan: 'community', plan_parasign: 'pro' }) });
    }
    if (listStatus === 403) return route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'parasign_not_entitled', message: 'This account is not entitled to the ParaSign API.' }) });
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ keys: [] }) });
  });
  await page.goto(ORIGIN + '/developer', { waitUntil: 'networkidle' });
  await page.locator('#psk-new').click();
  await page.locator('#psk-label').fill('demo');
  await page.locator('#psk-generate').click();
  await page.locator('[data-view="secret"]:not([hidden])').waitFor();
  const meta = await page.locator('#psk-meta').innerText();
  ok('the new key shows its ParaSign tier, not the legacy plan', /abonnement pro/.test(meta) && !/community/.test(meta), meta);
  await page.close();

  const p2 = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await p2.route((u) => !u.href.startsWith(ORIGIN), (route) => route.abort());
  await p2.route('**/api/user/developer/snapshot', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"tiers":{"parasign":"free"},"quota":{"caps":{}},"audit":[]}' }));
  listStatus = 403;
  await p2.route('**/api/user/developer/parasign-keys', (route) => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'parasign_not_entitled', message: 'This account is not entitled to the ParaSign API.' }) }));
  await p2.goto(ORIGIN + '/developer', { waitUntil: 'networkidle' });
  const list = await p2.locator('#psk-keys').innerText();
  ok('a 403 on the key list is said in words', /geen toegang tot de API voor Ondertekenen/.test(list) && !/konden de API-sleutels niet ophalen/.test(list), list);
  await p2.close();
}

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\napi-docs-browser: ${checks.length} checks passed`);
