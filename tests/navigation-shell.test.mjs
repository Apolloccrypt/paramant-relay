import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2' };
const aliases = { '/':'/index.html', '/dashboard':'/dashboard.html', '/developer':'/developer.html' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  pathname = aliases[pathname] || pathname;
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
const checks = [];
function ok(name, condition, detail='') { checks.push({ name, pass:!!condition, detail:String(detail) }); }

const publicPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await publicPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:401, contentType:'application/json', body:'{"authenticated":false}' }));
await publicPage.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
await publicPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Product,Security,Pricing,Docs');
const publicDesktop = await publicPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('public navigation has four clear destinations', JSON.stringify(publicDesktop) === JSON.stringify(['Product','Security','Pricing','Docs']), publicDesktop.join(', '));
await publicPage.locator('#nav-hamburger').click();
const publicMobile = await publicPage.locator('#nav-mobile a').allInnerTexts();
ok('public mobile menu matches desktop without legacy groups', publicMobile.map((item) => item.toLowerCase()).join(',') === publicDesktop.map((item) => item.toLowerCase()).join(',') && await publicPage.locator('#nav-mobile .nav-mobile-group').count() === 0, publicMobile.join(', '));
ok('public mobile menu fits the phone viewport', await publicPage.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), await publicPage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
await publicPage.close();

const appPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await appPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await appPage.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"email":"demo@example.com","label":"Demo","plan":"pro","created_at":"2026-06-01T10:00:00.000Z","backup_codes_remaining":8,"session_expires_at":"2026-07-21T16:00:00.000Z","usage_purpose":"organisation"}' }));
await appPage.route('**/api/user/documents', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"documents":[]}' }));
await appPage.route('**/api/user/account/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await appPage.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
await appPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Documents,Send,Sign,Verify,Settings');
const appDesktop = await appPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('signed-in navigation follows document work', JSON.stringify(appDesktop) === JSON.stringify(['Documents','Send','Sign','Verify','Settings']), appDesktop.join(', '));
ok('dashboard removes its duplicate marketing drawer', await appPage.locator('#nav-mobile-marketing').count() === 0 && await appPage.locator('nav.nav .nav-links').count() === 1, await appPage.locator('nav.nav .nav-links').count());
await appPage.locator('#nav-hamburger').click();
const appMobile = await appPage.locator('#nav-mobile a').allInnerTexts();
ok('signed-in mobile menu matches the workspace', appMobile.map((item) => item.toLowerCase()).join(',') === appDesktop.map((item) => item.toLowerCase()).join(','), appMobile.join(', '));
ok('developer tools are settings, not a sixth product', await appPage.locator('.nav-user-menu a', { hasText:'Developer settings' }).count() === 1 && !appMobile.includes('Developer settings'), appMobile.join(', '));
await appPage.close();

const developerPage = await browser.newPage({ viewport:{ width:1280, height:900 } });
await developerPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await developerPage.route('**/api/developer/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await developerPage.goto(ORIGIN + '/developer', { waitUntil:'domcontentloaded' });
await developerPage.waitForFunction(() => Array.from(document.querySelectorAll('nav.nav .nav-links .nav-link')).map((node) => node.textContent).join(',') === 'Documents,Send,Sign,Verify,Settings');
const developerNav = await developerPage.locator('nav.nav .nav-links .nav-link').allInnerTexts();
ok('developer page is presented as settings inside the same shell', await developerPage.title() === 'Developer settings · Paramant' && developerNav.map((item) => item.toLowerCase()).join(',') === 'documents,send,sign,verify,settings', await developerPage.title());
await developerPage.close();

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
server.closeAllConnections();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nnavigation-shell: ${checks.length} checks passed`);
