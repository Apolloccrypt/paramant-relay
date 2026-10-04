// Fase 2 (2026-10-04), de balk na de sessiecheck:
//  SITE-06-A: op een Engelse pagina zette nav-auth.js "Sign in" en "Create
//    account" terug naar de Nederlandse /auth/login en /signup.
//  SITE-02-K: een 429 op /api/user/session/verify gaf een ingelogde klant
//    "Inloggen / Account maken". Nu: opnieuw vragen, en lukt het niet, dan
//    geen "Account maken" maar "Mijn account".
// Run: node --test tests/nav-sessie-fase2.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/' ) p = '/index.html';
  else if (!path.extname(p)) p = fs.existsSync(path.join(ROOT, p + '.html')) ? p + '.html' : p + '/index.html';
  const f = path.join(ROOT, p);
  if (!f.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

async function bar(url, verify) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', verify);
  await page.goto(origin + url, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !/Even kijken|Checking session/.test(document.getElementById('nav-auth')?.textContent || 'x'), null, { timeout: 15000 });
  const links = await page.locator('#nav-auth a').evaluateAll((as) => as.map((a) => [a.textContent.trim(), a.getAttribute('href')]));
  const nav = await page.locator('nav.nav .nav-links .nav-link').evaluateAll((as) => as.map((a) => a.getAttribute('href')));
  await page.close();
  return { links, nav };
}

test('EN uitgelogd: Help, Sign in en Create account blijven Engels', async () => {
  const { links } = await bar('/en/pricing', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":false}' }));
  assert.deepEqual(links, [['Help', '/en/help'], ['Sign in', '/en/auth/login'], ['Create account', '/en/signup']]);
});

test('EN ingelogd: de werkbalk wijst naar de Engelse pagina\'s', async () => {
  const { nav } = await bar('/en/pricing', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' }));
  assert.deepEqual(nav, ['/en/dashboard', '/en/parashare', '/en/sign', '/en/vault', '/en/verify', '/en/account']);
});

test('NL: blijvende 429 op de sessiecheck geeft geen "Account maken"', async () => {
  const { links } = await bar('/pricing', (r) => r.fulfill({ status: 429, headers: { 'Retry-After': '1' }, body: '' }));
  assert.ok(!links.some(([t]) => /Account maken|Inloggen/.test(t)), JSON.stringify(links));
  assert.ok(links.some(([t, h]) => t === 'Mijn account' && h === '/account'), JSON.stringify(links));
});

test('NL: één 429 en daarna ingelogd: de klant ziet de werkbalk', async () => {
  let n = 0;
  const { nav } = await bar('/pricing', (r) => (n++ === 0
    ? r.fulfill({ status: 429, headers: { 'Retry-After': '1' }, body: '' })
    : r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' })));
  assert.deepEqual(nav, ['/dashboard', '/parashare', '/sign', '/vault', '/verify', '/account']);
});

test('home: één 429 en daarna ingelogd: het ingelogde blok verschijnt', async () => {
  let n = 0;
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', (r) => (n++ < 2
    ? r.fulfill({ status: 429, headers: { 'Retry-After': '1' }, body: '' })
    : r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' })));
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => document.documentElement.getAttribute('data-session') === 'in', null, { timeout: 15000 });
  await page.close();
});

// ACCT-09-F (fase 1, P06): na het koppelen van de app op /auth/setup bleef
// "Account maken" in de kop staan. auth-setup.js meldt de nieuwe sessie
// (paramant:session-changed) en nav-auth.js tekent de kop dan opnieuw.
test('/auth/setup: na het koppelen staat er geen "Account maken" meer in de kop', async () => {
  const setupJs = fs.readFileSync(path.join(ROOT, 'js', 'auth-setup.js'), 'utf8');
  assert.match(setupJs, /show\('state-success'\);[\s\S]{0,200}paramant:session-changed/);
  let signedIn = false;
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: signedIn ? '{"authenticated":true,"email":"sandeep@example.com"}' : '{"authenticated":false}' }));
  await page.goto(origin + '/auth/setup', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => /Account maken/.test(document.getElementById('nav-auth')?.textContent || ''), null, { timeout: 15000 });
  signedIn = true;
  await page.evaluate(() => window.dispatchEvent(new Event('paramant:session-changed')));
  await page.waitForFunction(() => /sandeep/.test(document.getElementById('nav-auth')?.textContent || ''), null, { timeout: 15000 });
  const text = await page.locator('#nav-auth').textContent();
  assert.doesNotMatch(text, /Account maken|Inloggen/);
  await page.close();
});
