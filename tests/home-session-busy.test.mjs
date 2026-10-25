// Fase 2 SITE-02-K: a relay that keeps answering 429 on /api/user/session/verify
// is not "signed out". home-auth.js used to give up after two retries and leave
// a signed-in customer on the signed-out pitch with "Create account".
//
// Since 25 October 2026 the homepage draws no workbench: a signed-in visitor
// goes on to "Je documenten" on /dashboard. So a browser that nav-auth.js
// marked as signed in (paramant.local.owner, removed on sign-out) is sent to
// /dashboard under a lasting 429 as well, never shown the pitch, and
// /dashboard then says in words that it is busy, with a retry, and that the
// reader is still signed in. A visitor without that mark keeps the pitch.
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json' };
const ALIAS = { '/': '/index.html', '/en': '/en/index.html', '/dashboard': '/dashboard.html', '/en/dashboard': '/en/dashboard.html' };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const file = path.join(ROOT, ALIAS[url.pathname] || url.pathname);
  if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ executablePath: EXE });

async function open(slug, { signedInHere, verify }) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  if (signedInHere) await page.addInitScript(() => { try { localStorage.setItem('paramant.local.owner', 'abc'); } catch (e) { /* off */ } });
  const state = { verify };
  await page.route('**/api/**', (route) => {
    if (route.request().url().includes('/api/user/session/verify')) return state.verify(route);
    if (route.request().url().includes('/api/user/me') && state.me) return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(state.me) });
    return route.fulfill({ status: 429, headers: { 'Retry-After': '1' }, body: '' });
  });
  await page.goto(ORIGIN + slug);
  const read = () => page.evaluate(() => ({
    path: location.pathname,
    session: document.documentElement.getAttribute('data-session'),
    pitch: !!document.querySelector('.h-hero') && document.querySelector('.h-hero').offsetHeight > 0
      && getComputedStyle(document.querySelector('.h-hero')).visibility !== 'hidden',
    error: (() => { const n = document.getElementById('dh-error'); return n && n.offsetHeight > 0 ? n.innerText.trim() : ''; })(),
  }));
  return { ctx, page, state, read };
}
const busy = (route) => route.fulfill({ status: 429, headers: { 'Retry-After': '1' }, contentType: 'text/html', body: '<html>429</html>' });

test.after(async () => { await browser.close(); server.close(); });

for (const [slug, target, words] of [['/', '/dashboard', /Even te veel verzoeken tegelijk.*Je bent nog ingelogd/s], ['/en', '/en/dashboard', /Too many requests at once.*You are still signed in/s]]) {
  test(`${slug}: a signed-in browser under a lasting 429 goes to its documents, not the pitch`, async () => {
    const t = await open(slug, { signedInHere: true, verify: busy });
    // Before the answer the pitch is not shown at all.
    const early = await t.read();
    assert.ok(!early.pitch, 'the pitch flashed for a signed-in browser: ' + JSON.stringify(early));
    await t.page.waitForURL(ORIGIN + target, { timeout: 10000, waitUntil: 'commit' });
    await t.page.waitForSelector('#dh-error:not([hidden])', { timeout: 10000 });
    const s = await t.read();
    assert.equal(s.path, target, JSON.stringify(s));
    assert.match(s.error, words, JSON.stringify(s));
    assert.equal(await t.page.locator('#dh-error-retry').isVisible(), true, 'a busy server offers a retry');
    assert.equal(await t.page.locator('#dh-error-login').isVisible(), false, 'a busy server does not send the reader to sign in');
    await t.ctx.close();
  });
}

test('/: a visitor this browser never saw signed in keeps the pitch under a lasting 429', async () => {
  const t = await open('/', { signedInHere: false, verify: busy });
  await t.page.waitForTimeout(4500);
  const s = await t.read();
  assert.ok(s.pitch && s.path === '/' && s.session !== 'in', JSON.stringify(s));
  await t.ctx.close();
});

test('/: a browser with the mark that the server says is signed out gets the pitch back', async () => {
  const t = await open('/', { signedInHere: true, verify: (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":false}' }) });
  await t.page.waitForTimeout(1500);
  const s = await t.read();
  assert.ok(s.pitch && s.path === '/' && s.session === null, JSON.stringify(s));
  await t.ctx.close();
});

test('/: once the check answers signed in, the documents open, and the heading carries no local-part', async () => {
  const t = await open('/', { signedInHere: true, verify: busy });
  t.state.me = { email: 'afzender@kantoor.nl', label: null };
  t.state.verify = (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"afzender@kantoor.nl"}' });
  await t.page.waitForURL(ORIGIN + '/dashboard', { timeout: 10000, waitUntil: 'commit' });
  await t.page.waitForSelector('#dh-root:not([hidden])', { timeout: 10000 });
  // The greeting used to be the local-part of the address ("Je documenten,
  // afzender."), acceptatie 3.1.1 taal 41. The heading is plain now.
  assert.equal((await t.page.textContent('#dh-h1')).trim(), 'Je documenten.');
  await t.ctx.close();
});

test('/dashboard: the account behind the initials uses the name the customer gave', async () => {
  const t = await open('/dashboard', { signedInHere: true, verify: busy });
  t.state.me = { email: 'anna@kantoor.nl', label: 'Demo Acme' };
  await t.page.reload();
  await t.page.waitForSelector('#dh-root:not([hidden])', { timeout: 10000 });
  assert.equal((await t.page.textContent('#pa-avatar')).trim(), 'DA');
  assert.equal(await t.page.getAttribute('#pa-avatar', 'href'), '/account');
  await t.ctx.close();
});
