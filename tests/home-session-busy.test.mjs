// Fase 2 SITE-02-K: a relay that keeps answering 429 on /api/user/session/verify
// is not "signed out". home-auth.js used to give up after two retries and leave
// a signed-in customer on the signed-out pitch with "Create account". Now a
// browser that nav-auth.js marked as signed in (paramant.local.owner, removed on
// sign-out) gets the workbench with one honest line that the check is pending,
// keeps asking, and drops back to the pitch only when the relay says so. A
// visitor without that mark keeps the pitch.
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
const ALIAS = { '/': '/index.html', '/en': '/en/index.html' };

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
    session: document.documentElement.getAttribute('data-session'),
    pitch: document.querySelector('[data-home="out"]').offsetHeight > 0,
    bench: document.querySelector('[data-home="in"]').offsetHeight > 0,
    notice: (() => { const n = document.querySelector('[data-home-notice]'); return n && n.offsetHeight > 0 ? n.textContent.trim() : ''; })(),
  }));
  return { ctx, page, state, read };
}
const busy = (route) => route.fulfill({ status: 429, headers: { 'Retry-After': '1' }, contentType: 'text/html', body: '<html>429</html>' });

test.after(async () => { await browser.close(); server.close(); });

for (const [slug, words] of [['/', /niet controleren/], ['/en', /cannot check your session/]]) {
  test(`${slug}: a signed-in browser under a lasting 429 sees its workbench with a pending line, not the pitch`, async () => {
    const t = await open(slug, { signedInHere: true, verify: busy });
    await t.page.waitForTimeout(4500);
    const s = await t.read();
    assert.equal(s.session, 'in', JSON.stringify(s));
    assert.ok(s.bench && !s.pitch, JSON.stringify(s));
    assert.match(s.notice, words, JSON.stringify(s));
    // The relay recovers and says: not signed in after all. Back to the pitch.
    t.state.verify = (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":false}' });
    await t.page.waitForTimeout(6500);
    const after = await t.read();
    assert.ok(after.pitch && !after.bench && after.session !== 'in', JSON.stringify(after));
    await t.ctx.close();
  });
}

test('/: a visitor this browser never saw signed in keeps the pitch under a lasting 429', async () => {
  const t = await open('/', { signedInHere: false, verify: busy });
  await t.page.waitForTimeout(4500);
  const s = await t.read();
  assert.ok(s.pitch && !s.bench && s.session !== 'in', JSON.stringify(s));
  await t.ctx.close();
});

test('/: the pending workbench turns into the real one once the check answers', async () => {
  const t = await open('/', { signedInHere: true, verify: busy });
  await t.page.waitForTimeout(4500);
  t.state.me = { email: 'anna@kantoor.nl', label: 'Demo Acme' };
  t.state.verify = (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"anna@kantoor.nl"}' });
  await t.page.waitForTimeout(6500);
  const s = await t.read();
  assert.ok(s.bench && !s.pitch && s.notice === '', JSON.stringify(s));
  // The greeting is the name the customer gave, never the local-part of the
  // address (acceptatie 3.1.1, taal 41).
  assert.equal(await t.page.textContent('[data-home-name]'), ', Demo Acme');
  await t.ctx.close();
});

test('/: without a name on the account the heading stays plain, no local-part', async () => {
  const t = await open('/', { signedInHere: true, verify: busy });
  await t.page.waitForTimeout(4500);
  t.state.me = { email: 'afzender@kantoor.nl', label: null };
  t.state.verify = (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"afzender@kantoor.nl"}' });
  await t.page.waitForTimeout(6500);
  const s = await t.read();
  assert.ok(s.bench && !s.pitch, JSON.stringify(s));
  assert.equal(await t.page.textContent('[data-home-name]'), '');
  await t.ctx.close();
});
