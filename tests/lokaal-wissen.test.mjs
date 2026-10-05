// Security review ronde 2 (a2, a3): wat een klant in DEZE browser achterlaat.
// Het concept van /sign (IndexedDB) en de hele documentsleutel K per envelop
// (localStorage) gaan weg bij uitloggen en als een ander account hier inlogt;
// verlopen gegevens gaan weg op elke pagina. Een oude K zonder vervaltijd
// krijgt er een.
// Run: node --test tests/lokaal-wissen.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/' || p === '/pricing') p = '/pricing.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

const json = (route, status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
let who = 'a@example.com';
const ctx = await browser.newContext();
const page = await ctx.newPage();
await page.route('**/api/**', (r) => json(r, 200, { ok: true }));
await page.route('**/api/user/session/verify', (r) => json(r, 200, who ? { authenticated: true, email: who } : { authenticated: false }));
await page.route('**/api/user/logout', (r) => json(r, 200, { success: true }));

const seedDraft = (v, expiresAt) => page.evaluate(([v, expiresAt]) => new Promise((resolve) => {
  const r = indexedDB.open('paramant-sign-draft', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('kv');
  r.onsuccess = () => {
    const t = r.result.transaction('kv', 'readwrite');
    t.objectStore('kv').put({ v, savedAt: Date.now(), expiresAt, m: { iv: new Uint8Array(12), ct: new Uint8Array(4) } }, 'current');
    t.oncomplete = () => { r.result.close(); resolve(true); };
  };
}), [v, expiresAt]);
const draftLeft = () => page.evaluate(() => indexedDB.databases().then((l) => l.some((d) => d.name === 'paramant-sign-draft')
  ? new Promise((resolve) => { const r = indexedDB.open('paramant-sign-draft'); r.onsuccess = () => { try { const g = r.result.transaction('kv').objectStore('kv').get('current'); g.onsuccess = () => { r.result.close(); resolve(!!g.result); }; } catch { r.result.close(); resolve(false); } }; })
  : false));
const keys = () => page.evaluate(() => Object.fromEntries(Object.keys(localStorage).filter((k) => k.startsWith('paramant.cosign.key.v1:')).map((k) => [k, localStorage.getItem(k)])));
const settle = () => page.waitForTimeout(700);

// 1. Sweep on any page: expired K and an expired or old-format draft go; a bare K gets an expiry.
await page.goto(ORIGIN + '/pricing', { waitUntil: 'domcontentloaded' });
await page.evaluate(() => {
  localStorage.setItem('paramant.cosign.key.v1:OUD', '#doc=v1.oud');
  localStorage.setItem('paramant.cosign.key.v1:VERLOPEN', JSON.stringify({ f: '#doc=v1.x', exp: Date.now() - 1000 }));
  localStorage.setItem('paramant.cosign.key.v1:GELDIG', JSON.stringify({ f: '#doc=v1.y', exp: Date.now() + 864e5 }));
});
await seedDraft(1, 0);
await page.reload({ waitUntil: 'domcontentloaded' });
await settle();
const swept = { keys: await keys(), draft: await draftLeft() };

// 2. Same account again: nothing goes. Then another account signs in here: everything goes.
await seedDraft(2, Date.now() + 3600e3);
await page.reload({ waitUntil: 'domcontentloaded' });
await settle();
const sameAccount = { keys: Object.keys(await keys()).length, draft: await draftLeft() };
who = 'b@example.com';
await page.reload({ waitUntil: 'domcontentloaded' });
await settle();
const otherAccount = { keys: Object.keys(await keys()).length, draft: await draftLeft() };

// 3. Sign out from the menu: everything goes.
await page.evaluate(() => localStorage.setItem('paramant.cosign.key.v1:NIEUW', JSON.stringify({ f: '#doc=v1.z', exp: Date.now() + 864e5 })));
await seedDraft(2, Date.now() + 3600e3);
await page.locator('.nav-user-trigger').click();
await page.locator('#nav-signout').click();
await page.waitForLoadState('domcontentloaded');
await settle();
who = '';
const signedOut = { keys: Object.keys(await keys()).length, draft: await draftLeft() };
// 4. Review #555, M4: K lives at most 24 hours, and a session that ran out
// (no sign-out) takes K with it. A K from before (31 days) is cut to 24 hours.
const ctx2 = await browser.newContext();
const page2 = await ctx2.newPage();
let who2 = 'c@example.com';
await page2.route('**/api/**', (r) => json(r, 200, { ok: true }));
await page2.route('**/api/user/session/verify', (r) => json(r, 200, who2 ? { authenticated: true, email: who2 } : { authenticated: false }));
await page2.goto(ORIGIN + '/pricing', { waitUntil: 'domcontentloaded' });
await page2.evaluate(() => localStorage.setItem('paramant.cosign.key.v1:LANG', JSON.stringify({ f: '#doc=v1.lang', exp: Date.now() + 31 * 864e5 })));
await page2.reload({ waitUntil: 'domcontentloaded' });
await page2.waitForTimeout(700);
const capped = await page2.evaluate(() => localStorage.getItem('paramant.cosign.key.v1:LANG'));
who2 = '';
await page2.reload({ waitUntil: 'domcontentloaded' });
await page2.waitForTimeout(700);
const afterExpiry = await page2.evaluate(() => Object.keys(localStorage).filter((k) => k.startsWith('paramant.cosign.key.v1:')).length);
await ctx2.close();
await ctx.close();

test('een sleutel leeft hoogstens 24 uur', () => {
  const rec = JSON.parse(capped);
  assert.equal(rec.f, '#doc=v1.lang');
  assert.ok(rec.exp <= Date.now() + 864e5 + 5000, 'expiry cut to 24 hours: ' + new Date(rec.exp).toISOString());
});

test('een verlopen sessie wist de sleutels ook, zonder uitloggen', () => {
  assert.equal(afterExpiry, 0);
});

test('op elke pagina: verlopen sleutels en concepten weg, een oude sleutel krijgt een vervaltijd', () => {
  assert.equal(swept.keys['paramant.cosign.key.v1:VERLOPEN'], undefined);
  assert.ok(swept.keys['paramant.cosign.key.v1:GELDIG']);
  const oud = JSON.parse(swept.keys['paramant.cosign.key.v1:OUD']);
  assert.equal(oud.f, '#doc=v1.oud');
  assert.ok(oud.exp > Date.now() && oud.exp <= Date.now() + 864e5 + 5000);
  assert.equal(swept.draft, false, 'een concept in het oude, onversleutelde formaat is gewist');
});

test('hetzelfde account houdt zijn gegevens, een ander account niet', () => {
  assert.equal(sameAccount.keys, 2);
  assert.equal(sameAccount.draft, true);
  assert.equal(otherAccount.keys, 0, 'de sleutels van het vorige account zijn weg');
  assert.equal(otherAccount.draft, false, 'het concept van het vorige account is weg');
});

test('uitloggen wist concept en sleutels', () => {
  assert.equal(signedOut.keys, 0);
  assert.equal(signedOut.draft, false);
});
