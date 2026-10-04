// Na inloggen met een oudere authenticator-app: geen jargon, en de klant gaat
// vanzelf terug naar het document (hertest 2026-10-04, T5-5).
//
// De hertest: de melding sprak over "SHA-1-codes" en "een SHA-256-app zoals
// Raivo", de knop heette "Verder naar uw account" terwijl hij naar de
// teken-link ging, en zonder klik bleef de klant op /auth/login staan.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/auth/login') p = '/auth/login.html';
  if (p === '/en/auth/login') p = '/en/auth/login.html';
  if (p === '/co-sign' || p === '/en/co-sign') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>doc</title><p>het document</p>'); }
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

for (const [route, button] of [['/auth/login', /Verder naar het document/], ['/en/auth/login', /Continue to the document/]]) {
  test(`${route}: de tip na een oudere app is zonder jargon en gaat vanzelf door`, async () => {
    const page = await browser.newPage();
    await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
    await page.route('**/api/user/login', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"totp_algorithm":"sha1"}' }));
    const next = (route.startsWith('/en') ? '/en' : '') + '/co-sign?env=env_demo_tipxyz&p=0&t=' + 't'.repeat(43);
    await page.goto(ORIGIN + route + '?next=' + encodeURIComponent(next), { waitUntil: 'domcontentloaded' });
    await page.locator('#email').fill('sandeep@example.com');
    await page.locator('#show-code-btn').click();
    await page.locator('#totp').fill('123456');
    await page.locator('#submit-btn').click();
    await page.locator('#sha1-notice:not([hidden])').waitFor({ timeout: 10000 });
    const text = await page.locator('#sha1-notice').innerText();
    const btn = await page.locator('#sha1-continue').innerText();
    const moved = await page.waitForURL(/\/co-sign\?env=env_demo_tipxyz/, { timeout: 15000 }).then(() => true, () => false);
    await page.close();
    assert.doesNotMatch(text, /SHA-1|SHA-256|Raivo|Aegis/, text);
    assert.match(btn, button, btn);
    assert.ok(moved, 'de klant gaat vanzelf door naar het document');
  });
}
