// Matrix DASH-27-N (original fase-1 harness, review #565): the dashboard links
// every customer to /developer, and for a customer without developer access
// /api/user/developer/snapshot answers 404 (developerGate). The page then said
// "Verbruik wordt geladen." for ever. Now it says where the usage is.
// Chromium; in WebKit via ~/bin/pw-webkit.sh.
// Run: node --test tests/developer-zonder-toegang.test.mjs
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
  if (p === '/developer') p = '/developer.html';
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

test('/developer zonder ontwikkelaarstoegang blijft niet op "Verbruik wordt geladen."', async () => {
  const ctx = await browser.newContext();
  await ctx.route('https://**/**', (r) => r.abort());
  await ctx.route('**/api/user/account', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"email":"demo@example.com"}' }));
  await ctx.route('**/api/user/developer/**', (r) => r.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"not_found"}' }));
  await ctx.route('**/api/user/**', (r) => r.fallback());
  const page = await ctx.newPage();
  await page.goto(origin + '/developer', { waitUntil: 'load' });
  const note = page.locator('#usage-note');
  await page.waitForFunction(() => !/wordt geladen/.test(document.getElementById('usage-note').textContent), null, { timeout: 15000 });
  assert.match(await note.innerText(), /staat voor uw account op het dashboard/);
  assert.equal(await note.locator('a').getAttribute('href'), '/dashboard');
  await ctx.close();
});
