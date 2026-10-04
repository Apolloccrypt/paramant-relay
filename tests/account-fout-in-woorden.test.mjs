// /account zegt een mislukte lading in woorden, nooit "(HTTP 429)"
// (hertest 2026-10-04, T5-1). De hertest zag "De geregistreerde sleutels
// konden niet worden geladen (HTTP 429)" en hetzelfde bij de passkeys.
// Echte pagina, API nagebootst: de sleutels en passkeys geven 429 en 503.
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
const aliases = { '/account': '/account.html', '/en/account': '/en/account.html' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  p = aliases[p] || p;
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
const json = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function open(route, status) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (r) => json(r, {}));
  await page.route('**/api/user/account', (r) => json(r, { email: 'sandeep@example.com', plan: 'pro', created_at: '2026-01-01T00:00:00.000Z', sessions: [], backup_codes_remaining: 0 }));
  await page.route('**/api/user/account/signing-key', (r) => json(r, { error: 'rate_limited' }, status));
  await page.route('**/api/user/account/webauthn/credentials', (r) => json(r, { error: 'rate_limited' }, status));
  await page.goto(ORIGIN + route, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const a = document.getElementById('signing-empty'), b = document.getElementById('account-passkey-empty');
    return a && b && /\S/.test(a.textContent) && /\S/.test(b.textContent) && !/laden\.\.\.|Loading/i.test(a.textContent + b.textContent);
  }, null, { timeout: 15000 }).catch(() => {});
  const text = await page.evaluate(() => [document.getElementById('signing-empty')?.textContent || '', document.getElementById('account-passkey-empty')?.textContent || '']);
  await page.close();
  return text;
}

for (const [route, status, want] of [['/account', 429, /te veel verzoeken/], ['/en/account', 429, /too many requests/], ['/account', 503, /storing bij ons/]]) {
  test(`${route} bij ${status}: een zin, geen statuscode`, async () => {
    const [keys, passkeys] = await open(route, status);
    for (const t of [keys, passkeys]) {
      assert.doesNotMatch(t, /HTTP|\b4\d\d\b|\b5\d\d\b/, t);
      assert.match(t, want, t);
    }
  });
}
