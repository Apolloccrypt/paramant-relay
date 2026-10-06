// The English dashboard keeps its reader on English pages.
//
// Acceptatie 3.1.1, betalen punt 5: an English buyer landed on /en/dashboard
// and its links led to Dutch pages: /sign?mode=invite (the empty list's
// button), /account#passkey-section (the passkey pop-up), and /developer, which
// has no English copy. This renders /en/dashboard with the APIs mocked and
// reads every link on the page, the ones dashboard.js writes included.
//
// Allowed: /en/..., /api/..., the language switch (hreflang="nl"), mailto and
// anchors. /developer only with hreflang="nl" and a label that says it is in
// Dutch.

import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const aliases = { '/en/dashboard': '/en/dashboard.html', '/dashboard': '/dashboard.html' };

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
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }
const json = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function links(prefix) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (route) => json(route, {}));
  await page.route('**/api/user/me', (route) => json(route, {
    email: 'demo@example.com', label: null, plan: 'pro', plan_parasign: 'pro', plan_parasend: 'pro',
    paid_until_parasign: new Date(Date.now() + 40 * 86400000).toISOString(), paid_until_parasend: null,
    created_at: '2026-01-01T00:00:00.000Z', backup_codes_remaining: 3,
    session_expires_at: new Date(Date.now() + 3600000).toISOString(), usage_purpose: 'other',
  }));
  await page.route('**/api/user/documents**', (route) => json(route, { documents: [] }));
  await page.route('**/api/user/account/webauthn/credentials', (route) => json(route, { passkeys: [] }));
  await page.goto(ORIGIN + prefix + '/dashboard', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#dh-root.dh-loaded', { timeout: 10000 });
  await page.waitForSelector('.dh-empty-cta', { timeout: 10000 }).catch(() => {});
  await page.waitForSelector('a.dh-pm-item', { state: 'attached', timeout: 5000 }).catch(() => {});
  const all = await page.evaluate(() => [...document.querySelectorAll('a[href]')].map((a) => ({
    href: a.getAttribute('href'), hreflang: a.getAttribute('hreflang'), text: a.textContent.replace(/\s+/g, ' ').trim(),
  })));
  await page.close();
  return all;
}

const en = await links('/en');
const written = en.filter((l) => /\/sign\?mode=invite|#passkey-section/.test(l.href || ''));
ok('the links dashboard.js writes were rendered (empty-list button and passkey item)', written.length >= 2, JSON.stringify(written));
const dutch = en.filter((l) => {
  const h = l.href || '';
  if (!h.startsWith('/')) return false; // mailto:, #anchor, https://
  if (h.startsWith('/en/') || h === '/en' || h.startsWith('/api/')) return false;
  if (/\.(css|js|svg|png|ico)(\?|$)/.test(h)) return false;
  if (l.hreflang === 'nl' && (h === '/dashboard' || h === '/developer')) return false;
  return true;
});
ok('/en/dashboard links to no Dutch page', dutch.length === 0, JSON.stringify(dutch));
const dev = en.filter((l) => l.href === '/developer');
ok('the Dutch-only /developer says so on the English page', dev.length > 0 && dev.every((l) => /in Dutch/.test(l.text) && l.hreflang === 'nl'), JSON.stringify(dev));

// The Dutch page keeps its own paths.
const nl = await links('');
ok('/dashboard links stay Dutch', !nl.some((l) => /^\/en\/(sign|account|verify|co-sign)/.test(l.href || '')), JSON.stringify(nl.filter((l) => (l.href || '').startsWith('/en/'))));
ok('/dashboard writes /sign?mode=invite', nl.some((l) => l.href === '/sign?mode=invite'), '');

await browser.close();
server.close();

for (const c of checks) console.log(`${c.pass ? 'ok' : 'FAIL'} - ${c.name}${c.pass ? '' : ` :: ${c.detail}`}`);
const failed = checks.filter((c) => !c.pass);
console.log(`${checks.length} checks, ${failed.length} failed`);
if (failed.length) process.exit(1);
