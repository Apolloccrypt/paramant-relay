// "Probeer het zelf" onder Versturen, zonder account: geen kale inlogpagina.
//
// Prodtoets 06-10-2026, kanttekening 2: de knop op de landing gaat naar
// /parashare, nginx zet daar een auth_request voor en stuurt een bezoeker
// zonder sessie door naar /auth/login?next=/parashare. Daar stond "Welkom
// terug" en verder niets, terwijl de tegel net "Met een gratis account" zei.
// De inlogpagina zegt nu bij die next waarom u er bent en biedt het gratis
// account aan. Bij een gewone inlog (next=/dashboard) blijft dat blok weg.
//
// Echte pagina's, API nagebootst. Ook in WebKit:
//   ~/bin/pw-webkit.sh tests/login-context-versturen.test.mjs
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

async function open(route, next) {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":false}' }));
  await page.goto(ORIGIN + route + '?next=' + encodeURIComponent(next), { waitUntil: 'load' });
  return { page, errors };
}

const CASES = [
  ['/auth/login', '/parashare', /Om te versturen heb je een gratis account nodig/, /Gratis account maken/, '/signup?next=%2Fparashare'],
  ['/en/auth/login', '/en/parashare', /To send a file you need a free account/, /Create a free account/, '/en/signup?next=%2Fen%2Fparashare'],
];

for (const [route, next, sentence, button, href] of CASES) {
  test(`${route}?next=${next}: says why, and offers the free account`, async () => {
    const { page, errors } = await open(route, next);
    const ctx = page.locator('#login-context');
    await ctx.waitFor({ state: 'visible', timeout: 10000 });
    const text = await ctx.innerText();
    const link = page.locator('#login-context-signup');
    const linkText = await link.innerText();
    const linkHref = await link.getAttribute('href');
    const formVisible = await page.locator('#login-form').isVisible();
    await page.close();
    assert.match(text, sentence, text);
    assert.match(linkText, button, linkText);
    assert.equal(linkHref, href);
    assert.ok(formVisible, 'whoever already has an account can still sign in right there');
    assert.deepEqual(errors, []);
  });

  test(`${route}?next=/dashboard: an ordinary sign-in gets no send note`, async () => {
    const { page, errors } = await open(route, route.startsWith('/en') ? '/en/dashboard' : '/dashboard');
    await page.waitForTimeout(300);
    const visible = await page.locator('#login-context').isVisible();
    await page.close();
    assert.equal(visible, false);
    assert.deepEqual(errors, []);
  });
}

test('the homepage button still leads to a free account first, in both languages', () => {
  // Since 25 October 2026 neither homepage has a send tile: the one button is
  // "Probeer het gratis" / "Try it free" and goes to /signup, so a visitor
  // learns that it starts with a free account before any send page.
  const nl = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  assert.ok(nl.includes('<a class="h-cta" href="/signup">Probeer het gratis</a>'), 'index.html: the one button no longer leads to a free account');
  const en = fs.readFileSync(path.join(ROOT, 'en/index.html'), 'utf8');
  assert.ok(en.includes('<a class="h-cta" href="/en/signup">Try it free</a>'), 'en/index.html: the one button no longer leads to a free account');
});
