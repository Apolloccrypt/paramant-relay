// /get for a receiver whose link did not arrive whole.
//
// A token that is not 48 hex characters used to reach the relay, fall through
// to its auth gate and come back as "Download failed: HTTP 401" next to
// "Open your dashboard", which is a customer screen shown to somebody who is
// not a customer. The paste box sent any text to new URL(), which never fails
// on plain text, so "hello" navigated to /hello and a 404. Enter did nothing,
// and a link to another site was followed.
//
// Run: node --test tests/get-invalid-link.test.mjs
//      (PLAYWRIGHT_CHROMIUM_PATH=... to pick a browser)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const GIL_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const GIL_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const GIL_MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };
const GIL_KEY = 'A'.repeat(59); // 44 bytes of base64url: a key of the right length
const GIL_TOKEN = 'b'.repeat(48);

let gilServer;
let gilBrowser;
let GIL_ORIGIN;
const gilRelayCalls = [];

before(async () => {
  gilServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const rel = url.pathname === '/get' ? '/get.html' : url.pathname === '/en/get' ? '/en/get.html' : url.pathname;
    const file = path.join(GIL_ROOT, rel);
    if (!file.startsWith(GIL_ROOT)) { res.writeHead(403); return res.end('no'); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': GIL_MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  await new Promise((r) => gilServer.listen(0, '127.0.0.1', r));
  GIL_ORIGIN = `http://localhost:${gilServer.address().port}`;
  gilBrowser = await chromium.launch({ headless: true, ...(GIL_EXE ? { executablePath: GIL_EXE } : {}) });
});

after(async () => {
  if (gilBrowser) await gilBrowser.close();
  if (gilServer) await new Promise((r) => gilServer.close(r));
});

async function open(url, relayStatus = 401) {
  const page = await gilBrowser.newPage();
  await page.route('https://*.paramant.app/**', (route) => {
    gilRelayCalls.push(route.request().url());
    return route.fulfill({ status: relayStatus, contentType: 'application/json', body: '{"error":"x"}' });
  });
  await page.goto(url);
  await page.waitForLoadState('domcontentloaded');
  return page;
}

async function activeStep(page) {
  await page.waitForFunction(() => {
    const a = document.querySelector('.step.active');
    return a && a.id !== 'step-loading';
  }, null, { timeout: 5000 });
  return page.evaluate(() => document.querySelector('.step.active').id);
}

async function visibleText(page) {
  return page.evaluate(() => document.querySelector('.step.active').innerText);
}

// Both languages: /get is Dutch, /en/get keeps the original English words.
const LANGS = [
  { name: 'nl', pre: '', invalid: /ongeldig of onvolledig/i,
    bad: /lijkt geen geldige link om iets te ontvangen/, foreign: /geen link van .*, dus hij wordt hier niet geopend/ },
  { name: 'en', pre: '/en', invalid: /invalid or incomplete/i,
    bad: /does not look like a valid receive link/, foreign: /not a .* link/ },
];

for (const L of LANGS) {
  for (const [name, query] of [
    ['a token cut short', `t=${GIL_TOKEN.slice(0, 30)}#${GIL_KEY}`],
    ['a token with capitals', `t=${GIL_TOKEN.toUpperCase()}#${GIL_KEY}`],
    ['a token without the key after #', `t=${GIL_TOKEN}`],
    ['a key cut short', `t=${GIL_TOKEN}#${GIL_KEY.slice(0, 20)}`],
  ]) {
    test(`/get with ${name} says the link is invalid or incomplete, and never asks the relay (${L.name})`, async () => {
      const before = gilRelayCalls.length;
      const page = await open(`${GIL_ORIGIN}${L.pre}/get?${query}`);
      try {
        assert.equal(await activeStep(page), 'step-invalid');
        const text = await visibleText(page);
        assert.match(text, L.invalid);
        assert.doesNotMatch(text, /HTTP \d{3}/);
        assert.doesNotMatch(text, /dashboard/i);
        assert.equal(gilRelayCalls.length, before, 'no request reached the relay');
      } finally { await page.close(); }
    });
  }

  test(`/get with a well-formed token the relay refuses (401) also says invalid, not HTTP 401 (${L.name})`, async () => {
    const page = await open(`${GIL_ORIGIN}${L.pre}/get?t=${GIL_TOKEN}#${GIL_KEY}`, 401);
    try {
      assert.equal(await activeStep(page), 'step-invalid');
      const text = await visibleText(page);
      assert.doesNotMatch(text, /HTTP 401/);
      assert.doesNotMatch(text, /dashboard/i);
    } finally { await page.close(); }
  });

  async function paste(page, value, how) {
    await page.fill('#enter-link', value);
    if (how === 'enter') await page.press('#enter-link', 'Enter');
    else await page.click('[data-click="goReceive"]');
  }

  test(`the paste box: plain text shows the error and stays on /get (${L.name})`, async () => {
    const page = await open(`${GIL_ORIGIN}${L.pre}/get`);
    try {
      assert.equal(await activeStep(page), 'step-enter');
      await paste(page, 'hello there', 'click');
      await page.waitForTimeout(300);
      assert.equal(new URL(page.url()).pathname, L.pre + '/get');
      assert.match(await page.textContent('#enter-err'), L.bad);
    } finally { await page.close(); }
  });

  test(`the paste box: Enter submits (${L.name})`, async () => {
    const page = await open(`${GIL_ORIGIN}${L.pre}/get`);
    try {
      await activeStep(page);
      await paste(page, 'nonsense', 'enter');
      await page.waitForTimeout(300);
      assert.match(await page.textContent('#enter-err'), L.bad);
      await page.fill('#enter-link', `${GIL_ORIGIN}${L.pre}/get?t=${GIL_TOKEN}#${GIL_KEY}`);
      await Promise.all([page.waitForURL(/\?t=/), page.press('#enter-link', 'Enter')]);
      assert.equal(new URL(page.url()).searchParams.get('t'), GIL_TOKEN);
    } finally { await page.close(); }
  });

  test(`the paste box: a link to another site is refused and not followed (${L.name})`, async () => {
    const page = await open(`${GIL_ORIGIN}${L.pre}/get`);
    try {
      await activeStep(page);
      await paste(page, `https://example.com${L.pre}/get?t=${GIL_TOKEN}#${GIL_KEY}`, 'click');
      await page.waitForTimeout(300);
      assert.equal(new URL(page.url()).origin, GIL_ORIGIN);
      assert.match(await page.textContent('#enter-err'), L.foreign);
    } finally { await page.close(); }
  });

  test(`the paste box: a same-site link with a truncated token is refused (${L.name})`, async () => {
    const page = await open(`${GIL_ORIGIN}${L.pre}/get`);
    try {
      await activeStep(page);
      await paste(page, `${GIL_ORIGIN}${L.pre}/get?t=${GIL_TOKEN.slice(0, 10)}#${GIL_KEY}`, 'click');
      await page.waitForTimeout(300);
      assert.equal(new URL(page.url()).search, '');
      assert.match(await page.textContent('#enter-err'), L.bad);
    } finally { await page.close(); }
  });
}
