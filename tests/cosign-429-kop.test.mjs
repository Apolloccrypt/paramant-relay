// Acceptatie ronde 2, punt 4: bij een 429 stond de juiste zin ("te veel
// verzoeken") onder de kop "De link is ongeldig of verlopen". De kop past nu
// bij de oorzaak: 429 = even te druk, 5xx = storing bij ons, 404 = de link.
// Run: node --test tests/cosign-429-kop.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/co-sign') p = '/co-sign.html';
  const f = path.join(ROOT, p);
  if (!f.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

async function open(status) {
  const page = await browser.newPage();
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/v2/envelopes/**', (r) => r.fulfill({ status, contentType: 'application/json', body: '{"error":"x"}' }));
  await page.goto(ORIGIN + '/co-sign?env=env_demo_429_abcdefghijkl&p=0&t=' + 't'.repeat(43), { waitUntil: 'domcontentloaded' });
  await page.locator('#step-error').waitFor({ state: 'visible', timeout: 15000 });
  const out = { h1: await page.locator('#step-error h1').innerText(), sub: await page.locator('#step-error .sub').innerText(), msg: await page.locator('#error-msg').innerText() };
  await page.close();
  return out;
}

test('429: de kop zegt "even te druk", niet "klopt niet of is verlopen"', async () => {
  const r = await open(429);
  assert.match(r.h1, /Even te druk/);
  assert.doesNotMatch(r.sub, /klopt niet of is verlopen/);
  // Mick 05-10: taalronde
  assert.match(r.msg, /Even te veel tegelijk/);
});

test('5xx: de kop zegt dat het aan ons ligt', async () => {
  const r = await open(503);
  assert.match(r.h1, /storing/);
  assert.doesNotMatch(r.sub, /klopt niet of is verlopen/);
});

test('404: de kop over de link blijft', async () => {
  const r = await open(404);
  // Mick 05-10: taalronde
  assert.match(r.h1, /opent niet/);
  assert.match(r.sub, /klopt niet, of het verzoek is verlopen/);
});
