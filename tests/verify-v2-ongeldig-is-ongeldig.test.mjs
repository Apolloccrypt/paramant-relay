// Hertest ronde 2, regressie R2: an old v1/v2 proof checked against the wrong
// document. The relay answers 422 { valid:false, errors:[...] } (relay.js
// POST /v2/verify); the page said "storing bij ons, probeer opnieuw". A 422 is
// a verdict: red INVALID with the reason. A real fault (500) still says fault.
// Run: node --test tests/verify-v2-ongeldig-is-ongeldig.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png' };

function serve() {
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (p === '/') p = '/index.html';
    const file = path.join(ROOT, p);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, body) => {
      if (e) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
}

const envelope = {
  version: 'paramant-sign-v2', algorithm: 'ML-DSA-65', signed_at: '2026-01-02T03:04:05Z',
  document_hash: 'aa'.repeat(32),
  signer: { label: 'Oud bewijs', public_key: 'AAAA' },
  notary: { relay_pk_hash: 'bb'.repeat(32), ct_log_index: 1 },
};

async function check(url, relayStatus, relayBody) {
  const server = await serve();
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
  try {
    const page = await browser.newPage();
    await page.route('**/v2/verify', (route) => route.fulfill({ status: relayStatus, contentType: 'application/json', body: JSON.stringify(relayBody) }));
    await page.route('**/v2/lookup-signer/**', (route) => route.fulfill({ status: 404, body: '{}' }));
    await page.goto(origin + url, { waitUntil: 'domcontentloaded' });
    await page.locator('#vf-document').setInputFiles({ name: 'ander.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4 een ander document') });
    await page.locator('#vf-envelope').setInputFiles({ name: 'oud.psign', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(envelope)) });
    await page.locator('#vf-verify').click();
    await page.waitForFunction(() => {
      const b = document.querySelector('#vf-result .ps-banner');
      return b && !b.classList.contains('info');
    }, null, { timeout: 15000 });
    return {
      text: await page.locator('#vf-result').innerText(),
      banner: await page.locator('#vf-result .ps-banner').first().getAttribute('class'),
    };
  } finally { await browser.close(); server.close(); }
}

const bad = { valid: false, errors: ['document_hash mismatch: expected aaaa, got bbbb'], verified_at: '2026-10-04T00:00:00Z' };

// Acceptatie r4, punt 3: a wrong file gets the prescribed heading, the same
// words a v3 proof gets, not a reason of its own.
test('NL: 422 wrong file is red with the prescribed text, not "storing bij ons"', async () => {
  const r = await check('/verify.html', 422, bad);
  assert.match(r.banner, /\berr\b/, r.banner);
  assert.match(r.text, /Dit is niet het ondertekende bestand\. Controleer met het originele bestand\./, r.text);
  assert.doesNotMatch(r.text, /storing bij ons/, r.text);
});

test('EN: 422 wrong file is red with the prescribed text', async () => {
  const r = await check('/en/verify.html', 422, bad);
  assert.match(r.banner, /\berr\b/, r.banner);
  assert.match(r.text, /This is not the signed file\. Check with the original file\./, r.text);
  assert.doesNotMatch(r.text, /fault on our side/, r.text);
});

test('NL: 422 with a bad signature as well stays a red INVALID with the reasons', async () => {
  const r = await check('/verify.html', 422, { valid: false, errors: ['document_hash mismatch: x', 'signature invalid'] });
  assert.match(r.banner, /\berr\b/, r.banner);
  assert.match(r.text, /ONGELDIG/, r.text);
  assert.match(r.text, /Een handtekening in het bewijs klopt niet/, r.text);
});

test('a real fault (500) still says it is a fault, not a verdict', async () => {
  const r = await check('/verify.html', 500, { error: 'boom' });
  assert.match(r.text, /storing bij ons/, r.text);
  assert.doesNotMatch(r.text, /ONGELDIG/, r.text);
});
