// De eigen code van de afzender, aan de verzendkant, in een echte browser.
//
// Elke send op naam gaat met een code die de browser van de afzender maakt en
// die de afzender zelf doorgeeft. Deze suite stuurt een bestand naar twee
// mensen op /parashare en /en/parashare en kijkt naar twee dingen:
//
//   - wat naar de server gaat: een zout en per ontvanger een check, nooit de
//     code, in welke schrijfwijze ook
//   - wat op het scherm staat: de code, in twee groepjes van vijf, met uitleg,
//     en het is ECHT de code die de wikkeling opent
//
// Run: node --test tests/parashare-afzendercode-browser.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FE = path.join(ROOT, 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm', '.json': 'application/json' };
const ALIASES = { '/': '/index.html', '/parashare': '/parashare.html', '/en/parashare': '/en/parashare.html' };

// De browsercode ook hier, om na te rekenen wat het scherm toont.
const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(fs.readFileSync(path.join(FE, 'js', 'send-wrap.js'), 'utf8'), scope);
const W = scope.paramantSendWrap;

let server;
let browser;
let ORIGIN;

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const file = path.join(FE, ALIASES[url.pathname] || url.pathname);
    if (!file.startsWith(FE)) { res.writeHead(403); return res.end('no'); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  ORIGIN = `http://localhost:${server.address().port}`;
  browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
});

after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise((r) => server.close(r));
});

async function openSender(pagePath) {
  const seen = { all: [], sends: [] };
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.on('request', (r) => { seen.all.push(r.postData() || ''); });
  await page.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (r) => r.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }),
  }));
  for (const host of ['legal', 'finance', 'iot', 'relay']) await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  await page.route('https://health.paramant.app/v2/check-key', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms: 86400000,
      link_ttl_ms_by_plan: { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 } }),
  }));
  await page.route('https://health.paramant.app/v2/sends/precheck', (r) => r.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, limit: 30, count: 2 }) }));
  await page.route('https://health.paramant.app/v2/sends', (r) => {
    seen.sends.push(r.request().postData() || '');
    return r.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({
      ok: true, send_id: 's1', recipients: 2, invited: 2, delivered: 2, size: 100,
      expires_at: new Date(Date.now() + 3600e3).toISOString() }) });
  });
  let n = 0;
  await page.route('https://health.paramant.app/v2/inbound', (r) => {
    const up = JSON.parse(r.request().postData() || '{}');
    n++;
    return r.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ ok: true, hash: up.hash, ttl_ms: 3600000, size: 0, download_token: String(n).padStart(48, 'a') }) });
  });
  await page.goto(`${ORIGIN}${pagePath}`, { waitUntil: 'domcontentloaded' });
  return { page, seen };
}

for (const [pad, taal] of [['/parashare', 'nl'], ['/en/parashare', 'en']]) {
  test(`${taal}: elke send op naam gaat met een eigen code, en die code verlaat de browser niet`, async () => {
    const { page, seen } = await openSender(pad);
    try {
      assert.equal(await page.locator('#ps-own-code').count(), 0, 'er is geen vinkje meer: de code is altijd aan');
      await page.locator('#file-input').setInputFiles({ name: 'stuk.pdf', mimeType: 'application/pdf', buffer: crypto.randomBytes(20 * 1024) });
      await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 15000 });
      await page.locator('#ps-mode-group').click();
      await page.fill('#recipients-input', 'demo1@example.com, demo2@example.com');
      await page.locator('#btn-create-session').click();
      await page.waitForSelector('#done-own-code', { state: 'visible', timeout: 60000 });

      // ── het scherm ─────────────────────────────────────────────────────
      const getoond = (await page.textContent('#done-own-code-value')).trim();
      assert.match(getoond, /^[2-9A-HJKMNP-Z]{5}-[2-9A-HJKMNP-Z]{5}$/, 'de code staat in twee groepjes van vijf: ' + getoond);
      const uitleg = await page.textContent('#done-own-code');
      assert.match(uitleg, taal === 'nl'
        ? /Geef deze code zelf door aan de ontvanger, bijvoorbeeld telefonisch of via een app\. Zonder deze code kan niemand het bestand openen, ook wij niet\./
        : /Pass this code on to the recipient yourself, for example by phone or through an app\. Without this code nobody can open the file, not even us\./);
      assert.equal(await page.locator('#done-own-code button[data-click="copyOwnCode"]').count(), 1, 'de code is te kopieren');

      // ── wat er naar de server ging ─────────────────────────────────────
      assert.equal(seen.sends.length, 1);
      const body = JSON.parse(seen.sends[0]);
      assert.match(body.sender_code && body.sender_code.salt || '', /^[A-Za-z0-9_-]{22}$/, 'de vlag met het zout');
      const code = W.normaliseCode(getoond);
      const alles = seen.all.join('\n');
      for (const v of [code, getoond, code.toLowerCase(), getoond.toLowerCase()]) {
        assert.ok(!alles.includes(v), 'de code ging mee in een verzoek: ' + v);
      }

      // ── en het is echt de code die het slot opent ──────────────────────
      const gerekt = await W.stretchCode(code, body.sender_code.salt);
      const adressen = Object.keys(body.sealed);
      assert.deepEqual(adressen.sort(), ['demo1@example.com', 'demo2@example.com']);
      for (const a of adressen) {
        const r = body.sealed[a];
        assert.match(r.code_check, /^[A-Za-z0-9_-]{43}$/);
        const bewijs = await W.proofFor(r.token, gerekt);
        const check = crypto.createHash('sha256').update(Buffer.from(bewijs, 'base64url')).digest('base64url');
        assert.equal(check, r.code_check, 'de server herkent het bewijs bij de getoonde code');
        const sleutel = await W.unwrapWithCode(r.token, r.wrapped_key, gerekt);
        assert.equal(sleutel.rawKey.length, 32);
        await assert.rejects(() => W.unwrap(r.token, r.wrapped_key), 'de link alleen opent het niet');
      }
    } finally { await page.close(); }
  });
}
