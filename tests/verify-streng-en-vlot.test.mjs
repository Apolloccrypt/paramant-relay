// /verify: dezelfde manifestregels als de andere twee normaliseerders, en een
// groot bestand bevriest de pagina niet (hertest 2026-10-04, T2-B5 en T3-9).
//
//   - De verifier normaliseerde het weergavemanifest zonder iets te
//     controleren. Een bewijs met een veld buiten de pagina (x + w > 1), dat
//     signer en relay allebei weigeren, kwam hier als geldig door. Nu niet.
//     Een geldig manifest geeft byte voor byte dezelfde hash als voorheen.
//   - Een bestand van 500 MB hield de pagina 20 seconden vast (de SHA3 in één
//     keer op de hoofdthread). Nu in stukken: de pagina blijft antwoorden.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.png': 'image/png' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/') p = '/index.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

// A v3 solo proof, signed for real, over a given appearance manifest. The
// appearance hash is made the way the OLD verifier made it (round, no checks),
// so only the verifier's own rule decides.
async function makeProof(page, fields) {
  return page.evaluate(async (fields) => {
    const pqc = await import('/vendor/paramant-pqc.js');
    const enc = new TextEncoder();
    const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    const unhex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
    const b64 = (b) => { let v = ''; for (const x of b) v += String.fromCharCode(x); return btoa(v); };
    const cat = (arrs) => { const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };
    const appearance = { version: 1, fields };
    const loose = { version: 1, fields: fields.map((f) => ({ type: String(f.type), page_index: Number(f.page_index), x: Math.round(f.x * 1e6) / 1e6, y: Math.round(f.y * 1e6) / 1e6, w: Math.round(f.w * 1e6) / 1e6, h: Math.round(f.h * 1e6) / 1e6 })) };
    const appHash = pqc.sha3_256(enc.encode(JSON.stringify(loose)));
    const source = enc.encode('een overeenkomst om te controleren');
    const docHash = hex(pqc.sha3_256(source));
    const keys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
    const emailHash = hex(pqc.sha3_256(enc.encode('sandeep@example.com')));
    const envId = 'env_streng_vlot_proef';
    const msg = pqc.sha3_256(cat([enc.encode('paramant/parasign/doc/v1'), new Uint8Array([0]), enc.encode(envId), unhex(docHash), enc.encode('0'), unhex(emailHash), keys.publicKey, appHash]));
    return {
      source: Array.from(source),
      psign: {
        version: 'parasign-doc-3', recipe_version: 5, sign_domain: 'paramant/parasign/doc/v1', algorithm: 'ML-DSA-65', hash_algorithm: 'SHA3-256',
        original_filename: 'o.txt', document_hash: docHash, signer_public_key: b64(keys.publicKey), party_email_hash: emailHash,
        appearance, appearance_hash: hex(appHash), signature: b64(pqc.ml_dsa65.sign(keys.secretKey, msg)),
        multiparty: { envelope_id: envId, party_index: 0, party_count: 1 },
      },
    };
  }, fields);
}

async function verifyOn(page, proof, docBuffer) {
  await page.goto(origin + '/verify.html', { waitUntil: 'domcontentloaded' });
  await page.route('https://relay.paramant.app/**', (r) => r.abort('internetdisconnected'));
  await page.locator('#vf-document').setInputFiles({ name: 'o.txt', mimeType: 'text/plain', buffer: docBuffer || Buffer.from(proof.source) });
  await page.locator('#vf-envelope').setInputFiles({ name: 'o.psign', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(proof.psign)) });
  await page.locator('#vf-verify').click();
  await page.waitForFunction(() => /klopt|geldig|ONGELDIG|aangepast/.test(document.querySelector('#vf-result')?.textContent || ''), null, { timeout: 120000 });
  return page.locator('#vf-result').innerText();
}

test('een manifest dat signer en relay weigeren, weigert de verifier ook', async () => {
  const page = await browser.newPage();
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
  const outside = await makeProof(page, [{ type: 'seal', page_index: 0, x: 0.9, y: 0.1, w: 0.3, h: 0.1 }]);
  const fine = await makeProof(page, [{ type: 'seal', page_index: 0, x: 0.5, y: 0.8, w: 0.3, h: 0.1 }]);
  const bad = await verifyOn(page, outside);
  const good = await verifyOn(page, fine);
  await page.close();
  assert.match(bad, /ONGELDIG/, bad);
  assert.match(bad, /zichtbare handtekening in het bestand is beschadigd/, bad);
  assert.doesNotMatch(good, /ONGELDIG/, 'een geldig manifest blijft geldig: ' + good);
  assert.match(good, /De handtekening klopt met dit document/, good);
});

test('een groot bestand houdt de pagina niet vast', async () => {
  const page = await browser.newPage();
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
  const proof = await makeProof(page, []);
  const bigPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'verify-groot-')), 'groot.bin');
  fs.writeFileSync(bigPath, Buffer.alloc(120 * 1024 * 1024, 7));
  await page.goto(origin + '/verify.html', { waitUntil: 'domcontentloaded' });
  await page.route('https://relay.paramant.app/**', (r) => r.abort('internetdisconnected'));
  await page.locator('#vf-document').setInputFiles(bigPath);
  await page.locator('#vf-envelope').setInputFiles({ name: 'o.psign', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(proof.psign)) });
  // A probe that notes the largest gap in the event loop while the file is checked.
  await page.evaluate(() => { window.__gap = 0; let last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - last); last = n; }, 20); });
  await page.locator('#vf-verify').click();
  await page.waitForFunction(() => /klopt|geldig|ONGELDIG|aangepast/.test(document.querySelector('#vf-result')?.textContent || ''), null, { timeout: 180000 });
  const gap = await page.evaluate(() => { clearInterval(window.__probe); return window.__gap; });
  const text = await page.locator('#vf-result').innerText();
  await page.close();
  fs.rmSync(path.dirname(bigPath), { recursive: true, force: true });
  assert.match(text, /ONGELDIG|niet het document/, 'het grote bestand is niet het ondertekende');
  assert.ok(gap < 1000, `de pagina stond ${Math.round(gap)} ms stil`);
});
