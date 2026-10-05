// Acceptatie ronde 2, punt 5: een solo-bewijs met het ORIGINEEL (van voor de
// zegel) gaf rood ONGELDIG, terwijl co-sign met de gestempelde kopie oranje
// geeft. Nu gelijk en eerlijk: oranje "controleer met de ondertekende versie"
// alleen als de handtekening zelf klopt en het bewijs dit bestand als het
// origineel noemt; elk ander bestand, of een kapotte handtekening, blijft rood.
// En de naam staat erbij als "opgegeven, niet gecontroleerd".
// Run: node --test tests/verify-origineel-oranje.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.png': 'image/png' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') p = '/index.html';
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
const page = await browser.newPage({ viewport: { width: 1000, height: 900 } });
await page.route('**/v2/lookup-signer/**', (r) => r.abort());
await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });

const fx = await page.evaluate(async () => {
  const pqc = await import('/vendor/paramant-pqc.js');
  const signer = await import('/js/parasign-signer.js?v=22');
  const enc = new TextEncoder();
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const b64 = (b) => { let v = ''; for (const x of b) v += String.fromCharCode(x); return btoa(v); };
  const original = enc.encode('%PDF-1.4 het contract zoals het was');
  const stamped = enc.encode('%PDF-1.4 het contract zoals het was, met de zegel erop');
  const keys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const pk = b64(keys.publicKey);
  const emailHash = hex(pqc.sha3_256(enc.encode('solo@example.test')));
  const appearance = signer.normaliseSigningAppearance({ version: 1, fields: [] });
  const envelopeId = 'env_solo_original_pair';
  const stampedHash = hex(pqc.sha3_256(stamped));
  const msg = signer.buildDocSignMessage({ envelopeId, docHash: stampedHash, partyIndex: 0, emailHash, recipeVersion: 5, signerPublicKey: pk, appearance });
  const psign = {
    version: 'parasign-doc-3', recipe_version: 5, sign_domain: 'paramant/parasign/doc/v1',
    algorithm: 'ML-DSA-65', hash_algorithm: 'SHA3-256', original_filename: 'contract.pdf',
    original_hash: hex(pqc.sha3_256(original)), stamped_hash: stampedHash, stamped_filename: 'contract-getekend.pdf',
    signer_name: 'Ayşe Yılmaz', signer_public_key: pk, party_email_hash: emailHash,
    appearance, appearance_hash: hex(signer.signingAppearanceHash(appearance)),
    signature: b64(pqc.ml_dsa65.sign(keys.secretKey, msg)),
    multiparty: { envelope_id: envelopeId, party_index: 0 },
  };
  const broken = { ...psign, signature: b64(new Uint8Array(3309)) };
  return { original: Array.from(original), stamped: Array.from(stamped), psign, broken };
});

async function check(doc, psign) {
  await page.goto(origin + '/verify.html', { waitUntil: 'domcontentloaded' });
  await page.locator('#vf-document').setInputFiles({ name: 'doc.pdf', mimeType: 'application/pdf', buffer: Buffer.from(doc) });
  await page.locator('#vf-envelope').setInputFiles({ name: 'p.psign', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(psign)) });
  await page.locator('#vf-verify').click();
  await page.waitForFunction(() => { const b = document.querySelector('#vf-result .ps-banner'); return b && !/Lokaal|hashen/i.test(b.textContent) && !b.classList.contains('info') || (b && /klopt met dit document/.test(b.textContent)); }, null, { timeout: 15000 });
  await page.waitForTimeout(200);
  return { text: await page.locator('#vf-result').innerText(), cls: await page.locator('#vf-result .ps-banner').first().getAttribute('class') };
}

test('het origineel naast een kloppend bewijs: oranje, met de naam als opgegeven', async () => {
  const r = await check(fx.original, fx.psign);
  assert.match(r.cls, /\bwarn\b/, r.cls + ' ' + r.text);
  assert.match(r.text, /vóór het ondertekenen/);
  assert.match(r.text, /contract-getekend\.pdf/);
  assert.match(r.text, /Ayşe Yılmaz/);
  assert.doesNotMatch(r.text, /ONGELDIG/);
});

test('het origineel met een kapotte handtekening: rood', async () => {
  const r = await check(fx.original, fx.broken);
  assert.match(r.cls, /\berr\b/, r.text);
  assert.match(r.text, /ONGELDIG/);
});

test('een ander bestand: rood', async () => {
  const other = fx.original.slice(); other[5] ^= 1;
  const r = await check(other, fx.psign);
  assert.match(r.cls, /\berr\b/, r.text);
});

test('de ondertekende versie zelf: klopt', async () => {
  const r = await check(fx.stamped, fx.psign);
  assert.doesNotMatch(r.text, /ONGELDIG/, r.text);
  assert.match(r.cls, /\b(info|ok)\b/, r.cls);
});
