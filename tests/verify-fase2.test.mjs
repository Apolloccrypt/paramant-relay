// Fase 2 (2026-10-04), /verify:
//  VERIFY-05-A: bij de pdf-route staat de opgegeven naam in coords.name; /verify
//    las alleen signer_name, dus de naam stond nergens. Nu: "Naam: ... (opgegeven,
//    niet gecontroleerd)".
//  VERIFY-06-C: mislukt "Wie hoort bij deze sleutel?" (500/429/geen netwerk), dan
//    verdween de knop zonder melding. Nu: een melding en de knop blijft.
// Run: node --test tests/verify-fase2.test.mjs
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
await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });

const fx = await page.evaluate(async () => {
  const pqc = await import('/vendor/paramant-pqc.js');
  const signer = await import('/js/parasign-signer.js?v=23');
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
    coords: { pageIndex: 0, x: 10, y: 10, w: 100, h: 40, name: 'Jan Jansen', date: '4-10-2026' }, signer_public_key: pk, party_email_hash: emailHash,
    appearance, appearance_hash: hex(signer.signingAppearanceHash(appearance)),
    signature: b64(pqc.ml_dsa65.sign(keys.secretKey, msg)),
    multiparty: { envelope_id: envelopeId, party_index: 0 },
  };
  const broken = { ...psign, signature: b64(new Uint8Array(3309)) };
  return { original: Array.from(original), stamped: Array.from(stamped), psign, broken };
});

async function run(lang, lookup) {
  await page.unroute('**/v2/lookup-signer/**');
  await page.route('**/v2/lookup-signer/**', lookup);
  await page.goto(origin + (lang === 'en' ? '/en/verify.html' : '/verify.html'), { waitUntil: 'domcontentloaded' });
  await page.locator('#vf-document').setInputFiles({ name: 'doc.pdf', mimeType: 'application/pdf', buffer: Buffer.from(fx.stamped) });
  await page.locator('#vf-envelope').setInputFiles({ name: 'p.psign', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(fx.psign)) });
  await page.locator('#vf-verify').click();
  await page.locator('#vf-lookup').waitFor({ timeout: 15000 });
  return page.locator('#vf-result').innerText();
}

test('NL: naam uit coords.name staat erbij als opgegeven, niet gecontroleerd', async () => {
  const text = await run('nl', (r) => r.abort());
  assert.match(text, /Naam: Jan Jansen \(opgegeven door de ondertekenaar, niet gecontroleerd\)/, text);
});

test('EN: name from coords.name is shown as stated, not checked', async () => {
  const text = await run('en', (r) => r.abort());
  assert.match(text, /Name: Jan Jansen \(stated by the signer, not checked\)/, text);
});

for (const [label, lookup] of [
  ['500', (r) => r.fulfill({ status: 500, body: 'x' })],
  ['429', (r) => r.fulfill({ status: 429, body: 'x' })],
  ['geen netwerk', (r) => r.abort()],
]) {
  test(`opzoeken mislukt (${label}): melding, knop blijft`, async () => {
    await run('nl', lookup);
    await page.locator('#vf-lookup').click();
    await page.locator('#vf-lookup-failed').waitFor({ timeout: 10000 });
    const text = await page.locator('#vf-result').innerText();
    assert.match(text, /Het opzoeken lukte nu niet/, text);
    assert.equal(await page.locator('#vf-lookup').isEnabled(), true);
    assert.doesNotMatch(text, /Handtekening geldig/);
  });
}

// VERIFY-13 en VERIFY-14-N: de lijst "Wat er wordt gecontroleerd" beloofde een
// verloopcontrole die bij echte bewijzen nooit afgaat, en "werkt ook offline"
// zonder het voorbehoud voor v1/v2 (die gaan langs de relay).
test('verify.html NL/EN: geen verloopbelofte, offline met voorbehoud', () => {
  for (const [f, verlopen, offline] of [
    ['verify.html', /De envelop is niet verlopen/, /oude envelop \(v1 of v2\) gaat langs de relay/],
    ['en/verify.html', /The envelope has not expired/, /old envelope \(v1 or v2\) goes past the relay/],
  ]) {
    const html = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert.doesNotMatch(html, verlopen, f);
    assert.match(html, offline, f);
  }
});
