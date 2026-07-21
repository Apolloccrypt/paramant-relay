import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.wasm':'application/wasm', '.png':'image/png' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/') pathname = '/index.html';
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const page = await browser.newPage({ viewport:{ width:390, height:844 } });
await page.goto(origin + '/', { waitUntil:'domcontentloaded' });

const fixture = await page.evaluate(async () => {
  const pqc = await import('/vendor/paramant-pqc.js');
  const signer = await import('/js/parasign-signer.js?v=14');
  const enc = new TextEncoder();
  const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const b64 = (bytes) => { let value = ''; for (const byte of bytes) value += String.fromCharCode(byte); return btoa(value); };
  const canonical = (value) => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  };
  const source = enc.encode('generic source document for multi signer verification');
  const documentHash = hex(pqc.sha3_256(source));
  const signerKeys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const relayKeys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const signerPublicKey = b64(signerKeys.publicKey);
  const emailHash = hex(pqc.sha3_256(enc.encode('generic recipient binding')));
  const appearance = signer.normaliseSigningAppearance({ version:1, fields:[
    { type:'seal', page_index:0, x:.4, y:.7, w:.36, h:.105 },
  ] });
  const envelopeId = 'env_demo_multi_verify';
  const message = signer.buildDocSignMessage({ envelopeId, docHash:documentHash, partyIndex:0, emailHash, recipeVersion:5, signerPublicKey, appearance });
  const receipt = {
    type:'parasign-envelope-receipt', version:'2', algorithm:'ML-DSA-65',
    envelope_id:envelopeId, document_hash:documentHash, document_hash_algo:'sha3-256',
    binding_mode:'email', recipe_version:5, sign_recipe:5, status:'completed',
    created_at:'2026-07-21T11:00:00.000Z', completed_at:'2026-07-21T12:00:00.000Z', expires_at:'2026-08-20T12:00:00.000Z',
    parties:[{
      index:0, label:'Signer Demo', email_hash:emailHash, status:'signed', signed_at:'2026-07-21T12:00:00.000Z',
      public_key:signerPublicKey, signature:b64(pqc.ml_dsa65.sign(signerKeys.secretKey, message)),
      signer_pk_hash:hex(pqc.sha3_256(signerKeys.publicKey)), appearance,
      appearance_hash:hex(signer.signingAppearanceHash(appearance)),
    }],
    notary:{ relay_pk_hash:hex(pqc.sha3_256(relayKeys.publicKey)), relay_public_key:b64(relayKeys.publicKey), relay_pubkey_url:'https://paramant.app/v2/pubkey' },
  };
  receipt.notary_signature = b64(pqc.ml_dsa65.sign(relayKeys.secretKey, enc.encode(canonical(receipt))));
  return { source:Array.from(source), receipt };
});

await page.goto(origin + '/verify.html', { waitUntil:'domcontentloaded' });
await page.locator('#vf-document').setInputFiles({ name:'source-demo.pdf', mimeType:'application/pdf', buffer:Buffer.from(fixture.source) });
await page.locator('#vf-envelope').setInputFiles({ name:'source-demo.psign', mimeType:'application/json', buffer:Buffer.from(JSON.stringify(fixture.receipt)) });
await page.locator('#vf-verify').click();
await page.waitForFunction(() => /Signature valid|Signature INVALID/.test(document.querySelector('#vf-result')?.textContent || ''));
const result = await page.locator('#vf-result').innerText();
const keyHidden = await page.locator('#vf-key-block').isHidden();
const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

await browser.close();
server.close();
if (!/Signature valid/.test(result)) throw new Error(result);
if (!/verified offline/.test(result)) throw new Error('offline result missing');
if (!keyHidden) throw new Error('API key field visible for self-contained proof');
if (overflow > 1) throw new Error('phone overflow: ' + overflow);
console.log('parasign-multi-verify: recipe 5 receipt verifies offline in Chromium');
