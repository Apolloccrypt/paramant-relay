import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { signMessageBytes, normaliseAppearance, appearanceHash } = require('../relay/envelope.js');
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.html':'text/html', '.wasm':'application/wasm' };
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

const envelopeId = 'env_demo_appearance_contract';
const docHash = 'a'.repeat(64);
const emailHash = 'b'.repeat(64);
const signerPublicKey = Buffer.from('generic-public-key').toString('base64');
const appearance = normaliseAppearance({ version: 1, fields: [
  { type: 'seal', page_index: 2, x: .4200004, y: .7, w: .36, h: .105 },
  { type: 'date', page_index: 2, x: .55, y: .82, w: .22, h: .055 },
] });
const expected = signMessageBytes(envelopeId, docHash, 1, emailHash, 5, signerPublicKey, appearanceHash(appearance)).toString('hex');

const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const page = await browser.newPage();
await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil:'domcontentloaded' });
const actual = await page.evaluate(async (input) => {
  const signer = await import('/js/parasign-signer.js?v=14');
  const normalized = signer.normaliseSigningAppearance(input.appearance);
  const message = signer.buildDocSignMessage({
    envelopeId: input.envelopeId,
    docHash: input.docHash,
    partyIndex: 1,
    emailHash: input.emailHash,
    recipeVersion: 5,
    signerPublicKey: input.signerPublicKey,
    appearance: normalized,
  });
  return {
    hex: Array.from(message, (byte) => byte.toString(16).padStart(2, '0')).join(''),
    normalized,
  };
}, { envelopeId, docHash, emailHash, signerPublicKey, appearance });

await browser.close();
server.close();

if (actual.hex !== expected) throw new Error(`browser/relay recipe mismatch: ${actual.hex} != ${expected}`);
if (JSON.stringify(actual.normalized) !== JSON.stringify(appearance)) throw new Error('browser/relay appearance normalization mismatch');
console.log('cosign-appearance-contract: browser and relay recipe 5 bytes match');
