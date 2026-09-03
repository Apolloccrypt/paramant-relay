// /verify, the delivery-receipt half.
//
// The page promises a receipt anyone can check "without us". This suite holds
// it to that literally: the browser is switched to offline and every request is
// aborted BEFORE the receipt is checked, so a verdict can only come from code
// that already ran. It also builds its receipts with the relay's own hash
// primitives (relay/lib/ct-hash.js) and the same ML-DSA-65 implementation the
// browser loads, so a drift between relay.js and the client verifier fails here
// instead of on a customer's screen.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const SHOTS = process.env.RECEIPT_SHOTS_DIR || '';

const require = createRequire(import.meta.url);
const { ctTreeHash, ctInclusionProof, blobLeafHash } = require('../relay/lib/ct-hash.js');
const pqc = await import(path.join(ROOT, 'vendor', 'paramant-pqc.js'));

const MIME = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.woff2': 'font/woff2', '.json': 'application/json', '.ico': 'image/x-icon',
};
const aliases = { '/verify': '/verify.html' };

// Byte-identical to relay.js canonicalJSON.
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

// A receipt exactly as relay.js builds one at GET /v2/outbound/:hash, signed by
// a throwaway relay identity so the suite needs no secret and no live relay.
function buildReceipt() {
  const keys = pqc.ml_dsa65.keygen(new Uint8Array(32).fill(7));
  const sign = (msg) => Buffer.from(pqc.ml_dsa65.sign(keys.secretKey, Buffer.from(msg, 'utf8'))).toString('base64');
  const sector = 'relay';
  const ts = '2026-09-01T10:15:30.123Z';
  const blobHash = crypto.createHash('sha3-256').update('a delivered payload').digest('hex');

  const entries = [];
  for (let i = 0; i < 4; i++) entries.push({ leaf_hash: crypto.createHash('sha3-256').update('other-' + i).digest('hex') });
  const leafHash = blobLeafHash(blobHash, sector, ts);
  entries.push({ leaf_hash: leafHash });
  const index = entries.length - 1;
  const root = ctTreeHash(entries);

  const sthPayload = {
    relay_id: 'https://relay.paramant.app', sha3_root: root,
    timestamp: Date.parse('2026-09-01T10:15:31Z'), tree_size: entries.length, version: 1,
  };
  const sth = { ...sthPayload, signature: sign(canonicalJSON(sthPayload)) };

  const payload = {
    blob_hash: blobHash, ts,
    retrieved_at: Date.parse('2026-09-01T14:22:07Z'),
    sector, relay_id: 'https://relay.paramant.app',
    tree_size_at_retrieval: entries.length,
    inclusion_proof: {
      leaf_hash: leafHash, leaf_index: index, tree_size: entries.length,
      audit_path: ctInclusionProof(entries, index), root, sth, sth_signature: sth.signature,
    },
    burn_confirmed: true,
  };
  const receipt = { ...payload, signature: sign(canonicalJSON(payload)) };
  const tampered = JSON.parse(JSON.stringify(receipt));
  tampered.blob_hash = tampered.blob_hash.slice(0, -1) + (tampered.blob_hash.endsWith('a') ? 'b' : 'a');

  return {
    key: Buffer.from(keys.publicKey).toString('base64'),
    valid: Buffer.from(JSON.stringify(receipt)).toString('base64url'),
    tampered: Buffer.from(JSON.stringify(tampered)).toString('base64url'),
    blobHash,
  };
}

function startServer() {
  const server = http.createServer((req, res) => {
    let name = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    name = aliases[name] || name;
    const file = path.join(ROOT, name);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, body) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// Load the page, then take the network away and keep a record of anything that
// still tries to leave. Everything after this point is the offline promise.
async function offlinePage(browser, origin) {
  const context = await browser.newContext({ viewport: { width: 1100, height: 900 } });
  const page = await context.newPage();
  await page.goto(origin + '/verify', { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('rv-check'));
  await page.waitForLoadState('networkidle');

  const attempted = [];
  await page.route('**/*', (route) => { attempted.push(route.request().url()); return route.abort(); });
  await context.setOffline(true);
  return { context, page, attempted };
}

async function checkReceipt(page, text, key) {
  await page.click('#tab-receipt');
  await page.evaluate(() => { document.getElementById('rv-keyblock').open = true; });
  await page.fill('#rv-input', text);
  await page.fill('#rv-key', key);
  await page.click('#rv-check');
  await page.waitForSelector('#rv-result .rv-checks li');
  return page.textContent('#rv-result');
}

const fixture = buildReceipt();
const server = await startServer();
const ORIGIN = 'http://127.0.0.1:' + server.address().port;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

test('a genuine receipt is confirmed with the network switched off', async () => {
  const { context, page, attempted } = await offlinePage(browser, ORIGIN);
  const text = await checkReceipt(page, fixture.valid, fixture.key);

  // Signed by a throwaway key, so the verdict may not borrow Paramant's name:
  // every check passes, and the page says so without calling it "genuine".
  assert.match(text, /This receipt is unchanged/,
    'a receipt built with the relay own primitives must pass every check');
  assert.doesNotMatch(text, /This receipt is genuine/,
    'an unrecognised signer must never be presented as a Paramant receipt');
  assert.match(text, /The receipt is about this file and no other/);
  assert.match(text, /It really is in the public transparency log/);
  assert.match(text, /The signature holds/);
  assert.match(text, /The log itself was signed at that moment too/);

  // Plain language, not field names: a reader gets the key, the moment and the
  // file fingerprint in sentences.
  assert.match(text, /It was signed by a key this page does not recognise/,
    'a throwaway key must be named as unrecognised rather than silently trusted');
  assert.match(text, /handed over on 1 September 2026 at 14:22 UTC/);
  assert.ok(text.includes(fixture.blobHash), 'the fingerprint of the file must be on screen in full');
  assert.match(text, /destroyed its copy of the file/);
  assert.match(text, /entry 5 in a public log that held 5 entries/);
  assert.doesNotMatch(text, /signature valid|valid: true|blob_hash:/i,
    'the verdict is written for a reader, not for a developer');

  assert.deepEqual(attempted, [],
    'checking a receipt must not touch the network: ' + attempted.join(', '));

  if (SHOTS) await page.evaluate(() => window.scrollTo(0, 0));
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, 'receipt-valid.png'), fullPage: true });
  await context.close();
});

test('a receipt with one character changed is refused, offline, with a reason', async () => {
  const { context, page, attempted } = await offlinePage(browser, ORIGIN);
  const text = await checkReceipt(page, fixture.tampered, fixture.key);

  assert.match(text, /Do not trust this receipt/);
  assert.match(text, /The receipt does not match the file it names/);
  assert.match(text, /The signature does not hold/);
  assert.deepEqual(attempted, [],
    'refusing a receipt must not touch the network either: ' + attempted.join(', '));

  // The reason a check failed is the whole point of the failure screen, so it
  // may not end up squeezed into a column one character wide.
  const reason = await page.locator('.rv-bad .rv-detail').first().boundingBox();
  assert.ok(reason && reason.width > 300,
    'the explanation of a failed check must get the width of the panel, got ' + JSON.stringify(reason));

  if (SHOTS) await page.evaluate(() => window.scrollTo(0, 0));
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, 'receipt-tampered.png'), fullPage: true });
  await context.close();
});

test('the page ships the relay key it needs, so no key has to be pasted', async () => {
  const { context, page } = await offlinePage(browser, ORIGIN);
  const pinned = await page.evaluate(async () => {
    const mod = await import('/js/relay-trust-anchors.js');
    const anchor = mod.defaultAnchor();
    return { key: anchor && anchor.key, fingerprint: anchor && anchor.fingerprint, host: anchor && anchor.host };
  });
  assert.equal(Buffer.from(pinned.key, 'base64').length, 1952, 'an ML-DSA-65 public key is 1952 bytes');
  assert.equal(
    crypto.createHash('sha3-256').update(Buffer.from(pinned.key, 'base64')).digest('hex'),
    pinned.fingerprint,
    'the pinned fingerprint must be the fingerprint of the pinned key');
  assert.equal(pinned.host, 'relay.paramant.app');
  await context.close();
});

test('rubbish in the box gets a sentence, not a stack trace', async () => {
  const { context, page } = await offlinePage(browser, ORIGIN);
  await page.click('#tab-receipt');
  await page.fill('#rv-input', 'this is just a note to myself');
  await page.click('#rv-check');
  await page.waitForSelector('#rv-result .ps-banner');
  const text = await page.textContent('#rv-result');
  assert.match(text, /This is not a receipt/);
  assert.doesNotMatch(text, /undefined|TypeError|SyntaxError/);
  await context.close();
});

test('the receipt tab opens straight from /verify#receipt', async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(ORIGIN + '/verify#receipt', { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('rv-check'));
  assert.equal(await page.isVisible('#panel-receipt'), true);
  assert.equal(await page.isVisible('#panel-doc'), false);
  await context.close();
});

test.after(async () => {
  await browser.close();
  server.close();
  server.closeAllConnections();
});
