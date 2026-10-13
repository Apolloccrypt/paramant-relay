// protocol-trail.test.mjs: every protocol name the trail shows was measured.
//
// While a file is sent, collected, signed or checked, js/protocol-trail.js
// writes a narrow list of what is happening, with the protocol that did the
// work after each row: AES-256-GCM, ML-KEM-768 + ECDH P-256, TLS 1.3,
// ML-DSA-65, SHA3-256, the index in the public log. The rule is that no name on
// that list is typed into a page; each one is read from the call that ran.
//
// So every block here runs the real page twice where it can: once as
// production does it, and once with the execution changed underneath (another
// key length, no TLS header from the edge, no log entry, a sealed block from
// somewhere else, a tampered signature). The row has to follow the execution:
// change, or disappear. A row that stays the same when the work underneath
// changed is a row that was typed.
//
// The relay is stubbed at the network edge, the same way end-screen-calm and
// parasend-send-a-link do it. No relay, no redis, no account.
//
// Run: node --test tests/protocol-trail.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { webcrypto as wc } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadPdfLibs } from './helpers/sign-pdf-libs.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm',
  '.json': 'application/json', '.ico': 'image/x-icon' };
const ALIAS = { '/': '/index.html', '/parashare': '/parashare.html', '/en/parashare': '/en/parashare.html',
  '/get': '/get.html', '/en/get': '/en/get.html', '/sign': '/sign.html', '/en/sign': '/en/sign.html',
  '/verify': '/verify.html', '/en/verify': '/en/verify.html' };
const PHONE = { width: 390, height: 844 };
const TLS13 = 'tls1.3 TLS_AES_128_GCM_SHA256';

let server, browser, ORIGIN;
before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const rel = ALIAS[url.pathname] || url.pathname;
    const file = path.join(ROOT, rel);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end('no'); }
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
  if (server) { server.close(); server.closeAllConnections(); }
});

// The rows as a reader gets them: which step, done or under way, the words and
// the small name after them.
async function rows(page, sel) {
  return page.evaluate((s) => [...document.querySelectorAll(s + ' .pa-trail-row')].map((r) => {
    const tech = r.querySelector('.pa-trail-tech');
    return {
      step: r.dataset.step,
      state: r.classList.contains('is-done') ? 'done' : 'now',
      text: r.querySelector('.pa-trail-text').textContent,
      tech: tech && !tech.hidden ? tech.textContent : '',
      title: tech ? tech.title : '',
    };
  }), sel);
}
const row = (list, step) => list.find((r) => r.step === step);

// A relay answer with the header the TLS edge adds, and the CORS line that lets
// the page read it. `tls: null` is an edge that does not send it.
function relayHeaders(tls) {
  return { 'Access-Control-Allow-Origin': '*', 'Access-Control-Expose-Headers': 'X-Paramant-Tls',
    ...(tls ? { 'X-Paramant-Tls': tls } : {}) };
}

// ── /parashare: send a link ────────────────────────────────────────────────
const MERKLE = { leaf_hash: 'b'.repeat(64), leaf_index: 41, tree_size: 42,
  audit_path: ['c'.repeat(64)], root: 'd'.repeat(64), sth: { signature: 'e'.repeat(40) }, sth_signature: 'e'.repeat(40) };

async function stubSender(page, { tls = TLS13, proof = MERKLE } = {}) {
  await page.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }) }));
  for (const host of ['legal', 'finance', 'iot']) await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  await page.route('https://relay.paramant.app/**', (r) => r.abort());
  await page.route('https://health.paramant.app/v2/check-key', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms: 86400000,
      link_ttl_ms_by_plan: { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 } }) }));
  await page.route('https://health.paramant.app/v2/inbound', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    headers: relayHeaders(tls),
    body: JSON.stringify({ ok: true, hash: 'a'.repeat(64), ttl_ms: 86400000, size: 0,
      download_token: 'a'.repeat(48), ...(proof ? { merkle_proof: proof } : {}) }) }));
  await page.route('https://health.paramant.app/v2/dl/**', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, enc_meta: null, file_size: 0, ttl_left_s: 3600, used: false }) }));
  await page.route('https://health.paramant.app/v2/session/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
}

async function sendLink(pathname, opts = {}, init) {
  const page = await browser.newPage({ viewport: PHONE });
  if (init) await page.addInitScript(init);
  await stubSender(page, opts);
  await page.goto(`${ORIGIN}${pathname}`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ps-mode-link').click();
  await page.locator('#file-input').setInputFiles({ name: 'loonstrook-2026-09.pdf', mimeType: 'application/pdf',
    buffer: Buffer.from(Array.from({ length: 777 }, (_, i) => (i * 37 + 11) % 256)) });
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 20000 });
  await page.locator('#btn-create-session').click();
  await page.waitForSelector('#step-link.active', { timeout: 30000 });
  const list = await rows(page, '#step-link');
  await page.close();
  return list;
}

test('send a link: the names come from the key, the edge and the relay answer', async () => {
  const list = await sendLink('/parashare');
  assert.deepEqual(list.map((r) => r.step), ['seal', 'send', 'kept', 'log']);
  assert.ok(list.every((r) => r.state === 'done'), JSON.stringify(list));
  assert.equal(row(list, 'seal').text, 'Versleuteld op dit apparaat');
  assert.equal(row(list, 'seal').tech, 'AES-256-GCM');
  assert.equal(row(list, 'send').tech, 'TLS 1.3');
  assert.equal(row(list, 'send').title, 'TLS_AES_128_GCM_SHA256');
  assert.equal(row(list, 'log').tech, 'logboek #41');
});

test('send a link, English: the same rows in English', async () => {
  const list = await sendLink('/en/parashare');
  assert.equal(row(list, 'seal').text, 'Encrypted on this device');
  assert.equal(row(list, 'send').text, 'Sent to the server');
  assert.equal(row(list, 'log').tech, 'log #41');
});

test('send a link: a 128-bit key is named as one', async () => {
  // The page asks for a 256-bit key; this makes the browser hand back 128. The
  // row has to say what sealed the file, not what the code asked for.
  const list = await sendLink('/parashare', {}, () => {
    const orig = crypto.subtle.generateKey.bind(crypto.subtle);
    crypto.subtle.generateKey = (alg, ...rest) => orig(alg && alg.name === 'AES-GCM' ? { ...alg, length: 128 } : alg, ...rest);
  });
  assert.equal(row(list, 'seal').tech, 'AES-128-GCM');
});

test('send a link: no header from the edge, no TLS name; no proof, no log row', async () => {
  const list = await sendLink('/parashare', { tls: null, proof: null });
  assert.equal(row(list, 'send').tech, '', JSON.stringify(list));
  assert.equal(row(list, 'log'), undefined);
  assert.ok(!list.some((r) => /TLS/.test(r.tech + r.text)));
});

test('send a link: a header that is not a TLS version is not shown', async () => {
  const list = await sendLink('/parashare', { tls: 'TLS 1.3 because we say so' });
  assert.equal(row(list, 'send').tech, '');
});

// ── /parashare: the live hand-over ─────────────────────────────────────────
// The receiver's keys are real: ML-KEM-768 from the vendored noble bundle and
// P-256 from WebCrypto, made in the page, so the WASM seals for real.
async function sendLive({ stubSeal = false } = {}) {
  const page = await browser.newPage({ viewport: PHONE });
  if (stubSeal) {
    await page.addInitScript(() => {
      const stub = { initCrypto: async () => {}, encryptBlob: async (p) => crypto.getRandomValues(new Uint8Array(p.length + 32)),
        decryptBlob: async () => new Uint8Array() };
      Object.defineProperty(window, '_cryptoBridge', { get: () => stub, set: () => {}, configurable: true });
    });
  }
  await stubSender(page);
  let receiver = null;
  await page.route('https://health.paramant.app/v2/pubkey/**', (r) => receiver
    ? r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(receiver) })
    : r.fulfill({ status: 404, body: '' }));
  await page.route('https://health.paramant.app/v2/pubkey', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'domcontentloaded' });
  const keys = await page.evaluate(async () => {
    const { ml_kem768 } = await import('/noble-mlkem-bundle.js');
    const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
    const kem = ml_kem768.keygen();
    const ec = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return { kyber_pub: hex(kem.publicKey), ecdh_pub: hex(new Uint8Array(await crypto.subtle.exportKey('raw', ec.publicKey))) };
  });
  await page.locator('#ps-extra-safe').check();
  await page.locator('#file-input').setInputFiles({ name: 'IMG_4276.jpeg', mimeType: 'image/jpeg',
    buffer: Buffer.from(Array.from({ length: 2048 }, (_, i) => (i * 13 + 7) % 256)) });
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 20000 });
  await page.locator('#btn-create-session').click();
  await page.waitForSelector('#step-waiting.active', { timeout: 20000 });
  receiver = keys;
  await page.waitForFunction(() => /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test((document.getElementById('fp-display')?.textContent || '').trim()),
    null, { timeout: 20000, polling: 250 });
  await page.locator('#fp-confirm-check').check();
  await page.locator('#fp-confirm-btn').click();
  await page.waitForSelector('#step-done.active', { timeout: 60000 });
  const list = await rows(page, '#step-done');
  await page.close();
  return list;
}

test('live hand-over: the hybrid is read from the sealed block the WASM made', async () => {
  const list = await sendLive();
  assert.equal(row(list, 'seal').tech, 'ML-KEM-768 + ECDH P-256 · AES-256-GCM', JSON.stringify(list));
  assert.equal(row(list, 'send').tech, 'TLS 1.3');
});

test('live hand-over: a block that is not that wire format names nothing', async () => {
  const list = await sendLive({ stubSeal: true });
  assert.equal(row(list, 'seal').state, 'done');
  assert.equal(row(list, 'seal').tech, '', JSON.stringify(list));
  assert.ok(!list.some((r) => /ML-KEM|P-256/.test(r.tech)));
});

test('the measures themselves: sizes and headers that are not the real thing name nothing', async () => {
  const page = await browser.newPage();
  await page.goto(`${ORIGIN}/verify`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !!window.paramantTrail);
  const out = await page.evaluate(async () => {
    const m = window.paramantTrail.measure;
    const wire = (kemLen, pubLen, first) => {
      const u = new Uint8Array(5 + kemLen + 4 + pubLen + 20);
      const dv = new DataView(u.buffer);
      u[0] = 0x03; dv.setUint32(1, kemLen); dv.setUint32(5 + kemLen, pubLen); u[9 + kemLen] = first;
      return u;
    };
    const aes = async (n) => m.aes(await crypto.subtle.generateKey({ name: 'AES-GCM', length: n }, false, ['encrypt']));
    return {
      kem768: m.hybrid(wire(1088, 65, 4)) && m.hybrid(wire(1088, 65, 4)).kem,
      kem1024: m.hybrid(wire(1568, 65, 4)) && m.hybrid(wire(1568, 65, 4)).kem,
      x25519: m.hybrid(wire(1088, 32, 0)),
      oddKem: m.hybrid(wire(1000, 65, 4)),
      dsa44: m.mlDsa(new Uint8Array(1312), new Uint8Array(2420)),
      dsa65: m.mlDsa(new Uint8Array(1952), new Uint8Array(3309)),
      dsa87: m.mlDsa(new Uint8Array(2592), new Uint8Array(4627)),
      dsaMixed: m.mlDsa(new Uint8Array(1952), new Uint8Array(2420)),
      aes128: await aes(128), aes256: await aes(256),
      tlsCaddy: m.parseTls('tls1.3 TLS_AES_128_GCM_SHA256'),
      tlsNginx: m.parseTls('TLSv1.2 ECDHE-ECDSA-AES128-GCM-SHA256'),
      tlsJunk: m.parseTls('quantum safe'),
    };
  });
  await page.close();
  assert.equal(out.kem768, 'ML-KEM-768');
  assert.equal(out.kem1024, 'ML-KEM-1024');
  assert.equal(out.x25519, null);
  assert.equal(out.oddKem, null);
  assert.deepEqual([out.dsa44, out.dsa65, out.dsa87, out.dsaMixed], ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', null]);
  assert.deepEqual([out.aes128, out.aes256], ['AES-128-GCM', 'AES-256-GCM']);
  assert.equal(out.tlsCaddy.name, 'TLS 1.3');
  assert.equal(out.tlsNginx.name, 'TLS 1.2');
  assert.equal(out.tlsJunk, null);
});

// ── /get ───────────────────────────────────────────────────────────────────
async function sealForGet(fileName, fileBytes) {
  const nameBytes = Buffer.from(fileName, 'utf8');
  const head = Buffer.alloc(4); head.writeUInt32LE(nameBytes.length, 0);
  const rawKey = wc.getRandomValues(new Uint8Array(32));
  const iv = wc.getRandomValues(new Uint8Array(12));
  const key = await wc.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = Buffer.from(await wc.subtle.encrypt({ name: 'AES-GCM', iv }, key, Buffer.concat([head, nameBytes, Buffer.from(fileBytes)])));
  return { ct, frag: Buffer.concat([Buffer.from(rawKey), Buffer.from(iv)]).toString('base64url') };
}

async function collect(pre, { tls = TLS13, burned = true } = {}) {
  const { ct, frag } = await sealForGet('loonstrook-2026-09.txt', Buffer.from('salaris september'));
  const ctx = await browser.newContext({ viewport: PHONE, acceptDownloads: true });
  const page = await ctx.newPage();
  await page.route(/^https:\/\/health\.paramant\.app\/v2\/dl\/[^/]+\/get(\?|$)/, (r) =>
    r.fulfill({ status: 200, contentType: 'application/octet-stream', headers: relayHeaders(tls), body: ct }));
  await page.route('https://health.paramant.app/v2/dl/**/info', (r) => r.fulfill({ status: 200,
    contentType: 'application/json', body: JSON.stringify({ ok: true, file_size: 2000, ttl_left_s: 3600, used: false }) }));
  await page.route(/https:\/\/health\.paramant\.app\/v2\/dl\/.*\/(ack|release)$/, (r) => r.fulfill({ status: 200,
    contentType: 'application/json', body: JSON.stringify(burned ? { ok: true, burned: true } : { ok: true }) }));
  await page.goto(`${ORIGIN}${pre}/get?t=${'a'.repeat(48)}&r=health#${frag}`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#step-ready.active #ready-btn:not([disabled])', { timeout: 20000 });
  await page.click('#ready-btn');
  await page.waitForSelector('#step-done.active', { timeout: 20000 });
  const list = await rows(page, '#step-done');
  await ctx.close();
  return list;
}

test('/get: collected over the measured TLS, opened with the key from the link, wiped when the relay says so', async () => {
  const list = await collect('');
  assert.deepEqual(list.map((r) => r.step), ['fetch', 'open', 'wiped']);
  assert.equal(row(list, 'fetch').tech, 'TLS 1.3');
  assert.equal(row(list, 'open').tech, 'AES-256-GCM');
  assert.equal(row(list, 'wiped').text, 'Van de server gewist');
});

test('/get, English, no header and no burn confirmation: no TLS name and no wiped row', async () => {
  const list = await collect('/en', { tls: null, burned: false });
  assert.equal(row(list, 'fetch').text, 'Collected from the server');
  assert.equal(row(list, 'fetch').tech, '');
  assert.equal(row(list, 'wiped'), undefined, JSON.stringify(list));
});

// ── /sign ──────────────────────────────────────────────────────────────────
const ENV_ID = 'env_demo_abcdefghijklmnop';
const TOKEN = 't'.repeat(43);
async function stubSign(page, { tls = TLS13, ctIndex = 1234 } = {}) {
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ authenticated: true, email: 'demo@example.com' }) }));
  await page.route('**/api/user/account/signing-key/step-up/options', (r) =>
    r.fulfill({ status: 409, contentType: 'application/json', body: '{"error":"no_passkey"}' }));
  await page.route('**/api/user/account/signing-key', (r) => r.request().method() === 'POST'
    ? r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"totp_algorithm":"sha256"}' })
    : r.fulfill({ status: 200, contentType: 'application/json', body: '{"keys":[]}' }));
  await page.route('**/api/user/envelopes', (route) => route.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, envelope: { id: ENV_ID, party_count: 1, binding_mode: 'email',
      expires_at: new Date(Date.now() + 7 * 864e5).toISOString(),
      party_links: [{ party_index: 0, sign_path: `/co-sign?env=${ENV_ID}&p=0&t=${TOKEN}`, invite_token: TOKEN }] } }) }));
  await page.route('**/api/user/sign/activation', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ activation_id: 'act_demo_0001', email_hash: 'b'.repeat(64), recipe_version: 4 }) }));
  await page.route('**/api/user/sign/submit', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    headers: tls ? { 'X-Paramant-Tls': tls } : {},
    body: JSON.stringify({ ok: true, signed_count: 1, party_count: 1, status: 'complete', appearance_hash: null,
      ...(ctIndex != null ? { ct_index: ctIndex } : {}) }) }));
}

async function signAlone(pre, opts) {
  const page = await browser.newPage({ viewport: PHONE });
  await stubSign(page, opts);
  await page.goto(`${ORIGIN}${pre}/sign?mode=alone`, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    doc.addPage([595, 842]).drawText('Lease agreement', { x: 60, y: 760, size: 16 });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'Lease agreement.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"] canvas').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 400 } });
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-signer-name').fill('Signer Demo');
  await page.locator('#ds-identity-continue').click();
  await page.locator('#ds-sign-now').click();
  await page.locator('#ds-pass-panel:not([hidden])').waitFor({ timeout: 40000 });
  await page.locator('#ds-pass-input').fill('123456');
  await page.locator('#ds-pass-confirm').click();
  await page.locator('#step-done:not([hidden])').waitFor({ timeout: 90000 });
  const list = await rows(page, '#step-done');
  await page.close();
  return list;
}

test('/sign: the set from the key and signature that were made, TLS from the answer, the log index from the relay', async () => {
  const list = await signAlone('');
  assert.deepEqual(list.map((r) => r.step), ['sign', 'send', 'log'], JSON.stringify(list));
  assert.equal(row(list, 'sign').text, 'Ondertekend op dit apparaat');
  assert.equal(row(list, 'sign').tech, 'ML-DSA-65');
  assert.equal(row(list, 'send').tech, 'TLS 1.3');
  assert.equal(row(list, 'log').tech, 'logboek #1234');
});

test('/sign, English, an answer without a log index and without a TLS header', async () => {
  const list = await signAlone('/en', { tls: null, ctIndex: null });
  assert.equal(row(list, 'sign').text, 'Signed on this device');
  assert.equal(row(list, 'send').tech, '');
  assert.equal(row(list, 'log'), undefined, JSON.stringify(list));
});

// ── /verify ────────────────────────────────────────────────────────────────
async function makeProof(page) {
  return page.evaluate(async () => {
    const pqc = await import('/vendor/paramant-pqc.js');
    const signer = await import('/js/parasign-signer.js?v=24');
    const enc = new TextEncoder();
    const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    const b64 = (bytes) => { let v = ''; for (const b of bytes) v += String.fromCharCode(b); return btoa(v); };
    const source = enc.encode('a lease Acme signed');
    const documentHash = hex(pqc.sha3_256(source));
    const keys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
    const signerPublicKey = b64(keys.publicKey);
    const emailHash = hex(pqc.sha3_256(enc.encode('demo@example.com')));
    const appearance = signer.normaliseSigningAppearance({ version: 1, fields: [] });
    const envelopeId = 'env_demo_protocol_trail';
    const message = signer.buildDocSignMessage({ envelopeId, docHash: documentHash, partyIndex: 0, emailHash, recipeVersion: 5, signerPublicKey, appearance });
    return {
      source: Array.from(source),
      psign: {
        version: 'parasign-doc-3', recipe_version: 5, sign_domain: 'paramant/parasign/doc/v1',
        algorithm: 'ML-DSA-65', hash_algorithm: 'SHA3-256', original_filename: 'lease.txt',
        document_hash: documentHash, signer_public_key: signerPublicKey, party_email_hash: emailHash,
        appearance, appearance_hash: hex(signer.signingAppearanceHash(appearance)),
        signature: b64(pqc.ml_dsa65.sign(keys.secretKey, message)),
        multiparty: { envelope_id: envelopeId, party_index: 0, party_count: 1, signed_count: 1 },
      },
    };
  });
}

async function check(pre, { file, psign }) {
  const page = await browser.newPage({ viewport: PHONE });
  await page.route('https://relay.paramant.app/**', (r) => r.abort('internetdisconnected'));
  await page.goto(`${ORIGIN}${pre}/verify`, { waitUntil: 'domcontentloaded' });
  await page.locator('#vf-document').setInputFiles({ name: 'lease.txt', mimeType: 'text/plain', buffer: Buffer.from(file) });
  await page.locator('#vf-envelope').setInputFiles({ name: 'lease.psign', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(psign)) });
  await page.waitForFunction(() => !document.getElementById('vf-verify').disabled, null, { timeout: 10000 });
  await page.locator('#vf-verify').click();
  await page.waitForFunction(() => document.querySelector('#vf-result .ps-banner strong'), null, { timeout: 20000 });
  const list = await rows(page, '#vf-result');
  await page.close();
  return list;
}

let proof;
test('/verify: the checks that passed, named by what ran', async () => {
  const page = await browser.newPage();
  await page.goto(`${ORIGIN}/verify`, { waitUntil: 'domcontentloaded' });
  proof = await makeProof(page);
  await page.close();
  const list = await check('', { file: proof.source, psign: proof.psign });
  assert.deepEqual(list.map((r) => r.step), ['match', 'sigOk'], JSON.stringify(list));
  assert.equal(row(list, 'match').tech, 'SHA3-256');
  assert.equal(row(list, 'sigOk').text, 'Handtekening klopt');
  assert.equal(row(list, 'sigOk').tech, 'ML-DSA-65');
});

test('/verify: another file has no match row; a broken signature has no signature row', async () => {
  const other = await check('/en', { file: Array.from(Buffer.from('a different lease')), psign: proof.psign });
  assert.equal(row(other, 'match'), undefined, JSON.stringify(other));
  const sig = Buffer.from(proof.psign.signature, 'base64'); sig[10] ^= 0xff;
  const broken = await check('', { file: proof.source, psign: { ...proof.psign, signature: sig.toString('base64') } });
  assert.equal(row(broken, 'sigOk'), undefined, JSON.stringify(broken));
});
