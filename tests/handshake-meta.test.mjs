// handshake-meta.test.mjs: the sender and the receiver read one field the same way.
//
// WHY THIS SUITE EXISTS
//
// A live ParaSend hand-over is announced by posting a record to /v2/pubkey. The
// relay has two free text fields there, and the sender borrows `kyber_pub` to
// say what is coming. On 4 September 2026 the two sides were one field out of
// step: frontend/js/parashare.page.js wrote `name|chunks|ttl` and
// frontend/js/ontvang.page.js read `chunks|ttl`, so the receiver took the file
// name for the block count and the block count for the time to live. A
// single-block transfer arrived with `ttl_ms = 1`, and /ontvang printed a line
// claiming our copy had auto-expired at a clock time worked out from it.
//
// frontend/js/handshake-meta.js is now the only place that string is written or
// read. This suite holds three things:
//
//   1. Both formats decode, and they are told apart on the number of fields:
//      three means the first one is a name, two is a sender minted before the
//      name was added and still has to work.
//   2. The bug itself cannot come back: a named field decoded by the shared
//      reader gives the ttl the sender put in, not the block count.
//   3. The real pages agree. The sender page is driven through a hand-over in a
//      browser, the string it actually posts is captured off the wire, and the
//      receiver page decodes that exact string. Name, chunks and ttl have to
//      match what the sender had in hand.
//
// The relay is stubbed at the network edge, the same way
// tests/end-screen-calm.test.mjs does it. No relay, no redis, no account.
//
// Run: node tests/handshake-meta.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FRONTEND = path.join(ROOT, 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }
function eq(name, actual, expected) {
  ok(name, Object.is(actual, expected), `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

// ── 1. the module on its own ────────────────────────────────────────────────
// Loaded the way the browser loads it: a plain script that hangs one object off
// window. No import, no shim in the file itself.
const win = {};
new Function('window', fs.readFileSync(path.join(FRONTEND, 'js', 'handshake-meta.js'), 'utf8'))(win);
const H = win.paramantHandshake;

ok('the module hangs paramantHandshake off window', !!(H && H.encode && H.decode));

{
  // A sender minted before 5 September 2026 still puts its file name in the
  // first field. It is read off the wire so chunks and ttl land right, and then
  // dropped: the module has no key to hand it back in.
  const m = H.decode('IMG_4276.jpeg|1|86400000');
  eq('named: chunks is the block count', m.chunks, 1);
  eq('named: ttl is the ttl and not the block count', m.ttlMs, 86400000);
  eq('named: it is a single file', m.kind, 'file');
  eq('named: the format is recognised on three fields', m.format, 'named');
  ok('named: an old sender\'s file name is not handed on', !('name' in m), JSON.stringify(m));
}

{
  const m = H.decode('file|3|900000');
  eq('kinded: the first field is a kind, not a name', m.kind, 'file');
  eq('kinded: chunks survives', m.chunks, 3);
  eq('kinded: ttl survives', m.ttlMs, 900000);
  eq('kinded: the format says so', m.format, 'kinded');
}

{
  // What a sender built before the name was added still sends.
  const m = H.decode('3|3600000');
  eq('legacy: chunks is the first field', m.chunks, 3);
  eq('legacy: ttl is the second field', m.ttlMs, 3600000);
  ok('legacy: there is no name to give', !('name' in m), JSON.stringify(m));
  eq('legacy: the format is recognised on two fields', m.format, 'legacy');
}

{
  const m = H.decode('vault|4|604800000');
  eq('vault: it is recognised as a vault', m.kind, 'vault');
  eq('vault: chunks carries the file count', m.chunks, 4);
  eq('vault: ttl survives', m.ttlMs, 604800000);
}

{
  // An old sender's file name is whatever its disk allowed, "|" included. The
  // numbers are read from the end of the string, so such a name still leaves
  // chunks and ttl where they belong on the way to being discarded.
  const m = H.decode('holiday | budget.xlsx|2|3600000');
  eq('a name containing a pipe leaves chunks alone', m.chunks, 2);
  eq('a name containing a pipe leaves ttl alone', m.ttlMs, 3600000);
}

{
  // The promise, at the one place it can be made unbreakable: there is no
  // parameter that could put a file name on the wire. /dpa says filenames are
  // never stored in readable form, and this is the writer that used to.
  eq('encode writes a kind where the name used to be',
    H.encode({ kind: 'file', chunks: 2, ttlMs: 900000 }), 'file|2|900000');
  eq('encode writes a vault the same way',
    H.encode({ kind: 'vault', chunks: 3, ttlMs: 900000 }), 'vault|3|900000');
  eq('a name handed to encode anyway cannot reach the wire',
    H.encode({ kind: 'file', name: 'loonstrook-2026-09.pdf', chunks: 2, ttlMs: 900000 }), 'file|2|900000');
  eq('and it cannot reach the wire through the vault branch either',
    H.encode({ kind: 'vault', name: 'loonstrook-2026-09.pdf', chunks: 3, ttlMs: 900000 }), 'vault|3|900000');
  const round = H.decode(H.encode({ kind: 'file', chunks: 7, ttlMs: 86400000 }));
  ok('encode and decode are each other\'s inverse',
    round.kind === 'file' && round.chunks === 7 && round.ttlMs === 86400000,
    JSON.stringify(round));
}

{
  // Nothing usable in, something usable out. No caller has to check the shape.
  const m = H.decode('');
  ok('an empty field still answers with a usable record',
    m.kind === 'file' && m.chunks === 1 && m.ttlMs === H.DEFAULT_TTL_MS, JSON.stringify(m));
  const n = H.decode('file|not-a-number|also-not');
  ok('unreadable numbers fall back rather than becoming NaN',
    n.chunks === 1 && n.ttlMs === H.DEFAULT_TTL_MS, JSON.stringify(n));
}

// The bug in one line: reading the named form with the old two-field rule.
{
  const field = H.encode({ kind: 'file', chunks: 1, ttlMs: 86400000 });
  const oldReading = parseInt(field.split('|')[1], 10);
  ok('the old two-field reading of a named field is exactly the reported bug',
    oldReading === 1 && H.decode(field).ttlMs === 86400000,
    `old reading gave ttl=${oldReading}, shared reader gives ttl=${H.decode(field).ttlMs}`);
}

// ── 2. the two real pages, in a browser ─────────────────────────────────────
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm',
  '.json': 'application/json', '.ico': 'image/x-icon' };
const ALIAS = { '/': '/index.html', '/parashare': '/parashare.html', '/ontvang': '/ontvang.html' };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const rel = ALIAS[url.pathname] || url.pathname;
  const file = path.join(FRONTEND, rel);
  if (!file.startsWith(FRONTEND)) { res.writeHead(403); return res.end('no'); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

const FILE_NAME = 'IMG_4276.jpeg';
const VAULT_NAMES = ['loonstrook-2026-09.pdf', 'opzegging-huurcontract.pdf'];
let posted = null;                    // the kyber_pub the sender actually put on the wire
let postedBody = null;                // the whole handshake record, to search for leaks
let vaultBody = null;                 // the same record for a multi-file send
let senderTtlMs = null;               // the ttl the sender had in hand

{
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await page.addInitScript(() => {
    const stub = { initCrypto: async () => {}, encryptBlob: async (p) => new Uint8Array(p.length + 32),
      decryptBlob: async () => new Uint8Array() };
    Object.defineProperty(window, '_cryptoBridge', { get: () => stub, set: () => {}, configurable: true });
  });
  await page.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }) }));
  for (const host of ['legal', 'finance', 'iot']) await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  await page.route('https://relay.paramant.app/**', (r) => r.abort());
  await page.route('https://health.paramant.app/v2/check-key', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms: 86400000,
      link_ttl_ms_by_plan: { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 } }) }));
  await page.route('https://health.paramant.app/v2/inbound', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, hash: 'a'.repeat(64), ttl_ms: 86400000, size: 0,
      download_token: 'a'.repeat(48), merkle_proof: null }) }));
  await page.route('https://health.paramant.app/v2/dl/**', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, enc_meta: null, file_size: 0, ttl_left_s: 3600, used: false }) }));
  let receiverThere = false;
  await page.route('https://health.paramant.app/v2/pubkey/**', (r) => receiverThere
    ? r.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ kyber_pub: 'ab'.repeat(64), ecdh_pub: 'cd'.repeat(32) }) })
    : r.fulfill({ status: 404, body: '' }));
  // The record under test. Captured rather than asserted here: what it has to
  // agree with is the receiver, not a string in this file.
  await page.route('https://health.paramant.app/v2/pubkey', (r) => {
    const body = r.request().postDataJSON();
    if (body && typeof body.device_id === 'string' && body.device_id.endsWith('_ready')) {
      posted = body.kyber_pub;
      postedBody = body;
    }
    return r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
  });

  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'domcontentloaded' });
  await page.locator('#file-input').setInputFiles({ name: FILE_NAME, mimeType: 'image/jpeg',
    buffer: Buffer.from(Array.from({ length: 2048 }, (_, i) => (i * 13 + 7) % 256)) });
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 20000 });
  await page.locator('#btn-create-session').click();
  await page.waitForSelector('#step-waiting.active', { timeout: 20000 });
  receiverThere = true;
  await page.waitForFunction(() => /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test((document.getElementById('fp-display')?.textContent || '').trim()),
    null, { timeout: 20000, polling: 250 });
  senderTtlMs = parseInt(await page.locator('#ttl-select').inputValue(), 10);
  await page.locator('#fp-confirm-check').check();
  await page.locator('#fp-confirm-btn').click();
  await page.waitForSelector('#step-done.active', { timeout: 40000 });
  await page.close();
}

ok('the sender page posts a handshake field at all', typeof posted === 'string' && posted.length > 0, String(posted));

// ── the leak this file now guards ───────────────────────────────────────────
// /dpa promises, in a contract customers sign: "Filenames not stored in
// plaintext (enc_meta ciphertext only)". Until 5 September 2026 the record
// below carried the file name in the clear, and the relay held it for an hour
// and handed it to anyone with the session token. The name still travels, but
// only inside the sealed chunk 0. This is the same check the link stand keeps
// at tests/parasend-send-a-link.test.mjs.
ok('the file name never reaches the relay in the handshake record',
  postedBody !== null && !JSON.stringify(postedBody).includes(FILE_NAME),
  JSON.stringify(postedBody));
ok('and neither does the stem of it, however the sender spelled it',
  postedBody !== null && !JSON.stringify(postedBody).toLowerCase().includes('img_4276'),
  JSON.stringify(postedBody));

// ── 3. a vault, where the leak was wider ────────────────────────────────────
// A multi-file send put its whole manifest in the other free field: a JSON list
// with every file name and every file size, stored verbatim on the relay for an
// hour. That is worse than the single-file case and the claims round missed it.
// What goes now is one token array per file and nothing else.
{
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await page.addInitScript(() => {
    const stub = { initCrypto: async () => {}, encryptBlob: async (p) => new Uint8Array(p.length + 32),
      decryptBlob: async () => new Uint8Array() };
    Object.defineProperty(window, '_cryptoBridge', { get: () => stub, set: () => {}, configurable: true });
  });
  await page.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }) }));
  for (const host of ['legal', 'finance', 'iot']) await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  await page.route('https://relay.paramant.app/**', (r) => r.abort());
  await page.route('https://health.paramant.app/v2/check-key', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms: 86400000,
      link_ttl_ms_by_plan: { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 } }) }));
  await page.route('https://health.paramant.app/v2/inbound', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, hash: 'a'.repeat(64), ttl_ms: 86400000, size: 0,
      download_token: 'a'.repeat(48), merkle_proof: null }) }));
  await page.route('https://health.paramant.app/v2/dl/**', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, enc_meta: null, file_size: 0, ttl_left_s: 3600, used: false }) }));
  let receiverThere = false;
  await page.route('https://health.paramant.app/v2/pubkey/**', (r) => receiverThere
    ? r.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ kyber_pub: 'ab'.repeat(64), ecdh_pub: 'cd'.repeat(32) }) })
    : r.fulfill({ status: 404, body: '' }));
  await page.route('https://health.paramant.app/v2/pubkey', (r) => {
    const body = r.request().postDataJSON();
    if (body && typeof body.device_id === 'string' && body.device_id.endsWith('_ready')) vaultBody = body;
    return r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
  });

  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'domcontentloaded' });
  await page.locator('#file-input').setInputFiles(VAULT_NAMES.map((name, i) => ({
    name, mimeType: 'application/pdf',
    buffer: Buffer.from(Array.from({ length: 1024 }, (_, j) => (j * 7 + i) % 256)) })));
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 20000 });
  await page.locator('#btn-create-session').click();
  await page.waitForSelector('#step-waiting.active', { timeout: 20000 });
  receiverThere = true;
  await page.waitForFunction(() => /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test((document.getElementById('fp-display')?.textContent || '').trim()),
    null, { timeout: 20000, polling: 250 });
  await page.locator('#fp-confirm-check').check();
  await page.locator('#fp-confirm-btn').click();
  await page.waitForSelector('#step-done.active', { timeout: 40000 });
  await page.close();
}

ok('a vault posts a handshake record too', vaultBody !== null, JSON.stringify(vaultBody));
ok('a vault manifest names none of its files',
  vaultBody !== null && !VAULT_NAMES.some((n) => JSON.stringify(vaultBody).includes(n)),
  JSON.stringify(vaultBody));
ok('a vault manifest carries no file sizes either',
  vaultBody !== null && !/"(size|name)"/.test(String(vaultBody.ecdh_pub || '')),
  String(vaultBody && vaultBody.ecdh_pub));
ok('what it does carry is one token array per file',
  vaultBody !== null && (() => {
    let list; try { list = JSON.parse(vaultBody.ecdh_pub); } catch { return false; }
    return Array.isArray(list) && list.length === VAULT_NAMES.length
      && list.every((f) => Object.keys(f).length === 1 && Array.isArray(f.tokens) && f.tokens.length > 0);
  })(),
  vaultBody && vaultBody.ecdh_pub);
ok('and the kind field says vault without saying anything else',
  vaultBody !== null && /^vault\|\d+\|\d+$/.test(vaultBody.kyber_pub || ''), vaultBody && vaultBody.kyber_pub);

{
  // The receiver page, reading the string the sender really sent. Loading
  // /ontvang gives us the module exactly as that page has it, cache-buster and
  // all, rather than a copy of the file this test picked up itself.
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await page.route('https://health.paramant.app/**', (r) => r.abort());
  await page.route('https://relay.paramant.app/**', (r) => r.abort());
  await page.goto(`${ORIGIN}/ontvang`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !!window.paramantHandshake, null, { timeout: 20000 });
  const read = await page.evaluate((field) => window.paramantHandshake.decode(field), posted);

  ok('the receiver is given no file name to read', !('name' in read), JSON.stringify(read));
  eq('sender and receiver agree that this is one file', read.kind, 'file');
  eq('sender and receiver agree on the block count', read.chunks, 1);
  eq('sender and receiver agree on the ttl', read.ttlMs, senderTtlMs);
  ok('the ttl the receiver reads is not the block count',
    read.ttlMs !== read.chunks, `ttl=${read.ttlMs} chunks=${read.chunks}`);

  // And the old sender still gets through the page that ships today.
  const legacy = await page.evaluate(() => window.paramantHandshake.decode('2|3600000'));
  ok('the receiver page still reads a sender that sends the old two-field form',
    legacy.chunks === 2 && legacy.ttlMs === 3600000 && legacy.format === 'legacy', JSON.stringify(legacy));
  await page.close();
}

await browser.close();
server.close();
server.closeAllConnections();

let failed = 0;
for (const c of checks) {
  console.log(`${c.pass ? 'ok  ' : 'FAIL'}  ${c.name}${c.pass || !c.detail ? '' : '  -- ' + c.detail}`);
  if (!c.pass) failed++;
}
console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
if (failed) process.exit(1);
