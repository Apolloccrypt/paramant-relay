// Paramant Vault, the KDF contract of the .prmnt container.
//
// Two things have to stay true at the same time, and they pull against each
// other:
//
//   1. NEW files are locked at the current iteration count. OWASP's Password
//      Storage Cheat Sheet puts PBKDF2-HMAC-SHA256 at 600,000 rounds; the page
//      prints that number in words, so the number in the header has to be the
//      number on the page.
//   2. OLD files still open. The count is written into the container header, so
//      decryptFile derives with whatever the file was written with rather than
//      with today's constant. This test forges a container at the previous
//      210,000 rounds -- with Node's WebCrypto, byte for byte in the shipped
//      layout -- and makes the real page open it.
//
// Without (2), raising the number would have silently bricked every file a user
// already locked, and nothing else in the suite would have noticed: the browser
// reports a wrong count as "wrong passphrase".
//
// Run:
//   PLAYWRIGHT_CHROMIUM_PATH=/usr/bin/google-chrome node tests/vault-kdf.test.mjs

import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const KDF_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const KDF_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const KDF_MIME = { '.css':'text/css', '.html':'text/html', '.js':'text/javascript', '.svg':'image/svg+xml', '.png':'image/png' };

// The container, as frontend/vault.js writes it:
//   MAGIC "PRMNT" (5) | VERSION (1) | KDF id (1) | ITER u32-LE (4)
//   | SALT (16) | NONCE (12) | CIPHERTEXT
// and inside the ciphertext: [metaLen u32-LE][meta JSON][file bytes].
const PRMNT_MAGIC = Buffer.from('PRMNT', 'latin1');
const PRMNT_VERSION = 1;
const PRMNT_KDF_PBKDF2 = 1;
const PRMNT_HDR_LEN = 39;
const OLD_ITERATIONS = 210000; // what shipped before the raise

// The source of truth for the new number, read out of the file under test so
// this suite cannot drift away from it.
const vaultSource = fs.readFileSync(path.join(KDF_ROOT, 'vault.js'), 'utf8');
const iterMatch = /const ITER = (\d+);/.exec(vaultSource);
assert.ok(iterMatch, 'frontend/vault.js must declare a literal ITER');
const CURRENT_ITERATIONS = Number(iterMatch[1]);

async function forgeOldContainer(bytes, meta, passphrase) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const base = await webcrypto.subtle.importKey('raw', Buffer.from(passphrase, 'utf8'), 'PBKDF2', false, ['deriveKey']);
  const key = await webcrypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:OLD_ITERATIONS, hash:'SHA-256' },
    base, { name:'AES-GCM', length:256 }, false, ['encrypt']
  );
  const metaBuf = Buffer.from(JSON.stringify(meta), 'utf8');
  const plain = Buffer.alloc(4 + metaBuf.length + bytes.length);
  plain.writeUInt32LE(metaBuf.length, 0);
  metaBuf.copy(plain, 4);
  bytes.copy(plain, 4 + metaBuf.length);
  const ct = Buffer.from(await webcrypto.subtle.encrypt({ name:'AES-GCM', iv:nonce }, key, plain));
  const out = Buffer.alloc(PRMNT_HDR_LEN + ct.length);
  PRMNT_MAGIC.copy(out, 0);
  out[5] = PRMNT_VERSION;
  out[6] = PRMNT_KDF_PBKDF2;
  out.writeUInt32LE(OLD_ITERATIONS, 7);
  Buffer.from(salt).copy(out, 11);
  Buffer.from(nonce).copy(out, 27);
  ct.copy(out, PRMNT_HDR_LEN);
  return out;
}

const kdfServer = http.createServer((req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const wanted = pathname === '/vault' ? '/vault.html' : decodeURIComponent(pathname);
  const file = path.join(KDF_ROOT, wanted);
  if (!file.startsWith(KDF_ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, body) => {
    if (err) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': KDF_MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => kdfServer.listen(0, '127.0.0.1', resolve));
const KDF_ORIGIN = `http://localhost:${kdfServer.address().port}`;

const kdfBrowser = await chromium.launch({ headless:true, ...(KDF_EXE ? { executablePath:KDF_EXE } : {}) });

try {
  // ── The number in the code is 600,000, and it is the number on the page ────
  //
  // OWASP's floor for PBKDF2-HMAC-SHA256. Pinned as a literal on purpose: a
  // regression that reads the constant back out of the same file it is checking
  // proves nothing.
  assert.equal(CURRENT_ITERATIONS, 600000,
    'PBKDF2-HMAC-SHA256 must run at the OWASP figure of 600,000 rounds');

  const context = await kdfBrowser.newContext({ baseURL:KDF_ORIGIN, acceptDownloads:true });
  const page = await context.newPage();
  await page.goto(`${KDF_ORIGIN}/vault`);

  const shown = (await page.locator('main').innerText()).replace(/\s+/g, ' ');
  assert.ok(shown.includes(CURRENT_ITERATIONS.toLocaleString('en-US')),
    `the page must print the iteration count the code uses (${CURRENT_ITERATIONS.toLocaleString('en-US')}); it says: ${shown}`);
  assert.ok(shown.includes('PBKDF2-SHA-256') && shown.includes('AES-256-GCM'),
    `the page must name the KDF and the cipher it actually uses; it says: ${shown}`);
  // The claim the security review struck. AES-256 is not what makes this
  // construction strong, a long passphrase is, so no page here may sell it as
  // quantum anything.
  assert.doesNotMatch(shown, /quantum/i,
    `the vault page may not make a quantum claim; it says: ${shown}`);
  // And the honest sentence: no recovery, because there is nothing to recover
  // from.
  assert.match(shown, /cannot reset it for you/i,
    `the page must say that a lost passphrase cannot be recovered; it says: ${shown}`);

  // ── A file locked TODAY carries the new count in its header ───────────────
  const plaintext = Buffer.from('the quick brown fox jumps over the lazy dog\n', 'utf8');
  const passphrase = 'correct horse battery staple';
  await page.setInputFiles('#lock-input', { name:'report.txt', mimeType:'text/plain', buffer:plaintext });
  await page.fill('#lock-pw', passphrase);
  await page.fill('#lock-pw2', passphrase);
  const [locked] = await Promise.all([page.waitForEvent('download'), page.click('#lock-run')]);
  const lockedBytes = fs.readFileSync(await locked.path());

  assert.equal(lockedBytes.subarray(0, 5).toString('latin1'), 'PRMNT', 'the container must start with its magic');
  assert.equal(lockedBytes[5], PRMNT_VERSION, 'the container version changed without this test hearing about it');
  assert.equal(lockedBytes[6], PRMNT_KDF_PBKDF2, 'the KDF id must still say PBKDF2');
  assert.equal(lockedBytes.readUInt32LE(7), CURRENT_ITERATIONS,
    'a newly locked container must record the current iteration count');
  assert.ok(lockedBytes.length > PRMNT_HDR_LEN, 'the container must carry ciphertext after its 39-byte header');
  // Salt and nonce are fixed-width fields, so "16-byte salt" on the page is a
  // statement about these offsets. Two containers of the same file must differ
  // in both, which is the only way to see that they are random and not reused.
  const second = await (async () => {
    await page.reload();
    await page.setInputFiles('#lock-input', { name:'report.txt', mimeType:'text/plain', buffer:plaintext });
    await page.fill('#lock-pw', passphrase);
    await page.fill('#lock-pw2', passphrase);
    const [again] = await Promise.all([page.waitForEvent('download'), page.click('#lock-run')]);
    return fs.readFileSync(await again.path());
  })();
  assert.notEqual(lockedBytes.subarray(11, 27).toString('hex'), second.subarray(11, 27).toString('hex'),
    'the 16-byte salt must be random per file');
  assert.notEqual(lockedBytes.subarray(27, 39).toString('hex'), second.subarray(27, 39).toString('hex'),
    'the 12-byte nonce must be random per file');

  // ── A file locked at the OLD count still opens ────────────────────────────
  //
  // This is the whole point of raising the number in a header field. The
  // container below was never touched by the page: it was built here, at
  // 210,000 rounds, the way the shipped code built them yesterday.
  const legacyName = 'Q3_board_minutes.pdf';
  const legacyBody = Buffer.from('%PDF-1.7\nboard minutes, locked last year\n', 'utf8');
  const legacy = await forgeOldContainer(legacyBody, { name:legacyName, type:'application/pdf', size:legacyBody.length }, passphrase);
  assert.equal(legacy.readUInt32LE(7), OLD_ITERATIONS, 'the forged container must carry the old count');

  await page.reload();
  await page.click('.vt-tab[data-mode="open"]');
  await page.setInputFiles('#open-input', { name:'paramant-vault.prmnt', mimeType:'application/octet-stream', buffer:legacy });
  await page.fill('#open-pw', passphrase);
  const [opened] = await Promise.all([page.waitForEvent('download'), page.click('#open-run')]);
  assert.equal(opened.suggestedFilename(), legacyName,
    'opening a container locked at the old iteration count must give the original file back');
  assert.equal(fs.readFileSync(await opened.path()).toString('utf8'), legacyBody.toString('utf8'),
    'the bytes that come back out of an old container must be the bytes that went in');
  assert.match(await page.locator('#open-status').innerText(), /Opened/,
    'the page must report success for a container written with the old parameters');

  // ── And a wrong passphrase is still refused, at either count ──────────────
  await page.reload();
  await page.click('.vt-tab[data-mode="open"]');
  await page.setInputFiles('#open-input', { name:'paramant-vault.prmnt', mimeType:'application/octet-stream', buffer:legacy });
  await page.fill('#open-pw', 'not the passphrase');
  await page.click('#open-run');
  await page.locator('#open-status.err').waitFor();
  assert.match(await page.locator('#open-status').innerText(), /Wrong passphrase/,
    'a wrong passphrase must be refused, not silently accepted');

  console.log('PASS: vault locks at 600,000 PBKDF2-SHA-256 rounds, still opens containers written at 210,000, and the page says so.');
} finally {
  await kdfBrowser.close();
  await new Promise((resolve) => kdfServer.close(resolve));
}
