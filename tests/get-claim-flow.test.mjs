// /get against a real relay: a one-time link burns when the receiver HAS the
// file, and not before.
//
// The 2026-10-04 ParaSend round (tester 4) found four ways the receiver lost a
// file he never got, each reproduced in a browser. This suite pins them:
//
//   1. a link from the Outlook add-in or the browser extension opens for a
//      receiver without an account: /parashare?t=..#k=.. reaches /get with the
//      fragment intact, both by the nginx-style 302 and by the page itself
//   2. a mail scanner that opens the link and runs its JavaScript, without a
//      click, burns nothing
//   3. a download that breaks off burns nothing; the receiver tries again
//   8. a key with one wrong character burns nothing; the right link still works
//
// plus the honest message for an expired link (finding 4), a sha256 roundtrip
// on every success, and a HAR scan: no key, no fragment, no plaintext and no
// file name of a web app link ever leaves the browser.
//
// Run: node --test tests/get-claim-flow.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { startRelay } from './_relay-stack.mjs';

const GCF_HERE = path.dirname(fileURLToPath(import.meta.url));
const GCF_ROOT = path.join(GCF_HERE, '..', 'frontend');
const GCF_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const GCF_MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };
const GCF_KEY = 'pgp_get_claim_flow_suite';
const GCF_TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'gcf-'));

let gcfStack;
let gcfServer;
let gcfBrowser;
let GCF_ORIGIN;

before(async () => {
  // PARAMANT_TEST_RELAY: a relay already running on the host (with GCF_KEY), for
  // a WebKit run in the Playwright container, which cannot load relay.js.
  gcfStack = process.env.PARAMANT_TEST_RELAY
    ? { basis: process.env.PARAMANT_TEST_RELAY, stop() {} }
    : await startRelay({
      env: { USERS_JSON: JSON.stringify({ api_keys: [{ key: GCF_KEY, active: true, plan: 'pro', account_id: 'acct_gcf', email: 'gcf@example.test' }] }) },
    });
  gcfServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    // What deploy/nginx-paramant-live.conf does in front of the login gate: a
    // /parashare address with ?t= is a receiving link, 302 to /get, query
    // intact, no fragment in the Location.
    if (url.pathname === '/gated/parashare' && url.searchParams.get('t')) {
      res.writeHead(302, { Location: '/get' + url.search });
      return res.end();
    }
    const map = { '/get': '/get.html', '/en/get': '/en/get.html', '/parashare': '/parashare.html', '/en/parashare': '/en/parashare.html' };
    const rel = map[url.pathname] || url.pathname;
    const file = path.join(GCF_ROOT, rel);
    if (!file.startsWith(GCF_ROOT)) { res.writeHead(403); return res.end('no'); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': GCF_MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  await new Promise((r) => gcfServer.listen(0, '127.0.0.1', r));
  GCF_ORIGIN = `http://localhost:${gcfServer.address().port}`;
  gcfBrowser = await chromium.launch({ headless: true, ...(GCF_EXE ? { executablePath: GCF_EXE } : {}) });
});

after(async () => {
  if (gcfBrowser) await gcfBrowser.close();
  if (gcfServer) await new Promise((r) => gcfServer.close(r));
  if (gcfStack) gcfStack.stop();
  try { fs.rmSync(GCF_TMP, { recursive: true, force: true }); } catch { /* gone */ }
});

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const b64url = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function upload(blob, ttlMs) {
  const hash = sha(blob);
  const r = await fetch(gcfStack.basis + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': GCF_KEY },
    body: JSON.stringify({ hash, payload: Buffer.from(blob).toString('base64'), ...(ttlMs ? { ttl_ms: ttlMs } : {}) }),
  });
  const j = await r.json();
  assert.equal(r.status, 200, 'upload refused: ' + JSON.stringify(j));
  return j.download_token;
}
const info = (token) => fetch(gcfStack.basis + '/v2/dl/' + token + '/info').then(async (r) => ({ status: r.status, json: await r.json() }));

// What the web app's "Later ophalen" stand seals: [u32 LE nameLen][name][data],
// AES-256-GCM, key and iv in the fragment.
async function webappLink(name, data, ttlMs) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const nb = Buffer.from(name, 'utf8');
  const head = Buffer.alloc(4); head.writeUInt32LE(nb.length, 0);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.concat([head, nb, data])), c.final(), c.getAuthTag()]);
  const token = await upload(ct, ttlMs);
  const frag = b64url(Buffer.concat([key, iv]));
  return { token, frag, url: `${GCF_ORIGIN}/get?t=${token}&r=health#${frag}` };
}

// Every relay host the page may call goes to the local relay; nothing else
// leaves the machine.
async function receiverContext() {
  const harPath = path.join(GCF_TMP, `r-${crypto.randomBytes(4).toString('hex')}.har`);
  const ctx = await gcfBrowser.newContext({ acceptDownloads: true, recordHar: { path: harPath, content: 'embed' } });
  const calls = [];
  const plan = { abortNextGet: false };
  await ctx.route(/^https:\/\/(relay|health|legal|finance|iot)\.paramant\.app\//, async (route) => {
    const req = route.request();
    const u = new URL(req.url());
    calls.push(req.method() + ' ' + u.pathname + u.search);
    if (plan.abortNextGet && /\/get$/.test(u.pathname)) { plan.abortNextGet = false; return route.abort('connectionreset'); }
    const resp = await route.fetch({ url: gcfStack.basis + u.pathname + u.search, maxRedirects: 0 });
    await route.fulfill({ response: resp, headers: { ...resp.headers(), 'access-control-allow-origin': GCF_ORIGIN } });
  });
  await ctx.route(/^https?:\/\/(?!localhost|127\.0\.0\.1)/, (route) => {
    if (/^https:\/\/(relay|health|legal|finance|iot)\.paramant\.app\//.test(route.request().url())) return route.fallback();
    return route.abort();
  });
  return { ctx, calls, plan, harPath };
}

async function activeStep(page) {
  await page.waitForFunction(() => {
    const a = document.querySelector('.step.active');
    return a && a.id !== 'step-loading';
  }, null, { timeout: 20000 });
  return page.evaluate(() => document.querySelector('.step.active').id);
}

async function clickAndSave(page) {
  const dl = page.waitForEvent('download', { timeout: 20000 });
  await page.click('#ready-btn');
  const d = await dl;
  const p = path.join(GCF_TMP, 'dl-' + Date.now());
  await d.saveAs(p);
  await page.waitForSelector('#step-done.active', { timeout: 20000 });
  return { name: d.suggestedFilename(), bytes: fs.readFileSync(p) };
}

test('2: opening the link without a click fetches nothing and burns nothing; the click then delivers, sha256 intact', async () => {
  const data = crypto.randomBytes(300_000);
  const name = 'Loonstrook oktober.pdf.bin';
  const link = await webappLink(name, data);
  const { ctx, calls, harPath } = await receiverContext();
  const page = await ctx.newPage();
  await page.goto(link.url);
  assert.equal(await activeStep(page), 'step-ready');
  await page.waitForFunction(() => !document.getElementById('ready-btn').disabled, null, { timeout: 10000 });
  // A scanner sits here for a while and leaves.
  await page.waitForTimeout(2500);
  assert.deepEqual(calls.filter((c) => /\/get/.test(c)), [], 'the page fetched the file without a click');
  assert.equal((await info(link.token)).status, 200, 'merely opening the link burned it');

  const got = await clickAndSave(page);
  assert.equal(got.name, name);
  assert.equal(sha(got.bytes), sha(data), 'sha256 roundtrip broke');
  assert.ok(calls.some((c) => /^POST \/v2\/dl\/[a-f0-9]{48}\/ack$/.test(c)), 'the page never confirmed the download');
  const after = await info(link.token);
  assert.equal(after.status, 404);
  assert.equal(after.json.reason, 'downloaded');

  // The second visit: the right message, not a fake success.
  const p2 = await ctx.newPage();
  await p2.goto(link.url);
  assert.equal(await activeStep(p2), 'step-burned');
  assert.match(await p2.locator('#burned-msg').innerText(), /al gedownload/);
  await ctx.close();

  // Nothing secret on the wire: not the key, not the fragment, not the name,
  // not a recognisable piece of the plaintext.
  const har = fs.readFileSync(harPath, 'utf8');
  const keyB64 = Buffer.from(b64urlDecode(link.frag)).subarray(0, 32).toString('base64');
  for (const [what, needle] of [['fragment', link.frag], ['key', keyB64], ['file name', name], ['plaintext', data.subarray(1000, 1024).toString('base64')]]) {
    assert.ok(!har.includes(needle), `the ${what} appears in the HAR`);
  }
});

function b64urlDecode(s) { return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }

test('8: a key with one wrong character burns nothing, and the right link still works', async () => {
  const data = crypto.randomBytes(50_000);
  const link = await webappLink('contract.bin', data);
  const flip = link.frag[5] === 'A' ? 'B' : 'A';
  const badFrag = link.frag.slice(0, 5) + flip + link.frag.slice(6);
  const { ctx, calls } = await receiverContext();
  const page = await ctx.newPage();
  await page.goto(`${GCF_ORIGIN}/get?t=${link.token}&r=health#${badFrag}`);
  await page.waitForFunction(() => !document.getElementById('ready-btn').disabled, null, { timeout: 10000 });
  await page.click('#ready-btn');
  assert.equal(await page.waitForSelector('#step-error.active', { timeout: 20000 }).then(() => 'step-error'), 'step-error');
  assert.match(await page.locator('#error-msg').innerText(), /niets gewist/);
  assert.ok(!calls.some((c) => /\/ack$/.test(c)), 'a failed decryption must never be confirmed');
  await page.waitForTimeout(300);
  assert.equal((await info(link.token)).status, 200, 'a wrong key burned the file');

  const p2 = await ctx.newPage();
  await p2.goto(link.url);
  await p2.waitForFunction(() => !document.getElementById('ready-btn').disabled, null, { timeout: 10000 });
  const got = await clickAndSave(p2);
  assert.equal(sha(got.bytes), sha(data));
  await ctx.close();
});

test('3: a download that breaks off burns nothing, and "try again" delivers the file', async () => {
  const data = crypto.randomBytes(120_000);
  const link = await webappLink('scan.bin', data);
  const { ctx, plan } = await receiverContext();
  const page = await ctx.newPage();
  await page.goto(link.url);
  await page.waitForFunction(() => !document.getElementById('ready-btn').disabled, null, { timeout: 10000 });
  plan.abortNextGet = true;
  await page.click('#ready-btn');
  await page.waitForSelector('#step-error.active', { timeout: 20000 });
  assert.match(await page.locator('#error-msg').innerText(), /niets gewist/);
  assert.equal((await info(link.token)).status, 200, 'a broken download burned the file');
  const dl = page.waitForEvent('download', { timeout: 20000 });
  await page.click('#error-retry');
  const d = await dl;
  const p = path.join(GCF_TMP, 'retry-' + Date.now());
  await d.saveAs(p);
  assert.equal(sha(fs.readFileSync(p)), sha(data));
  await ctx.close();
});

test('3: no hard deadline on the whole download, only on a line that goes silent', () => {
  const src = fs.readFileSync(path.join(GCF_ROOT, 'js', 'get.page.js'), 'utf8');
  assert.ok(!/AbortSignal\.timeout\(/.test(src), 'get.page.js puts a fixed deadline on a request again; a slow line then loses the file');
  assert.match(src, /STALL_MS/);
});

test('4: an expired link says it expired, not that it was downloaded', async () => {
  const link = await webappLink('kort.bin', crypto.randomBytes(1000), 1200);
  await new Promise((r) => setTimeout(r, 1700));
  const { ctx } = await receiverContext();
  const page = await ctx.newPage();
  await page.goto(link.url);
  assert.equal(await activeStep(page), 'step-burned');
  assert.match(await page.locator('#burned-msg').innerText(), /verlopen/);
  assert.doesNotMatch(await page.locator('#step-burned').innerText(), /al gedownload/);
  await ctx.close();
});

// The add-in and the extension seal with extensions/shared/paramant-core.js.
async function fileLink(name, data) {
  const core = await import('../extensions/shared/paramant-core.js');
  const tokens = [];
  const keys = [];
  const fileId = core.randomFileId();
  const total = core.chunkCount(data.length);
  for (let i = 0; i < total; i++) {
    const chunk = new Uint8Array(data.subarray(i * core.CHUNK_PLAIN, (i + 1) * core.CHUNK_PLAIN));
    const { padded, rawKey } = await core.encryptChunk(chunk, { name, size: data.length, chunk: i, total, fileId });
    tokens.push(await upload(Buffer.from(padded)));
    keys.push(b64url(rawKey));
  }
  const url = core.buildShareUrl({ tokens, name, chunks: total, relay: 'https://legal.paramant.app', keys });
  assert.ok(url.startsWith('https://paramant.app/get?'), 'the extension still mints links to a page behind the login');
  return { tokens, url };
}

for (const [label, entry] of [
  ['the nginx 302 in front of the login gate', '/gated/parashare'],
  ['/parashare itself, on a server without that gate', '/parashare'],
]) {
  test(`1: an add-in link to /parashare reaches /get with its key, via ${label}`, async () => {
    const data = crypto.randomBytes(5_300_000); // two chunks
    const name = 'Jaarstukken 2026.zip';
    const link = await fileLink(name, data);
    const old = link.url.replace('https://paramant.app/get', GCF_ORIGIN + entry);
    const { ctx } = await receiverContext();
    const page = await ctx.newPage();
    await page.goto(old);
    await page.waitForURL(/\/get\?/, { timeout: 20000 });
    assert.match(page.url(), /#k=/, 'the key in the fragment was lost on the way to /get');
    assert.equal(await activeStep(page), 'step-ready');
    await page.waitForFunction(() => !document.getElementById('ready-btn').disabled, null, { timeout: 10000 });
    const got = await clickAndSave(page);
    assert.equal(got.name, name);
    assert.equal(sha(got.bytes), sha(data), 'sha256 roundtrip broke on the extension format');
    for (const tk of link.tokens) assert.equal((await info(tk)).json.reason, 'downloaded');
    await ctx.close();
  });
}

// Fase 1, EXT-16-A: the browser extension up to 1.0.1 sealed every attachment
// as 0 bytes while the seal still said the real size. The receiver got an empty
// file under "U hebt het bestand", and the one-time link was spent on it. The
// page now compares what it opened with the size in the seal, burns nothing on
// a mismatch, and says so. The ready screen also stopped showing the 5 MB
// padding of a FileLink block as the file's size.
test('EXT-16-A: a FileLink that holds fewer bytes than its seal says is refused, and nothing is burned', async () => {
  const core = await import('../extensions/shared/paramant-core.js');
  const { padded, rawKey } = await core.encryptChunk(new Uint8Array(0), { file_id: core.randomFileId(), file_name: 'rapport.pdf', file_size: 2097155, chunk_index: 0, total_chunks: 1, chunk_size: 0 });
  const token = await upload(Buffer.from(padded));
  const url = core.buildShareUrl({ tokens: [token], chunks: 1, relay: 'https://legal.paramant.app', keys: [b64url(rawKey)] }).replace('https://paramant.app', GCF_ORIGIN);
  const { ctx, calls } = await receiverContext();
  const page = await ctx.newPage();
  await page.goto(url);
  await page.waitForFunction(() => !document.getElementById('ready-btn').disabled, null, { timeout: 10000 });
  assert.doesNotMatch(await page.locator('#ready-meta').innerText(), /5[,.]0 MB/, 'the ready screen shows the padding as the size');
  await page.click('#ready-btn');
  await page.waitForSelector('#step-error.active', { timeout: 20000 });
  assert.match(await page.locator('#error-msg').innerText(), /niet goed ingepakt.*niets gewist/s);
  assert.ok(!calls.some((c) => /\/ack$/.test(c)), 'an empty file was confirmed and burned');
  await page.waitForTimeout(300);
  assert.equal((await info(token)).status, 200);
  await ctx.close();
});

test('P04: a Dutch /get writes sizes with a decimal comma', async () => {
  const link = await webappLink('komma.bin', crypto.randomBytes(40_000));
  const { ctx } = await receiverContext();
  const page = await ctx.newPage();
  await page.goto(link.url);
  await page.waitForFunction(() => /Grootte/.test(document.getElementById('ready-meta').textContent), null, { timeout: 10000 });
  assert.match(await page.locator('#ready-meta').innerText(), /Grootte \d+,\d KB/);
  await ctx.close();
});
