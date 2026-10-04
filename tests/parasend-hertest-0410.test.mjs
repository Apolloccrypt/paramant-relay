// ParaSend, hertest of 2026-10-04 (deel 4), the front-end half. Each test
// names the finding it holds shut. The relay half is in
// relay/test/route-dl-claim.test.js and relay/test/pickup-aanval.test.js.
//
//   T4-9   the file name went to the relay and the mailer (POST /v2/sends
//          `filename`), and into the extension's link (&n=)
//   T4-11  a 24 MB send counted five transfers: blocks carried no file_id
//   T4-L1  "Sending x, part 1 of 5" in English on the Dutch page
//   T4-13  "verstuurd als één pakket" while every file got its own link
//   T4-15  the sender's link list was gone after a reload
//   T4-L5  "30 seconden" in the expiry chooser
//   T4-12  "blokken van vast 5 MB" on /parasend, untrue for a link
//   T4-L2  "Naar uw overzicht" (/dashboard) for a receiver without an account
//   T4-L3  #enter-link without a label
//   new    a reopened link said "already being downloaded" for three minutes
//   T4-14  a dead "Samen, nu" link waited forever
//
// Run: node --test tests/parasend-hertest-0410.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FE = path.join(ROOT, 'frontend');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm', '.json': 'application/json' };
const ALIASES = { '/': '/index.html', '/parashare': '/parashare.html', '/en/parashare': '/en/parashare.html' };

let server;
let browser;
let ORIGIN;

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const file = path.join(FE, ALIASES[url.pathname] || url.pathname);
    if (!file.startsWith(FE)) { res.writeHead(403); return res.end('no'); }
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
  if (server) await new Promise((r) => server.close(r));
});

async function openSender(pagePath) {
  const seen = { inbound: [], sends: [] };
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.addInitScript(() => {
    window.__seal = [];
    new MutationObserver(() => {
      const el = document.getElementById('seal-status');
      if (el && el.textContent && window.__seal[window.__seal.length - 1] !== el.textContent) window.__seal.push(el.textContent);
    }).observe(document, { subtree: true, childList: true, characterData: true });
  });
  await page.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (r) => r.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }),
  }));
  for (const host of ['legal', 'finance', 'iot', 'relay']) await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  await page.route('https://health.paramant.app/v2/check-key', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms: 86400000,
      link_ttl_ms_by_plan: { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 } }),
  }));
  await page.route('https://health.paramant.app/v2/sends/precheck', (r) => r.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, limit: 30, count: 1 }) }));
  await page.route('https://health.paramant.app/v2/sends', (r) => {
    seen.sends.push(r.request().postData() || '');
    return r.fulfill({ status: 500, contentType: 'application/json', body: '{}' });
  });
  let n = 0;
  await page.route('https://health.paramant.app/v2/inbound', (r) => {
    const up = JSON.parse(r.request().postData() || '{}');
    seen.inbound.push(up.meta || {});
    n++;
    return r.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ ok: true, hash: up.hash, ttl_ms: 3600000, size: 0, download_token: String(n).padStart(48, 'a') }) });
  });
  await page.route(/^https:\/\/health\.paramant\.app\/v2\/dl\/[^/]+\/info$/, (r) => r.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, file_size: 600, ttl_left_s: 3500 }) }));
  await page.goto(`${ORIGIN}${pagePath}`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ps-mode-link').click();
  return { page, seen };
}

const NAME = 'geheim-rapport-q3.pdf';

test('T4-9, T4-11, T4-L1: a send to a person carries no file name, one file_id over every block, and Dutch progress', async () => {
  const { page, seen } = await openSender('/parashare');
  try {
    await page.locator('#file-input').setInputFiles({ name: NAME, mimeType: 'application/pdf', buffer: Buffer.alloc(6 * 1024 * 1024, 7) });
    await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 15000 });
    await page.fill('#recipients-input', 'ontvanger@example.com');
    await page.locator('#btn-create-session').click();
    await page.waitForFunction(() => document.querySelector('#seal-back') && !document.querySelector('#seal-back').hidden, null, { timeout: 30000 });

    assert.equal(seen.inbound.length, 2, 'a 6 MB file goes up in two blocks');
    const ids = seen.inbound.map((m) => m.file_id);
    assert.ok(/^[a-f0-9]{32}$/.test(ids[0] || ''), `every block names its file: ${JSON.stringify(seen.inbound)}`);
    assert.equal(ids[1], ids[0], 'both blocks carry the same file_id, so the relay counts one transfer');
    for (const m of seen.inbound) assert.ok(!JSON.stringify(m).includes(NAME), 'no name in the block meta');

    assert.equal(seen.sends.length, 1, 'POST /v2/sends was made');
    const body = JSON.parse(seen.sends[0]);
    assert.equal(body.filename, undefined, 'the relay and the mailer get no file name');
    assert.ok(!seen.sends[0].includes(NAME), 'not anywhere in the body');

    const seal = await page.evaluate(() => window.__seal);
    assert.ok(!seal.some((s) => /^Sending /.test(s)), `English progress on the Dutch page: ${JSON.stringify(seal)}`);
    assert.ok(seal.some((s) => s.includes(NAME + ' wordt verstuurd, deel 1 van 2')), `Dutch progress expected: ${JSON.stringify(seal)}`);
  } finally { await page.close(); }
});

test('T4-15: the link list survives a reload of the tab, and no key or plaintext leaves the browser (HAR check)', async () => {
  const { page } = await openSender('/parashare');
  const wire = [];
  page.on('request', (r) => wire.push({ url: r.url(), body: r.postData() || '', headers: JSON.stringify(r.headers()) }));
  try {
    const PLAIN = 'hallo daar, dit is geheim ' + 'x'.repeat(40);
    await page.locator('#file-input').setInputFiles({ name: 'klein-geheim.txt', mimeType: 'text/plain', buffer: Buffer.from(PLAIN) });
    await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 15000 });
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-link.active', { timeout: 20000 });
    assert.equal(await page.locator('#ps-link-list li').count(), 1);
    // The HAR check of the hertest, on this flow: the key (the fragment of the
    // link), the plaintext and the file name never appear in a request.
    const link = (await page.locator('#ps-link-list .ps-link-url').first().textContent()).trim();
    const frag = link.split('#')[1] || '';
    assert.ok(frag.length >= 40, 'the link carries its key in the fragment');
    for (const w of wire) {
      const all = w.url + '\n' + w.body + '\n' + w.headers;
      assert.ok(!all.includes(frag), `the key left the browser: ${w.url}`);
      assert.ok(!all.includes(PLAIN) && !all.includes(Buffer.from(PLAIN).toString('base64').slice(0, 40)), `plaintext left the browser: ${w.url}`);
      assert.ok(!all.includes('klein-geheim'), `the file name left the browser: ${w.url}`);
      assert.ok(!/referer":"[^"]*#/.test(w.headers), 'a Referer with a fragment');
    }
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#ps-earlier:not([hidden])', { timeout: 10000 });
    assert.equal(await page.locator('#ps-earlier-list li').count(), 1, 'the link is still listed after the reload');
    assert.match(await page.locator('#ps-earlier-list .ps-link-url').first().textContent(), /\/get\?t=/);
    const where = await page.evaluate(() => ({
      local: Object.keys(localStorage).filter((k) => k.includes('sentLinks')).length,
      session: Object.keys(sessionStorage).filter((k) => k.includes('sentLinks')).length,
    }));
    assert.deepEqual(where, { local: 0, session: 1 }, 'kept for the tab only, never in localStorage (the link carries its key)');
  } finally { await page.close(); }
});

test('T4-13, T4-L5: no "one package" claim, no 30-second expiry', async () => {
  const { page } = await openSender('/parashare');
  try {
    await page.locator('#file-input').setInputFiles([
      { name: 'a.txt', mimeType: 'text/plain', buffer: Buffer.from('a') },
      { name: 'b.txt', mimeType: 'text/plain', buffer: Buffer.from('b') },
    ]);
    const st = await page.textContent('#file-status');
    assert.doesNotMatch(st, /pakket/, st);
    const opts = await page.$$eval('#ttl-select option', (os) => os.map((o) => o.value));
    assert.ok(!opts.includes('30000'), `ttl options: ${opts}`);
  } finally { await page.close(); }
  for (const f of ['frontend/parashare.html', 'frontend/en/parashare.html']) {
    const s = read(f);
    assert.doesNotMatch(s, /value="30000"/, f);
    assert.doesNotMatch(s, /één pakket|single package/, f);
  }
});

test('T4-12, T4-L2, T4-L3: page texts and the receive landing', () => {
  for (const f of ['frontend/parasend.html', 'frontend/en/parasend.html']) {
    assert.doesNotMatch(read(f), /blokken van vast 5 MB|blocks of a fixed 5 MB/, f);
  }
  for (const f of ['frontend/get.html', 'frontend/en/get.html']) {
    const s = read(f);
    assert.doesNotMatch(s, /href="\/dashboard"/, `${f}: a receiver has no dashboard`);
    assert.match(s, /<label[^>]+for="enter-link"/, `${f}: the link field needs a label`);
  }
});

test('T4-9: the extension link carries no file name, and /get reads it from the seal', () => {
  const core = read('extensions/shared/paramant-core.js');
  const fn = core.slice(core.indexOf('export function buildShareUrl'), core.indexOf('}', core.indexOf('export function buildShareUrl')) + 1);
  assert.doesNotMatch(fn, /&n=/, fn);
  assert.match(read('frontend/js/get.page.js'), /meta\.file_name/, 'get.page.js must read the name the core writes');
});

test('new: a reopened link is not told to wait for its own claim', () => {
  const g = read('frontend/js/get.page.js');
  assert.match(g, /localStorage/, 'the claim id is shared by the tabs of one browser');
  assert.match(g, /addEventListener\('pagehide'[\s\S]{0,400}\/release/, 'a closed tab gives its claim back');
  assert.doesNotMatch(g, /over een paar minuten|in a few minutes/, 'the busy text no longer promises minutes');
  const o = read('frontend/js/ontvang.page.js');
  assert.match(o, /\/get\?claim=\$\{DL_CLAIM\}/, 'the live receiver claims its blocks');
  assert.match(o, /await dlAck\(tok\)/, 'and acks only after decrypting');
});

test('T4-14: a dead "Samen, nu" link stops waiting and says so', () => {
  const o = read('frontend/js/ontvang.page.js');
  assert.match(o, /SENDER_WAIT_MS\s*=\s*10 \* 60 \* 1000/);
  assert.match(o, /showError\(t\('senderGone'\)\)/);
  assert.match(o, /senderGone: 'De afzender heeft deze sessie niet afgemaakt/);
});
