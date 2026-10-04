// /parashare, /ontvang and the end screens after fase 1 (P04, P05), in a real
// browser. The relay half that matters (the rejection record) runs against a
// real relay.js; everything else is stubbed at the network edge.
//
//   P04 bij SEND-03-A  a 429 on /v2/check-key read as "invalid key"
//   SENDNAME-09-RAM    a 503 from the relay's memory guard broke the send
//   SENDNAME-12-A      the send-to-people end screen lost its explanation and
//                      its way to the dashboard (done-state.js knew two fields)
//   SENDNAME-28-A      the receiver never heard that the sender rejected the code
//   SENDNAME-49-A      "Open de webapp" on /download went to the home page
//
// Run: node --test tests/parashare-fase2-browser.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { startRelay } from './_relay-stack.mjs';

const PF_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const PF_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const PF_MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm', '.json': 'application/json', '.jpg': 'image/jpeg' };
const PF_ALIAS = { '/parashare': '/parashare.html', '/en/parashare': '/en/parashare.html', '/ontvang': '/ontvang.html', '/en/ontvang': '/en/ontvang.html', '/get': '/get.html' };

let pfStack;
let pfServer;
let pfBrowser;
let PF_ORIGIN;

before(async () => {
  // PARAMANT_TEST_RELAY: a relay already running on the host, for a WebKit run
  // in the Playwright container (~/bin/pw-webkit.sh), which cannot load relay.js.
  pfStack = process.env.PARAMANT_TEST_RELAY
    ? { basis: process.env.PARAMANT_TEST_RELAY, stop() {} }
    : await startRelay({ env: { USERS_JSON: JSON.stringify({ api_keys: [{ key: 'pgp_pf_suite_key', active: true, plan: 'pro', account_id: 'acct_pf' }] }) } });
  pfServer = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://localhost');
    const file = path.join(PF_ROOT, PF_ALIAS[u.pathname] || u.pathname);
    if (!file.startsWith(PF_ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, body) => {
      if (e) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': PF_MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  await new Promise((r) => pfServer.listen(0, '127.0.0.1', r));
  PF_ORIGIN = `http://localhost:${pfServer.address().port}`;
  pfBrowser = await chromium.launch({ headless: true, ...(PF_EXE ? { executablePath: PF_EXE } : {}) });
});

after(async () => {
  if (pfBrowser) await pfBrowser.close();
  if (pfServer) await new Promise((r) => pfServer.close(r));
  if (pfStack) pfStack.stop();
});

const TTLS = { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 };

// The sender page with a session token and one answering sector. `checkKey` and
// `inbound` decide what the relay says.
async function senderPage({ checkKey, inbound }) {
  const page = await pfBrowser.newPage();
  await page.route('**/api/user/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }) }));
  for (const host of ['legal', 'finance', 'iot', 'relay']) await page.route(`https://${host}.paramant.app/**`, (route) => route.abort());
  await page.route('https://health.paramant.app/v2/check-key', checkKey);
  if (inbound) await page.route('https://health.paramant.app/v2/inbound', inbound);
  await page.route('https://health.paramant.app/v2/dl/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, file_size: 0, ttl_left_s: 3600 }) }));
  return page;
}

test('P04: a 429 on check-key says "too many checks", never that the key is invalid', async () => {
  const page = await senderPage({ checkKey: (route) => route.fulfill({ status: 429, contentType: 'application/json', body: '{"error":"rate_limited"}' }) });
  await page.goto(PF_ORIGIN + '/parashare');
  await page.waitForFunction(() => /controles/.test(document.getElementById('key-status')?.textContent || ''), null, { timeout: 15000 });
  const status = await page.locator('#key-status').innerText();
  assert.match(status, /te veel controles/i);
  assert.doesNotMatch(status, /ongeldig|ingetrokken|hoort bij geen/i);
  await page.close();
});

test('SENDNAME-09-RAM: a 503 with Retry-After is waited out, and the link still comes', async () => {
  let calls = 0;
  const page = await senderPage({
    checkKey: (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms: 86400000, link_ttl_ms_by_plan: TTLS }) }),
    inbound: async (route) => {
      calls++;
      if (calls === 1) return route.fulfill({ status: 503, headers: { 'Retry-After': '1' }, contentType: 'application/json', body: '{"error":"ram_limit"}' });
      const body = JSON.parse(route.request().postData() || '{}');
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, hash: body.hash, ttl_ms: 3600000, download_token: 'c'.repeat(48) }) });
    },
  });
  await page.goto(PF_ORIGIN + '/parashare');
  await page.locator('#ps-mode-link').click();
  await page.locator('#file-input').setInputFiles({ name: 'a.bin', mimeType: 'application/octet-stream', buffer: crypto.randomBytes(500) });
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 15000 });
  await page.locator('#btn-create-session').click();
  await page.waitForSelector('#step-link.active', { timeout: 20000 });
  assert.equal(calls, 2, 'the block was not sent again after the 503');
  await page.close();
});

test('SENDNAME-12-A: the end screen shows lead, note and the dashboard link', async () => {
  const page = await senderPage({ checkKey: (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms_by_plan: TTLS }) }) });
  await page.goto(PF_ORIGIN + '/parashare');
  await page.waitForFunction(() => window.paramantDone && window.paramantDone.fill, null, { timeout: 10000 });
  await page.evaluate(() => {
    window.paramantDone.fill('step-done', { title: 'T', lead: '2 van 2 uitnodigingen zijn onderweg.', note: 'Iedere ontvanger bevestigt eerst.', actions: [{ label: 'Naar uw dashboard', href: '/dashboard' }] });
    document.getElementById('step-done').classList.add('active');
  });
  const text = await page.locator('#step-done').innerText();
  assert.match(text, /uitnodigingen zijn onderweg/);
  assert.match(text, /bevestigt eerst/);
  assert.equal(await page.locator('#step-done .done-payload a[href="/dashboard"]').count(), 1);
  const src = fs.readFileSync(path.join(PF_ROOT, 'js/parashare.page.js'), 'utf8');
  assert.match(src, /lead: t\('invitesLead'\)\(aantal\),\s*note: t\('invitesNote'\)/);
  await page.close();
});

test('SENDNAME-28-A: the sender\'s rejection reaches the receiver, through a real relay', async () => {
  const inv = 'inv_' + crypto.randomBytes(16).toString('hex');
  // 1. What rejectFingerprint() posts, caught on the sender page.
  const sender = await senderPage({ checkKey: (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms_by_plan: TTLS }) }) });
  let posted = null;
  await sender.route('https://health.paramant.app/v2/pubkey', async (route) => { posted = JSON.parse(route.request().postData() || '{}'); await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }); });
  await sender.goto(PF_ORIGIN + '/parashare');
  await sender.waitForFunction(() => typeof rejectFingerprint === 'function', null, { timeout: 10000 });
  await sender.evaluate((t) => { sessionToken = t; rejectFingerprint(); }, inv);
  await sender.waitForFunction(() => document.getElementById('step-setup').classList.contains('active'), null, { timeout: 5000 });
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(posted, 'rejecting posted nothing the receiver could see');
  assert.equal(posted.device_id, inv + '_ready');
  await sender.close();

  // 2. The real relay accepts that record under its handshake grammar.
  const r = await fetch(pfStack.basis + '/v2/pubkey', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(posted) });
  assert.equal(r.status, 200, 'the relay refused the rejection record: ' + await r.text());

  // 3. The receiver, polling that relay, stops waiting and says why.
  const ctx = await pfBrowser.newContext();
  await ctx.route(/^https:\/\/(relay|health)\.paramant\.app\//, async (route) => {
    const u = new URL(route.request().url());
    const resp = await route.fetch({ url: pfStack.basis + u.pathname + u.search });
    await route.fulfill({ response: resp, headers: { ...resp.headers(), 'access-control-allow-origin': PF_ORIGIN } });
  });
  const recv = await ctx.newPage();
  await recv.goto(`${PF_ORIGIN}/ontvang?s=${inv}&r=health`);
  await recv.waitForSelector('#step-error.active', { timeout: 30000 });
  assert.match(await recv.locator('#step-error').innerText(), /andere controlecode/);
  await ctx.close();
});

test('SENDNAME-49-A: "Open de webapp" opens the web app, not the home page', () => {
  assert.match(fs.readFileSync(path.join(PF_ROOT, 'download.html'), 'utf8'), /href="\/parashare">Open de webapp/);
  assert.match(fs.readFileSync(path.join(PF_ROOT, 'en/download.html'), 'utf8'), /href="\/en\/parashare">Open the web app/);
});

test('P04: the file line says KB with a decimal comma, and a file name stays text', async () => {
  const page = await senderPage({ checkKey: (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms_by_plan: TTLS }) }) });
  await page.goto(PF_ORIGIN + '/parashare');
  await page.locator('#file-input').setInputFiles({ name: 'loonstrook.pdf', mimeType: 'application/pdf', buffer: crypto.randomBytes(40_000) });
  assert.match(await page.locator('#file-status').innerText(), /loonstrook\.pdf \(39,1 KB\)/);
  await page.locator('#file-input').setInputFiles([
    { name: '<img src=x onerror=window.__pwned=1>.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(10) },
    { name: 'b.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(10) },
  ]);
  await page.waitForTimeout(200);
  assert.equal(await page.evaluate(() => window.__pwned || 0), 0, 'a file name became markup');
  assert.match(await page.locator('#vault-list').innerText(), /<img src=x/);
  await page.close();
});

test('jargon: the Dutch messages on /parashare do not speak of a relay or a sector', () => {
  const src = fs.readFileSync(path.join(PF_ROOT, 'js/parashare.page.js'), 'utf8');
  const nl = src.slice(src.indexOf('\n  nl: {'), src.indexOf('\n};', src.indexOf('\n  nl: {')));
  const lines = nl.split('\n').filter((l) => /^\s+\w+: /.test(l) && !/^\s+relayLoc:/.test(l));
  // Only what a reader sees: drop the key, arrow parameters and ${...} slots.
  const said = (l) => l.replace(/^\s+\w+:/, '').replace(/\([^)]*\)\s*=>/g, '').replace(/\$\{[^}]*\}/g, '');
  const hits = lines.filter((l) => /\brelay\b|\bsector\b/i.test(said(l)));
  assert.deepEqual(hits, []);
});
