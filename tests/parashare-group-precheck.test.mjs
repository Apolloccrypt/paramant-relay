// /parashare, Send a link to named people, against a stubbed relay.
//
// Three faults reproduced on 57b0fdf9:
//   - a Community sender with two addresses sealed and uploaded the file, and
//     only then heard "Your plan allows 1 recipients per send", stuck on
//     "Sealing 0%". The list is now checked first (POST /v2/sends/precheck)
//     and nothing is uploaded when it does not fit;
//   - the stand cards stayed clickable while a session ran, and switching
//     flipped the mode under it without going back to step 1;
//   - a failed upload left the sender on a progress bar with no way back.
//
// Run: node --test tests/parashare-group-precheck.test.mjs
//      (PLAYWRIGHT_CHROMIUM_PATH=... to pick a browser)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const GP_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const GP_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const GP_MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm', '.json': 'application/json' };
const GP_ALIASES = { '/': '/index.html', '/parashare': '/parashare.html', '/en/parashare': '/en/parashare.html' };

let gpServer;
let gpBrowser;
let GP_ORIGIN;

before(async () => {
  gpServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const file = path.join(GP_ROOT, GP_ALIASES[url.pathname] || url.pathname);
    if (!file.startsWith(GP_ROOT)) { res.writeHead(403); return res.end('no'); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': GP_MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  await new Promise((r) => gpServer.listen(0, '127.0.0.1', r));
  GP_ORIGIN = `http://localhost:${gpServer.address().port}`;
  gpBrowser = await chromium.launch({ headless: true, ...(GP_EXE ? { executablePath: GP_EXE } : {}) });
});

after(async () => {
  if (gpBrowser) await gpBrowser.close();
  if (gpServer) await new Promise((r) => gpServer.close(r));
});

// opts.precheck: (recipients) => { status, body }
// opts.inbound:  'ok' | 'fail' | 'hang'
async function openSender(opts) {
  const calls = { inbound: 0, sends: 0, precheck: 0 };
  const page = await gpBrowser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/parasend/token', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ token: 'pst_' + 'b'.repeat(64), expires_in_s: 900 }),
  }));
  for (const host of ['legal', 'finance', 'iot']) {
    await page.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  }
  await page.route('https://health.paramant.app/v2/check-key', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ valid: true, plan: 'community', link_ttl_ms: 3600000,
      link_ttl_ms_by_plan: { community: 3600000, pro: 86400000, business: 604800000, enterprise: 604800000 } }),
  }));
  await page.route('https://health.paramant.app/v2/sends/precheck', async (r) => {
    calls.precheck++;
    const body = JSON.parse(r.request().postData() || '{}');
    const out = opts.precheck(body.recipients || []);
    await r.fulfill({ status: out.status, contentType: 'application/json', body: JSON.stringify(out.body) });
  });
  await page.route('https://health.paramant.app/v2/sends', (r) => { calls.sends++; return r.fulfill({ status: 500, body: '{}' }); });
  await page.route('https://health.paramant.app/v2/inbound', async (r) => {
    calls.inbound++;
    if (opts.inbound === 'hang') return; // never answered
    if (opts.inbound === 'fail') return r.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"boom"}' });
    const up = JSON.parse(r.request().postData() || '{}');
    return r.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ ok: true, hash: up.hash, ttl_ms: 3600000, size: 0, download_token: 'a'.repeat(48) }) });
  });
  // De Engelse pins hieronder gelden voor /en/parashare; de Nederlandse
  // tests onderaan openen /parashare.
  await page.goto(`${GP_ORIGIN}${opts.path || '/en/parashare'}`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ps-mode-link').click();
  await page.locator('#file-input').setInputFiles({ name: 'doc.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(600, 7) });
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 15000 });
  return { page, calls };
}

const activeStep = (page) => page.evaluate(() => (document.querySelector('.step.active') || {}).id);

test('Community with two addresses is told before anything is uploaded, with /pricing and a way back', async () => {
  const { page, calls } = await openSender({
    precheck: (list) => list.length > 1
      ? { status: 403, body: { error: 'over_limit', dimension: 'max_recipients', plan: 'community', limit: 1, asked: list.length } }
      : { status: 200, body: { ok: true, limit: 1, count: 1 } },
    inbound: 'ok',
  });
  try {
    await page.fill('#recipients-input', 'a@example.com\nb@example.com');
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-over-limit.active', { timeout: 10000 });
    const line = await page.textContent('#over-limit-line');
    assert.match(line, /Your plan sends to 1 person at a time\. You listed 2\./);
    assert.doesNotMatch(line, /1 recipients/);
    assert.equal(await page.getAttribute('#step-over-limit a.btn', 'href'), '/pricing');
    assert.equal(calls.precheck, 1);
    assert.equal(calls.inbound, 0, 'nothing was uploaded');
    assert.equal(calls.sends, 0);
    await page.click('#step-over-limit [data-click="backToSetup"]');
    assert.equal(await activeStep(page), 'step-setup');
    assert.equal(await page.inputValue('#recipients-input'), 'a@example.com\nb@example.com', 'the list is still there to trim');
    assert.equal(await page.locator('#ps-mode-live').isDisabled(), false, 'the cards are usable again on step 1');
  } finally { await page.close(); }
});

test('a Firm sender with 31 addresses gets the same screen, naming 30 and 31', async () => {
  const { page, calls } = await openSender({
    precheck: (list) => ({ status: 403, body: { error: 'over_limit', plan: 'pro', limit: 30, asked: list.length } }),
    inbound: 'ok',
  });
  try {
    const list = Array.from({ length: 31 }, (_, i) => `r${i}@example.com`).join('\n');
    await page.fill('#recipients-input', list);
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-over-limit.active', { timeout: 10000 });
    assert.match(await page.textContent('#over-limit-line'), /sends to 30 people at a time\. You listed 31\./);
    assert.equal(calls.inbound, 0);
  } finally { await page.close(); }
});

test('while sealing, the stand cards are locked and the mode does not change', async () => {
  const { page } = await openSender({
    precheck: () => ({ status: 200, body: { ok: true, limit: 1, count: 1 } }),
    inbound: 'hang',
  });
  try {
    await page.fill('#recipients-input', 'a@example.com');
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-sealing.active', { timeout: 10000 });
    assert.equal(await page.locator('#ps-mode-live').isDisabled(), true);
    await page.locator('#ps-mode-live').click({ force: true }).catch(() => {});
    assert.equal(await page.getAttribute('#ps-mode-link', 'aria-checked'), 'true');
    assert.equal(await page.getAttribute('#ps-mode-live', 'aria-checked'), 'false');
    assert.equal(await activeStep(page), 'step-sealing');
  } finally { await page.close(); }
});

test('a failed upload shows a Back button instead of a bar that never moves', async () => {
  const { page } = await openSender({
    precheck: () => ({ status: 200, body: { ok: true } }),
    inbound: 'fail',
  });
  try {
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#seal-back:not([hidden])', { timeout: 10000 });
    await page.click('#seal-back');
    assert.equal(await activeStep(page), 'step-setup');
  } finally { await page.close(); }
});

test('the live stand says that a group goes through Send a link', async () => {
  const { page } = await openSender({ precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    await page.locator('#ps-mode-live').click();
    assert.match(await page.textContent('#ps-live-note'), /Sending to a group\? Choose Send a link/);
  } finally { await page.close(); }
});

// ── De Nederlandse /parashare ───────────────────────────────────────────────
// Dezelfde weigering en dezelfde verwijzing, in de taal van de pagina.
test('Community met twee adressen hoort het voor er iets is geüpload, in het Nederlands', async () => {
  const { page, calls } = await openSender({
    path: '/parashare',
    precheck: (list) => list.length > 1
      ? { status: 403, body: { error: 'over_limit', dimension: 'max_recipients', plan: 'community', limit: 1, asked: list.length } }
      : { status: 200, body: { ok: true, limit: 1, count: 1 } },
    inbound: 'ok',
  });
  try {
    await page.fill('#recipients-input', 'a@example.com\nb@example.com');
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-over-limit.active', { timeout: 15000 });
    const line = await page.textContent('#over-limit-line');
    assert.match(line, /Uw abonnement verstuurt naar 1 ontvanger tegelijk\. U noemde er 2\./);
    assert.equal(await page.getAttribute('#step-over-limit a.btn', 'href'), '/pricing');
    assert.equal(calls.inbound, 0, 'er is niets geüpload');
    assert.equal(calls.sends, 0);
  } finally { await page.close(); }
});

test('Firm met 31 adressen noemt 30 en 31, in het Nederlands', async () => {
  const { page, calls } = await openSender({
    path: '/parashare',
    precheck: (list) => ({ status: 403, body: { error: 'over_limit', dimension: 'max_recipients', plan: 'pro', limit: 30, asked: list.length } }),
    inbound: 'ok',
  });
  try {
    await page.fill('#recipients-input', Array.from({ length: 31 }, (_, i) => `p${i}@example.com`).join('\n'));
    await page.locator('#btn-create-session').click();
    await page.waitForSelector('#step-over-limit.active', { timeout: 15000 });
    assert.match(await page.textContent('#over-limit-line'), /verstuurt naar 30 ontvangers tegelijk\. U noemde er 31\./);
    assert.equal(calls.inbound, 0);
  } finally { await page.close(); }
});

test('de live stand zegt dat een groep via Later ophalen gaat', async () => {
  const { page } = await openSender({ path: '/parashare', precheck: () => ({ status: 200, body: { ok: true } }), inbound: 'ok' });
  try {
    await page.locator('#ps-mode-live').click();
    assert.match(await page.textContent('#ps-live-note'), /Versturen naar een groep\? Kies Later ophalen/);
  } finally { await page.close(); }
});
