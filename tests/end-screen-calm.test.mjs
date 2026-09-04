// end-screen-calm.test.mjs: the four end screens, held to one shape.
//
// WHY THIS SUITE EXISTS
//
// On 4 September 2026 the owner sent a photo through ParaSend on a phone and
// read the screen that came back. Above the answer sat the two stands he had
// already chosen between and the five-stage bar he had already walked. Below it
// the same fact was stated four times over: a mascot the size of half the page
// saying "Done. And cryptographically proven. Receipt signed with ML-DSA-65
// (FIPS 204); the relay never saw your key", a headline "Sent.", a card headed
// TRANSFER COMPLETE with "IMG_4276.jpeg sent securely", and four badges reading
// ML-KEM-768, Burn-on-read, Fingerprint verified, Relay never saw key. One of
// those sentences was also untrue of a live hand-over: it told him the receiver
// could now download the file, on the screen he reached by handing it over.
//
// THE SHAPE THIS PINS, on every end screen the product has
//
//   1. Nothing on the face of the screen is written in algorithm. The names are
//      not deleted, they are one fold down under "What made this safe", and the
//      fold is closed. This test reads the screen with the <details> cut out.
//   2. Exactly one button carries the loud paint. Every other way out is a
//      quiet line under it. A screen with two primaries is a screen that has
//      not decided what it wants the reader to do.
//   3. What is left fits a phone. Measured as the end screen's own height with
//      the fold shut, against a 390x844 viewport, so somebody who has just
//      finished a job can read the whole answer without scrolling for it.
//
// Everything the relay would do is stubbed at the network edge, the same way
// tests/parasend-send-a-link.test.mjs and tests/sign-invite-delivery.test.mjs
// do it. No relay, no redis, no account.
//
// Run: node tests/end-screen-calm.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { webcrypto as wc } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm',
  '.json': 'application/json', '.ico': 'image/x-icon' };
const ALIAS = { '/': '/index.html', '/parashare': '/parashare.html', '/get': '/get.html',
  '/ontvang': '/ontvang.html', '/sign': '/sign.html' };

const server = http.createServer((req, res) => {
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
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const PHONE = { width: 390, height: 844 };

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }

// The vocabulary an end screen may not put in front of somebody. Deliberately
// short and deliberately about NAMES, not about ideas: "sealed", "wiped" and
// "nobody can open it" are all still allowed and are what the screens now say.
const JARGON = /\bML-KEM\b|\bML-DSA\b|\bFIPS\b|\bSHA-?3\b|\bfingerprint\b|\brelay\b/i;

// Read the screen the way a person does: the fold is shut, so what is inside it
// is not on the screen yet. Anything display:none or hidden is not there either.
async function faceText(page, sel) {
  return page.evaluate((s) => {
    const root = document.querySelector(s);
    if (!root) return '';
    const clone = root.cloneNode(true);
    clone.querySelectorAll('details, script, style').forEach((n) => n.remove());
    // Mirror what is actually painted: walk the live tree and drop the text of
    // anything the browser is not showing.
    const liveHidden = [...root.querySelectorAll('*')].filter((el) => {
      const cs = getComputedStyle(el);
      return el.hidden || cs.display === 'none' || cs.visibility === 'hidden';
    });
    const hiddenText = liveHidden.map((el) => el.textContent || '');
    let text = clone.textContent || '';
    for (const h of hiddenText) { if (h.trim().length > 2) text = text.split(h).join(' '); }
    return text.replace(/\s+/g, ' ').trim();
  }, sel);
}

// One loud button, counted the way it is painted and not the way it is classed.
async function loudButtons(page, sel) {
  return page.evaluate((s) => {
    const root = document.querySelector(s);
    if (!root) return -1;
    return [...root.querySelectorAll('.done-actions .done-primary')]
      .filter((el) => {
        const cs = getComputedStyle(el);
        return !el.hidden && cs.display !== 'none' && cs.visibility !== 'hidden';
      }).length;
  }, sel);
}

// The end screen's own height with the fold shut, against one phone screen.
async function faceHeight(page, sel) {
  return page.evaluate((s) => {
    const root = document.querySelector(s);
    if (!root) return -1;
    let h = root.getBoundingClientRect().height;
    root.querySelectorAll('details').forEach((d) => {
      const cs = getComputedStyle(d);
      if (!d.hidden && cs.display !== 'none') h -= d.getBoundingClientRect().height;
    });
    return Math.round(h);
  }, sel);
}

async function audit(page, label, sel) {
  const text = await faceText(page, sel);
  const hit = text.match(JARGON);
  ok(`${label}: no algorithm name on the face of the screen`, !hit,
    hit ? `found "${hit[0]}" in: ${text.slice(0, 200)}` : '');
  const loud = await loudButtons(page, sel);
  ok(`${label}: exactly one primary button`, loud === 1, `found ${loud}`);
  const h = await faceHeight(page, sel);
  ok(`${label}: the answer fits one phone screen with the fold shut`, h > 0 && h <= 844, `${h}px`);
  const closed = await page.evaluate((s) => [...document.querySelectorAll(s + ' details')].every((d) => !d.open), sel);
  ok(`${label}: the technical account starts folded away`, closed);
  return text;
}

// ── /parashare, both stands ─────────────────────────────────────────────────
const MERKLE = { leaf_hash: 'b'.repeat(64), leaf_index: 41, tree_size: 42,
  audit_path: ['c'.repeat(64)], root: 'd'.repeat(64), sth: { signature: 'e'.repeat(40) },
  sth_signature: 'e'.repeat(40) };

async function stubSender(page) {
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
      download_token: 'a'.repeat(48), merkle_proof: MERKLE }) }));
  await page.route('https://health.paramant.app/v2/dl/**', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, enc_meta: null, file_size: 0, ttl_left_s: 3600, used: false }) }));
}

{
  const page = await browser.newPage({ viewport: PHONE });
  await stubSender(page);
  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ps-mode-link').click();
  await page.locator('#file-input').setInputFiles({ name: 'loonstrook-2026-09.pdf', mimeType: 'application/pdf',
    buffer: Buffer.from(Array.from({ length: 777 }, (_, i) => (i * 37 + 11) % 256)) });
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 20000 });
  await page.locator('#btn-create-session').click();
  await page.waitForSelector('#step-link.active', { timeout: 30000 });
  const text = await audit(page, '/parashare Send a link', '#step-link');
  ok('/parashare Send a link: the two stands and the stage bar are gone',
    !(await page.locator('#ps-mode').isVisible()) && !(await page.locator('#ps-stepper').isVisible()));
  ok('/parashare Send a link: one line says how often it opens and when it stops',
    /Works once, until \d{1,2} \w+ \d{4}, \d{2}:\d{2} UTC/.test(text), text.slice(0, 200));
  ok('/parashare Send a link: the receipt is offered as a quiet line',
    await page.locator('#ps-link-receipt').isVisible());
  await page.close();
}

{
  const page = await browser.newPage({ viewport: PHONE });
  await page.addInitScript(() => {
    const stub = { initCrypto: async () => {}, encryptBlob: async (p) => new Uint8Array(p.length + 32),
      decryptBlob: async () => new Uint8Array() };
    Object.defineProperty(window, '_cryptoBridge', { get: () => stub, set: () => {}, configurable: true });
  });
  await stubSender(page);
  let receiverThere = false;
  await page.route('https://health.paramant.app/v2/pubkey/**', (r) => receiverThere
    ? r.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ kyber_pub: 'ab'.repeat(64), ecdh_pub: 'cd'.repeat(32) }) })
    : r.fulfill({ status: 404, body: '' }));
  await page.route('https://health.paramant.app/v2/pubkey', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'domcontentloaded' });
  await page.locator('#file-input').setInputFiles({ name: 'IMG_4276.jpeg', mimeType: 'image/jpeg',
    buffer: Buffer.from(Array.from({ length: 2048 }, (_, i) => (i * 13 + 7) % 256)) });
  await page.waitForFunction(() => !document.getElementById('btn-create-session').disabled, null, { timeout: 20000 });
  await page.locator('#btn-create-session').click();
  await page.waitForSelector('#step-waiting.active', { timeout: 20000 });
  receiverThere = true;
  await page.waitForFunction(() => /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test((document.getElementById('fp-display')?.textContent || '').trim()),
    null, { timeout: 20000, polling: 250 });
  await page.locator('#fp-confirm-check').check();
  await page.locator('#fp-confirm-btn').click();
  await page.waitForSelector('#step-done.active', { timeout: 40000 });
  const text = await audit(page, '/parashare live hand-over', '#step-done');
  ok('/parashare live hand-over: the two stands and the stage bar are gone',
    !(await page.locator('#ps-mode').isVisible()) && !(await page.locator('#ps-stepper').isVisible()));
  // The screen a sender reaches by handing a file over cannot tell them the
  // file is now downloadable: that is the OTHER stand's sentence, and it was on
  // this screen until 4 September 2026.
  ok('/parashare live hand-over: it does not read the sender the link stand\'s promise',
    !/can now download/i.test(text), text.slice(0, 200));
  ok('/parashare live hand-over: it names the file and who it went to',
    /IMG_4276\.jpeg/.test(text) && /compared the code with/.test(text), text.slice(0, 200));
  ok('/parashare live hand-over: the receipt is offered as a quiet line',
    await page.locator('#done-receipt').isVisible());
  await page.close();
}

// ── /get, received through a link ───────────────────────────────────────────
{
  const FILE_NAME = 'loonstrook-2026-09.pdf';
  const fileBytes = Buffer.from(Array.from({ length: 1777 }, (_, i) => (i * 37 + 11) % 256));
  const nameBytes = Buffer.from(FILE_NAME, 'utf8');
  const head = Buffer.alloc(4); head.writeUInt32LE(nameBytes.length, 0);
  const rawKey = wc.getRandomValues(new Uint8Array(32));
  const iv = wc.getRandomValues(new Uint8Array(12));
  const key = await wc.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = Buffer.from(await wc.subtle.encrypt({ name: 'AES-GCM', iv },
    key, Buffer.concat([head, nameBytes, fileBytes])));
  const frag = Buffer.concat([Buffer.from(rawKey), Buffer.from(iv)]).toString('base64url');

  const ctx = await browser.newContext({ viewport: PHONE, acceptDownloads: true });
  const page = await ctx.newPage();
  await page.route('https://health.paramant.app/v2/dl/**/get', (r) =>
    r.fulfill({ status: 200, contentType: 'application/octet-stream', body: ct }));
  const dl = page.waitForEvent('download', { timeout: 30000 });
  await page.goto(`${ORIGIN}/get?t=${'a'.repeat(48)}&r=health#${frag}`, { waitUntil: 'domcontentloaded' });
  await dl;
  await page.waitForSelector('#step-done.active', { timeout: 20000 });
  const text = await audit(page, '/get', '#step-done');
  ok('/get: it says the file is here and that our copy is gone',
    /is saved on your device/.test(text) && /permanently destroyed/.test(text), text.slice(0, 200));
  await ctx.close();
}

// ── /ontvang, live receive ──────────────────────────────────────────────────
{
  const meta = Buffer.from(JSON.stringify({ file_id: 'abc', file_name: 'IMG_4276.jpeg' }));
  const mlen = Buffer.alloc(4); mlen.writeUInt32BE(meta.length, 0);
  const PLAIN = Array.from(Buffer.concat([Buffer.from([0x50, 0x52, 0x53, 0x48]), mlen, meta,
    Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 13 + 7) % 256))]));
  const S = 'inv_' + '0'.repeat(32);

  const ctx = await browser.newContext({ viewport: PHONE, acceptDownloads: true });
  const page = await ctx.newPage();
  await page.addInitScript((plain) => {
    const stub = { initCrypto: async () => {}, encryptBlob: async () => new Uint8Array(),
      decryptBlob: async () => new Uint8Array(plain) };
    Object.defineProperty(window, '_cryptoBridge', { get: () => stub, set: () => {}, configurable: true });
    Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true });
  }, PLAIN);
  let ready = false;
  await page.route('https://relay.paramant.app/**', (r) => r.abort());
  await page.route(`https://health.paramant.app/v2/pubkey/${S}_ready`, (r) => ready
    ? r.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ ecdh_pub: 'tok_' + 'c'.repeat(44), kyber_pub: '1|3600000' }) })
    : r.fulfill({ status: 404, body: '' }));
  await page.route('https://health.paramant.app/v2/pubkey', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.route('https://health.paramant.app/v2/dl/**/get', (r) => r.fulfill({ status: 200,
    contentType: 'application/octet-stream', headers: { 'X-Hash': 'deadbeefcafe01234567890abcdef' },
    body: Buffer.from([1, 2, 3]) }));
  const dl = page.waitForEvent('download', { timeout: 40000 }).catch(() => null);
  await page.goto(`${ORIGIN}/ontvang?s=${S}`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test((document.getElementById('fp-display')?.textContent || '').trim()),
    null, { timeout: 40000, polling: 250 });
  ready = true;
  await page.waitForSelector('#step-done.active', { timeout: 40000 });
  await dl;
  const text = await audit(page, '/ontvang', '#step-done');
  ok('/ontvang: it says the file is here and that our copy is gone',
    /is saved on your device/.test(text) && /permanently destroyed/.test(text), text.slice(0, 200));
  await ctx.close();
}

// ── /sign, both endings ─────────────────────────────────────────────────────
const ENV_ID = 'env_demo_abcdefghijklmnop';
const TOKEN = 't'.repeat(43);

async function stubSign(page, { partyCount = 1, bindingMode = 'email' } = {}) {
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ authenticated: true, email: 'demo@example.com' }) }));
  await page.route('**/api/user/account/signing-key/step-up/options', (r) =>
    r.fulfill({ status: 409, contentType: 'application/json', body: '{"error":"no_passkey"}' }));
  await page.route('**/api/user/account/signing-key', (r) => r.request().method() === 'POST'
    ? r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"totp_algorithm":"sha256"}' })
    : r.fulfill({ status: 200, contentType: 'application/json', body: '{"keys":[]}' }));
  await page.route('**/api/user/envelopes', async (route) => {
    const b = route.request().postDataJSON();
    const n = b.include_requester === false ? b.recipients.length : (b.recipients.length + 1);
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, envelope: {
      id: ENV_ID, party_count: n, binding_mode: bindingMode, expires_at: '2026-10-20T12:00:00.000Z',
      party_links: Array.from({ length: n }, (_, party_index) => ({ party_index,
        sign_path: `/co-sign?env=${ENV_ID}&p=${party_index}&t=${TOKEN}`, invite_token: TOKEN })) } }) });
  });
  await page.route(`**/api/user/envelopes/${ENV_ID}/document`, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  await page.route(`**/api/user/envelopes/${ENV_ID}/invitations`, async (route) => {
    const b = route.request().postDataJSON();
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true,
      partial_failure: false, failed_party_indexes: [],
      results: b.invitations.map((i) => ({ party_index: i.party_index, ok: true })) }) });
  });
  await page.route('**/api/user/sign/activation', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ activation_id: 'act_demo_0001', email_hash: 'b'.repeat(64), recipe_version: 4 }) }));
  await page.route('**/api/user/sign/submit', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ ok: true, signed_count: 1, party_count: partyCount, status: 'complete', appearance_hash: null }) }));
}

async function pickPdf(page, name) {
  await page.evaluate(async (n) => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    doc.addPage([595, 842]).drawText('Lease agreement', { x: 60, y: 760, size: 16 });
    doc.addPage([595, 842]).drawText('Signature page', { x: 60, y: 760, size: 16 });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], n, { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, name);
}

{
  const page = await browser.newPage({ viewport: PHONE });
  await stubSign(page, { partyCount: 2 });
  await page.goto(`${ORIGIN}/sign?mode=invite`, { waitUntil: 'domcontentloaded' });
  await pickPdf(page, 'Service order Nuremberg.pdf');
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="1"] canvas').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="1"]').click({ position: { x: 150, y: 300 } });
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-add-recipient').click();
  await page.locator('[data-field="label"]').fill('Marije de Vries');
  await page.locator('[data-field="email"]').fill('marije@example.com');
  await page.locator('#ds-recipients-continue').click();
  await page.locator('#step-done:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('.ds-pl-copy').first().waitFor({ timeout: 20000 });
  const text = await audit(page, '/sign invitations sent', '#step-done');
  ok('/sign invitations sent: the stage bar is gone', !(await page.locator('#ds-stepper').isVisible()));
  ok('/sign invitations sent: it says what is true now, in words',
    /Invitations are on their way/.test(text), text.slice(0, 160));
  await page.close();
}

{
  const page = await browser.newPage({ viewport: PHONE });
  await stubSign(page, { partyCount: 1 });
  await page.goto(`${ORIGIN}/sign?mode=alone`, { waitUntil: 'domcontentloaded' });
  await pickPdf(page, 'Lease agreement 2026.pdf');
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"] canvas').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 400 } });
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-signer-name').fill('Mick Beer');
  await page.locator('#ds-identity-continue').click();
  await page.locator('#ds-sign-now').click();
  await page.locator('#ds-pass-panel:not([hidden])').waitFor({ timeout: 40000 });
  await page.locator('#ds-pass-input').fill('123456');
  await page.locator('#ds-pass-confirm').click();
  await page.locator('#step-done:not([hidden])').waitFor({ timeout: 90000 });
  await page.locator('#ds-signed-preview canvas').first().waitFor({ timeout: 40000 });
  const text = await audit(page, '/sign signed yourself', '#step-done');
  ok('/sign signed yourself: the stage bar is gone', !(await page.locator('#ds-stepper').isVisible()));
  ok('/sign signed yourself: it says to keep both files, without naming a scheme',
    /Save both files now/.test(text), text.slice(0, 200));
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
