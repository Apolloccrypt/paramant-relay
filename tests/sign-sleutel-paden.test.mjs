// Hoe een ondertekenaar aan een sleutel komt, en wat er misgaat als dat niet
// lukt (hertest 2026-10-04: T3-4, T2-B6 en de TOTP-terugval zonder WebAuthn).
//
//   1. Een browser zonder WebAuthn tekent met de authenticator-code. Voorheen
//      stopte /sign met "Deze browser ondersteunt geen passkeys" en kon de
//      klant niet tekenen.
//   2. Een account zonder passkey vraagt geen step-up-challenge aan: de 409
//      no_passkey stond bij elke handtekening rood in de console.
//   3. De sleutel wordt pas in de browser bewaard als de koppeling aan het
//      account gelukt is. Voorheen bleef bij een mislukte koppeling een
//      sleutel achter die de relay daarna altijd weigerde (signer_not_enrolled).
//   4. /co-sign zegt bij 403 signer_not_enrolled wat er echt aan de hand is en
//      biedt "Sleutel opnieuw koppelen", in plaats van "ander e-mailadres".
// Echte Chromium, echte paginacode, netwerk nagebootst.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPdfLibs } from './helpers/sign-pdf-libs.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/__blank') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>leeg</title>'); }
  if (p === '/sign') p = '/sign.html';
  if (p === '/co-sign') p = '/co-sign.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

const json = (route, status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const NO_WEBAUTHN = () => { try { delete window.PublicKeyCredential; } catch { /* */ } window.PublicKeyCredential = undefined; };

// /sign alleen tekenen, tot het scherm met de code, en daarna klaar.
async function soloSign({ noWebAuthn, passkeys, download }) {
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 900 }, acceptDownloads: true });
  if (noWebAuthn) await ctx.addInitScript(NO_WEBAUTHN);
  const page = await ctx.newPage();
  const calls = [];
  const consoleErrors = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('request', (r) => { if (r.url().includes('/api/')) calls.push(r.method() + ' ' + new URL(r.url()).pathname); });
  await page.route('**/api/**', (r) => json(r, 200, { ok: true }));
  await page.route('**/api/user/session/verify', (r) => json(r, 200, { authenticated: true, email: 'demo@example.com' }));
  await page.route('**/api/user/account/webauthn/credentials', (r) => json(r, 200, { passkeys: passkeys || [], total: (passkeys || []).length }));
  await page.route('**/api/user/account/signing-key/step-up/options', (r) => json(r, 409, { error: 'no_passkey' }));
  await page.route('**/api/user/account/signing-key', (r) => r.request().method() === 'POST' ? json(r, 200, { ok: true, totp_algorithm: 'sha256' }) : json(r, 200, { keys: [] }));
  await page.route('**/api/user/envelopes', (r) => json(r, 200, { ok: true, envelope: { id: 'env_demo_sleutelpadenxyz', party_count: 2, expires_at: '2026-11-01T00:00:00.000Z',
    party_links: [0, 1].map((i) => ({ party_index: i, sign_path: '/co-sign?env=env_demo_sleutelpadenxyz&p=' + i + '&t=GEHEIMTOKEN' + i, invite_token: 'GEHEIMTOKEN' + i })) } }));
  await page.route('**/api/user/sign/activation', (r) => json(r, 200, { activation_id: 'act_demo_0001', email_hash: 'b'.repeat(64), recipe_version: 4 }));
  await page.route('**/api/user/sign/submit', (r) => json(r, 200, { ok: true, signed_count: 1, party_count: 1, status: 'complete' }));
  await page.goto(`${ORIGIN}/sign?mode=alone`, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    doc.addPage([595, 842]).drawText('Huurovereenkomst', { x: 60, y: 760, size: 16 });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'huur.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"] canvas').waitFor({ timeout: 30000 });
  await page.waitForTimeout(400);
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="0"]').click({ position: { x: 150, y: 400 } });
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-signer-name').fill('Sandeep Prasad');
  await page.locator('#ds-identity-continue').click();
  await page.locator('#ds-sign-now').click();
  const panel = await page.locator('#ds-pass-panel:not([hidden])').waitFor({ timeout: 40000 }).then(() => true, () => false);
  const statusText = await page.locator('#ds-sign-status').innerText().catch(() => '');
  let done = false;
  if (panel) {
    await page.locator('#ds-pass-input').fill('123456');
    await page.locator('#ds-pass-confirm').click();
    done = await page.locator('#step-done:not([hidden])').waitFor({ timeout: 90000 }).then(() => true, () => false);
  }
  let psign = null;
  if (done && download) {
    const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('#ds-dl-psign').click()]);
    psign = fs.readFileSync(await dl.path(), 'utf8');
  }
  await ctx.close();
  return { panel, done, statusText, calls, consoleErrors, psign };
}

test('zonder WebAuthn tekent de klant met de code uit de authenticator-app', async () => {
  const r = await soloSign({ noWebAuthn: true });
  assert.ok(r.panel, `geen codevraag; de pagina zei: ${r.statusText}`);
  assert.ok(r.done, 'ondertekenen met de code komt bij het eindscherm');
});

test('een account zonder passkey vraagt geen step-up aan, dus geen 409 in de console', async () => {
  const r = await soloSign({ noWebAuthn: false, passkeys: [] });
  assert.ok(r.panel, `geen codevraag; de pagina zei: ${r.statusText}`);
  assert.ok(!r.calls.some((c) => c.includes('step-up/options')), `step-up werd toch gevraagd: ${r.calls.join(', ')}`);
  assert.ok(!r.consoleErrors.some((t) => /409/.test(t)), `409 in de console: ${r.consoleErrors.join(' | ')}`);
  assert.ok(r.done);
});

test('een sleutel wordt pas bewaard als de koppeling aan het account gelukt is', async () => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.route('**/api/user/account/webauthn/credentials', (r) => json(r, 200, { passkeys: [{ credId: 'Y3JlZA' }], total: 1 }));
  await page.route('**/api/user/account/signing-key/step-up/options', (r) => json(r, 200, { flowId: 'flow1', options: { challenge: 'AAAAAAAAAAAAAAAAAAAAAA', allowCredentials: [{ id: 'Y3JlZA' }], timeout: 5000 } }));
  let binds = 0;
  await page.route('**/api/user/account/signing-key/step-up/bind', (r) => { binds++; return json(r, 403, { error: 'step_up_failed' }); });
  await page.goto(`${ORIGIN}/__blank`);
  const r = await page.evaluate(async () => {
    // A passkey that answers with a PRF result, as a PRF-capable authenticator does.
    const buf = (n, v) => new Uint8Array(n).fill(v).buffer;
    window.PublicKeyCredential = window.PublicKeyCredential || function PublicKeyCredential() {};
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: async () => ({
      id: 'Y3JlZA', type: 'public-key', rawId: buf(4, 7),
      response: { clientDataJSON: buf(8, 1), authenticatorData: buf(37, 2), signature: buf(64, 3) },
      getClientExtensionResults: () => ({ prf: { results: { first: buf(32, 9) } } }),
    }) } });
    const vault = await import('/vendor/vault.js?v=5');
    const signer = await import('/js/parasign-signer.js?v=21');
    const before = (await vault.vaultList()).length;
    let err = null;
    try { await signer.ensureSigningKey({ rpId: location.hostname, label: 'proef' }); } catch (e) { err = String(e && (e.message || e)); }
    return { before, after: (await vault.vaultList()).length, err };
  });
  await ctx.close();
  assert.equal(binds, 1, 'de koppeling is geprobeerd');
  assert.ok(r.err, 'een mislukte koppeling is een fout');
  assert.equal(r.after, r.before, `na een mislukte koppeling staan er ${r.after - r.before} sleutel(s) in deze browser`);
});

test('/co-sign noemt een niet-gekoppelde sleutel bij naam en biedt opnieuw koppelen', async () => {
  const ENV_ID = 'env_demo_nietgekoppeldxy';
  const TOKEN = 't'.repeat(43);
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 900 } });
  await ctx.addInitScript(NO_WEBAUTHN);
  const page = await ctx.newPage();
  await page.goto(ORIGIN + '/__blank');
  await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
  const fixture = await page.evaluate(async ({ envelopeId }) => {
    const pqc = await import('/vendor/paramant-pqc.js');
    const delivery = await import('/js/parasign-document-capsule.js?v=2');
    const pdf = await window.PDFLib.PDFDocument.create();
    pdf.addPage([595, 842]).drawText('Overeenkomst', { x: 56, y: 760, size: 14 });
    const bytes = new Uint8Array(await pdf.save());
    const docHash = Array.from(pqc.sha3_256(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
    const out = await delivery.encryptDocumentCapsule({ bytes, filename: 'o.pdf', mime: 'application/pdf', envelopeId, docHash });
    return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash };
  }, { envelopeId: ENV_ID });
  await page.route('**/api/**', (r) => json(r, 200, { ok: true }));
  await page.route('https://health.paramant.app/v2/envelopes/**', (route) => {
    if (new URL(route.request().url()).pathname.endsWith('/view')) return json(route, 200, { ok: true });
    return json(route, 200, { envelope: { id: ENV_ID, doc_hash: fixture.docHash, original_filename: 'o.pdf', recipe_version: 5,
      created_at: '2026-10-04T12:00:00.000Z', expires_at: '2026-11-03T12:00:00.000Z', status: 'sent', signed_count: 0, party_count: 1,
      parties: [{ index: 0, label: 'Pieter', status: 'pending' }] } });
  });
  await page.route(`**/api/user/envelopes/${ENV_ID}/document*`, (r) => r.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fixture.capsule) }));
  await page.route('**/api/user/account', (r) => json(r, 200, { email: 'demo@example.com' }));
  await page.route('**/api/user/account/signing-key', (r) => json(r, 200, { ok: true, totp_algorithm: 'sha256' }));
  await page.route('**/api/user/sign/activation', (r) => json(r, 200, { activation_id: 'act_demo_0001', email_hash: 'b'.repeat(64), recipe_version: 5 }));
  await page.route('**/api/user/sign/submit', (r) => json(r, 403, { error: 'signer_not_enrolled' }));
  await page.goto(`${ORIGIN}/co-sign?env=${ENV_ID}&p=0&t=${TOKEN}${fixture.fragment}`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !document.querySelector('#sign-confirm')?.disabled && document.querySelectorAll('.doc-page[data-page-index]').length === 1, null, { timeout: 30000 });
  page.on('dialog', (d) => d.accept());
  await page.locator('#sign-confirm').click();
  await page.locator('#cs-pass-panel:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#cs-pass-input').fill('123456');
  await page.locator('#cs-pass-confirm').click();
  await page.waitForFunction(() => /niet aan uw account gekoppeld|e-mailadres/.test(document.querySelector('#sign-status')?.textContent || ''), null, { timeout: 30000 });
  const text = await page.locator('#sign-status').innerText();
  const relink = await page.locator('#cs-relink-key').count();
  await ctx.close();
  assert.match(text, /niet aan uw account gekoppeld/, text);
  assert.doesNotMatch(text, /ander e-mailadres/, text);
  assert.equal(relink, 1, 'er is een knop om de sleutel opnieuw te koppelen');
});

test('het .psign-bestand bevat geen uitnodigingslinks of -tokens', async () => {
  const r = await soloSign({ noWebAuthn: false, passkeys: [], download: true });
  assert.ok(r.psign, 'het bewijs is gedownload');
  assert.doesNotMatch(r.psign, /GEHEIMTOKEN|invite_token|party_links/, 'uitnodigingen in het bewijs');
  const env = JSON.parse(r.psign);
  assert.equal(env.multiparty.envelope_id, 'env_demo_sleutelpadenxyz', 'de verwijzing naar de envelop blijft');
  assert.equal(env.multiparty.party_count, 2);
});
