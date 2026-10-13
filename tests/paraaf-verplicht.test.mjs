// De afzender kan een paraaf op elke pagina verplicht stellen
// (hertest 2026-10-04, T5-4).
//
// De hertest: "afzender kan paraaf nog niet verplicht stellen (Dat doet elke
// ondertekenaar zelf ... met het vinkje)". Nu staat in de uitnodigingsmodus
// van /sign een vinkje "Paraaf op elke pagina, verplicht voor iedereen". Dat
// zet in het bestaande verzoek per partij (requested_appearance) een
// paraafveld, vrij van tekst, en /co-sign laat die paraaf dan niet weghalen.
// Geen protocolwijziging: alleen het veld dat er al was.
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

test('/sign: het vinkje zet een paraaf per partij in het verzoek, vrij van tekst', async () => {
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  const creates = [];
  await page.route('**/api/**', (r) => json(r, 200, { ok: true }));
  await page.route('**/api/user/session/verify', (r) => json(r, 200, { authenticated: true, email: 'sandeep@example.com' }));
  await page.route('**/api/user/envelopes', (r) => { creates.push(r.request().postDataJSON()); return json(r, 500, { error: 'stop_here' }); });
  await page.goto(`${ORIGIN}/sign?mode=invite`, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    const doc = await window.PDFLib.PDFDocument.create();
    const font = await doc.embedFont(window.PDFLib.StandardFonts.Helvetica);
    for (let p = 0; p < 3; p++) {
      const pg = doc.addPage([595.28, 841.89]);
      for (let y = 790; y >= 40; y -= 14) pg.drawText('Artikel ' + p + '. Deze regel tekst mag niet bedekt worden door een paraaf.', { x: 56, y, size: 10, font });
    }
    const saved = await doc.save();
    // The text boxes of page 1 as pdf.js reads them, to hold the parafen to.
    const pd = await window.pdfjsLib.getDocument({ data: saved.slice() }).promise;
    const p1 = await pd.getPage(1);
    window.__boxes = (await p1.getTextContent()).items.filter((it) => it.str.trim()).map((it) => {
      const fs = Math.hypot(it.transform[2], it.transform[3]);
      return { x: it.transform[4] / 595.28, y: 1 - (it.transform[5] + fs) / 841.89, w: it.width / 595.28, h: 1.25 * fs / 841.89 };
    });
    const t = new DataTransfer();
    t.items.add(new File([saved], 'drie.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="2"] canvas').waitFor({ timeout: 30000 });
  const textBoxes = await page.evaluate(() => window.__boxes);
  const box = page.locator('#ds-invite-paraaf');
  assert.equal(await box.count(), 1, 'er is een vinkje voor een verplichte paraaf');
  await box.check();
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 20000 });
  for (const [i, n] of [['Sandeep', 'sandeep@example.com'], ['Marije', 'marije@example.com'], ['Pieter', 'pieter@example.com']].entries()) {
    await page.locator('#ds-add-recipient').click();
    await page.locator('[data-field="label"]').nth(i).fill(n[0]);
    await page.locator('[data-field="email"]').nth(i).fill(n[1]);
  }
  await page.locator('#ds-recipients-continue').click();
  await page.waitForFunction(() => true);
  for (let i = 0; i < 100 && !creates.length; i++) await page.waitForTimeout(100);
  await page.close();
  assert.equal(creates.length, 1);
  const reqs = creates[0].recipients.map((r) => r.requested_appearance);
  assert.equal(reqs.length, 3);
  const parafen = reqs.map((r) => r && r.fields.find((f) => f.all_pages));
  parafen.forEach((p, i) => assert.ok(p, `partij ${i + 1} krijgt een paraaf in het verzoek`));
  // Text runs from 40 pt above the bottom edge to the top on every page: a
  // paraaf over it would sit between y = 0.05 and 0.95 of the page height.
  const hit = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
  assert.ok(textBoxes.length > 40, 'de tekst van pagina 1 is gelezen');
  for (const p of parafen) for (const t of textBoxes) assert.ok(!hit(p, t), `paraaf ${JSON.stringify(p)} ligt over tekst ${JSON.stringify(t)}`);
});

test('/co-sign: een gevraagde paraaf staat klaar en gaat er niet af', async () => {
  const ENV_ID = 'env_demo_paraafverplicht';
  const TOKEN = 't'.repeat(43);
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  await page.goto(ORIGIN + '/__blank');
  await page.addScriptTag({ url: ORIGIN + '/vendor/pdf-lib/pdf-lib.min.js' });
  const fixture = await page.evaluate(async ({ envelopeId }) => {
    const pqc = await import('/vendor/paramant-pqc.js');
    const delivery = await import('/js/parasign-document-capsule.js?v=2');
    const pdf = await window.PDFLib.PDFDocument.create();
    for (let p = 0; p < 2; p++) pdf.addPage([595, 842]).drawText('Overeenkomst pagina ' + (p + 1), { x: 56, y: 760, size: 14 });
    const bytes = new Uint8Array(await pdf.save());
    const docHash = Array.from(pqc.sha3_256(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
    const out = await delivery.encryptDocumentCapsule({ bytes, filename: 'o.pdf', mime: 'application/pdf', envelopeId, docHash });
    return { capsule: Array.from(out.capsule), fragment: out.fragment, docHash };
  }, { envelopeId: ENV_ID });
  const requested = { version: 2, fields: [
    { type: 'seal', page_index: 1, x: 0.1, y: 0.6, w: 0.3, h: 0.085 },
    { type: 'seal', page_index: 0, x: 0.845, y: 0.937, w: 0.12, h: 0.038, all_pages: true },
  ] };
  await page.route('**/api/**', (r) => json(r, 200, { ok: true }));
  await page.route('https://health.paramant.app/v2/envelopes/**', (route) => {
    if (new URL(route.request().url()).pathname.endsWith('/view')) return json(route, 200, { ok: true });
    return json(route, 200, { envelope: { id: ENV_ID, doc_hash: fixture.docHash, original_filename: 'o.pdf', recipe_version: 5,
      created_at: '2026-10-04T12:00:00.000Z', expires_at: '2026-11-03T12:00:00.000Z', status: 'sent', signed_count: 0, party_count: 2,
      requested_appearance: requested, requested_for_party: true,
      parties: [{ index: 0, label: 'Pieter', status: 'pending' }, { index: 1, label: 'Marije', status: 'pending' }] } });
  });
  await page.route(`**/api/user/envelopes/${ENV_ID}/document*`, (r) => r.fulfill({ status: 200, contentType: 'application/octet-stream', body: Buffer.from(fixture.capsule) }));
  await page.route('**/api/user/account', (r) => json(r, 200, { email: 'demo@example.com' }));
  await page.goto(`${ORIGIN}/co-sign?env=${ENV_ID}&p=0&t=${TOKEN}${fixture.fragment}`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !document.querySelector('#sign-confirm')?.disabled && document.querySelectorAll('.doc-page[data-page-index]').length === 2, null, { timeout: 30000 });
  const state = await page.evaluate(() => ({
    checked: document.getElementById('appearance-allpages').checked,
    disabled: document.getElementById('appearance-allpages').disabled,
    note: !document.getElementById('appearance-allpages-required')?.hidden,
    paraaf: window.__cosignDebug.appearance().fields.some((f) => f.all_pages),
  }));
  await page.locator('#appearance-clear').click();
  const afterClear = await page.evaluate(() => window.__cosignDebug.appearance().fields.filter((f) => f.all_pages).length);
  await page.close();
  assert.ok(state.paraaf, 'de gevraagde paraaf staat in wat er getekend wordt');
  assert.ok(state.checked && state.disabled, 'het vinkje staat aan en kan niet uit');
  assert.ok(state.note, 'de pagina zegt dat de afzender erom vraagt');
  assert.equal(afterClear, 1, 'wissen laat de gevraagde paraaf staan');
});
