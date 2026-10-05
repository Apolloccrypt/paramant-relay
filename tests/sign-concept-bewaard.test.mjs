// Het werk op /sign overleeft een verlopen sessie (hertest 2026-10-04, T5-6).
//
// De hertest: viel de sessie halverwege weg, dan zei /sign "Log eerst in (via
// /auth/login) en kom dan hier terug", en na terugkomen stond de klant weer op
// de eerste stap met 0 ontvangers. Deze suite zet een uitnodiging klaar
// (document, plek, twee ontvangers, een bericht), laat het aanmaken met 401
// weigeren, drukt op de knop, en komt terug op /sign?herstel=1. Ze eist dat
// alles terug is, dat het concept daarna uit de browser weg is, en dat het
// document niet leesbaar in IndexedDB stond.
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
  if (p === '/auth/login') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><meta charset=utf-8><title>login</title><p>login</p>'); }
  if (p === '/sign') p = '/sign.html';
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
const ctx = await browser.newContext({ viewport: { width: 1100, height: 900 } });
const page = await ctx.newPage();
await page.route('**/api/**', (r) => json(r, 200, { ok: true }));
await page.route('**/api/user/session/verify', (r) => json(r, 200, { authenticated: true, email: 'sandeep@example.com' }));
await page.route('**/api/user/envelopes', (r) => json(r, 401, { error: 'unauthorized' }));
// The account's draft key (admin/server.js GET /api/user/sign-draft-key).
const keyA = Buffer.alloc(32, 7).toString('base64url');
const keyB = Buffer.alloc(32, 9).toString('base64url');
let currentKey = keyA;
await page.route('**/api/user/sign-draft-key', (r) => json(r, 200, { key: currentKey }));

await page.goto(`${ORIGIN}/sign?mode=invite`, { waitUntil: 'domcontentloaded' });
await loadPdfLibs(page);
await page.evaluate(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
  const doc = await window.PDFLib.PDFDocument.create();
  doc.addPage([595, 842]).drawText('Samenwerkingsovereenkomst Sandeep', { x: 60, y: 760, size: 16 });
  doc.addPage([595, 842]).drawText('Handtekeningen', { x: 60, y: 760, size: 16 });
  const t = new DataTransfer();
  t.items.add(new File([await doc.save()], 'samenwerking.pdf', { type: 'application/pdf' }));
  const input = document.getElementById('ds-doc-input');
  input.files = t.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
});
await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="1"] canvas').waitFor({ timeout: 30000 });
await page.waitForTimeout(400);
await page.locator('#ds-pdf-canvas-list .ds-page-wrap[data-page-index="1"]').click({ position: { x: 200, y: 300 } });
const before = await page.evaluate(() => { const m = document.querySelector('.ds-stamp-marker'); const w = m.closest('.ds-page-wrap'); return { page: w.dataset.pageIndex, left: m.style.left, top: m.style.top }; });
// The paraaf, required for everyone (acceptance r2, 3: it came back OFF).
await page.locator('#ds-invite-paraaf').check();
await page.locator('#ds-place-continue').click();
await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 20000 });
await page.locator('#ds-add-recipient').click();
await page.locator('[data-field="label"]').nth(0).fill('Sandeep Prasad');
await page.locator('[data-field="email"]').nth(0).fill('sandeep@example.com');
await page.locator('#ds-add-recipient').click();
await page.locator('[data-field="label"]').nth(1).fill('Marije de Vries');
await page.locator('[data-field="email"]').nth(1).fill('marije@example.com');
await page.locator('#ds-invite-message').fill('Graag voor vrijdag tekenen.');
await page.locator('#ds-recipients-continue').click();
const lost = await page.locator('#ds-signin-keep').waitFor({ timeout: 20000 }).then(() => true, () => false);
const lostText = await page.locator('#ds-recipients-hint').innerText().catch(() => '');
let stored = null;
if (lost) {
  await page.locator('#ds-signin-keep').click();
  await page.waitForURL(/\/auth\/login/, { timeout: 15000 });
  // What sits in IndexedDB while the customer signs in.
  stored = await page.evaluate(() => new Promise((resolve) => {
    const r = indexedDB.open('paramant-sign-draft');
    r.onsuccess = () => {
      try {
        const g = r.result.transaction('kv').objectStore('kv').get('current');
        g.onsuccess = () => {
          const v = g.result;
          const latin = (u8) => (u8 ? new TextDecoder('latin1').decode(u8) : '');
          const all = v ? latin(v.b && v.b.ct) + latin(v.m && v.m.ct) + JSON.stringify(Object.keys(v)) : '';
          const anyKey = v ? Object.values(v).some((x) => x && typeof x === 'object' && (x instanceof CryptoKey || x.key instanceof CryptoKey)) : null;
          resolve({ has: !!v, plainPdf: all.includes('%PDF') || all.includes('Samenwerkingsovereenkomst'),
            plainPeople: /sandeep|marije|samenwerking|vrijdag/i.test(all), keyStored: anyKey, meta: v && v.meta, ttlH: v ? (v.expiresAt - v.savedAt) / 3600000 : 0 });
        };
        g.onerror = () => resolve({ has: false });
      } catch { resolve({ has: false }); }
    };
    r.onerror = () => resolve({ has: false });
  }));
}
// Back, signed in again (the stub never refuses a session here).
await page.unroute('**/api/user/envelopes');
await page.goto(`${ORIGIN}/sign?herstel=1`, { waitUntil: 'domcontentloaded' });
const back = await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 30000 }).then(() => true, () => false);
const restored = await page.evaluate(() => ({
  labels: [...document.querySelectorAll('[data-field="label"]')].map((i) => i.value),
  emails: [...document.querySelectorAll('[data-field="email"]')].map((i) => i.value),
  message: document.getElementById('ds-invite-message')?.value,
  hint: document.getElementById('ds-recipients-hint')?.textContent || '',
  marker: (() => { const m = document.querySelector('.ds-stamp-marker'); if (!m) return null; const w = m.closest('.ds-page-wrap'); return { page: w.dataset.pageIndex, left: m.style.left, top: m.style.top }; })(),
}));
// Back to Place: the paraaf box is still on, and no solo paraaf preview.
await page.locator('#ds-recipients-back').click();
await page.locator('#step-place:not([hidden])').waitFor({ timeout: 10000 });
await page.waitForTimeout(800);
const backOnPlace = await page.evaluate(() => ({ paraaf: document.getElementById('ds-invite-paraaf').checked, ghosts: document.querySelectorAll('.ds-stamp-ghost').length }));
const left = await page.evaluate(() => new Promise((resolve) => {
  const r = indexedDB.open('paramant-sign-draft');
  r.onsuccess = () => { try { const g = r.result.transaction('kv').objectStore('kv').get('current'); g.onsuccess = () => resolve(!!g.result); g.onerror = () => resolve(false); } catch { resolve(false); } };
  r.onerror = () => resolve(false);
}));
await ctx.close();

// Another account in the same browser (shared pc): the draft does not open with
// its key, is not put back, and is wiped (security review r2 (a)).
const ctx2 = await browser.newContext({ viewport: { width: 1100, height: 900 } });
const p2 = await ctx2.newPage();
await p2.route('**/api/**', (r) => json(r, 200, { ok: true }));
await p2.route('**/api/user/session/verify', (r) => json(r, 200, { authenticated: true, email: 'sandeep@example.com' }));
await p2.route('**/api/user/sign-draft-key', (r) => json(r, 200, { key: currentKey }));
await p2.goto(`${ORIGIN}/sign`, { waitUntil: 'domcontentloaded' });
await p2.evaluate(async (k) => {
  const m = await import('/js/sign-draft.js?v=4');
  await m.loadAccountKey(async () => new Response(JSON.stringify({ key: k })));
  await m.saveDraft({ docName: 'van-A.pdf', recipients: [{ label: 'Piet', email: 'piet@example.com' }] }, new TextEncoder().encode('%PDF geheim'));
}, keyA);
currentKey = keyB;
await p2.goto(`${ORIGIN}/sign?herstel=1`, { waitUntil: 'domcontentloaded' });
await p2.waitForTimeout(2500);
const other = await p2.evaluate(() => new Promise((resolve) => {
  const r = indexedDB.open('paramant-sign-draft');
  r.onsuccess = () => { try { const g = r.result.transaction('kv').objectStore('kv').get('current'); g.onsuccess = () => resolve({ left: !!g.result, offered: !!document.getElementById('ds-draft-offer'), recip: [...document.querySelectorAll('[data-field="email"]')].map((i) => i.value) }); } catch { resolve({ left: false }); } };
}));
const expired = await p2.evaluate(async (k) => {
  const m = await import('/js/sign-draft.js?v=4');
  await m.loadAccountKey(async () => new Response(JSON.stringify({ key: k })));
  await m.saveDraft({ docName: 'oud.pdf' }, new TextEncoder().encode('x'));
  const later = Date.now() + 25 * 3600 * 1000;
  return { has: await m.hasDraft(later), load: await m.loadDraft(later), after: await m.hasDraft() };
}, keyB);
await ctx2.close();


test('een verlopen sessie biedt inloggen aan zonder dat het werk verloren gaat', () => {
  assert.ok(lost, `geen knop om in te loggen en verder te gaan; de pagina zei: ${lostText}`);
  assert.match(lostText, /verlopen/);
  assert.ok(stored && stored.has, 'het concept staat in deze browser');
  assert.equal(stored.plainPdf, false, 'het document staat niet leesbaar in IndexedDB');
  assert.equal(stored.keyStored, false, 'de sleutel staat niet naast het concept');
  assert.equal(stored.plainPeople, false, 'naam, ontvangers, e-mails en bericht staan niet leesbaar in IndexedDB');
  assert.equal(stored.meta, undefined, 'geen onversleutelde meta');
  assert.ok(stored.ttlH > 0 && stored.ttlH <= 24, 'het concept heeft een vervaltijd');
});

test('na het inloggen staan document, plek, ontvangers en bericht weer klaar', () => {
  assert.ok(back, 'terug op de stap Ontvangers');
  assert.deepEqual(restored.labels, ['Sandeep Prasad', 'Marije de Vries']);
  assert.deepEqual(restored.emails, ['sandeep@example.com', 'marije@example.com']);
  assert.equal(restored.message, 'Graag voor vrijdag tekenen.');
  assert.ok(restored.marker, 'de plek voor de handtekening staat er weer');
  assert.equal(restored.marker.page, before.page, 'op dezelfde pagina');
  assert.match(restored.hint, /Welkom terug/);
});

test('na Terug staat "paraaf verplicht" nog aan, zonder solo-paraafvoorbeeld', () => {
  assert.equal(backOnPlace.paraaf, true);
  assert.equal(backOnPlace.ghosts, 0);
});

test('het concept is weg zodra het is teruggezet', () => {
  assert.equal(left, false);
});

test('een ander account in dezelfde browser krijgt het concept niet, en het wordt gewist', () => {
  assert.equal(other.offered, false);
  assert.deepEqual(other.recip, []);
  assert.equal(other.left, false, 'het concept van account A is gewist');
});

test('een concept vervalt', () => {
  assert.equal(expired.has, false);
  assert.equal(expired.load, null);
  assert.equal(expired.after, false, 'een verlopen concept wordt bij het lezen gewist');
});
