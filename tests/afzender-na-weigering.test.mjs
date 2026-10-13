// Acceptatie ronde 2, punt 2: de statuspagina van de afzender na een weigering
// zei "Vraag de afzender om een nieuw verzoek" (tegen de afzender), beloofde
// een bewijs "zodra iedereen heeft getekend" op een gestopt verzoek, en toonde
// een rode "Kies het originele document" met een knop die nergens heen leidde.
// Het dashboard zette het onder "Geannuleerd", terwijl de mail belooft dat de
// afzender daar ziet wie weigerde.
// Run: node --test tests/afzender-na-weigering.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.json': 'application/json', '.ttf': 'font/ttf' };
const ALIAS = { '/co-sign': '/co-sign.html', '/dashboard': '/dashboard.html' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  p = ALIAS[p] || p;
  const f = path.join(ROOT, p);
  if (!f.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream' });
    res.end(b);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
after(async () => { await browser.close(); server.close(); });

const ENV_ID = 'env_declined_owner_view_0001';
const envelope = {
  id: ENV_ID, doc_hash: 'ab'.repeat(32), original_filename: 'huurcontract.pdf', status: 'void', void_reason: 'declined',
  binding_mode: 'email', recipe_version: 5, created_at: '2026-10-01T10:00:00Z', expires_at: '2026-10-31T10:00:00Z',
  voided_at: '2026-10-02T09:00:00Z', party_count: 2, signed_count: 0,
  parties: [
    { index: 0, label: 'Pieter Partner', status: 'declined', signed_at: null, declined_at: '2026-10-02T09:00:00Z' },
    { index: 1, label: 'Anna', status: 'pending', signed_at: null, declined_at: null },
  ],
};
const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

test('de statuspagina van de afzender na een weigering', async () => {
  const page = await browser.newPage();
  const asked = [];
  await page.route('**/api/**', (r) => json(r, {}));
  await page.route('**/api/user/session/verify', (r) => json(r, { authenticated: true, email: 's@example.nl' }));
  await page.route('**/api/user/envelopes/**', (r) => {
    asked.push(new URL(r.request().url()).pathname);
    if (r.request().url().includes('/owner-view')) return json(r, { envelope });
    return json(r, { error: 'voided' }, 410);
  });
  await page.goto(ORIGIN + '/co-sign?owner=' + ENV_ID, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => /Geweigerd door/.test(document.body.innerText), null, { timeout: 15000 }).catch(() => {});
  const text = await page.locator('body').innerText();
  const resultHidden = await page.locator('#result-card').isHidden();
  const pickHidden = await page.locator('#verify-file-cta').isHidden();
  await page.close();
  assert.match(text, /Geweigerd door Pieter Partner/, text.slice(0, 600));
  assert.doesNotMatch(text, /Vraag de afzender/);
  assert.doesNotMatch(text, /komt beschikbaar zodra iedereen heeft getekend/);
  assert.doesNotMatch(text, /Kies het originele document/);
  assert.ok(resultHidden, 'geen resultaatkaart op een gestopt verzoek');
  assert.ok(pickHidden, 'geen knop om een document te kiezen');
  assert.ok(!asked.some((p) => /owner-document/.test(p)), 'geen verzoek om het document (dat gaf 410): ' + asked.join(', '));
});

test('het dashboard: "Geweigerd door" met de naam, onder Gestopt', async () => {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/api/**', (r) => json(r, {}));
  await page.route('**/api/user/session/verify', (r) => json(r, { authenticated: true, email: 's@example.nl' }));
  await page.route('**/api/user/documents**', (r) => json(r, { documents: [{ id: ENV_ID, original_filename: 'huurcontract.pdf', status: 'void', created_at: envelope.created_at, expires_at: envelope.expires_at, party_count: 2, signed_count: 0, parties: envelope.parties.map(({ index, label, status, signed_at }) => ({ index, label, status, signed_at })) }] }));
  await page.goto(ORIGIN + '/dashboard', { waitUntil: 'domcontentloaded' });
  const tab = page.locator('[data-doc-filter="cancelled"]');
  await tab.waitFor({ timeout: 15000 });
  await page.waitForTimeout(1500);
  await tab.click();
  await page.waitForTimeout(500);
  const list = await page.locator('#dh-documents').innerText().catch(() => '');
  const tabText = await tab.innerText();
  await page.close();
  assert.match(tabText, /Gestopt/);
  assert.match(list, /Geweigerd door Pieter Partner/, list);
});
