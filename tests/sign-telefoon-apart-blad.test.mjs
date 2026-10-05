// Acceptatie r5, D: op een iPhone stond de keuze "apart handtekeningblad"
// verstopt onder "Tekst, datum en meer". Hij staat nu zichtbaar bij de
// plaatsingskeuze, ook op een telefoon, zonder dat de knoppen buiten hun vak
// lopen en zonder dat pagina 1 uit beeld zakt.
// Draait in Chromium; in WebKit via ~/bin/pw-webkit.sh.
// Run: node --test tests/sign-telefoon-apart-blad.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, devices } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPdfLibs } from './helpers/sign-pdf-libs.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/sign') p = '/sign.html';
  if (p === '/en/sign') p = '/en/sign.html';
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

async function open(device, route) {
  const ctx = await browser.newContext({ ...devices[device] });
  const page = await ctx.newPage();
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"a@example.nl"}' }));
  await page.goto(ORIGIN + route, { waitUntil: 'domcontentloaded' });
  await loadPdfLibs(page);
  await page.evaluate(async () => {
    for (let i = 0; i < 600 && !(window.PDFLib && window.pdfjsLib); i++) await new Promise((r) => setTimeout(r, 20));
    const doc = await window.PDFLib.PDFDocument.create();
    for (let i = 0; i < 3; i++) doc.addPage([595, 842]).drawText('Pagina ' + (i + 1), { x: 60, y: 760, size: 16 });
    const t = new DataTransfer();
    t.items.add(new File([await doc.save()], 'contract.pdf', { type: 'application/pdf' }));
    const input = document.getElementById('ds-doc-input');
    input.files = t.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#step-place:not([hidden])').waitFor({ timeout: 30000 });
  await page.locator('#ds-pdf-canvas-list .ds-page-wrap canvas').first().waitFor({ timeout: 30000 });
  await page.waitForTimeout(1200);
  return { ctx, page };
}

for (const device of ['iPhone 13', 'iPhone SE']) {
  for (const route of ['/sign?mode=alone', '/en/sign?mode=alone']) {
    test(`${device} ${route}: apart handtekeningblad staat in beeld en werkt met een tik`, async () => {
      const { ctx, page } = await open(device, route);
      const r = await page.evaluate(() => {
        const sheet = document.getElementById('ds-seal-sheet');
        const label = sheet.closest('label');
        const lb = label.getBoundingClientRect();
        const c = document.querySelector('#ds-pdf-canvas-list .ds-page-wrap canvas').getBoundingClientRect();
        const labels = [...document.querySelectorAll('.ds-seal-choice .ds-seal-check')];
        return {
          toolsOpen: document.getElementById('step-place').classList.contains('tools-open'),
          labelTop: lb.top, labelBottom: lb.bottom, labelH: lb.height, vh: innerHeight,
          rowH: document.querySelector('.ds-seal-choice').getBoundingClientRect().height,
          text: label.innerText.trim(),
          over: labels.map((l) => l.scrollWidth - l.clientWidth),
          right: Math.max(...labels.map((l) => l.getBoundingClientRect().right)), vw: innerWidth,
          pageVisible: Math.max(0, Math.min(innerHeight, c.bottom) - Math.max(0, c.top)) / c.height,
        };
      });
      assert.equal(r.toolsOpen, false, 'de extra gereedschappen zijn dicht');
      assert.ok(await page.locator('#ds-seal-sheet').isVisible(), 'de keuze apart blad is zichtbaar zonder "Tekst, datum en meer"');
      assert.ok(r.labelTop >= 0 && r.labelBottom <= r.vh, `de keuze staat in het eerste scherm (y ${Math.round(r.labelTop)}..${Math.round(r.labelBottom)} van ${r.vh})`);
      assert.ok(r.labelH >= 40, `de keuze is groot genoeg om te tikken (${Math.round(r.labelH)} px)`);
      assert.match(r.text, /blad|sheet/i);
      for (const o of r.over) assert.ok(o <= 1, `een keuzeknop loopt ${o}px buiten zijn vak`);
      assert.ok(r.right <= r.vw + 1, `de keuzes passen in de breedte (${Math.round(r.right)} van ${r.vw})`);
      // The phone the earlier measurement used (sign-telefoon-document-in-beeld):
      // there the choices fit on one row and page 1 stays mostly in view.
      if (device === 'iPhone 13') {
        assert.ok(r.rowH <= 48, `de keuzes staan op een rij (${Math.round(r.rowH)} px hoog)`);
        assert.ok(r.pageVisible >= 0.5, `pagina 1 staat nog grotendeels in beeld (${Math.round(r.pageVisible * 100)}%)`);
      }
      await page.locator('#ds-seal-sheet').tap();
      assert.equal(await page.locator('#ds-seal-sheet').isChecked(), true, 'een tik kiest het aparte blad');
      await ctx.close();
    });
  }
}
