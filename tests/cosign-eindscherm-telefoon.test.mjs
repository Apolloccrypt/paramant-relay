// Het eindscherm van /co-sign op een telefoon (hertest 2026-10-04, T2-B4 en
// A8/T5-7).
//
//   - De knoptekst "DOWNLOAD DE PDF MET DE HANDTEKENINGEN TOT NU TOE" liep op
//     een iPhone 135 px buiten de knop (scrollWidth 391 tegen clientWidth 256).
//   - De tags "ML-DSA-65" en "Zero-knowledge" stonden in het hoofdpad.
//   - De uitgenodigde kon het origineel niet downloaden, en de gestempelde pdf
//     wordt op /verify nooit groen.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/co-sign') p = '/co-sign.html';
  if (p === '/en/co-sign') p = '/en/co-sign.html';
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

for (const route of ['/co-sign', '/en/co-sign']) {
  test(`${route}: op 375 px past elke knop, zonder algoritmetags, met het origineel`, async () => {
    const page = await browser.newPage({ viewport: { width: 375, height: 812 }, deviceScaleFactor: 2 });
    await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
    await page.route('https://**/**', (r) => r.abort());
    await page.goto(ORIGIN + route + '?env=env_demo_eindschermxyzab&p=0&t=' + 't'.repeat(43), { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(500);
    const r = await page.evaluate(() => {
      document.querySelectorAll('.step').forEach((s) => { s.hidden = true; });
      const done = document.getElementById('step-done');
      done.hidden = false;
      const pdf = document.getElementById('done-download-pdf');
      pdf.hidden = false;
      pdf.textContent = document.documentElement.lang === 'en' ? 'Download the pdf with the signatures so far' : 'Download de pdf met de handtekeningen tot nu toe';
      const btns = [...done.querySelectorAll('.btn')].filter((b) => !b.hidden);
      return {
        overflow: btns.map((b) => ({ id: b.id, over: b.scrollWidth - b.clientWidth })),
        tags: [...done.querySelectorAll('.tag')].map((t) => t.textContent.trim()),
        original: !!document.getElementById('done-download-original'),
        pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    });
    await page.close();
    for (const b of r.overflow) assert.ok(b.over <= 1, `knop ${b.id} loopt ${b.over}px buiten zichzelf`);
    assert.ok(r.pageOverflow <= 1, `pagina ${r.pageOverflow}px te breed`);
    assert.ok(!r.tags.some((t) => /ML-DSA|Zero-knowledge/i.test(t)), `jargon in het hoofdpad: ${r.tags.join(', ')}`);
    assert.ok(r.original, 'er is een knop voor het originele document');
  });
}
