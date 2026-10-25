// De voorbeelddatums op de home, gerekend vanaf vandaag (13-10-2026).
//
// Een datum die vast in de markup staat veroudert: over drie maanden toont het
// voorbeeldoverzicht dan een kantoor dat sinds oktober niets meer deed.
// js/home-demo.js rekent elke <time data-wp-when> bij het laden terug vanaf de
// klok van de bezoeker en schrijft hem met js/format-date.js, dezelfde
// formatter als /dashboard. Deze test zet de klok op een dag ver van de datums
// in de markup en kijkt wat er staat; blijft een datum hangen, dan wordt hij
// rood. Ook voor 09:12: dan is "vandaag 09:12" nog toekomst en wordt het
// gisteren. Zonder script blijft de datum uit de markup staan.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const ALIAS = { '/': '/index.html', '/en': '/en/index.html' };
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;

async function rows(url, when, { js = true } = {}) {
  const server = http.createServer((req, res) => {
    const p = ALIAS[new URL(req.url, 'http://x').pathname] || new URL(req.url, 'http://x').pathname;
    const file = path.join(FE, p);
    if (!file.startsWith(FE)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, b) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' }); res.end(b); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
  try {
    const ctx = await browser.newContext({ timezoneId: 'Europe/Amsterdam', javaScriptEnabled: js });
    const page = await ctx.newPage();
    if (when) await page.clock.setFixedTime(new Date(when));
    await page.route('**/api/**', (r) => r.fulfill({ status: 401, contentType: 'application/json', body: '{"authenticated":false}' }));
    await page.goto(`http://127.0.0.1:${server.address().port}${url}`, { waitUntil: 'load' });
    if (js) await page.waitForFunction(() => document.querySelector('time[data-wp-when]')?.hasAttribute('datetime'));
    return await page.$$eval('[data-wp-demo] .dh-document-name > span, [data-wp-demo] .dh-send-name > span', (n) => n.map((e) => e.textContent.trim()));
  } finally { await browser.close(); server.close(); }
}

// Sinds 25-10-2026 heeft de Nederlandse home geen voorbeelddashboard meer
// (een vraag, een antwoord, een knop). js/home-demo.js vindt dan geen
// [data-wp-demo] en doet niets; de Engelse home draagt de rijen nog.
test('NL: de home heeft geen voorbeeldrijen meer, en dus geen datums die verouderen', async () => {
  assert.deepEqual(await rows('/', null, { js: false }), []);
});

test('EN: hetzelfde, in de Engelse notatie', async () => {
  assert.deepEqual(await rows('/en', '2027-03-10T13:00:00Z'), [
    'Created 9 March 2027', 'Sent 10 March 2027 at 09:12 (CET)', 'Created 2 March 2027',
  ]);
});

test('zonder script blijft de datum uit de markup staan', async () => {
  const r = await rows('/en', null, { js: false });
  assert.equal(r.length, 3);
  for (const t of r) assert.match(t, /^(Created|Sent) \d{1,2} [A-Z][a-z]+ \d{4}/);
});
