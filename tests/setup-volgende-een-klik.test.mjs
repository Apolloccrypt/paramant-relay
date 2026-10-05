// /setup, stap 2 (matrix ACCT-42): wie het domein wist en meteen op Volgende
// klikt, verloor de eerste klik. De DNS-regel werd bij blur herschreven, klapte
// in, en de knop schoof tussen mousedown en mouseup weg. Nu: de DNS-controle
// loopt tijdens het typen en de regel houdt zijn hoogte. Ook: de knoppen zijn
// opgemaakt en "Bezig met instellen..." staat niet meer onder het klaar-scherm.
// NL en EN. Ook in WebKit: ~/bin/pw-webkit.sh tests/setup-volgende-een-klik.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const aliases = { '/setup': '/setup.html', '/en/setup': '/en/setup.html' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  p = aliases[p] || p;
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
const json = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

for (const route of ['/setup', '/en/setup']) {
  test(`${route}: domein wissen en één klik op Volgende gaat door`, async () => {
    const page = await browser.newPage({ viewport: { width: 1000, height: 800 } });
    await page.route('**/v2/setup/check', (r) => json(r, { setupMode: true }));
    await page.route('**/v2/setup/dns-check*', (r) => json(r, { resolves: false }));
    await page.route('**/v2/setup/apply', (r) => json(r, { ok: true, admin_key: 'pgp_' + 'a'.repeat(64) }));
    await page.goto(ORIGIN + route, { waitUntil: 'domcontentloaded' });
    const step = (n) => page.locator(`.step[data-step="${n}"]`);
    // Opgemaakte knoppen, niet als platte tekst.
    const cls = await step(1).locator('button.next').getAttribute('class');
    assert.match(cls, /\bbtn\b/, cls);
    await step(1).locator('button.next').click();
    await step(2).waitFor({ state: 'visible' });
    const domain = step(2).locator('[name="domain"]');
    await domain.fill('relay.voorbeeld-kantoor.nl');
    await page.keyboard.press('Tab');
    await page.waitForFunction(() => /\S/.test(document.getElementById('dns-status').textContent), null, { timeout: 5000 });
    await domain.click();
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.press('Backspace');
    const next = step(2).locator('button.next');
    const box = await next.boundingBox();
    // Een echte klik: mousedown (het veld verliest de focus), dan mouseup.
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await step(3).waitFor({ state: 'visible', timeout: 2000 });
    await page.close();
  });
}

test('/setup: na het toepassen staat "Bezig met instellen" er niet meer', async () => {
  const page = await browser.newPage();
  await page.route('**/v2/setup/check', (r) => json(r, { setupMode: true }));
  let sentToken = null;
  await page.route('**/v2/setup/apply', (r) => { sentToken = r.request().headers()['x-setup-token'] || null; return json(r, { ok: true }); });
  await page.goto(ORIGIN + '/setup', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => { document.querySelectorAll('.step').forEach((s) => { s.hidden = s.dataset.step !== '6'; }); });
  // The relay refuses an anonymous apply (setup_token_required): the
  // installation code goes along in X-Setup-Token.
  await page.fill('#setup-token', 'pst_' + 'b'.repeat(48));
  await page.evaluate(() => document.getElementById('apply').click());
  await page.locator('.step[data-step="done"]').waitFor({ state: 'visible', timeout: 5000 });
  assert.equal((await page.locator('#apply-status').textContent()).trim(), '');
  assert.equal(sentToken, 'pst_' + 'b'.repeat(48));
  await page.close();
});

for (const [route, re] of [['/setup', /installatiecode/i], ['/en/setup', /setup code/i]]) {
  test(`${route}: zonder installatiecode gaat er niets naar de relay`, async () => {
    const page = await browser.newPage();
    let calls = 0;
    await page.route('**/v2/setup/check', (r) => json(r, { setupMode: true }));
    await page.route('**/v2/setup/apply', (r) => { calls++; return json(r, { ok: true }); });
    await page.goto(ORIGIN + route, { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => { document.querySelectorAll('.step').forEach((s) => { s.hidden = s.dataset.step !== '6'; }); });
    await page.evaluate(() => document.getElementById('apply').click());
    await page.waitForTimeout(300);
    assert.equal(calls, 0);
    assert.match(await page.locator('#apply-status').textContent(), re);
    await page.close();
  });
}
