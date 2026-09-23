// /ontvang and /ontvang/ without a token. Somebody who typed the address or
// followed a menu has no link, and nothing went wrong. The page used to say
// "Transfer failed: Invalid or missing session token" with a "Try again" that
// reloaded the same empty page, or "This link cannot be used". Now: one calm
// heading, one sentence, one way forward, no loop.
//
// Run: node --test tests/ontvang-empty.test.mjs
//      (PLAYWRIGHT_CHROMIUM_PATH=... to pick a browser)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OE_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const OE_EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const OE_MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json', '.wasm': 'application/wasm' };

let oeServer;
let oeBrowser;
let OE_ORIGIN;

// The production routing, as far as these two addresses go: /ontvang is
// ontvang.html (try_files $uri.html), everything under /ontvang/ is ophalen.html.
function oeFile(p) {
  if (p === '/ontvang') return '/ontvang.html';
  if (p.startsWith('/ontvang/')) return '/ophalen.html';
  return p;
}

before(async () => {
  oeServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const file = path.join(OE_ROOT, oeFile(url.pathname));
    if (!file.startsWith(OE_ROOT)) { res.writeHead(403); return res.end('no'); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': OE_MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  await new Promise((r) => oeServer.listen(0, '127.0.0.1', r));
  OE_ORIGIN = `http://localhost:${oeServer.address().port}`;
  oeBrowser = await chromium.launch({ headless: true, ...(OE_EXE ? { executablePath: OE_EXE } : {}) });
});

after(async () => {
  if (oeBrowser) await oeBrowser.close();
  if (oeServer) await new Promise((r) => oeServer.close(r));
});

async function visibleActions(page) {
  return page.evaluate(() => [...document.querySelectorAll('main a, main button')]
    .filter((e) => e.offsetParent !== null && e.getBoundingClientRect().height > 0)
    .map((e) => ({ tag: e.tagName, text: e.textContent.trim(), href: e.getAttribute('href') })));
}

// The page speaks the language of its <html lang>: ophalen.html (/ontvang/) is
// Dutch since 23 September 2026. Each language has its own exact sentences, and
// the page is held to the ones of the language it declares.
const EMPTY_COPY = {
  en: { title: /Nothing to pick up yet/, lead: /This page opens by itself from the link you were sent\./, button: 'Send something yourself',
    wrong: /Transfer failed|Invalid or missing|cannot be used|Try again/i },
  nl: { title: /Nog niets op te halen/, lead: /Deze pagina opent vanzelf via de link die u kreeg\./, button: 'Zelf iets versturen',
    wrong: /Transfer failed|Invalid or missing|cannot be used|Try again|werkt niet|mislukt|Probeer het opnieuw/i },
};
for (const addr of ['/ontvang', '/ontvang/']) {
  test(`${addr} without a token is a calm empty state with one button to /parasend`, async () => {
    const page = await oeBrowser.newPage({ viewport: { width: 390, height: 844 } });
    await page.route('https://*.paramant.app/**', (r) => r.abort());
    try {
      await page.goto(OE_ORIGIN + addr);
      const lang = await page.evaluate(() => document.documentElement.lang);
      const copy = EMPTY_COPY[lang];
      assert.ok(copy, `unexpected <html lang="${lang}">`);
      await page.waitForFunction((title) => {
        const h = [...document.querySelectorAll('h1')].find((e) => e.offsetParent !== null);
        return h && new RegExp(title).test(h.textContent);
      }, copy.title.source, { timeout: 5000 });
      const text = await page.evaluate(() => document.querySelector('main').innerText);
      assert.match(text, copy.lead);
      assert.doesNotMatch(text, copy.wrong);
      const actions = await visibleActions(page);
      assert.equal(actions.length, 1, JSON.stringify(actions));
      assert.equal(actions[0].text, copy.button);
      assert.equal(actions[0].href, '/parasend');
    } finally { await page.close(); }
  });
}

test('/ontvang with a malformed session token still says the link is invalid', async () => {
  const page = await oeBrowser.newPage();
  try {
    await page.goto(OE_ORIGIN + '/ontvang?s=inv_short');
    await page.waitForFunction(() => document.querySelector('#step-error.active'), null, { timeout: 5000 });
    assert.match(await page.textContent('#error-msg'), /Invalid or missing session token/);
  } finally { await page.close(); }
});

test('/ontvang/<short token> still says the link cannot be used', async () => {
  const page = await oeBrowser.newPage();
  await page.route('https://*.paramant.app/**', (r) => r.abort());
  try {
    await page.goto(OE_ORIGIN + '/ontvang/abc');
    await page.waitForFunction(() => { const s = document.getElementById('step-stop'); return s && !s.hidden; }, null, { timeout: 5000 });
    // ophalen.html is Dutch: "Deze link werkt niet" is its "this link cannot be used".
    assert.match(await page.textContent('#stop-title'), /Deze link werkt niet/);
  } finally { await page.close(); }
});
