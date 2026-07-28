// Product heartbeat: does the site still DO anything, in a real browser.
//
// Three breaks shipped silently in July 2026 and none of them was caught by a
// test, because all three failed in the browser and nowhere else:
//
//   042b4c5 (07-02)  CSP extraction moved inline code into js/. A relative
//                    import moved with it and 404'd. Sending a file was dead
//                    for three weeks.
//   before 7da4e39   Three pages loaded a module as a classic script. The
//                    browser rejected the file as a SyntaxError and ran none
//                    of it. Sending, receiving and the account page were dead.
//   PR 278 (07)      Signup died on a CSP-blocked inline script.
//
// Every one of them is invisible to a Node test suite and loud in a browser
// console. So this suite opens each page in Chromium and fails on:
//
//   1. any uncaught page error (SyntaxError, ReferenceError, ...)
//   2. any console error, including CSP refusals
//   3. any failed request for one of our own static assets (a 404 on a script,
//      stylesheet, module import or wasm blob)
//   4. a per-page heartbeat: the one global that proves the page's core
//      machinery actually initialised
//
// Rules 1-3 need no maintenance and cover features nobody wrote a check for.
// Rule 4 is where a product owner states what "alive" means for a page.
//
// Local  : node tests/product-heartbeat.test.mjs          (serves frontend/)
// Prod   : PARAMANT_BASE_URL=https://paramant.app node tests/product-heartbeat.test.mjs
// CI     : npx playwright install --with-deps chromium, then as local.
import { chromium } from 'playwright';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.webp':'image/webp','.woff2':'font/woff2','.ico':'image/x-icon' };

// A page is alive when its core machinery left something behind on window.
// Keep this list short and mean it: every entry is a promise to the user.
const PAGES = [
  {
    url: '/parashare.html',
    what: 'ParaSend, sending a file',
    // parashare.page.js:304 refuses to encrypt without this. It was undefined
    // on production from 2026-07-02 until 2026-07-26.
    heartbeat: () => typeof window._cryptoBridge?.encryptBlob === 'function',
    because: 'window._cryptoBridge.encryptBlob is missing, so the send aborts with "WASM crypto module not loaded"',
  },
  {
    url: '/ontvang.html',
    what: 'ParaSend, receiving a file',
    // A well-formed token that no relay will accept. Enough to make the page
    // run its real client-side work: generate the keypair and show the
    // fingerprint. Whether the relay then knows the token is not our business
    // here.
    query: '?s=inv_00000000000000000000000000000000',
    heartbeat: () => typeof window._cryptoBridge?.decryptBlob === 'function',
    because: 'window._cryptoBridge.decryptBlob is missing, so ontvang.page.js throws "WASM crypto bridge not ready"',
    // The globals above were all present on 2026-07-28 while the page sat on
    // "Generating keypair..." forever: a lost readiness event meant init() was
    // never called. Loaded is not the same as working, so this asserts the user
    // actually gets somewhere.
    progress: () => /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test(document.getElementById('fp-display')?.textContent?.trim() || ''),
    stuck: 'keygen never completed: no fingerprint on screen, so receiving a file is dead',
  },
  { url: '/index.html',   what: 'homepage' },
  { url: '/pricing.html', what: 'pricing, the paid funnel' },
  { url: '/signup.html',  what: 'signup' },
  { url: '/sign.html',    what: 'ParaSign' },
  { url: '/verify.html',  what: 'signature verification' },
  { url: '/paraid.html',  what: 'ParaID' },
];

// Only our own static assets. A 401 on /api/* without a session is correct
// behaviour, not a break, and third party hosts are not ours to police.
const OUR_ASSET = /\.(js|mjs|css|wasm|woff2?|svg|png|webp|ico)(\?|$)/i;

const BASE = process.env.PARAMANT_BASE_URL?.replace(/\/$/, '');
let server = null;
let origin = BASE;

if (!BASE) {
  server = http.createServer((req, res) => {
    const p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    const file = path.join(ROOT, p);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, b) => {
      if (e) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(b);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${server.address().port}`;
}

const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

test.after(async () => {
  await browser.close();
  server?.close();
});

for (const page of PAGES) {
  test(`${page.url} — ${page.what}`, async () => {
    const ctx = await browser.newContext();
    const tab = await ctx.newPage();
    const problems = [];

    tab.on('pageerror', (e) => problems.push(`uncaught ${e.message}`));
    // "Failed to load resource" carries no url, so it is useless on its own and
    // duplicates what the response handler below reports with a path. Every
    // other console error is kept, CSP refusals included.
    tab.on('console', (m) => {
      if (m.type() !== 'error') return;
      if (/^Failed to load resource/.test(m.text())) return;
      problems.push(`console: ${m.text()}`);
    });
    tab.on('requestfailed', (r) => {
      if (OUR_ASSET.test(r.url()) && new URL(r.url()).origin === new URL(origin).origin) {
        problems.push(`request failed ${r.url()} (${r.failure()?.errorText})`);
      }
    });
    tab.on('response', (r) => {
      if (r.status() >= 400 && OUR_ASSET.test(r.url()) && new URL(r.url()).origin === new URL(origin).origin) {
        problems.push(`HTTP ${r.status()} on our own asset ${new URL(r.url()).pathname}`);
      }
    });

    // A page with a progress check opens a relay connection and keeps polling,
    // so it never goes network-idle. The request and response handlers above
    // stay attached either way, and the progress poll below keeps the page open
    // long enough for a late 404 to still be caught.
    const settled = page.progress ? 'load' : 'networkidle';
    const resp = await tab.goto(origin + page.url + (page.query || ''), { waitUntil: settled, timeout: 45000 });
    assert.ok(resp?.ok(), `${page.url} did not load: HTTP ${resp?.status()}`);
    await tab.waitForTimeout(1200);   // let deferred modules and wasm settle

    if (page.heartbeat) {
      const alive = await tab.evaluate(page.heartbeat);
      assert.ok(alive, `${page.what} is dead: ${page.because}`);
    }

    // Rule 5: does the page get the user anywhere? Every global can be present
    // and correct while the page does nothing at all, which is precisely how
    // /ontvang hung for three weeks. Poll rather than sleep: keygen is fast on a
    // laptop and slow on a loaded CI runner.
    if (page.progress) {
      const moved = await tab.waitForFunction(page.progress, null, { timeout: 25000, polling: 250 })
        .then(() => true).catch(() => false);
      assert.ok(moved, `${page.what} does not work: ${page.stuck}`);
    }

    // The relay is a separate host with its own gate (tests/transfer-canary),
    // and the test token is deliberately one no relay will accept, so a refused
    // socket to it says nothing about the frontend. Filtering this is only safe
    // BECAUSE the progress check above already proved the page did its work.
    const RELAY_NOISE = /wss?:\/\/[^ ]*relay\.paramant\.app|WebSocket connection to/;

    // A console error the page recovers from is still a break waiting to be
    // reported by a user, so it fails here too. Drop the noise, not the signal.
    const real = problems.filter((p) => !/favicon|\/api\/|401|403|Failed to load resource: the server responded with a status of 40[13]/.test(p) && !RELAY_NOISE.test(p));
    assert.deepEqual(real, [], `\n  ${page.url}\n  ${real.join('\n  ')}\n`);

    await ctx.close();
  });
}
