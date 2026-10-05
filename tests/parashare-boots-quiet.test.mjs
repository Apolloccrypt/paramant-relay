// The send page boots quiet: no 3D globe until somebody asks for one.
//
// WHAT WENT WRONG
//
// /parashare has a globe. It is a WebGL scene built by globe.gl on top of
// three.js, it autorotates, it draws pulsing rings, and it lives in
// #globe-overlay, which is display:none. There is no button for it. The only
// way in is Ctrl+G, and the CSS comment above the overlay says so.
//
// Until 6 September 2026 the page built it 400 ms after every load anyway,
// from a DOMContentLoaded handler. Every visit to the send page fetched
// globe.gl.min.js (992 KB) plus earth-night.jpg, earth-topology.png and
// night-sky.png (1.9 MB together), created a WebGL context and started a
// render loop that ran for as long as the tab was open, for a scene nobody
// had opened and almost nobody knew was there. On a phone that is battery and
// data spent on a decoration behind an invisible overlay.
//
// In CI it is worse, because a headless runner has no GPU and Chromium falls
// back to software rendering. Measured on this repo, pinned to one core:
// building the globe is ONE task of 26.3 seconds in which the renderer runs no
// animation frame at all. Playwright's actionability budget is 30 seconds and
// every one of its waits polls on an animation frame, so the whole margin was
// 3.7 seconds of whatever else the runner happened to be doing.
//
// It had already been paid for three times before anyone looked at the cause:
//
//   - scripts/ui-contrast-sweep.mjs stopped scrolling pages to the bottom,
//     because scrolling woke the globe and "never gave the main thread back";
//   - tests/motion-safety.test.mjs was restructured to load each page once
//     instead of twice, because the globe's node count "never came to rest
//     within twenty seconds" on the runner;
//   - tests/handshake-meta.test.mjs and tests/end-screen-calm.test.mjs were
//     entered in tests/known-flaky.tsv on 5 September, both of them timing out
//     inside a /parashare hand-over, handshake-meta with the tell in the log:
//     "waiting for element to be stable".
//
// Three workarounds and a flaky register, for something a visitor never sees.
// The globe now builds on the first Ctrl+G, which is what the comment inside
// initGlobe() ("alleen als globe geopend wordt") had claimed all along.
//
// WHAT THIS FILE HOLDS
//
//   1. A plain load of /parashare asks for none of the globe's 2.9 MB and
//      builds no canvas. Measured off the wire, so it does not depend on how
//      fast the machine is: no request, no bytes, no context.
//   2. Ctrl+G still gives you the globe: the canvas arrives, the loading ring
//      leaves, and while the scene ticks the page throws nothing. That last
//      part is the guard PR #431 needed and did not have: moving
//      GLOBE_ACCENT_RGB inside initGlobe() made every ring tick throw
//      "GLOBE_ACCENT_RGB is not defined" on live deploy 25. It used to be
//      caught by accident, because every page load ran the scene. Now that
//      only an opened globe runs it, the check is made here on purpose.
//   3. Sabotage: put the load-time boot back and check 1 goes red.
//
// Run: node tests/parashare-boots-quiet.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FRONTEND = path.join(ROOT, 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;

const checks = [];
function ok(name, condition, detail = '') { checks.push({ name, pass: !!condition, detail: String(detail) }); }

// Everything the globe needs and nothing else. Named here rather than matched
// on a pattern, so a fourth texture added to initGlobe() has to be added here
// too instead of quietly slipping past.
const GLOBE_ASSETS = [
  '/globe.gl.min.js',
  '/images/globe/earth-night.jpg',
  '/images/globe/earth-topology.png',
  '/images/globe/night-sky.png',
];
const GLOBE_BYTES = GLOBE_ASSETS.reduce((n, rel) => n + fs.statSync(path.join(FRONTEND, rel)).size, 0);

const MIME = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2',
  '.wasm': 'application/wasm', '.json': 'application/json', '.ico': 'image/x-icon' };
const ALIAS = { '/': '/index.html', '/parashare': '/parashare.html' };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const rel = ALIAS[url.pathname] || url.pathname;
  const file = path.join(FRONTEND, rel);
  if (!file.startsWith(FRONTEND)) { res.writeHead(403); return res.end('no'); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

// A page on the send screen, with the relay stubbed at the network edge the
// same way tests/handshake-meta.test.mjs does it. `sabotage` puts the boot that
// was removed back, from outside the page, so check 1 can be shown to fire.
async function sendPage({ sabotage = false } = {}) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  await ctx.addInitScript(() => {
    const stub = { initCrypto: async () => {}, encryptBlob: async (p) => new Uint8Array(p.length + 32),
      decryptBlob: async () => new Uint8Array() };
    Object.defineProperty(window, '_cryptoBridge', { get: () => stub, set: () => {}, configurable: true });
  });
  if (sabotage) {
    await ctx.addInitScript(() => {
      document.addEventListener('DOMContentLoaded', () => setTimeout(() => window.initGlobe && window.initGlobe(), 400));
    });
  }
  await ctx.route('**/api/user/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  for (const host of ['legal', 'finance', 'iot', 'relay']) await ctx.route(`https://${host}.paramant.app/**`, (r) => r.abort());
  await ctx.route('https://health.paramant.app/**', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ valid: true, plan: 'pro', link_ttl_ms: 86400000 }) }));

  const asked = [];
  const page = await ctx.newPage();
  page.on('request', (r) => {
    const p = new URL(r.url(), ORIGIN).pathname;
    if (GLOBE_ASSETS.includes(p)) asked.push(p);
  });
  const thrown = [];
  page.on('pageerror', (e) => thrown.push('uncaught: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') thrown.push('console.error: ' + m.text()); });
  return { ctx, page, asked, thrown };
}

// The page's own handler waits 400 ms and then loads a megabyte. Two seconds is
// five times that wait plus the fetches, on a static server on loopback. It is
// a window in which the boot WOULD show, not a deadline anything has to beat:
// the sabotage below is what proves the window is wide enough to see it.
const SETTLE_MS = 2000;

// ── 1. a plain load asks for none of it ─────────────────────────────────────
{
  const { ctx, page, asked, thrown } = await sendPage();
  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'load' });
  await page.waitForTimeout(SETTLE_MS);

  ok(`loading /parashare asks for none of the globe's ${(GLOBE_BYTES / 1024 / 1024).toFixed(1)} MB`,
    asked.length === 0, asked.join(', '));
  ok('and builds no WebGL canvas for a scene nobody opened',
    (await page.locator('#globe-canvas-wrap canvas').count()) === 0);
  ok('the overlay it would have gone in is still shut',
    !(await page.locator('#globe-overlay').isVisible()));
  ok('the send button is there and reachable, which is the point of all this',
    (await page.locator('#btn-create-session').count()) === 1);
  ok('and the page throws nothing on the way', thrown.length === 0, thrown.join(' | '));
  await ctx.close();
}

// ── 2. Ctrl+G still gives you the globe ─────────────────────────────────────
{
  const { ctx, page, asked, thrown } = await sendPage();
  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'load' });
  await page.waitForTimeout(SETTLE_MS);
  ok('before the shortcut: nothing fetched', asked.length === 0, asked.join(', '));

  await page.keyboard.press('Control+g');
  await page.locator('#globe-canvas-wrap canvas').waitFor({ state: 'attached', timeout: 60000 });

  ok('Ctrl+G opens the overlay', await page.locator('#globe-overlay').isVisible());
  ok('Ctrl+G is what fetches the globe, all of it',
    GLOBE_ASSETS.every((a) => asked.includes(a)), asked.join(', '));
  ok('the canvas is really there', (await page.locator('#globe-canvas-wrap canvas').count()) === 1);
  // The ring used to be unable to leave: initGlobe() hid it with an inline
  // display:none against a rule marked !important. It never showed, because the
  // globe was always built before the overlay was ever opened.
  await page.waitForFunction(() => document.getElementById('globe-overlay').classList.contains('globe-ready'), null, { timeout: 60000 });
  ok('and the loading ring gets out of the way once it is built',
    !(await page.locator('#globe-loading').isVisible()));

  // Let the scene tick. This is the #431 check: the ring animation reads
  // GLOBE_ACCENT_RGB from module scope on every tick, and a refactor that puts
  // it out of reach throws here and nowhere else.
  await page.waitForTimeout(2500);
  ok('a running globe throws nothing on its animation ticks', thrown.length === 0, thrown.join(' | '));

  // Escape closes it, and closing stops the stats poll rather than leaving a
  // timer behind on a page the sender is still using.
  await page.keyboard.press('Escape');
  ok('Escape shuts it again', !(await page.locator('#globe-overlay.globe-fullscreen').count()));
  await ctx.close();
}

// ── 3. the sabotage ─────────────────────────────────────────────────────────
// Boot the globe from a load handler again, from outside the page, and check 1
// has to see it. Without this the first block passes just as well on a page
// that has no globe at all, which is not what is being claimed.
{
  const { ctx, page, asked } = await sendPage({ sabotage: true });
  await page.goto(`${ORIGIN}/parashare`, { waitUntil: 'load' });
  await page.waitForTimeout(SETTLE_MS);
  ok('sabotage: a globe booted from load is caught by the check above',
    asked.length > 0 && asked.includes('/globe.gl.min.js'), asked.join(', '));
  await ctx.close();
}

await browser.close();
server.close();
server.closeAllConnections();

let failed = 0;
for (const c of checks) {
  console.log(`${c.pass ? 'ok  ' : 'FAIL'}  ${c.name}${c.pass || !c.detail ? '' : '  -- ' + c.detail}`);
  if (!c.pass) failed++;
}
console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
if (failed) process.exit(1);
