// Geometry gate for the Place step on /sign.
//
// The step ends in a sticky Back/Continue bar. A sticky bottom bar floats over
// everything above it inside its containing block, and with the whole step as
// that block the opaque bar landed on the rows the step is explaining: a buyer
// review on a 390x844 phone reported the bar cutting through the hint line, and
// at 320 and 360 it covered the "sign every page" hint and the page switcher.
//
// The fix is structural: the bar is wrapped together with the page list in
// .ds-place-doc, so the document is its containing block and the bar can hover
// over pages (which reserve room for it) and over nothing else. This test pins
// that with bounding boxes, at the four widths the review used, at three scroll
// positions each. It is a layout gate only; the signing behaviour itself is
// covered by tests/sign-full.test.mjs.
//
// Run: node tests/sign-place-toolbar.test.mjs
// Local: PLAYWRIGHT_CHROMIUM_PATH=<chrome binary> node tests/sign-place-toolbar.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png','.woff2':'font/woff2' };

const server = http.createServer((req, res) => {
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
const ORIGIN = `http://localhost:${server.address().port}`;

const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const checks = [];
const ok = (name, pass, detail = '') => checks.push({ name, pass: !!pass, detail: String(detail) });

// Every row of the step that carries words. None of them may end up under the
// bar, at any scroll offset, at any of the four widths.
const READABLE = [
  '#ds-place-hint',
  '#step-place .ds-sub',
  '#ds-zoom',
  '#ds-invite-tools',
  '#ds-edit-tools-hint',
  '#step-place .ds-edit-tip',
  '#ds-seal-tools',
  '#ds-seal-tip',
  '#ds-page-nav',
];

for (const [width, height] of [[320, 844], [360, 844], [390, 844], [1440, 900]]) {
  const context = await browser.newContext({ viewport: { width, height } });
  const page = await context.newPage();
  await page.route('**/api/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }));
  // Signed in: this measures the signer's toolbar, not the signed-out bar. Last
  // registered wins in Playwright, so this sits under the catch-all above.
  await page.route('**/api/user/session/verify', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"email":"demo@example.com"}' }));
  await page.goto(`${ORIGIN}/sign.html`, { waitUntil: 'domcontentloaded' });

  const reached = await page.evaluate(async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    for (let i = 0; i < 400 && !(window.PDFLib && window.pdfjsLib); i++) await sleep(20);
    if (!window.PDFLib || !window.pdfjsLib) return false;
    const source = await window.PDFLib.PDFDocument.create();
    for (let i = 0; i < 3; i++) source.addPage([595, 842]).drawText('Page ' + (i + 1), { x: 40, y: 780, size: 18 });
    const bytes = await source.save();
    const input = document.getElementById('ds-doc-input');
    const transfer = new DataTransfer();
    transfer.items.add(new File([bytes], 'toolbar-probe.pdf', { type: 'application/pdf' }));
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
    for (let i = 0; i < 400 && document.getElementById('step-place').hidden; i++) await sleep(20);
    await sleep(300);
    return !document.getElementById('step-place').hidden;
  });
  ok(`${width}px reaches the Place step`, reached);

  ok(`${width}px keeps the action bar inside the document wrapper`,
    await page.evaluate(() => {
      const bar = document.querySelector('.ds-place-actions');
      const list = document.getElementById('ds-pdf-canvas-list');
      return !!bar && !!list && bar.parentElement.classList.contains('ds-place-doc') && list.parentElement === bar.parentElement;
    }));

  for (const offset of [0, 200, 100000]) {
    await page.evaluate((y) => window.scrollTo(0, y), offset);
    await page.waitForTimeout(150);
    const frame = await page.evaluate((selectors) => {
      const rect = (selector) => {
        const el = document.querySelector(selector);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return null;
        if (getComputedStyle(el).visibility === 'hidden') return null;
        return { selector, top: r.top, bottom: r.bottom, left: r.left, right: r.right };
      };
      return { bar: rect('.ds-place-actions'), rows: selectors.map(rect).filter(Boolean), scrollY: window.scrollY };
    }, READABLE);

    ok(`${width}px @${offset === 100000 ? 'bottom' : offset} has a measurable action bar`, !!frame.bar, JSON.stringify(frame.bar));
    const hit = frame.bar
      ? frame.rows.filter((row) => row.bottom > frame.bar.top && row.top < frame.bar.bottom && row.right > frame.bar.left && row.left < frame.bar.right)
      : [];
    ok(`${width}px @${offset === 100000 ? 'bottom' : offset} the action bar overlaps no row of words`,
      frame.bar && hit.length === 0,
      JSON.stringify({ bar: frame.bar, hit }));
  }

  // Scrolled into the document the bar has to be on screen: that is the whole
  // point of making it sticky.
  await page.evaluate(() => document.getElementById('ds-pdf-canvas-list').scrollIntoView({ block: 'start' }));
  await page.waitForTimeout(150);
  const pinned = await page.evaluate(() => {
    const r = document.querySelector('.ds-place-actions').getBoundingClientRect();
    return { top: r.top, bottom: r.bottom, height: r.height, viewport: window.innerHeight };
  });
  ok(`${width}px pins the action bar to the bottom once the document is in view`,
    pinned.bottom <= pinned.viewport + 1 && pinned.top >= 0,
    JSON.stringify(pinned));
  // One row of buttons, not two: at 320 the two 160px minimums wrapped and the
  // bar took 123px of an 844px screen.
  ok(`${width}px keeps the action bar to a single row`, pinned.height < 90, JSON.stringify(pinned));

  if (process.env.PARAMANT_PLACE_SHOT_DIR) {
    await page.screenshot({ path: path.join(process.env.PARAMANT_PLACE_SHOT_DIR, `place-toolbar-${width}.png`) });
  }
  await context.close();
}

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
server.closeAllConnections();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nsign-place-toolbar: ${checks.length} checks passed`);
