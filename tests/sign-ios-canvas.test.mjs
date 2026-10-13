// iOS: WebKit draws a canvas larger than about 4096 px a side or 16.7 M pixels
// as a blank, silently. On an iPhone (devicePixelRatio 3) a zoomed page on
// /sign passed that and showed a white sheet (diagnosis 2026-06-24, PR #249).
//
// Chromium has no such limit, so this suite gives it one: an init script makes
// getContext('2d') on an over-limit canvas hand back the context of a detached
// canvas, so whatever is drawn never reaches the visible one. That is the
// WebKit behaviour: no error, just nothing.
// Run: node --test tests/sign-ios-canvas.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, launch, newPage, openSign, makePdf, pickBytes, waitPlaced, clickPage } from './helpers/sign-flow-harness.mjs';

const { server, origin } = await startServer();
const browser = await launch();
after(async () => { await browser.close(); server.close(); });

// side/area: the simulated engine limit.
async function simulateLimit(page, side, area) {
  await page.addInitScript(({ side, area }) => {
    const orig = HTMLCanvasElement.prototype.getContext;
    const sink = document.createElement('canvas');
    HTMLCanvasElement.prototype.getContext = function (type, ...rest) {
      if (type === '2d' && (this.width > side || this.height > side || this.width * this.height > area)) {
        sink.width = 1; sink.height = 1;
        return orig.call(sink, type, ...rest);
      }
      return orig.call(this, type, ...rest);
    };
  }, { side, area });
}

const pageCanvases = (page) => page.evaluate(() => [...document.querySelectorAll('#ds-pdf-canvas-list .ds-page-wrap canvas')].map((c) => {
  const p = document.createElement('canvas'); p.width = 16; p.height = 16;
  const ctx = p.getContext('2d'); ctx.drawImage(c, 0, 0, 16, 16);
  const d = ctx.getImageData(0, 0, 16, 16).data;
  let drawn = false; for (let i = 3; i < d.length; i += 4) if (d[i]) { drawn = true; break; }
  return { w: c.width, h: c.height, drawn };
}));

async function zoomTo400(page) {
  for (let i = 0; i < 7; i++) { await page.click('#ds-zoom-in'); await page.waitForTimeout(150); }
  await page.waitForFunction(() => /400%/.test(document.getElementById('ds-zoom-pct').textContent), null, { timeout: 10000 });
  await page.waitForTimeout(1500);
}

test('iPhone at 400% zoom: every page canvas stays within the limit and is drawn', async () => {
  const page = await newPage(browser, { mobile: true });
  await simulateLimit(page, 4096, 16777216);
  await openSign(page, origin);
  const pdf = await makePdf(page, { pages: [{ lines: true }, { lines: true }] });
  await pickBytes(page, pdf, 'iphone.pdf');
  await waitPlaced(page, 2).catch(() => {});
  await zoomTo400(page);
  const cs = await pageCanvases(page);
  assert.ok(cs.length === 2);
  for (const c of cs) {
    assert.ok(c.w <= 4096 && c.h <= 4096 && c.w * c.h <= 16777216, `canvas ${c.w}x${c.h} passes the WebKit limit`);
    assert.ok(c.drawn, 'the page is drawn, not blank');
  }
  assert.equal(await page.locator('.ds-blank-note').count(), 0);
  // The seal still lands where the page is clicked at this zoom (left edge:
  // at 400% the page is wider than the phone).
  await clickPage(page, 0, 0.1, 0.3);
  assert.equal(await page.locator('.ds-stamp-marker').count(), 1);
  await page.context().close();
});

test('a canvas that still comes out blank is drawn again smaller', async () => {
  const page = await newPage(browser, { mobile: true });
  await simulateLimit(page, 4096, 16777216);
  // Lift the app's own cap, so the first render does pass the engine limit.
  await page.addInitScript(() => { window.__paramantCanvasCap = { side: 1e6, area: 1e12 }; });
  await openSign(page, origin);
  const pdf = await makePdf(page, { pages: [{ lines: true }] });
  await pickBytes(page, pdf, 'retry.pdf');
  await waitPlaced(page, 1).catch(() => {});
  await zoomTo400(page);
  const [c] = await pageCanvases(page);
  assert.ok(c.drawn, `the page came back after the blank check (${c.w}x${c.h})`);
  assert.ok(c.w * c.h <= 16777216);
  await page.context().close();
});

test('a page no size can draw says so instead of showing white', async () => {
  const page = await newPage(browser);
  await simulateLimit(page, 1e6, 2000);   // nothing bigger than ~45x45 px draws
  await openSign(page, origin);
  const pdf = await makePdf(page, { pages: [{ lines: true }] });
  await pickBytes(page, pdf, 'never.pdf');
  await page.locator('.ds-blank-note').first().waitFor({ timeout: 30000 });
  // Mick 05-10: taalronde
  assert.match(await page.locator('.ds-blank-note').first().textContent(), /kan deze pagina niet tonen/);
  await page.context().close();
});
