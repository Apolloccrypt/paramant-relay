// WYSIWYS on pages that are turned or cropped: what the signer places on /sign
// lands on that same spot of the signed PDF, upright, within 1% of the page.
//
// Test report 2026-10-04 (tester 1): on /Rotate 90/180/270 pages the seal and
// every extra landed 50-77% away from where the UI showed them, and sideways;
// the app's own rotate button made such pages itself. A CropBox or MediaBox not
// at 0,0 shifted everything 10-17%. No suite baked a PDF and measured it.
//
// Every case here walks the real UI in Chromium (pick, click, sign with a TOTP
// code against stubbed server answers), downloads the PDF the real
// buildStampedPdf made, renders it with pdf.js and measures the pixels.
// Run: node --test tests/sign-geometry.test.mjs
// PARAMANT_SIGN_SHOT_DIR=<dir> also writes the signed pages as PNG.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startServer, launch, newPage, openSign, makePdf, pickBytes, waitPlaced, clickPage, uiBoxes, signAndDownload, measurePdf, savePngs } from './helpers/sign-flow-harness.mjs';

const SHOTS = process.env.PARAMANT_SIGN_SHOT_DIR || '';
const TOL = 0.01;   // 1% of the page, in each direction

const { server, origin } = await startServer();
const browser = await launch();
after(async () => { await browser.close(); server.close(); });

const near = (a, b, what) => assert.ok(Math.abs(a - b) <= TOL, `${what}: signed ${a.toFixed(4)} vs shown ${b.toFixed(4)} (off by ${(Math.abs(a - b) * 100).toFixed(2)}%)`);
const nearBox = (got, want, what) => {
  assert.ok(got, `${what}: nothing found on the signed page`);
  for (const k of ['x', 'y', 'w', 'h']) near(got[k], want[k], `${what} ${k}`);
};

// One page with the seal, a highlight and a date placed through the UI.
async function placeAndSign(spec, { pageIndex = 0, rotateButton = false, label }) {
  const page = await newPage(browser);
  await openSign(page, origin);
  const pdf = await makePdf(page, spec);
  await pickBytes(page, pdf, label + '.pdf');
  await waitPlaced(page, spec.pages.length);
  if (rotateButton) {
    await page.locator(`#ds-pdf-canvas-list .ds-page-wrap[data-page-index="${pageIndex}"] .ds-page-bar button`).nth(2).click();
    await page.waitForFunction((i) => {
      const c = document.querySelector(`#ds-pdf-canvas-list .ds-page-wrap[data-page-index="${i}"] canvas`);
      return c && c.width > c.height && c.width > 400;
    }, pageIndex, { timeout: 20000 });
    await waitPlaced(page, spec.pages.length);
  }
  await clickPage(page, pageIndex, 0.55, 0.72);
  await page.click('#ds-add-highlight');
  await clickPage(page, pageIndex, 0.12, 0.2);
  await page.click('#ds-add-date');
  await clickPage(page, pageIndex, 0.12, 0.42);
  const ui = (await uiBoxes(page)).filter((b) => b.page === pageIndex);
  const res = await signAndDownload(page);
  assert.equal(res.error, undefined, res.error);
  const m = await measurePdf(page, res.pdf, SHOTS ? 1 : 0);
  savePngs(SHOTS, label, m);
  if (SHOTS) fs.writeFileSync(path.join(SHOTS, label + '.pdf'), res.pdf);
  await page.context().close();
  return { ui, m: m[pageIndex] };
}

function checkPage({ ui, m }, label) {
  const seal = ui.find((b) => b.kind === 'seal');
  const hl = ui.find((b) => b.kind === 'highlight');
  const date = ui.find((b) => b.kind === 'date');
  assert.ok(seal && hl && date, `${label}: the UI shows seal, highlight and date`);
  nearBox(m.navy, seal, `${label} seal`);
  nearBox(m.highlight, hl, `${label} highlight`);
  // Upright: the wordmark sits in the top of the seal as the page is shown and
  // runs left to right. (The seal used to have a solid navy band to look for;
  // since T1-10 it is see-through with a thin line, so the words decide.)
  const mark = m.texts.find((x) => x.str.includes('ParaMANT'));
  assert.ok(mark, `${label}: the seal's wordmark is in the signed PDF`);
  assert.ok(mark.y > seal.y && mark.y < seal.y + seal.h * 0.4, `${label}: the seal is not upright (wordmark at ${mark.y.toFixed(3)}, seal ${seal.y.toFixed(3)}..${(seal.y + seal.h).toFixed(3)})`);
  assert.ok(mark.dirX > 0 && Math.abs(mark.dirY) < 1e-6, `${label}: the wordmark does not run left to right`);
  // The date: where its box says, and running left to right on the shown page.
  const dateStr = date.text.replace(/[^0-9-]/g, '').slice(0, 10);
  const t = m.texts.find((x) => x.str === dateStr);
  assert.ok(t, `${label}: the date ${dateStr} is in the signed PDF`);
  const size = date.h / 1.35;                       // as a fraction of the page height
  const wantX = date.x + 0.1 * size * (m.view.h / m.view.w);
  const wantY = date.y + date.h - 0.35 * size;      // baseline, from the top
  near(t.x, wantX, `${label} date x`);
  near(t.y, wantY, `${label} date baseline`);
  assert.ok(t.dirX > 0 && Math.abs(t.dirY) < 1e-6, `${label}: the date runs sideways (${t.dirX}, ${t.dirY})`);
}

const A4 = [595.28, 841.89];
const cases = [
  ['rotate-0', { pages: [{ size: A4 }] }],
  ['rotate-90', { pages: [{ size: A4, rotate: 90 }] }],
  ['rotate-180', { pages: [{ size: A4, rotate: 180 }] }],
  ['rotate-270', { pages: [{ size: A4, rotate: 270 }] }],
  ['rotate-90-landscape', { pages: [{ size: [841.89, 595.28], rotate: 90 }] }],
  ['cropbox-offset', { pages: [{ size: A4, cropBox: [50, 80, 450, 650] }] }],
  ['mediabox-origin', { pages: [{ size: A4, mediaBox: [-100, -100, 595.28, 841.89] }] }],
  ['rotate-270-cropbox', { pages: [{ size: A4, cropBox: [40, 60, 500, 700], rotate: 270 }] }],
];
for (const [label, spec] of cases) {
  test(`${label}: seal, highlight and date land where they were shown, upright`, async () => {
    checkPage(await placeAndSign(spec, { label }), label);
  });
}

test('mixed rotation: the seal on a turned page 2 of 3 lands where it was shown', async () => {
  const spec = { pages: [{ size: A4 }, { size: A4, rotate: 90 }, { size: A4, rotate: 180 }] };
  checkPage(await placeAndSign(spec, { pageIndex: 1, label: 'rotate-mixed' }), 'rotate-mixed p2');
});

test('the rotate button in the app: the seal follows the turned page', async () => {
  checkPage(await placeAndSign({ pages: [{ size: A4 }] }, { rotateButton: true, label: 'rotate-button' }), 'rotate-button');
});

test('sign every page on turned pages: each paraaf lands on its preview, in a free corner, upright', async () => {
  const page = await newPage(browser);
  await openSign(page, origin);
  const spec = { pages: [0, 90, 180, 270, 0].map((rotate, i) => ({ size: A4, rotate, lines: true, ...(i === 4 ? { cropBox: [30, 40, 520, 760] } : {}) })) };
  const pdf = await makePdf(page, spec);
  await pickBytes(page, pdf, 'paraaf-rotated.pdf');
  await waitPlaced(page, spec.pages.length);
  await page.locator('#ds-allpages').check();
  await clickPage(page, 0, 0.5, 0.5);
  await page.waitForFunction(() => document.querySelectorAll('.ds-paraaf').length >= 4, null, { timeout: 20000 });
  const ui = await uiBoxes(page);
  const res = await signAndDownload(page);
  assert.equal(res.error, undefined, res.error);
  const m = await measurePdf(page, res.pdf, SHOTS ? 1 : 0);
  savePngs(SHOTS, 'paraaf-rotated', m);
  const src = await measurePdf(page, pdf, 0);
  for (let i = 1; i < spec.pages.length; i++) {
    const want = ui.find((b) => b.kind === 'paraaf' && b.page === i);
    assert.ok(want, `page ${i + 1}: a paraaf is shown`);
    nearBox(m[i].navy, want, `page ${i + 1} (rotate ${spec.pages[i].rotate}) paraaf`);
    // Initials run left to right on the page as shown.
    const ini = m[i].texts.find((t) => /^S\.T\.$/.test(t.str));
    assert.ok(ini, `page ${i + 1}: initials S.T. in the PDF`);
    assert.ok(ini.dirX > 0 && Math.abs(ini.dirY) < 1e-6, `page ${i + 1}: initials run sideways`);
    // Not on the text: no source text item starts inside the paraaf.
    for (const t of src[i].texts) {
      const inside = t.x > want.x && t.x < want.x + want.w && t.y > want.y && t.y < want.y + want.h;
      assert.ok(!inside, `page ${i + 1}: the paraaf covers "${t.str.slice(0, 20)}"`);
    }
  }
  await page.context().close();
});
