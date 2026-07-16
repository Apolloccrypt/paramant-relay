// Unit tests for the ParaSign page-operations module, run against the SAME
// vendored pdf-lib bundle the browser uses (no separate npm dependency, so a
// vendor bump is automatically what gets tested).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const PDFLib = require('../frontend/vendor/pdf-lib/pdf-lib.min.js');
const Ops = require('../frontend/js/parasign-pdf-ops.js');

// A test PDF whose pages are distinguishable by width: page i is (100+i) wide.
async function makePdf(n) {
  const doc = await PDFLib.PDFDocument.create();
  for (let i = 0; i < n; i++) doc.addPage([100 + i, 200]);
  return await doc.save();
}
async function widths(bytes) {
  const doc = await PDFLib.PDFDocument.load(bytes);
  return doc.getPages().map(p => Math.round(p.getSize().width));
}

test('pageCount', async () => {
  assert.equal(await Ops.pageCount(PDFLib, await makePdf(4)), 4);
});

test('deletePage removes exactly the indexed page', async () => {
  const out = await Ops.deletePage(PDFLib, await makePdf(4), 1);
  assert.deepEqual(await widths(out), [100, 102, 103]);
});

test('deletePage refuses to delete the last page', async () => {
  const one = await makePdf(1);
  await assert.rejects(() => Ops.deletePage(PDFLib, one, 0), /last page/);
});

test('movePage up and down', async () => {
  const base = await makePdf(4);
  assert.deepEqual(await widths(await Ops.movePage(PDFLib, base, 2, 0)), [102, 100, 101, 103]);
  assert.deepEqual(await widths(await Ops.movePage(PDFLib, base, 0, 3)), [101, 102, 103, 100]);
  assert.deepEqual(await widths(await Ops.movePage(PDFLib, base, 1, 1)), [100, 101, 102, 103]);
});

test('reorderPages validates the permutation', async () => {
  const base = await makePdf(3);
  await assert.rejects(() => Ops.reorderPages(PDFLib, base, [0, 1]), /every page/);
  await assert.rejects(() => Ops.reorderPages(PDFLib, base, [0, 1, 1]), /permutation/);
  await assert.rejects(() => Ops.reorderPages(PDFLib, base, [0, 1, 3]), /permutation/);
  assert.deepEqual(await widths(await Ops.reorderPages(PDFLib, base, [2, 0, 1])), [102, 100, 101]);
});

test('rotatePage stacks on the existing rotation and normalises', async () => {
  const base = await makePdf(2);
  let out = await Ops.rotatePage(PDFLib, base, 1, 90);
  out = await Ops.rotatePage(PDFLib, out, 1, 90);
  const doc = await PDFLib.PDFDocument.load(out);
  assert.equal(doc.getPage(1).getRotation().angle, 180);
  assert.equal(doc.getPage(0).getRotation().angle, 0);
  const back = await Ops.rotatePage(PDFLib, out, 1, -270);
  const doc2 = await PDFLib.PDFDocument.load(back);
  assert.equal(doc2.getPage(1).getRotation().angle, 270);
});

test('appendPdf merges all pages of the second document at the end', async () => {
  const a = await makePdf(2);
  const bDoc = await PDFLib.PDFDocument.create();
  bDoc.addPage([300, 200]); bDoc.addPage([301, 200]);
  const out = await Ops.appendPdf(PDFLib, a, await bDoc.save());
  assert.deepEqual(await widths(out), [100, 101, 300, 301]);
});

test('extractRange copies an inclusive range and leaves the source alone', async () => {
  const base = await makePdf(5);
  const out = await Ops.extractRange(PDFLib, base, 1, 3);
  assert.deepEqual(await widths(out), [101, 102, 103]);
  assert.deepEqual(await widths(base), [100, 101, 102, 103, 104]);
  await assert.rejects(() => Ops.extractRange(PDFLib, base, 3, 9), /invalid page range/);
});

test('parsePageRange accepts "3" and "2-5", rejects junk', () => {
  assert.deepEqual(Ops.parsePageRange('3', 5), { from: 2, to: 2 });
  assert.deepEqual(Ops.parsePageRange(' 2 - 5 ', 5), { from: 1, to: 4 });
  assert.equal(Ops.parsePageRange('5-2', 5), null);
  assert.equal(Ops.parsePageRange('0', 5), null);
  assert.equal(Ops.parsePageRange('2-9', 5), null);
  assert.equal(Ops.parsePageRange('abc', 5), null);
});
