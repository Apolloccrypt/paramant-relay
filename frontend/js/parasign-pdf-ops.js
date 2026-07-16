'use strict';
// ParaSign page operations: pure byte-in/byte-out transforms on top of pdf-lib.
// No DOM, no state - the editor (sign-flow.js) owns state and re-renders after
// every op. Also loadable in Node (tests) via module.exports; in the browser it
// hangs off window.ParasignPdfOps. PDFLib is passed in, never imported, so the
// browser build keeps using the vendored bundle.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ParasignPdfOps = factory();
})(typeof self !== 'undefined' ? self : this, function () {

  async function pageCount(PDFLib, bytes) {
    const doc = await PDFLib.PDFDocument.load(bytes);
    return doc.getPageCount();
  }

  // Rebuild the document with pages in the given order (array of 0-based source
  // indexes). Used for move-up/move-down; also validates the order server of truth.
  async function reorderPages(PDFLib, bytes, order) {
    const src = await PDFLib.PDFDocument.load(bytes);
    const n = src.getPageCount();
    if (!Array.isArray(order) || order.length !== n) throw new Error('order must list every page exactly once');
    const seen = new Set(order);
    if (seen.size !== n || order.some(i => !Number.isInteger(i) || i < 0 || i >= n)) {
      throw new Error('order must be a permutation of 0..' + (n - 1));
    }
    const out = await PDFLib.PDFDocument.create();
    const pages = await out.copyPages(src, order);
    for (const p of pages) out.addPage(p);
    return await out.save();
  }

  async function movePage(PDFLib, bytes, from, to) {
    const n = await pageCount(PDFLib, bytes);
    if (from === to || from < 0 || to < 0 || from >= n || to >= n) return bytes;
    const order = [];
    for (let i = 0; i < n; i++) if (i !== from) order.push(i);
    order.splice(to, 0, from);
    return await reorderPages(PDFLib, bytes, order);
  }

  async function deletePage(PDFLib, bytes, index) {
    const doc = await PDFLib.PDFDocument.load(bytes);
    if (doc.getPageCount() <= 1) throw new Error('cannot delete the last page');
    if (index < 0 || index >= doc.getPageCount()) throw new Error('page index out of range');
    doc.removePage(index);
    return await doc.save();
  }

  // Rotate one page by delta degrees (multiples of 90); stacks on any /Rotate
  // the page already carries.
  async function rotatePage(PDFLib, bytes, index, deltaDeg) {
    const doc = await PDFLib.PDFDocument.load(bytes);
    const page = doc.getPage(index);
    const cur = page.getRotation().angle || 0;
    page.setRotation(PDFLib.degrees(((cur + deltaDeg) % 360 + 360) % 360));
    return await doc.save();
  }

  // Append every page of another PDF (merge). Keeps the base document's
  // metadata; the merged pages are deep-copied.
  async function appendPdf(PDFLib, bytes, otherBytes) {
    const doc = await PDFLib.PDFDocument.load(bytes);
    const other = await PDFLib.PDFDocument.load(otherBytes);
    const pages = await doc.copyPages(other, other.getPageIndices());
    for (const p of pages) doc.addPage(p);
    return await doc.save();
  }

  // Extract an inclusive 0-based page range into a fresh document (split/export).
  // Leaves the source untouched.
  async function extractRange(PDFLib, bytes, from, to) {
    const src = await PDFLib.PDFDocument.load(bytes);
    const n = src.getPageCount();
    if (from < 0 || to < from || to >= n) throw new Error('invalid page range');
    const idx = [];
    for (let i = from; i <= to; i++) idx.push(i);
    const out = await PDFLib.PDFDocument.create();
    const pages = await out.copyPages(src, idx);
    for (const p of pages) out.addPage(p);
    return await out.save();
  }

  // Parse a human range like "3", "2-5" or "2 - 5" against a page total.
  // Returns { from, to } 0-based inclusive, or null when unparseable.
  function parsePageRange(input, total) {
    const m = String(input || '').trim().match(/^(\d+)\s*(?:-\s*(\d+))?$/);
    if (!m) return null;
    const a = parseInt(m[1], 10), b = m[2] ? parseInt(m[2], 10) : parseInt(m[1], 10);
    if (a < 1 || b < a || b > total) return null;
    return { from: a - 1, to: b - 1 };
  }

  return { pageCount, reorderPages, movePage, deletePage, rotatePage, appendPdf, extractRange, parsePageRange };
});
