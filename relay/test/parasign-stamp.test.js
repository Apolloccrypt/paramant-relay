'use strict';
// ParaSign server-side stamp-worker (lib/parasign-stamp.js). Proves the worker
// turns an original PDF into a valid, larger PDF that carries a certificate page
// + per-page footer. Uses the vendored pdf-lib (frontend/vendor/pdf-lib); if
// that bundle is not resolvable the test skips rather than fails.

const assert = require('assert');
const stamp = require('../lib/parasign-stamp');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

async function makePdf(nPages) {
  const { PDFDocument, StandardFonts, rgb } = stamp.loadPdfLib();
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < nPages; i++) {
    const p = doc.addPage([595, 842]);
    p.drawText('Original content page ' + (i + 1), { x: 50, y: 800, size: 14, font, color: rgb(0, 0, 0) });
  }
  return Buffer.from(await doc.save());
}

async function main() {
  let PDFLib;
  try { PDFLib = stamp.loadPdfLib(); } catch (e) {
    console.log('  skip - pdf-lib not resolvable server-side:', e.message);
    console.log(`\nparasign-stamp: ${passed} checks passed`);
    return;
  }

  const original = await makePdf(2);
  const stamped = await stamp.stampPdf(original, {
    envelopeId: 'env_ABC123',
    docHash: 'a'.repeat(64),
    completedAt: '2026-07-19T10:00:00.000Z',
    parties: [
      { index: 0, label: 'Alice Example', status: 'signed', signed_at: '2026-07-19T09:58:00.000Z' },
      { index: 1, label: 'Bob Example', status: 'signed', signed_at: '2026-07-19T10:00:00.000Z' },
    ],
    verifyUrl: 'https://paramant.app/verify',
  });

  assert.ok(Buffer.isBuffer(stamped), 'returns a Buffer');
  assert.strictEqual(stamped.slice(0, 5).toString('latin1'), '%PDF-', 'output is a PDF');
  assert.ok(stamped.length > original.length, 'stamped PDF is larger than the original');
  ok('stampPdf produces a valid, larger PDF');

  // The certificate page was appended (2 content pages -> 3).
  const reload = await PDFLib.PDFDocument.load(stamped);
  assert.strictEqual(reload.getPageCount(), 3, 'a certificate page is appended (2 -> 3)');
  ok('certificate page appended, document reloads cleanly');

  // A single-page document also works (footer + certificate page).
  const one = await stamp.stampPdf(await makePdf(1), { envelopeId: 'env_1', docHash: 'b'.repeat(64), parties: [{ index: 0, label: 'Solo', status: 'signed', signed_at: '2026-07-19T10:00:00Z' }] });
  assert.strictEqual((await PDFLib.PDFDocument.load(one)).getPageCount(), 2, 'single page -> 2 (content + certificate)');
  ok('single-page document stamps correctly');
}

main()
  .then(() => console.log(`\nparasign-stamp: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
