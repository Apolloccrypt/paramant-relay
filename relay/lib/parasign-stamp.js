'use strict';
// ParaSign server-side stamp-worker.
//
// GET /v1/envelopes/:id/document used to serve the ORIGINAL, unstamped PDF
// (X-ParaSign-Stamped: false). This bakes a visible, human-readable signature
// block + verification info into the completed PDF so the downloaded file itself
// carries proof of who signed it and how to verify it. The cryptographic .psign
// (GET /receipt) remains the SOURCE OF TRUTH; the stamp is the presentation
// layer, exactly like DocuSign's certificate page.
//
// Rendering uses the pdf-lib already vendored for the browser sign-flow
// (frontend/vendor/pdf-lib). It is pure JS with no DOM dependency, so it loads
// and runs server-side unchanged. The require is LAZY + guarded: if the bundle
// is ever missing, stampPdf throws and the caller falls back to the original
// bytes (never blocks a download over a cosmetic layer).

let _PDFLib = null;
function loadPdfLib() {
  if (_PDFLib) return _PDFLib;
  // Candidate locations, most-likely first. relay/lib -> repo/frontend/vendor.
  const candidates = [
    '../../frontend/vendor/pdf-lib/pdf-lib.min.js',
    '../frontend/vendor/pdf-lib/pdf-lib.min.js',
    'pdf-lib',
  ];
  let lastErr = null;
  for (const c of candidates) {
    try { _PDFLib = require(c); return _PDFLib; }
    catch (e) { lastErr = e; }
  }
  throw new Error('pdf-lib not available: ' + (lastErr && lastErr.message));
}

// Truncate to n chars with an ellipsis so long ids/hashes never overflow.
function ellip(s, n) {
  s = String(s == null ? '' : s);
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

// Format an ISO timestamp as a compact, locale-neutral UTC string.
function fmtTs(iso) {
  if (!iso) return '-';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return String(iso);
  return new Date(t).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

// Bake the stamp. Returns a Buffer (stamped PDF) or throws (caller falls back).
//   opts: { envelopeId, docHash, parties:[{index,label,status,signed_at}],
//           completedAt, verifyUrl }
async function stampPdf(originalPdf, opts = {}) {
  const { PDFDocument, StandardFonts, rgb } = loadPdfLib();
  const doc = await PDFDocument.load(originalPdf);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);

  const pages = doc.getPages();
  if (!pages.length) throw new Error('pdf has no pages');

  const ink = rgb(0.09, 0.11, 0.15);
  const sub = rgb(0.33, 0.36, 0.42);
  const accent = rgb(0.10, 0.45, 0.90);
  const panel = rgb(0.97, 0.98, 1.0);
  const border = rgb(0.10, 0.45, 0.90);

  // ── Footer provenance strip on EVERY page ───────────────────────────────────
  // A small line at the bottom of each page so every sheet of a multi-page
  // document carries the envelope id + verify hint, not only the last one.
  const footer = `Signed with ParaSign  |  envelope ${ellip(opts.envelopeId, 24)}  |  verify: ${ellip(opts.verifyUrl || 'https://paramant.app/verify', 48)}`;
  for (let i = 0; i < pages.length; i++) {
    const p = pages[i];
    const { width } = p.getSize();
    const size = 7;
    p.drawRectangle({ x: 0, y: 0, width, height: 14, color: panel, opacity: 0.9 });
    p.drawText(ellip(footer, Math.max(20, Math.floor((width - 60) / (size * 0.5)))),
      { x: 12, y: 4, size, font, color: sub });
    p.drawText(`${i + 1}/${pages.length}`, { x: width - 34, y: 4, size, font, color: sub });
  }

  // ── Signature panel appended as a fresh certificate page ─────────────────────
  // A dedicated page keeps the block legible regardless of the source layout and
  // never obscures document content. Content pages already carry the footer.
  const A4 = [595.28, 841.89];
  const page = doc.addPage(A4);
  const { width: W, height: H } = page.getSize();
  const M = 48;
  let y = H - M;

  page.drawText('ParaSign signature certificate', { x: M, y: y - 6, size: 20, font: bold, color: ink });
  y -= 30;
  page.drawText('Post-quantum electronic signatures (ML-DSA-65, FIPS 204). This page summarises the',
    { x: M, y, size: 9, font, color: sub }); y -= 12;
  page.drawText('cryptographic record; the machine-verifiable .psign receipt is the source of truth.',
    { x: M, y, size: 9, font, color: sub }); y -= 24;

  // Metadata rows.
  const row = (label, value) => {
    page.drawText(label, { x: M, y, size: 9, font: bold, color: ink });
    page.drawText(ellip(value, 78), { x: M + 130, y, size: 9, font, color: ink });
    y -= 16;
  };
  row('Envelope ID', opts.envelopeId || '-');
  row('Document SHA3-256', opts.docHash || '-');
  row('Completed at', fmtTs(opts.completedAt));
  row('Signers', String((opts.parties || []).length));
  y -= 10;

  // Signer table header.
  page.drawRectangle({ x: M, y: y - 4, width: W - 2 * M, height: 20, color: panel, borderColor: border, borderWidth: 1 });
  page.drawText('#', { x: M + 8, y: y + 2, size: 9, font: bold, color: ink });
  page.drawText('Signer', { x: M + 34, y: y + 2, size: 9, font: bold, color: ink });
  page.drawText('Status', { x: M + 250, y: y + 2, size: 9, font: bold, color: ink });
  page.drawText('Signed at (UTC)', { x: M + 330, y: y + 2, size: 9, font: bold, color: ink });
  y -= 22;

  for (const p of (opts.parties || [])) {
    if (y < M + 40) { y = H - M; doc.addPage(A4); } // spill guard (rare)
    const label = p.label || `Party ${p.index}`;
    const status = (p.status === 'signed' || p.signed_at) ? 'signed' : (p.status || 'pending');
    page.drawText(String(p.index), { x: M + 8, y, size: 9, font, color: ink });
    page.drawText(ellip(label, 40), { x: M + 34, y, size: 9, font, color: ink });
    page.drawText(status, { x: M + 250, y, size: 9, font, color: status === 'signed' ? accent : sub });
    page.drawText(fmtTs(p.signed_at), { x: M + 330, y, size: 9, font, color: ink });
    y -= 16;
  }

  y -= 16;
  page.drawText('Verify this document', { x: M, y, size: 10, font: bold, color: ink }); y -= 14;
  page.drawText(ellip(opts.verifyUrl || 'https://paramant.app/verify', 90), { x: M, y, size: 9, font, color: accent }); y -= 12;
  page.drawText('Upload the .psign receipt to check every ML-DSA-65 signature and the relay counter-signature.',
    { x: M, y, size: 8, font, color: sub });

  const bytes = await doc.save();
  return Buffer.from(bytes);
}

module.exports = { stampPdf, loadPdfLib };
