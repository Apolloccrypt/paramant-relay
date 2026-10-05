'use strict';
// PAdES signature embedding through a real PDF incremental update.
//
// pdf-lib cannot do this: PDFDocument.save() rewrites the whole file, which
// would break any signature already in the document and makes "the original
// bytes are untouched" impossible to assert. So pdf-lib is used only as the
// object model (it parses the catalogue, the page tree and the AcroForm for
// us), and the bytes are written here: the original file, verbatim, followed
// by an update section holding the signature dictionary, the signature field,
// the objects that had to change, and a fresh cross-reference section.
//
// Two calls, because a QTSP sits between them:
//   prepare(pdf, opts) -> { pdf, byteRange, digest, contents: {start,end} }
//   embed(prepared, cmsDer)  -> the signed PDF
// Everything between the two is hash-only: the document never leaves.

const crypto = require('node:crypto');
const zlib = require('node:zlib');

let _PDFLib = null;
function loadPdfLib() {
  if (_PDFLib) return _PDFLib;
  // Same candidate order as relay/lib/parasign-stamp.js: the vendored browser
  // bundle first (it is bind-mounted into the container), the npm package last.
  const candidates = [
    '../../../frontend/vendor/pdf-lib/pdf-lib.min.js',
    '../../frontend/vendor/pdf-lib/pdf-lib.min.js',
    'pdf-lib',
  ];
  const tried = [];
  for (const c of candidates) {
    try { _PDFLib = require(c); return _PDFLib; } catch (e) { tried.push(c + ': ' + e.code); }
  }
  throw new Error('pdf-lib not available: ' + tried.join('; '));
}

const BYTE_RANGE_FIELD = 10; // decimal digits reserved per ByteRange entry
const DEFAULT_CONTENTS_BYTES = 16384;

function pdfLiteral(value) {
  return '(' + String(value == null ? '' : value).replace(/[\\()]/g, (c) => '\\' + c) + ')';
}

function pdfDate(date) {
  const d = new Date(date);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return "D:" + d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
    p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + "+00'00'";
}

// The offset of the last cross-reference section, and whether it is a classic
// table or a cross-reference stream. An update has to match the original: a
// classic table gets a classic table, a stream gets a stream.
function readLastXref(bytes) {
  const tailStart = Math.max(0, bytes.length - 4096);
  const tail = bytes.subarray(tailStart).toString('latin1');
  const idx = tail.lastIndexOf('startxref');
  if (idx < 0) throw new Error('PDF: no startxref');
  const m = /startxref\s+(\d+)/.exec(tail.slice(idx));
  if (!m) throw new Error('PDF: malformed startxref');
  const offset = parseInt(m[1], 10);
  if (!(offset >= 0 && offset < bytes.length)) throw new Error('PDF: startxref out of range');
  const classic = bytes.subarray(offset, offset + 4).toString('latin1') === 'xref';
  return { offset, classic };
}

// The highest object number the file already uses. pdf-lib's
// largestObjectNumber only counts objects it materialised, so it misses the
// object streams and cross-reference streams that hold everything else in a
// PDF 1.5+ file. Handing out a number that is already taken silently clobbers
// the object stream the page tree lives in, so all three sources are combined:
// what pdf-lib saw, the /Size in the last trailer, and every "N 0 obj" header.
function highestObjectNumber(bytes, xref, fromPdfLib) {
  let max = fromPdfLib || 0;

  const searchFrom = xref.classic ? bytes.indexOf(Buffer.from('trailer', 'latin1'), xref.offset) : xref.offset;
  if (searchFrom >= 0) {
    const window = bytes.subarray(searchFrom, Math.min(bytes.length, searchFrom + 8192)).toString('latin1');
    const m = /\/Size\s+(\d+)/.exec(window);
    if (m) max = Math.max(max, parseInt(m[1], 10) - 1);
  }

  const text = bytes.toString('latin1');
  const re = /(?:^|[\r\n\s])(\d{1,9})\s+\d{1,5}\s+obj\b/g;
  let hit;
  while ((hit = re.exec(text)) !== null) max = Math.max(max, parseInt(hit[1], 10));
  return max;
}

// Group object numbers into the contiguous runs a cross-reference section wants.
function subsections(numbers) {
  const sorted = [...new Set(numbers)].sort((x, y) => x - y);
  const out = [];
  for (const n of sorted) {
    const last = out[out.length - 1];
    if (last && n === last.start + last.count) last.count++;
    else out.push({ start: n, count: 1 });
  }
  return out;
}

function classicXref(entries, trailer) {
  let s = 'xref\n';
  for (const sub of subsections(entries.map((e) => e.num))) {
    s += sub.start + ' ' + sub.count + '\n';
    for (let n = sub.start; n < sub.start + sub.count; n++) {
      const e = entries.find((x) => x.num === n);
      s += String(e.offset).padStart(10, '0') + ' ' + String(e.gen || 0).padStart(5, '0') + ' n \n';
    }
  }
  s += 'trailer\n' + trailer + '\n';
  return Buffer.from(s, 'latin1');
}

function xrefStream(entries, dictEntries, selfNum, selfOffset) {
  const all = [...entries, { num: selfNum, offset: selfOffset, gen: 0 }]
    .sort((x, y) => x.num - y.num);
  const rows = [];
  for (const e of all) {
    const row = Buffer.alloc(7);
    row[0] = 1;
    row.writeUInt32BE(e.offset, 1);
    row.writeUInt16BE(e.gen || 0, 5);
    rows.push(row);
  }
  const data = zlib.deflateSync(Buffer.concat(rows));
  const index = subsections(all.map((e) => e.num)).map((s) => s.start + ' ' + s.count).join(' ');
  const dict = '<< /Type /XRef /W [1 4 2] /Index [' + index + '] ' + dictEntries +
    ' /Filter /FlateDecode /Length ' + data.length + ' >>';
  return Buffer.concat([
    Buffer.from(selfNum + ' 0 obj\n' + dict + '\nstream\n', 'latin1'),
    data,
    Buffer.from('\nendstream\nendobj\n', 'latin1'),
  ]);
}

// ── step 1: reserve the signature ───────────────────────────────────────────

// Appends an incremental update carrying a /Sig dictionary with a zero-filled
// /Contents placeholder, wires an invisible signature field into the AcroForm
// and onto the first page, and fills in the real /ByteRange. The returned
// digest is SHA-256 over exactly the bytes that ByteRange covers.
async function prepare(pdfBytes, opts = {}) {
  const PDFLib = loadPdfLib();
  const { PDFName, PDFRef, PDFArray, PDFNumber } = PDFLib;
  const original = Buffer.isBuffer(pdfBytes) ? pdfBytes : Buffer.from(pdfBytes);
  if (original.subarray(0, 5).toString('latin1') !== '%PDF-') throw new Error('not a PDF');

  const contentsBytes = Math.max(2048, Number(opts.contentsBytes) || DEFAULT_CONTENTS_BYTES);
  const signingTime = opts.signingTime ? new Date(opts.signingTime) : new Date();

  const doc = await PDFLib.PDFDocument.load(original, { ignoreEncryption: false });
  const ctx = doc.context;
  if (ctx.trailerInfo && ctx.trailerInfo.Encrypt) throw new Error('encrypted PDFs are not supported');

  const { offset: prevOffset, classic } = readLastXref(original);

  let next = highestObjectNumber(original, { offset: prevOffset, classic }, ctx.largestObjectNumber);
  const sigRef = PDFRef.of(++next);
  const fieldRef = PDFRef.of(++next);

  // Objects whose serialisation changes and therefore has to be re-emitted.
  const changed = new Map(); // objectNumber -> PDFObject
  const catalogRef = ctx.trailerInfo.Root;
  const catalog = doc.catalog;
  const page = doc.getPage(0);

  // AcroForm: reuse the document's own if it has one, otherwise add one.
  const acroRaw = catalog.get(PDFName.of('AcroForm'));
  if (acroRaw instanceof PDFRef) {
    const acro = ctx.lookup(acroRaw);
    const fieldsRaw = acro.get(PDFName.of('Fields'));
    if (fieldsRaw instanceof PDFRef) {
      ctx.lookup(fieldsRaw).push(fieldRef);
      changed.set(fieldsRaw.objectNumber, ctx.lookup(fieldsRaw));
    } else if (fieldsRaw instanceof PDFArray) {
      fieldsRaw.push(fieldRef);
    } else {
      acro.set(PDFName.of('Fields'), ctx.obj([fieldRef]));
    }
    acro.set(PDFName.of('SigFlags'), PDFNumber.of(3));
    changed.set(acroRaw.objectNumber, acro);
  } else if (acroRaw) {
    const fieldsRaw = acroRaw.get(PDFName.of('Fields'));
    if (fieldsRaw instanceof PDFArray) fieldsRaw.push(fieldRef);
    else acroRaw.set(PDFName.of('Fields'), ctx.obj([fieldRef]));
    acroRaw.set(PDFName.of('SigFlags'), PDFNumber.of(3));
    changed.set(catalogRef.objectNumber, catalog);
  } else {
    const acroRef = PDFRef.of(++next);
    const acro = ctx.obj({ Fields: [fieldRef], SigFlags: 3 });
    changed.set(acroRef.objectNumber, acro);
    catalog.set(PDFName.of('AcroForm'), acroRef);
    changed.set(catalogRef.objectNumber, catalog);
  }

  // The widget has to hang off a page, or the field is not reachable.
  const annotsRaw = page.node.get(PDFName.of('Annots'));
  if (annotsRaw instanceof PDFRef) {
    ctx.lookup(annotsRaw).push(fieldRef);
    changed.set(annotsRaw.objectNumber, ctx.lookup(annotsRaw));
  } else if (annotsRaw instanceof PDFArray) {
    annotsRaw.push(fieldRef);
    changed.set(page.ref.objectNumber, page.node);
  } else {
    page.node.set(PDFName.of('Annots'), ctx.obj([fieldRef]));
    changed.set(page.ref.objectNumber, page.node);
  }

  // The signature dictionary is written by hand: the placeholders have to sit
  // at byte positions we control, which no object model will promise.
  const zeroRange = Array(4).fill('0'.repeat(BYTE_RANGE_FIELD)).join(' ');
  let sigDict = '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached\n' +
    '/ByteRange [' + zeroRange + ']\n' +
    '/Contents <' + '0'.repeat(contentsBytes * 2) + '>\n' +
    '/M ' + pdfLiteral(pdfDate(signingTime)) + '\n';
  if (opts.signerName) sigDict += '/Name ' + pdfLiteral(opts.signerName) + '\n';
  if (opts.reason) sigDict += '/Reason ' + pdfLiteral(opts.reason) + '\n';
  if (opts.location) sigDict += '/Location ' + pdfLiteral(opts.location) + '\n';
  if (opts.contactInfo) sigDict += '/ContactInfo ' + pdfLiteral(opts.contactInfo) + '\n';
  sigDict += '>>';

  const fieldDict = '<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] /F 132\n' +
    '/T ' + pdfLiteral(opts.fieldName || 'ParaSign QES') + '\n' +
    '/V ' + sigRef.objectNumber + ' 0 R /P ' + page.ref.objectNumber + ' 0 R >>';

  // ── assemble the update section ───────────────────────────────────────────
  const chunks = [original];
  let cursor = original.length;
  if (original[original.length - 1] !== 0x0a) { chunks.push(Buffer.from('\n')); cursor += 1; }

  const entries = [];
  const pushObject = (num, body) => {
    const buf = Buffer.from(num + ' 0 obj\n' + body + '\nendobj\n', 'latin1');
    entries.push({ num, offset: cursor, gen: 0 });
    chunks.push(buf);
    cursor += buf.length;
    return buf;
  };

  const sigOffsetInFile = cursor;
  pushObject(sigRef.objectNumber, sigDict);
  pushObject(fieldRef.objectNumber, fieldDict);
  for (const [num, obj] of changed) pushObject(num, obj.toString());

  const trailerCommon =
    '/Size ' + (next + 1) +
    ' /Root ' + catalogRef.objectNumber + ' 0 R' +
    (ctx.trailerInfo.Info ? ' /Info ' + ctx.trailerInfo.Info.objectNumber + ' 0 R' : '') +
    ' /Prev ' + prevOffset +
    ' /ID [' + docId(ctx, PDFLib) + ']';

  const xrefOffset = cursor;
  if (classic) {
    const xref = classicXref(entries, '<< ' + trailerCommon + ' >>');
    chunks.push(xref);
    cursor += xref.length;
  } else {
    const selfNum = ++next;
    const xref = xrefStream(entries, '/Size ' + (next + 1) +
      ' /Root ' + catalogRef.objectNumber + ' 0 R' +
      (ctx.trailerInfo.Info ? ' /Info ' + ctx.trailerInfo.Info.objectNumber + ' 0 R' : '') +
      ' /Prev ' + prevOffset +
      ' /ID [' + docId(ctx, PDFLib) + ']', selfNum, xrefOffset);
    chunks.push(xref);
    cursor += xref.length;
  }
  const tail = Buffer.from('startxref\n' + xrefOffset + '\n%%EOF\n', 'latin1');
  chunks.push(tail);

  const out = Buffer.concat(chunks);

  // Locate the placeholder and fill in the real ByteRange. Both edits keep the
  // file length identical, so the offsets stay valid.
  const contentsMarker = Buffer.from('/Contents <', 'latin1');
  const markerAt = out.indexOf(contentsMarker, sigOffsetInFile);
  if (markerAt < 0) throw new Error('signature placeholder lost');
  const start = markerAt + contentsMarker.length - 1;      // the '<'
  const end = start + 1 + contentsBytes * 2;               // the '>'
  const byteRange = [0, start, end + 1, out.length - (end + 1)];

  const rangeMarker = Buffer.from('/ByteRange [', 'latin1');
  const rangeAt = out.indexOf(rangeMarker, sigOffsetInFile);
  if (rangeAt < 0) throw new Error('ByteRange placeholder lost');
  const rangeText = byteRange.map((n) => String(n).padEnd(BYTE_RANGE_FIELD, ' ')).join(' ');
  if (rangeText.length !== BYTE_RANGE_FIELD * 4 + 3) throw new Error('ByteRange does not fit');
  out.write(rangeText, rangeAt + rangeMarker.length, 'latin1');

  return {
    pdf: out,
    byteRange,
    contents: { start, end },
    contentsBytes,
    digest: digestByteRange(out, byteRange),
    signingTime: signingTime.toISOString(),
  };
}

function docId(ctx, PDFLib) {
  const fresh = crypto.randomBytes(16).toString('hex');
  const existing = ctx.trailerInfo && ctx.trailerInfo.ID;
  let first = fresh;
  if (existing && existing.get && existing.get(0) && existing.get(0) instanceof PDFLib.PDFHexString) {
    first = existing.get(0).toString().replace(/^<|>$/g, '');
  }
  return '<' + first + '> <' + fresh + '>';
}

// SHA-256 over the two ByteRange spans, in order. This is the only thing the
// QTSP ever gets to see of the document.
function digestByteRange(pdfBytes, byteRange) {
  const [a, b, c, d] = byteRange;
  const h = crypto.createHash('sha256');
  h.update(pdfBytes.subarray(a, a + b));
  h.update(pdfBytes.subarray(c, c + d));
  return h.digest();
}

// Read the ByteRange out of a signed PDF, for verification.
function readByteRange(pdfBytes) {
  const text = pdfBytes.toString('latin1');
  const m = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(text);
  if (!m) return null;
  return [1, 2, 3, 4].map((i) => parseInt(m[i], 10));
}

// Read the hex /Contents blob, stripping the zero padding, and return the DER.
function readContents(pdfBytes, byteRange) {
  const start = byteRange[1];
  const end = byteRange[2] - 1;
  if (pdfBytes[start] !== 0x3c || pdfBytes[end] !== 0x3e) return null; // '<' and '>'
  const hex = pdfBytes.subarray(start + 1, end).toString('latin1').replace(/[^0-9a-fA-F]/g, '');
  const der = Buffer.from(hex, 'hex');
  // Trim the reserved tail: read the outer DER length and cut there.
  if (der.length < 2 || der[0] !== 0x30) return der;
  let pos = 1;
  let len = der[pos++];
  if (len & 0x80) {
    const count = len & 0x7f;
    len = 0;
    for (let i = 0; i < count; i++) len = (len << 8) | der[pos++];
  }
  return der.subarray(0, Math.min(der.length, pos + len));
}

// ── step 2: put the signature in ────────────────────────────────────────────

// Writes the DER into the reserved /Contents span. Everything outside that span
// stays byte-identical, so the digest computed in prepare() still holds.
function embed(prepared, cmsDer) {
  const { pdf, contents, contentsBytes } = prepared;
  if (cmsDer.length > contentsBytes) {
    throw new Error('signature is ' + cmsDer.length + ' bytes, only ' + contentsBytes + ' reserved');
  }
  const out = Buffer.from(pdf); // copy: prepare()'s buffer stays reusable
  const hex = Buffer.concat([cmsDer, Buffer.alloc(contentsBytes - cmsDer.length)]).toString('hex');
  out.write(hex, contents.start + 1, 'latin1');
  return out;
}

module.exports = {
  prepare, embed, digestByteRange, readByteRange, readContents,
  loadPdfLib, readLastXref, DEFAULT_CONTENTS_BYTES,
};
