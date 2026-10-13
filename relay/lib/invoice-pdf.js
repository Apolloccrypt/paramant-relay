'use strict';
// A PDF, written by hand, in about two hundred lines.
//
// WHY NOT A LIBRARY. The repo has two PDF dependencies and neither one fits.
// frontend/vendor/pdf-lib is a browser bundle the relay does not load, and
// pdf.js only reads. Adding pdfkit or puppeteer to package.json to lay out a
// one-page invoice would put a large new dependency (and, for a headless
// browser, a whole Chromium) on the payment path, where a broken install means
// a paying customer gets no document. A one-page invoice needs the two things
// PDF has had since 1993: a page and some text on it.
//
// WHAT THIS SUPPORTS, deliberately narrowly:
//   - one or more A4 pages, portrait
//   - the base-14 fonts Helvetica, Helvetica-Bold and Courier, which every
//     reader has built in, so nothing is embedded and nothing is licensed
//   - left, right and centre aligned text, and horizontal rules
//   - WinAnsi (latin-1) text. Anything above U+00FF is transliterated; an
//     invoice must never fail to render because of one character in an address.
//
// The content stream is NOT compressed. That is a choice: it costs a few
// kilobytes and it means the text of an invoice can be read straight out of the
// bytes, which is what the test that checks the legally required fields does,
// and what anyone debugging a customer's document a year from now will do.

const { REVERSE_CHARGE_NL, REVERSE_CHARGE_EN } = require('./invoice');

const PAGE = { width: 595.28, height: 841.89 };   // A4 in points
const MARGIN = 56;                                 // ~20mm
const FONTS = { regular: 'F1', bold: 'F2', mono: 'F3' };

// Widths for the base-14 fonts, in 1/1000 em. Only enough of them to place
// right-aligned and centred text without embedding a metrics table: Helvetica
// per character, Courier fixed at 600. An estimate that is a percent out moves
// a right-aligned amount by a hair; being wrong here is a cosmetic bug, never a
// wrong number.
const HELV_WIDTHS = {
  ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191,
  '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278,
  '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556,
  '8': 556, '9': 556, ':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556,
  '@': 1015, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778,
  'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778,
  'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944,
  'X': 667, 'Y': 667, 'Z': 611, '[': 278, '\\': 278, ']': 278, '^': 469, '_': 556,
  '`': 333, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556,
  'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556,
  'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722,
  'x': 500, 'y': 500, 'z': 500, '{': 334, '|': 260, '}': 334, '~': 584,
};

function charWidth(ch, font) {
  if (font === FONTS.mono) return 600;
  const w = HELV_WIDTHS[ch];
  if (w === undefined) return 556;
  return font === FONTS.bold ? Math.round(w * 1.06) : w;
}

function textWidth(text, font, size) {
  let total = 0;
  for (const ch of String(text)) total += charWidth(ch, font);
  return (total / 1000) * size;
}

// Latin-1 or nothing. A euro sign, a dash the author copied out of a word
// processor, a name with a character outside latin-1: each is replaced by
// something a reader can still understand rather than dropped or, worse, left
// to produce mojibake in the middle of a legal document.
const TRANSLITERATE = new Map(Object.entries({
  '\u20ac': 'EUR',                                  // euro sign
  '\u2013': '-', '\u2014': '-',                     // en dash, em dash
  '\u2018': "'", '\u2019': "'",                     // curly single quotes
  '\u201c': '"', '\u201d': '"',                     // curly double quotes
  '\u2026': '...', '\u00a0': ' ', '\u2022': '-',   // ellipsis, nbsp, bullet
}));

function toWinAnsi(text) {
  let out = '';
  for (const ch of String(text == null ? '' : text)) {
    if (TRANSLITERATE.has(ch)) { out += TRANSLITERATE.get(ch); continue; }
    const code = ch.codePointAt(0);
    out += code <= 0xff ? ch : '?';
  }
  return out;
}

function escapePdfText(text) {
  return toWinAnsi(text).replace(/[\\()]/g, (c) => `\\${c}`).replace(/[\r\n]/g, ' ');
}

// ── a tiny page builder ──────────────────────────────────────────────────────
// Ops are collected per page and serialised at the end. y counts DOWN from the
// top of the page, because that is how anyone thinks about a document; the
// conversion to PDF's bottom-left origin happens once, here.
class Doc {
  constructor() {
    this.pages = [[]];
    this.page = 0;
  }
  ops() { return this.pages[this.page]; }
  newPage() { this.pages.push([]); this.page = this.pages.length - 1; }
  text(str, x, yDown, { font = FONTS.regular, size = 10, align = 'left', grey = 0 } = {}) {
    const s = escapePdfText(str);
    let px = x;
    if (align === 'right') px = x - textWidth(toWinAnsi(str), font, size);
    else if (align === 'center') px = x - textWidth(toWinAnsi(str), font, size) / 2;
    this.ops().push(
      `BT /${font} ${size} Tf ${grey ? `${grey} g ` : ''}1 0 0 1 ${px.toFixed(2)} ${(PAGE.height - yDown).toFixed(2)} Tm (${s}) Tj ET` +
      (grey ? ' 0 g' : ''));
    return this;
  }
  rule(x1, yDown, x2, { width = 0.6, grey = 0.75 } = {}) {
    const y = (PAGE.height - yDown).toFixed(2);
    this.ops().push(`q ${grey} G ${width} w ${x1.toFixed(2)} ${y} m ${x2.toFixed(2)} ${y} l S Q`);
    return this;
  }
}

// ── serialisation ────────────────────────────────────────────────────────────
function serialise(doc, meta) {
  const objects = [];              // 1-based; objects[i] is object i+1
  const push = (body) => { objects.push(body); return objects.length; };

  const fontObjs = {
    F1: push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'),
    F2: push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'),
    F3: push('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>'),
  };
  const resources = `<< /Font << /F1 ${fontObjs.F1} 0 R /F2 ${fontObjs.F2} 0 R /F3 ${fontObjs.F3} 0 R >> >>`;

  const pagesObjNum = objects.length + 1;
  push('');                        // placeholder for /Pages, filled in below

  const pageNums = [];
  for (const ops of doc.pages) {
    const stream = ops.join('\n');
    const contentNum = push(`<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`);
    pageNums.push(push(
      `<< /Type /Page /Parent ${pagesObjNum} 0 R /MediaBox [0 0 ${PAGE.width} ${PAGE.height}] ` +
      `/Resources ${resources} /Contents ${contentNum} 0 R >>`));
  }
  objects[pagesObjNum - 1] =
    `<< /Type /Pages /Count ${pageNums.length} /Kids [${pageNums.map((n) => `${n} 0 R`).join(' ')}] >>`;

  const infoNum = push(
    `<< /Title (${escapePdfText(meta.title || 'Invoice')}) /Author (${escapePdfText(meta.author || '')}) ` +
    `/Producer (Paramant relay) /CreationDate (D:${meta.date || '19700101000000'}Z) >>`);
  const catalogNum = push(`<< /Type /Catalog /Pages ${pagesObjNum} 0 R >>`);

  let out = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
  const offsets = [];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(Buffer.byteLength(out, 'latin1'));
    out += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefAt = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogNum} 0 R /Info ${infoNum} 0 R >>\n` +
         `startxref\n${xrefAt}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

// ── the invoice layout ───────────────────────────────────────────────────────
// In the buyer's language (WORDS below), no colour, mono for every number so a column of amounts lines up and
// an invoice number cannot be misread. Everything art. 35a asks for is on the
// page whether or not it is filled in: an empty "VAT" line is a visible gap, a
// missing line is one nobody notices.
function stamp(date) {
  const d = date instanceof Date ? date : new Date(date || Date.now());
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
}

// The words of the document in the buyer's language (acceptatie 3.1.1,
// betalen punt 5: a Dutch buyer got an English "Invoice"). record.lang is set
// from the checkout; a record without it is from before the field and keeps
// the English it was issued in, so a re-render of an old document does not
// change it. Numbers, names and the reverse-charge mention (already in both
// languages) are the same in both.
const WORDS = Object.freeze({
  en: {
    invoice: 'Invoice', receipt: 'Payment receipt', creditNote: 'Credit note', refundReceipt: 'Refund receipt',
    vatNone: 'VAT number: not yet issued', vat: 'VAT',
    creditNoteDate: 'Credit note date', refundDate: 'Refund date', invoiceDate: 'Invoice date', receiptDate: 'Receipt date',
    creditNoteNumber: 'Credit note number', documentNumber: 'Document number', invoiceNumber: 'Invoice number',
    creditFor: 'Credit for invoice', paymentRef: 'Payment reference', serviceUntil: 'Service until',
    billedTo: 'Billed to', description: 'Description', amount: 'Amount',
    subtotal: 'Subtotal excl. VAT', total: 'Total', totalCredited: 'Total credited',
    customerVat: 'Customer VAT', supplierVat: 'Supplier VAT',
    reverseNote: 'VAT to be accounted for by the customer (Article 196, Directive 2006/112/EC).',
    chargedBack: 'This amount was charged back and is no longer due. Nothing is payable.',
    refunded: 'This amount has been refunded to you. Nothing is payable.',
    paid: 'Paid in full. No payment is due.',
    partial: 'Partial credit. The remainder of the invoice named above still stands.',
    receiptCredit1: 'This receipt confirms the refund. It is not a VAT credit note: our VAT identification',
    receiptCredit2: 'number is not yet on file. You will receive the credit note for this refund as soon as it is.',
    receipt1: 'This receipt confirms your payment. It is not a VAT invoice: our VAT identification',
    receipt2: 'number is not yet on file. You will receive the invoice for this payment as soon as it is.',
    reversed: (d) => `Reversed on ${d} (chargeback). This document no longer represents money received.`,
    creditedBy: (l) => `Credited by ${l}.`,
    note: (n) => n,
  },
  nl: {
    invoice: 'Factuur', receipt: 'Betalingsbewijs', creditNote: 'Creditnota', refundReceipt: 'Terugbetalingsbewijs',
    vatNone: 'Btw-nummer: nog niet toegekend', vat: 'Btw',
    creditNoteDate: 'Datum creditnota', refundDate: 'Datum terugbetaling', invoiceDate: 'Factuurdatum', receiptDate: 'Datum betaling',
    creditNoteNumber: 'Nummer creditnota', documentNumber: 'Documentnummer', invoiceNumber: 'Factuurnummer',
    creditFor: 'Creditering van factuur', paymentRef: 'Betalingskenmerk', serviceUntil: 'Dienst tot',
    billedTo: 'Gefactureerd aan', description: 'Omschrijving', amount: 'Bedrag',
    subtotal: 'Subtotaal excl. btw', total: 'Totaal', totalCredited: 'Totaal gecrediteerd',
    customerVat: 'Btw afnemer', supplierVat: 'Btw leverancier',
    reverseNote: 'Btw verlegd naar de afnemer (artikel 196, Richtlijn 2006/112/EG).',
    chargedBack: 'Dit bedrag is teruggeboekt en niet meer verschuldigd. U hoeft niets te betalen.',
    refunded: 'Dit bedrag is aan u terugbetaald. U hoeft niets te betalen.',
    paid: 'Volledig betaald. U hoeft niets meer te betalen.',
    partial: 'Gedeeltelijke creditering. De rest van de factuur hierboven blijft staan.',
    receiptCredit1: 'Dit bewijs bevestigt de terugbetaling. Het is geen creditnota voor de btw: ons btw-nummer',
    receiptCredit2: 'is nog niet bekend. U krijgt de creditnota voor deze terugbetaling zodra het er is.',
    receipt1: 'Dit bewijs bevestigt uw betaling. Het is geen factuur voor de btw: ons btw-nummer',
    receipt2: 'is nog niet bekend. U krijgt de factuur voor deze betaling zodra het er is.',
    reversed: (d) => `Teruggeboekt op ${d}. Dit document staat niet meer voor ontvangen geld.`,
    creditedBy: (l) => `Gecrediteerd met ${l}.`,
    note: (n) => ({ 'Invoice with VAT number follows.': 'Factuur met btw-nummer volgt.', 'Credit note with VAT number follows.': 'Creditnota met btw-nummer volgt.' }[n] || n),
  },
});
const TITLE_NL = Object.freeze({ 'Invoice': 'Factuur', 'Payment receipt': 'Betalingsbewijs', 'Credit note': 'Creditnota', 'Refund receipt': 'Terugbetalingsbewijs' });
const NUMBER_DUTCH = (v) => String(v == null ? '' : v).replace(/^(-?\d+)\.(\d{2})$/, '$1,$2');
const HINT_NL = 'Vul uw bedrijfsgegevens in op uw accountpagina, dan staan ze op de factuur';

function render(record, opts = {}) {
  const nl = record.lang === 'nl';
  const W = nl ? WORDS.nl : WORDS.en;
  const amt = nl ? NUMBER_DUTCH : (v) => v;
  const titleOf = (t) => (nl ? (TITLE_NL[t] || t) : t);
  const doc = new Doc();
  const right = PAGE.width - MARGIN;
  const seller = record.seller || {};
  const buyer = record.buyer || {};
  // Three shapes off one layout. A credit note is the same document with the
  // amounts negative, its own series, and a line naming the invoice it credits
  // (art. 35a applies to it in full, and without that reference a bookkeeper
  // cannot match the reversal to anything). `isInvoice` stays what it always
  // meant: this document may call itself a VAT invoice. A credit note against a
  // receipt is a refund receipt and says so, on the same footing.
  const isCredit = record.kind === 'credit_note';
  const isInvoice = isCredit ? record.credits_kind === 'invoice' : record.kind === 'invoice';
  let y = MARGIN + 6;

  // Header: who is sending this, and what it is.
  doc.text(seller.name || '', MARGIN, y, { font: FONTS.bold, size: 15 });
  doc.text(titleOf(record.title) || (isInvoice ? W.invoice : W.receipt), right, y, { font: FONTS.bold, size: 15, align: 'right' });
  y += 20;
  doc.text(record.number || '', right, y, { font: FONTS.mono, size: 11, align: 'right' });
  y += 16;

  // Supplier block (name, address, KvK, VAT id): art. 35a items c and d.
  for (const line of String(seller.address || '').split('\n')) {
    if (!line.trim()) continue;
    doc.text(line.trim(), MARGIN, y, { size: 9, grey: 0.35 });
    y += 12;
  }
  doc.text(`KvK ${seller.kvk || '-'}`, MARGIN, y, { size: 9, grey: 0.35 });
  y += 12;
  doc.text(seller.vat ? `${W.vat} ${seller.vat}` : W.vatNone, MARGIN, y, { size: 9, grey: 0.35 });
  y += 22;

  doc.rule(MARGIN, y, right);
  y += 20;

  // Dates and payment reference. Invoice date is art. 35a item a; the payment
  // id is not required but is the only handle anyone has when a customer calls
  // about a specific charge.
  const label = (k, v, yy) => {
    doc.text(k, MARGIN, yy, { size: 9, grey: 0.4 });
    doc.text(v, MARGIN + 110, yy, { font: FONTS.mono, size: 9.5 });
  };
  const dateLabel = isCredit ? (isInvoice ? W.creditNoteDate : W.refundDate) : (isInvoice ? W.invoiceDate : W.receiptDate);
  const numberLabel = isCredit ? (isInvoice ? W.creditNoteNumber : W.documentNumber) : (isInvoice ? W.invoiceNumber : W.documentNumber);
  label(dateLabel, record.invoice_date || '', y); y += 14;
  label(numberLabel, record.number || '', y); y += 14;
  // The reference that makes a credit note bookable at all: which invoice, and
  // of what date. Both, because a number alone sends the reader hunting.
  if (isCredit) {
    label(W.creditFor, record.credit_for || '', y); y += 14;
    if (record.credit_for_date) { label(W.invoiceDate, String(record.credit_for_date).slice(0, 10), y); y += 14; }
  }
  label(W.paymentRef, record.payment_id || '', y); y += 14;
  if (record.service_period_end) { label(W.serviceUntil, String(record.service_period_end).slice(0, 10), y); y += 14; }
  y += 10;

  // Customer block: art. 35a item e. When the account carries no company
  // details the email address stands in and the document says, in one line,
  // how to get the real ones on the next invoice.
  doc.text(W.billedTo, MARGIN, y, { font: FONTS.bold, size: 9.5 });
  y += 14;
  const buyerLines = [];
  if (buyer.company) buyerLines.push(buyer.company);
  for (const l of String(buyer.address || '').split('\n')) if (l.trim()) buyerLines.push(l.trim());
  if (buyer.vat) buyerLines.push(`${W.vat} ${buyer.vat}`);
  if (buyer.email) buyerLines.push(buyer.email);
  for (const l of buyerLines) { doc.text(l, MARGIN, y, { size: 10 }); y += 13; }
  if (!buyer.company || !buyer.address) {
    doc.text(opts.buyerHint ? (nl ? HINT_NL : opts.buyerHint) : '', MARGIN, y, { size: 8.5, grey: 0.45 });
    y += 13;
  }
  y += 14;

  // The line itself. One line per document: a payment buys exactly one plan for
  // exactly one term.
  doc.rule(MARGIN, y, right);
  y += 15;
  doc.text(W.description, MARGIN, y, { font: FONTS.bold, size: 9 });
  doc.text(W.vat, right - 150, y, { font: FONTS.bold, size: 9, align: 'right' });
  doc.text(W.amount, right, y, { font: FONTS.bold, size: 9, align: 'right' });
  y += 8;
  doc.rule(MARGIN, y, right);
  y += 16;
  const cur = record.currency || 'EUR';
  doc.text((nl && record.description_nl) || (!nl && record.description_en) || record.description || '', MARGIN, y, { size: 10 });
  doc.text(`${record.vat_rate}%`, right - 150, y, { font: FONTS.mono, size: 10, align: 'right' });
  doc.text(`${cur} ${amt(record.amount_net)}`, right, y, { font: FONTS.mono, size: 10, align: 'right' });
  // The English line names the plan as Mollie and the site do; what it
  // supplied, product by product, stands right under it (Wet OB art. 35a).
  if (!nl && record.description_en && record.supply_en) {
    y += 13;
    doc.text(`Supplied: ${record.supply_en}`, MARGIN, y, { size: 8.5, grey: 0.35 });
  }
  y += 20;
  doc.rule(MARGIN, y, right);
  y += 16;

  // Totals: art. 35a items g, h and i. Net, then VAT per rate, then the total
  // that was actually collected.
  const total = (k, v, bold) => {
    doc.text(k, right - 150, y, { size: bold ? 10 : 9.5, align: 'right', font: bold ? FONTS.bold : FONTS.regular, grey: bold ? 0 : 0.35 });
    doc.text(v, right, y, { font: FONTS.mono, size: bold ? 11 : 10, align: 'right' });
    y += bold ? 18 : 14;
  };
  const reverseCharged = record.vat_treatment === 'reverse_charge';
  total(W.subtotal, `${cur} ${amt(record.amount_net)}`, false);
  total(reverseCharged ? W.vat : `${W.vat} ${record.vat_rate}%`, `${cur} ${amt(record.amount_vat)}`, false);
  total(isCredit ? W.totalCredited : W.total, `${cur} ${amt(record.amount_gross)}`, true);
  y += 6;
  // Reverse charge: the mention the law asks for, in both languages, with both
  // VAT numbers next to it so nobody has to look for them (Directive
  // 2006/112/EC art. 226; Wet OB art. 35a). The customer accounts for the VAT.
  if (reverseCharged) {
    doc.text(`${REVERSE_CHARGE_NL} / ${REVERSE_CHARGE_EN}`, right, y, { font: FONTS.bold, size: 10, align: 'right' });
    y += 14;
    doc.text(`${W.customerVat} ${buyer.vat || '-'} - ${W.supplierVat} ${seller.vat || '-'}`, right, y, { size: 9, align: 'right', grey: 0.35 });
    y += 12;
    doc.text(W.reverseNote, right, y, { size: 9, align: 'right', grey: 0.35 });
    y += 18;
  }
  // What the reader owes, in one line, and it is never "nothing to do here".
  // On a credit note the money has already moved back, by the same route it
  // came in, and saying so is what stops a support mail.
  doc.text(isCredit
    ? (record.reason === 'chargeback' ? W.chargedBack : W.refunded)
    : W.paid,
  right, y, { size: 9, align: 'right', grey: 0.4 });
  y += 26;

  // A partial credit note has to say what is left standing, or it reads as a
  // full reversal of an invoice that is still partly owed and partly booked.
  if (isCredit && record.partial) {
    doc.text(W.partial,
      MARGIN, y, { size: 9, grey: 0.35 });
    y += 18;
  }

  // What the document is not, when it is not an invoice yet.
  if (!isInvoice) {
    doc.rule(MARGIN, y, right);
    y += 16;
    doc.text(W.note(record.note || ''), MARGIN, y, { font: FONTS.bold, size: 10 });
    y += 14;
    if (isCredit) {
      doc.text(W.receiptCredit1, MARGIN, y, { size: 9, grey: 0.35 }); y += 12;
      doc.text(W.receiptCredit2, MARGIN, y, { size: 9, grey: 0.35 }); y += 12;
    } else {
      doc.text(W.receipt1, MARGIN, y, { size: 9, grey: 0.35 }); y += 12;
      doc.text(W.receipt2, MARGIN, y, { size: 9, grey: 0.35 }); y += 12;
    }
    y += 10;
  }

  // Only on an invoice: a credit note is the document that reverses, and can
  // never itself be reversed.
  if (!isCredit && record.reversed_at) {
    doc.text(W.reversed(String(record.reversed_at).slice(0, 10)),
      MARGIN, y, { font: FONTS.bold, size: 9 });
    y += 18;
    if (record.credit_notes && record.credit_notes.length) {
      doc.text(W.creditedBy(record.credit_notes.join(', ')), MARGIN, y, { size: 9, grey: 0.35 });
      y += 14;
    }
  }

  // Footer, on the last line of the page rather than after the content, so it
  // sits in the same place on every document.
  const footY = PAGE.height - MARGIN + 4;
  doc.rule(MARGIN, footY - 16, right);
  doc.text(`${seller.name || ''} - KvK ${seller.kvk || '-'}${seller.vat ? ` - ${W.vat} ${seller.vat}` : ''}`,
    MARGIN, footY, { size: 8, grey: 0.45 });
  doc.text(record.number || '', right, footY, { font: FONTS.mono, size: 8, align: 'right', grey: 0.45 });

  return serialise(doc, {
    title: `${titleOf(record.title) || W.invoice} ${record.number || ''}`.trim(),
    author: seller.name || '',
    date: stamp(record.issued_at),
  });
}

module.exports = { render, PAGE, MARGIN, FONTS, toWinAnsi, textWidth, Doc, serialise };
