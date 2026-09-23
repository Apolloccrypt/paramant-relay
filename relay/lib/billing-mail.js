'use strict';
// The text of the two money mails: the invoice (or payment receipt) and the
// credit note (or refund receipt). relay.js renders the PDF and sends; this
// file only says what the mail says, so the words can be tested without a
// relay, a redis or a PDF.
//
// Bilingual on the pattern of lib/plan-expiry.js: the Dutch text first, the
// English text below it unchanged, subject "Dutch / English". Amounts, numbers
// and the seller name are the same in both halves; the description is the line
// on the attached document and is quoted as it stands there.

const planExpiry = require('./plan-expiry');
const invoiceMod = require('./invoice');

const TITLE_NL = Object.freeze({
  'Invoice': 'Factuur',
  'Payment receipt': 'Betalingsbewijs',
  'Credit note': 'Creditnota',
  'Refund receipt': 'Terugbetalingsbewijs',
});

// The fixed sentences a record can carry, in Dutch. Anything not in here is
// quoted as it stands rather than guessed at.
const NOTE_NL = Object.freeze({
  'Invoice with VAT number follows.': 'Factuur met btw-nummer volgt.',
  'Credit note with VAT number follows.': 'Creditnota met btw-nummer volgt.',
});

const BUYER_HINT_NL = 'Vul uw bedrijfsgegevens in op uw accountpagina, dan staan ze op de factuur';

const titleNl = (t) => TITLE_NL[t] || t;
const noteNl = (n) => (n ? (NOTE_NL[n] || n) : '');
const dateNl = (d) => planExpiry.formatDateNl(d) || String(d || '');

// Drop a blank line that follows another blank line, as the mail always did.
const squeeze = (lines) => lines.filter((l, i, a) => !(l === '' && a[i - 1] === ''));

function invoiceMail(record) {
  const isInvoice = record.kind === 'invoice';
  const enTitle = isInvoice ? 'Invoice' : 'Payment receipt';
  const nlTitle = titleNl(enTitle);
  const subjectEn = `${enTitle} ${record.number} - ${record.seller.name}`;
  const subjectNl = `${nlTitle} ${record.number} - ${record.seller.name}`;
  const complete = invoiceMod.buyerIsComplete(record.buyer);
  const nl = squeeze([
    `Dank u voor uw betaling.`,
    ``,
    `${titleNl(record.title)} ${record.number}`,
    `Datum: ${dateNl(record.invoice_date)}`,
    `${record.description}`,
    `Totaal: ${record.currency} ${record.amount_gross} (incl. ${record.vat_rate}% btw, ${record.currency} ${record.amount_vat})`,
    ``,
    isInvoice ? '' : noteNl(invoiceMod.RECEIPT_NOTE),
    complete ? '' : `${BUYER_HINT_NL}.`,
    ``,
    `Het document zit in de bijlage. Al uw documenten blijven beschikbaar op uw accountpagina.`,
    ``,
    record.seller.name,
  ]);
  const en = squeeze([
    `Thank you for your payment.`,
    ``,
    `${record.title} ${record.number}`,
    `Date: ${record.invoice_date}`,
    `${record.description}`,
    `Total: ${record.currency} ${record.amount_gross} (incl. ${record.vat_rate}% VAT, ${record.currency} ${record.amount_vat})`,
    ``,
    isInvoice ? '' : `${invoiceMod.RECEIPT_NOTE}`,
    complete ? '' : `${invoiceMod.BUYER_HINT}.`,
    ``,
    `The document is attached, and every document stays available on your account page.`,
    ``,
    record.seller.name,
  ]);
  return {
    subject: planExpiry.bilingualSubject(subjectNl, subjectEn),
    text: planExpiry.bilingualText(nl.join('\n'), en.join('\n')),
  };
}

function creditNoteMail(record) {
  const chargedBack = record.reason === 'chargeback';
  const subjectEn = `${record.title} ${record.number} - ${record.seller.name}`;
  const subjectNl = `${titleNl(record.title)} ${record.number} - ${record.seller.name}`;
  const nl = squeeze([
    chargedBack
      ? `Uw betaling is teruggeboekt. Daarom is de factuur hieronder gecrediteerd.`
      : `Uw betaling is aan u terugbetaald. Daarom is de factuur hieronder gecrediteerd.`,
    ``,
    `${titleNl(record.title)} ${record.number}`,
    `Datum: ${dateNl(record.invoice_date)}`,
    `Creditering van factuur ${record.credit_for} van ${dateNl(record.credit_for_date)}`,
    `${record.description}`,
    `Totaal gecrediteerd: ${record.currency} ${record.amount_gross} (incl. ${record.vat_rate}% btw, ${record.currency} ${record.amount_vat})`,
    ``,
    record.partial ? 'Dit is een gedeeltelijke creditering. De rest van die factuur blijft staan.' : '',
    noteNl(record.note),
    ``,
    `Het document zit in de bijlage. Al uw documenten blijven beschikbaar op uw accountpagina.`,
    ``,
    record.seller.name,
  ]);
  const en = squeeze([
    chargedBack
      ? `Your payment was charged back, so the invoice below has been credited.`
      : `Your payment has been refunded, so the invoice below has been credited.`,
    ``,
    `${record.title} ${record.number}`,
    `Date: ${record.invoice_date}`,
    `Credit for invoice ${record.credit_for} of ${record.credit_for_date}`,
    `${record.description}`,
    `Total credited: ${record.currency} ${record.amount_gross} (incl. ${record.vat_rate}% VAT, ${record.currency} ${record.amount_vat})`,
    ``,
    record.partial ? 'This is a partial credit. The remainder of that invoice still stands.' : '',
    record.note || '',
    ``,
    `The document is attached, and every document stays available on your account page.`,
    ``,
    record.seller.name,
  ]);
  return {
    subject: planExpiry.bilingualSubject(subjectNl, subjectEn),
    text: planExpiry.bilingualText(nl.join('\n'), en.join('\n')),
  };
}

module.exports = { TITLE_NL, NOTE_NL, BUYER_HINT_NL, invoiceMail, creditNoteMail };
