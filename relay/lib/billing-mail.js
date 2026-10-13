'use strict';
// The text of the two money mails: the invoice (or payment receipt) and the
// credit note (or refund receipt). relay.js renders the PDF and sends; this
// file only says what the mail says, so the words can be tested without a
// relay, a redis or a PDF.
//
// Bilingual on the pattern of lib/plan-expiry.js: the Dutch text first, the
// English text below it unchanged, subject "Dutch / English". A buyer who
// bought in English gets the English text only. Amounts, numbers
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

// Money the way each language writes it: "EUR 35,09" in the Dutch half,
// "EUR 35.09" in the English half (acceptatie 3.1.1, taal #50).
const moneyNl = (v) => String(v == null ? '' : v).replace(/^(-?\d+)\.(\d{2})$/, '$1,$2');
const dateEn = (d) => planExpiry.formatDate(d) || String(d || '');
// The Dutch line of the document, when the record carries one; older records
// have only the English line, which is then quoted as it stands.
const descNl = (record) => record.description_nl || record.description;

// A buyer who bought in English gets the mail in English only: subject and
// text. He got "Factuur ..." and a Dutch block first (acceptatie 3.1.1,
// betalen punt 5), then the English first with the whole Dutch block still
// under it (ronde 2). A Dutch buyer, or a record from before the language
// field existed, keeps Dutch first with the English below the line.
function arrange(record, subjectNl, subjectEn, nl, en) {
  if (record.lang === 'en') return { subject: subjectEn, text: en.join('\n') };
  return { subject: planExpiry.bilingualSubject(subjectNl, subjectEn), text: planExpiry.bilingualText(nl.join('\n'), en.join('\n')) };
}

// The English line of the document: the plan named as Mollie and the site name
// it, for a record that carries it; older records keep their one line.
const descEn = (record) => (record.lang === 'en' && record.description_en) || record.description;

const titleNl = (t) => TITLE_NL[t] || t;
const noteNl = (n) => (n ? (NOTE_NL[n] || n) : '');
const dateNl = (d) => planExpiry.formatDateNl(d) || String(d || '');

// Drop a blank line that follows another blank line, as the mail always did.
const squeeze = (lines) => lines.filter((l, i, a) => !(l === '' && a[i - 1] === ''));

// What the total line says about VAT. A reverse-charged document has none to
// state, only the mention and the buyer number it was reverse charged to.
function vatNl(record) {
  if (record.vat_treatment === 'reverse_charge') {
    return `${invoiceMod.REVERSE_CHARGE_NL.toLowerCase()}, btw-nummer afnemer ${record.buyer.vat}`;
  }
  return `incl. ${record.vat_rate}% btw, ${record.currency} ${moneyNl(record.amount_vat)}`;
}
function vatEn(record) {
  if (record.vat_treatment === 'reverse_charge') {
    return `${invoiceMod.REVERSE_CHARGE_EN}, customer VAT number ${record.buyer.vat}`;
  }
  return `incl. ${record.vat_rate}% VAT, ${record.currency} ${record.amount_vat}`;
}

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
    `${descNl(record)}`,
    `Totaal: ${record.currency} ${moneyNl(record.amount_gross)} (${vatNl(record)})`,
    ``,
    isInvoice ? '' : noteNl(invoiceMod.RECEIPT_NOTE),
    complete ? '' : `${BUYER_HINT_NL}.`,
    ``,
    `Het document zit in de bijlage. U vindt al uw documenten ook op uw accountpagina.`,
    ``,
    record.seller.name,
  ]);
  const en = squeeze([
    `Thank you for your payment.`,
    ``,
    `${record.title} ${record.number}`,
    `Date: ${dateEn(record.invoice_date)}`,
    `${descEn(record)}`,
    `Total: ${record.currency} ${record.amount_gross} (${vatEn(record)})`,
    ``,
    isInvoice ? '' : `${invoiceMod.RECEIPT_NOTE}`,
    complete ? '' : `${invoiceMod.BUYER_HINT}.`,
    ``,
    `The document is attached. You can also find all your documents on your account page.`,
    ``,
    record.seller.name,
  ]);
  return arrange(record, subjectNl, subjectEn, nl, en);
}

function creditNoteMail(record) {
  const chargedBack = record.reason === 'chargeback';
  const subjectEn = `${record.title} ${record.number} - ${record.seller.name}`;
  const subjectNl = `${titleNl(record.title)} ${record.number} - ${record.seller.name}`;
  const nl = squeeze([
    chargedBack
      ? `Uw betaling is teruggeboekt. Daarom is de factuur hieronder gecrediteerd.`
      : `Wij hebben uw betaling terugbetaald. Daarom is de factuur hieronder gecrediteerd.`,
    ``,
    `${titleNl(record.title)} ${record.number}`,
    `Datum: ${dateNl(record.invoice_date)}`,
    `Creditering van factuur ${record.credit_for} van ${dateNl(record.credit_for_date)}`,
    `${descNl(record)}`,
    `Totaal gecrediteerd: ${record.currency} ${moneyNl(record.amount_gross)} (${vatNl(record)})`,
    ``,
    record.partial ? 'Dit is een gedeeltelijke creditering. De rest van die factuur blijft staan.' : '',
    noteNl(record.note),
    ``,
    `Het document zit in de bijlage. U vindt al uw documenten ook op uw accountpagina.`,
    ``,
    record.seller.name,
  ]);
  const en = squeeze([
    chargedBack
      ? `Your payment was charged back, so the invoice below has been credited.`
      : `Your payment has been refunded, so the invoice below has been credited.`,
    ``,
    `${record.title} ${record.number}`,
    `Date: ${dateEn(record.invoice_date)}`,
    `Credit for invoice ${record.credit_for} of ${dateEn(record.credit_for_date)}`,
    `${descEn(record)}`,
    `Total credited: ${record.currency} ${record.amount_gross} (${vatEn(record)})`,
    ``,
    record.partial ? 'This is a partial credit. The remainder of that invoice still stands.' : '',
    record.note || '',
    ``,
    `The document is attached. You can also find all your documents on your account page.`,
    ``,
    record.seller.name,
  ]);
  return arrange(record, subjectNl, subjectEn, nl, en);
}

module.exports = { TITLE_NL, NOTE_NL, BUYER_HINT_NL, invoiceMail, creditNoteMail };
