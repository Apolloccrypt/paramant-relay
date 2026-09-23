'use strict';
// The invoice and credit-note mails: Dutch first, the English text below it
// unchanged, subject "Dutch / English". No relay, redis or PDF needed.
//
//   cd relay && node --test test/billing-mail.test.js

const { test } = require('node:test');
const assert = require('assert');
const billingMail = require('../lib/billing-mail');

const seller = { name: 'Paramant' };
const base = {
  number: 'PS-2026-0001', seller, currency: 'EUR', amount_gross: '12.10',
  amount_vat: '2.10', vat_rate: 21, invoice_date: '2026-09-08',
  description: 'ParaSign Pro, 1 month',
  buyer: { email: 'b@example.com' },
};

const clean = (s) => !/\u2014/.test(s) && !/!/.test(s);

test('invoice mail: Dutch first, English unchanged below', () => {
  const m = billingMail.invoiceMail({ ...base, kind: 'invoice', title: 'Invoice',
    buyer: { email: 'b@example.com', company: 'X BV', address: 'Straat 1' } });
  assert.strictEqual(m.subject, 'Factuur PS-2026-0001 - Paramant / Invoice PS-2026-0001 - Paramant');
  assert.ok(m.text.startsWith('Dank u voor uw betaling.'), m.text);
  assert.ok(m.text.includes('Datum: 8 september 2026'), m.text);
  assert.ok(m.text.includes('Totaal: EUR 12.10 (incl. 21% btw, EUR 2.10)'), m.text);
  // The English half, as it always read.
  assert.ok(m.text.includes('Thank you for your payment.'), m.text);
  assert.ok(m.text.includes('Date: 2026-09-08'), m.text);
  assert.ok(m.text.includes('Total: EUR 12.10 (incl. 21% VAT, EUR 2.10)'), m.text);
  assert.ok(m.text.indexOf('Dank u') < m.text.indexOf('Thank you'), 'Dutch comes first');
  assert.ok(!m.text.includes('bedrijfsgegevens'), 'complete buyer gets no hint');
  assert.ok(clean(m.text));
});

test('receipt mail: receipt title, VAT note and buyer hint in both languages', () => {
  const m = billingMail.invoiceMail({ ...base, kind: 'receipt', title: 'Payment receipt' });
  assert.strictEqual(m.subject, 'Betalingsbewijs PS-2026-0001 - Paramant / Payment receipt PS-2026-0001 - Paramant');
  assert.ok(m.text.includes('Betalingsbewijs PS-2026-0001'), m.text);
  assert.ok(m.text.includes('Factuur met btw-nummer volgt.'), m.text);
  assert.ok(m.text.includes('Vul uw bedrijfsgegevens in op uw accountpagina, dan staan ze op de factuur.'), m.text);
  assert.ok(m.text.includes('Invoice with VAT number follows.'), m.text);
  assert.ok(m.text.includes('Add your company details on your account page to have them on the invoice.'), m.text);
  assert.ok(clean(m.text));
});

test('credit-note mail: chargeback and partial refund', () => {
  const cn = { ...base, number: 'CN-2026-0001', kind: 'credit_note', title: 'Credit note',
    credit_for: 'PS-2026-0001', credit_for_date: '2026-09-08', invoice_date: '2026-09-20', note: '' };
  const back = billingMail.creditNoteMail({ ...cn, reason: 'chargeback' });
  assert.strictEqual(back.subject, 'Creditnota CN-2026-0001 - Paramant / Credit note CN-2026-0001 - Paramant');
  assert.ok(back.text.startsWith('Uw betaling is teruggeboekt.'), back.text);
  assert.ok(back.text.includes('Creditering van factuur PS-2026-0001 van 8 september 2026'), back.text);
  assert.ok(back.text.includes('Totaal gecrediteerd: EUR 12.10'), back.text);
  assert.ok(back.text.includes('Your payment was charged back, so the invoice below has been credited.'), back.text);
  assert.ok(back.text.includes('Credit for invoice PS-2026-0001 of 2026-09-08'), back.text);
  assert.ok(clean(back.text));

  const refund = billingMail.creditNoteMail({ ...cn, reason: 'refund', partial: true,
    title: 'Refund receipt', note: 'Credit note with VAT number follows.' });
  assert.strictEqual(refund.subject, 'Terugbetalingsbewijs CN-2026-0001 - Paramant / Refund receipt CN-2026-0001 - Paramant');
  assert.ok(refund.text.startsWith('Uw betaling is aan u terugbetaald.'), refund.text);
  assert.ok(refund.text.includes('Dit is een gedeeltelijke creditering.'), refund.text);
  assert.ok(refund.text.includes('Creditnota met btw-nummer volgt.'), refund.text);
  assert.ok(refund.text.includes('Your payment has been refunded'), refund.text);
  assert.ok(refund.text.includes('This is a partial credit.'), refund.text);
  assert.ok(clean(refund.text));
});
