'use strict';
// The document money gets when it goes back: its own number, its reference to
// the invoice it credits, its VAT split, and the one rule that matters more
// than any of them, that a chargeback can only ever produce ONE of it.
//
// No redis and no network. The store is the same Map stand-in test/invoice.test.js
// uses, behind the five commands lib/credit-note.js calls, which is enough to
// drive the exact ordering a real client would see. The route half (auth, the
// listing, the PDF download) lives in test/route-billing-invoices.test.js.
//
// Run: node --test relay/test/credit-note.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const invoice = require('../lib/invoice');
const credit = require('../lib/credit-note');
const invoicePdf = require('../lib/invoice-pdf');
const catalog = require('../lib/billing-catalog');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('credit-note', checks));

function fakeRedis() {
  const kv = new Map();
  const lists = new Map();
  return {
    kv, lists,
    async get(k) { return kv.has(k) ? kv.get(k) : null; },
    async set(k, v, opts) {
      if (opts && opts.NX && kv.has(k)) return null;
      kv.set(k, String(v));
      return 'OK';
    },
    async incr(k) { const n = (parseInt(kv.get(k) || '0', 10) || 0) + 1; kv.set(k, String(n)); return n; },
    async rPush(k, v) { const l = lists.get(k) || []; l.push(v); lists.set(k, l); return l.length; },
    async lRange(k, start, stop) {
      const l = lists.get(k) || [];
      const a = start < 0 ? Math.max(0, l.length + start) : start;
      const b = stop < 0 ? l.length + stop : stop;
      return l.slice(a, b + 1);
    },
    async hGet() { return null; },
  };
}

const SELLER = {
  name: 'Paramantis Solutions B.V.',
  address: 'Example Street 1\n1234 AB Example City\nNetherlands',
  kvk: '42115132',
  vat: 'NL863456789B01',
};

const BUYER = {
  email: 'office@example.test',
  company: 'Acme B.V.',
  address: 'Example Road 12\n1015 BR Example City',
  vat: 'NL812345678B01',
};

const PAID_AT = new Date('2026-09-03T12:00:00Z');
const BACK_AT = new Date('2026-09-20T09:00:00Z');

function payment(id, value = '603.79', extra = {}) {
  return Object.assign({
    id, status: 'paid', method: 'ideal',
    amount: { value, currency: 'EUR' },
    metadata: { accountId: 'acct_demo', product: 'parasign', plan: 'pro', interval: 'yearly' },
  }, extra);
}

// A payment that has come back, in the two shapes Mollie sends: a chargeback
// (status flips, the counter follows later) and a refund (status stays 'paid'
// until the whole amount is back, and only the counter moves).
function chargedBack(p, value) {
  return Object.assign({}, p, {
    status: 'chargeback',
    amountChargedBack: value ? { value, currency: 'EUR' } : undefined,
  });
}
function refunded(p, value) {
  return Object.assign({}, p, { amountRefunded: { value, currency: 'EUR' } });
}

async function issueInvoice(redis, p) {
  const md = p.metadata;
  return invoice.issueDocument({
    payment: p,
    order: Object.assign({ accountId: md.accountId }, catalog.resolveOrder(md)),
    seller: SELLER,
    buyer: BUYER,
    now: PAID_AT,
    periodEnd: '2027-09-03T12:00:00Z',
  }, redis);
}

async function paidAndBack(reversal, value, redis = fakeRedis(), id = 'tr_back') {
  const p = payment(id);
  await issueInvoice(redis, p);
  const back = reversal(p, value);
  const out = await credit.issueCreditNote({ payment: back, now: BACK_AT }, redis);
  return { redis, invoicePayment: p, back, out };
}

// ── 1. one credit note per chargeback ────────────────────────────────────────

test('a chargeback produces exactly one credit note, numbered CN-2026-0001', async () => {
  const { out, redis } = await paidAndBack(chargedBack, '603.79');
  assert.strictEqual(out.result, 'issued');
  assert.strictEqual(out.number, 'CN-2026-0001', 'its own series, starting at one');
  assert.strictEqual(out.record.kind, 'credit_note');
  assert.strictEqual(out.record.title, 'Credit note');
  assert.strictEqual(out.record.credit_for, 'PS-2026-0001', 'it names the invoice it credits');
  assert.strictEqual(out.record.credit_for_date, '2026-09-03', 'and the date of that invoice');
  assert.strictEqual(out.record.reason, 'chargeback');
  assert.strictEqual(out.record.partial, false);
  assert.strictEqual(out.fully_credited, true);
  // Stored under the SAME document keyspace and in the same per-account list as
  // the invoice, so /account and the PDF route serve it without a second index.
  assert.ok(await redis.get(invoice.K.doc('CN-2026-0001')), 'the record is stored');
  assert.deepStrictEqual(await redis.lRange(invoice.K.byAcct('acct_demo'), 0, -1),
    ['PS-2026-0001', 'CN-2026-0001']);
  did();
});

test('the amounts are the invoice, negated, to the cent', async () => {
  const { out } = await paidAndBack(chargedBack, '603.79');
  assert.strictEqual(out.record.amount_gross, '-603.79');
  assert.strictEqual(out.record.amount_net, '-499.00');
  assert.strictEqual(out.record.amount_vat, '-104.79');
  assert.strictEqual(out.record.vat_rate, 21);
  assert.strictEqual(out.record.currency, 'EUR');
  did();
});

test('the seller and the buyer are the ones the invoice stated', async () => {
  const { out } = await paidAndBack(chargedBack, '603.79');
  assert.deepStrictEqual(out.record.seller, SELLER);
  assert.deepStrictEqual(out.record.buyer, BUYER);
  assert.strictEqual(out.record.account_id, 'acct_demo');
  assert.strictEqual(out.record.payment_id, 'tr_back');
  did();
});

test('the same chargeback webhook twice issues exactly one credit note', async () => {
  const { redis, back } = await paidAndBack(chargedBack, '603.79');
  const second = await credit.issueCreditNote({ payment: back, now: BACK_AT }, redis);
  assert.strictEqual(second.result, 'existing', 'the retry finds the document, it does not write one');
  assert.strictEqual(second.number, 'CN-2026-0001');
  const third = await credit.issueCreditNote({ payment: back, now: BACK_AT }, redis);
  assert.strictEqual(third.result, 'existing');
  assert.strictEqual(parseInt(await redis.get(credit.CK.seq(2026)), 10), 1,
    'and the counter was never drawn a second time');
  const list = await redis.lRange(invoice.K.byAcct('acct_demo'), 0, -1);
  assert.strictEqual(list.filter((n) => n.startsWith('CN-')).length, 1, 'one row on the account, not three');
  did();
});

test('a chargeback that reports no counter yet still credits the whole invoice', async () => {
  // Mollie flips the status before amountChargedBack is settled. Answering
  // "nothing was reversed" there would leave the customer holding an invoice
  // for money he no longer paid.
  const { out } = await paidAndBack(chargedBack, undefined);
  assert.strictEqual(out.result, 'issued');
  assert.strictEqual(out.record.amount_gross, '-603.79');
  assert.strictEqual(out.record.partial, false);
  did();
});

test('a payment with no invoice gets no credit note, and no error', async () => {
  const redis = fakeRedis();
  const out = await credit.issueCreditNote({ payment: chargedBack(payment('tr_orphan'), '10.00'), now: BACK_AT }, redis);
  assert.strictEqual(out.result, 'none');
  assert.strictEqual(out.reason, 'no_invoice');
  assert.strictEqual(await redis.get(credit.CK.seq(2026)), null, 'and no number was burned');
  did();
});

test('without redis nothing is written and nothing throws', async () => {
  const out = await credit.issueCreditNote({ payment: chargedBack(payment('tr_none'), '1.00') }, null);
  assert.strictEqual(out.result, 'unavailable');
  assert.strictEqual(out.reason, 'no_redis');
  did();
});

// ── 2. partial refunds ───────────────────────────────────────────────────────
// The half that has to be right to the cent, because a partial credit is the
// only case where the VAT is not simply copied off the invoice.

test('a partial refund credits the refunded amount, with VAT pro rata', async () => {
  const { out } = await paidAndBack(refunded, '100.00');
  assert.strictEqual(out.result, 'issued');
  assert.strictEqual(out.record.partial, true, 'and it says on its face that it is partial');
  assert.strictEqual(out.record.reason, 'refund');
  assert.strictEqual(out.record.amount_gross, '-100.00');
  // 100.00 gross at 21%: net 82.64, VAT 17.36, and the two halves add back up
  // to exactly what went back.
  assert.strictEqual(out.record.amount_net, '-82.64');
  assert.strictEqual(out.record.amount_vat, '-17.36');
  assert.strictEqual(
    invoice.centsOf(out.record.amount_net.slice(1)) + invoice.centsOf(out.record.amount_vat.slice(1)),
    invoice.centsOf(out.record.amount_gross.slice(1)),
    'net plus VAT is exactly the amount refunded');
  assert.strictEqual(out.fully_credited, false, 'the invoice is not reversed by a partial refund');
  did();
});

test('a partial refund is idempotent, and a further refund credits only the difference', async () => {
  const { redis, invoicePayment, out: first } = await paidAndBack(refunded, '100.00');
  assert.strictEqual(first.number, 'CN-2026-0001');

  // The same webhook again: Mollie reports the same cumulative total.
  const repeat = await credit.issueCreditNote(
    { payment: refunded(invoicePayment, '100.00'), now: BACK_AT }, redis);
  assert.strictEqual(repeat.result, 'existing');
  assert.strictEqual(repeat.number, 'CN-2026-0001');

  // A second refund. Mollie's counter is cumulative, so this says 250.00 in
  // total, of which 150.00 is new.
  const second = await credit.issueCreditNote(
    { payment: refunded(invoicePayment, '250.00'), now: BACK_AT }, redis);
  assert.strictEqual(second.result, 'issued');
  assert.strictEqual(second.number, 'CN-2026-0002');
  assert.strictEqual(second.record.amount_gross, '-150.00');
  assert.strictEqual(second.record.partial, true);
  did();
});

test('partial credits add back up to the invoice exactly, remainder and all', async () => {
  // 603.79 is not divisible by 1.21, and neither are the parts. Each note
  // carries the VAT of its own amount; the LAST one has to absorb whatever the
  // rounding left over, or the books do not close.
  const redis = fakeRedis();
  const p = payment('tr_thirds');
  await issueInvoice(redis, p);
  const notes = [];
  for (const cumulative of ['200.00', '400.00', '603.79']) {
    const out = await credit.issueCreditNote({ payment: refunded(p, cumulative), now: BACK_AT }, redis);
    assert.strictEqual(out.result, 'issued', `${cumulative} produced a note`);
    notes.push(out.record);
  }
  const sum = (field) => notes.reduce((t, r) => t + invoice.centsOf(String(r[field]).replace('-', '')), 0);
  assert.strictEqual(sum('amount_gross'), 60379, 'the totals add back up to the invoice');
  assert.strictEqual(sum('amount_net'), 49900, 'the net amounts add back up to the invoice net');
  assert.strictEqual(sum('amount_vat'), 10479, 'the VAT amounts add back up to the invoice VAT');
  assert.strictEqual(notes[2].partial, false, 'the note that closes it is not marked partial');
  const state = await credit.creditedAgainst('PS-2026-0001', redis);
  assert.deepStrictEqual(state.notes, ['CN-2026-0001', 'CN-2026-0002', 'CN-2026-0003']);
  assert.strictEqual(state.gross_cents, 60379);
  did();
});

test('a refund can never give back more than the invoice', async () => {
  const redis = fakeRedis();
  const p = payment('tr_over');
  await issueInvoice(redis, p);
  const out = await credit.issueCreditNote({ payment: refunded(p, '9999.00'), now: BACK_AT }, redis);
  assert.strictEqual(out.record.amount_gross, '-603.79', 'capped at what was invoiced');
  assert.strictEqual(out.fully_credited, true);
  // A chargeback on top of a refund that already took everything back reports
  // the same total, so it is the same reversal and finds the same document.
  const again = await credit.issueCreditNote({ payment: chargedBack(p, '603.79'), now: BACK_AT }, redis);
  assert.strictEqual(again.result, 'existing');
  assert.strictEqual(again.number, 'CN-2026-0001');
  did();
});

test('a claim that was lost still cannot produce a second credit note', async () => {
  // The claim key is what makes a retry cheap; the running total is what makes
  // it SAFE. Delete the claim (a redis eviction, or an attempt that timed out
  // past the takeover window) and the second pass must still find that there is
  // nothing left to credit, without drawing a number for it.
  const { redis, invoicePayment } = await paidAndBack(chargedBack, '603.79');
  redis.kv.delete(credit.CK.claim(`${invoicePayment.id}:60379`));
  const again = await credit.issueCreditNote(
    { payment: chargedBack(invoicePayment, '603.79'), now: BACK_AT }, redis);
  assert.strictEqual(again.result, 'none');
  assert.strictEqual(again.reason, 'already_credited');
  assert.strictEqual(again.fully_credited, true);
  assert.strictEqual(parseInt(await redis.get(credit.CK.seq(2026)), 10), 1, 'no number was burned');
  const list = await redis.lRange(invoice.K.byAcct('acct_demo'), 0, -1);
  assert.strictEqual(list.filter((n) => n.startsWith('CN-')).length, 1);
  did();
});

// ── 3. what counts as a reversal at all ──────────────────────────────────────

test('isReversal recognises a chargeback, a refunded status and a partial refund', () => {
  assert.strictEqual(credit.isReversal(payment('tr_a')), false, 'a plain paid payment is not one');
  assert.strictEqual(credit.isReversal(chargedBack(payment('tr_b'))), true);
  assert.strictEqual(credit.isReversal(Object.assign(payment('tr_c'), { status: 'charged_back' })), true);
  assert.strictEqual(credit.isReversal(Object.assign(payment('tr_d'), { status: 'refunded' })), true);
  assert.strictEqual(credit.isReversal(refunded(payment('tr_e'), '0.01')), true, 'one cent back is a reversal');
  assert.strictEqual(credit.isReversal(refunded(payment('tr_f'), '0.00')), false);
  assert.strictEqual(credit.isReversal(null), false);
  did();
});

test('the reason distinguishes a chargeback from a refund we sent', () => {
  assert.strictEqual(credit.reasonOf(chargedBack(payment('tr_g'), '1.00')), 'chargeback');
  assert.strictEqual(credit.reasonOf(refunded(payment('tr_h'), '1.00')), 'refund');
  did();
});

// ── 4. the PDF carries what a credit note must carry ─────────────────────────
// Same reasoning as the invoice suite: the content stream is uncompressed on
// purpose, so the text is readable straight out of the bytes.

test('the credit note PDF carries every field, and the invoice it credits', async () => {
  const { out } = await paidAndBack(chargedBack, '603.79');
  const pdf = invoicePdf.render(out.record, { buyerHint: invoice.BUYER_HINT });
  const text = pdf.toString('latin1');

  assert.ok(text.startsWith('%PDF-1.4'), 'it is a PDF');
  assert.ok(text.trimEnd().endsWith('%%EOF'), 'with a complete trailer');

  const required = {
    'a: issue date':                '2026-09-20',
    'b: sequential number':         'CN-2026-0001',
    'b: its own series':            'Credit note number',
    'c: supplier name':             'Paramantis Solutions B.V.',
    'c: supplier address':          '1234 AB Example City',
    'd: supplier VAT number':       'NL863456789B01',
    'e: customer name':             'Acme B.V.',
    'e: customer address':          '1015 BR Example City',
    'f: description':               'Paramant ParaSign Pro, yearly plan',
    'g: amount excluding VAT':      '-499.00',
    'h: VAT rate':                  '21%',
    'h: VAT amount':                '-104.79',
    'i: total':                     '-603.79',
    'the invoice it credits':       'PS-2026-0001',
    'the date of that invoice':     '2026-09-03',
    'extra: KvK number':            '42115132',
  };
  for (const [what, value] of Object.entries(required)) {
    assert.ok(text.includes(value), `${what} is on the document (${value})`);
  }
  for (const label of ['Credit note', 'Credit for invoice', 'Billed to', 'Subtotal excl. VAT', 'Total credited']) {
    assert.ok(text.includes(label), `the document is labelled: ${label}`);
  }
  assert.ok(text.includes('charged back'), 'it says why the money went back');
  assert.ok(!text.includes('Paid in full'), 'and never claims the customer paid it');
  did();
});

test('a partial credit note says so on the page', async () => {
  const { out } = await paidAndBack(refunded, '100.00');
  const text = invoicePdf.render(out.record, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('Partial credit'), 'a partial credit is labelled as one');
  assert.ok(text.includes('refunded to you'), 'and says the money was refunded, not charged back');
  assert.ok(text.includes('-100.00'));
  did();
});

test('crediting a receipt produces a refund receipt, not a VAT credit note', async () => {
  // No seller VAT id: the original could not call itself an invoice, so the
  // document that reverses it may not call itself a credit note either.
  const redis = fakeRedis();
  const p = payment('tr_no_vat');
  const md = p.metadata;
  await invoice.issueDocument({
    payment: p,
    order: Object.assign({ accountId: md.accountId }, catalog.resolveOrder(md)),
    seller: Object.assign({}, SELLER, { vat: '' }),
    buyer: BUYER,
    now: PAID_AT,
    periodEnd: '2027-09-03T12:00:00Z',
  }, redis);
  const out = await credit.issueCreditNote({ payment: chargedBack(p, '603.79'), now: BACK_AT }, redis);
  assert.strictEqual(out.result, 'issued');
  assert.strictEqual(out.record.title, 'Refund receipt');
  assert.strictEqual(out.record.note, credit.CREDIT_RECEIPT_NOTE);
  const text = invoicePdf.render(out.record, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('Refund receipt'));
  assert.ok(!/\(Credit note\) Tj/.test(text), 'and never calls itself a credit note');
  did();
});

// ── 5. what the invoice itself now says ──────────────────────────────────────

test('the invoice keeps its number and points at the note that credited it', async () => {
  const { redis } = await paidAndBack(chargedBack, '603.79');
  const original = JSON.parse(await redis.get(invoice.K.doc('PS-2026-0001')));
  assert.strictEqual(original.number, 'PS-2026-0001', 'the invoice is never renumbered');
  assert.deepStrictEqual(original.credit_notes, ['CN-2026-0001']);
  assert.strictEqual(original.credited_gross, '603.79');
  // The reversal marker is the relay's to set, on a FULL credit only, so the
  // record here is still unstamped: this suite drives the module, not the route.
  const withMarker = Object.assign({}, original, { reversed_at: '2026-09-20T09:00:00.000Z' });
  const text = invoicePdf.render(withMarker, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('Reversed on 2026-09-20'), 'the invoice PDF says it was reversed');
  assert.ok(text.includes('Credited by CN-2026-0001'), 'and names the document that did it');
  did();
});

test('a credit note is served by the same document lookup as an invoice', async () => {
  const { redis } = await paidAndBack(chargedBack, '603.79');
  assert.ok(invoice.parseDocumentNumber('CN-2026-0001'), 'the number parses');
  assert.ok(invoice.parseDocumentNumber('PS-2026-0001'));
  assert.strictEqual(invoice.parseDocumentNumber('XX-2026-0001'), null);
  const fetched = await invoice.getFor('acct_demo', 'CN-2026-0001', redis);
  assert.ok(fetched && fetched.number === 'CN-2026-0001');
  assert.strictEqual(await invoice.getFor('acct_other', 'CN-2026-0001', redis), null,
    'and never to another account');
  const listed = (await invoice.listFor('acct_demo', redis)).map((r) => r.number);
  assert.deepStrictEqual(listed, ['CN-2026-0001', 'PS-2026-0001'], 'newest first, both series');
  did();
});
