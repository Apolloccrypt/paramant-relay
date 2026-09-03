'use strict';
// The document a customer gets when money goes back: a credit note.
//
// WHY A MARKER WAS NOT ENOUGH. lib/invoice.js issues a numbered invoice for
// every payment and, when a chargeback arrived, stamped `reversed_at` on it.
// That keeps our own records from lying, and it is all it does. Dutch VAT law
// does not let an issued invoice be withdrawn: an invoice that has gone out
// stays out, and the money that goes back is documented by a SECOND document
// with its own sequential number that refers to the first (Wet OB art. 35a
// applies to it in full, and art. 29 is what makes the VAT correctable at all).
// A bookkeeper who is handed PS-2026-0001 and told "ignore that one" has
// nothing to book. Handed CN-2026-0001 he books a reversal, and the VAT return
// closes.
//
// WHAT A CREDIT NOTE HERE CARRIES:
//   - its own number from its own series, CN-2026-0001, per calendar year
//   - the number AND the date of the invoice it credits
//   - the same description, the same VAT rate, the same seller and buyer as
//     they stood on the original document
//   - negative net, negative VAT and a negative total
//   - the reason: a chargeback, or a refund we sent
//
// THE THREE RULES ARE lib/invoice.js's, and for the same reasons:
//
// 1. ONE DOCUMENT PER REVERSAL. Mollie retries a webhook for about a day and
//    the relay re-runs the handler; a second credit note for one chargeback
//    would hand the customer twice his money back on paper. The reversal is
//    claimed BEFORE a number is drawn, exactly as a payment is.
//
// 2. A NUMBER IS NEVER REUSED AND NEVER SKIPPED. INCR on one key per year, and
//    the number drawn is written back onto the claim, so a crash between the
//    draw and the record hands the SAME number to the retry.
//
// 3. AMOUNTS COME FROM THE ORIGINAL DOCUMENT AND FROM THE PAYMENT, never from
//    a request. What may be credited is capped by what was invoiced, and what
//    is already credited is tracked, so no series of partial refunds can ever
//    give back more than came in.
//
// PARTIAL REFUNDS, AND WHY THE SPLIT IS DONE AGAINST THE RUNNING TOTAL.
// Mollie reports `amountRefunded` and `amountChargedBack` as CUMULATIVE totals
// on the payment, not as the delta of one event. So this module computes the
// split for the cumulative amount and issues the DIFFERENCE against what it has
// already credited. Two consequences, both wanted:
//   - each note is the VAT of its own amount, pro rata, in whole cents;
//   - when the running total reaches the invoiced amount, the target split IS
//     the original split (same gross, same rate, same rounding), so the last
//     note absorbs every rounding remainder and the credit notes together add
//     back up to the invoice, to the cent.

const invoice = require('./invoice');

// ── redis key shapes ─────────────────────────────────────────────────────────
// No TTL, for the reason invoice.js gives: seven years of retention (AWR art.
// 52), and a credit note that expires is one that was never kept. Documents
// themselves live in invoice.K.doc and in the same per-account list, so the
// account page and the PDF route serve both series without a second index.
const CK = {
  claim:    (reversalId) => `paramant:billing:credit:for:${reversalId}`,
  seq:      (year)       => `paramant:billing:credit:seq:${year}`,
  against:  (number)     => `paramant:billing:credit:against:${number}`,
};

const PENDING_TAKEOVER_MS = invoice.PENDING_TAKEOVER_MS;

// The wording on a credit note against a document that could not call itself an
// invoice (no seller VAT id on file). Same honesty as RECEIPT_NOTE: the money
// really did go back, and the VAT document follows.
const CREDIT_RECEIPT_NOTE = 'Credit note with VAT number follows.';

// ── numbering ────────────────────────────────────────────────────────────────
// CN-2026-0001. A SEPARATE series from PS: mixing credit notes into the invoice
// series makes the invoice numbering non-consecutive for anyone reading only
// the invoices, which is the thing the sequence exists to prevent. Two series
// is explicitly allowed ("uit een of meer reeksen", art. 35a lid 1 sub b).
function formatNumber(year, seq) {
  return `CN-${year}-${String(seq).padStart(4, '0')}`;
}

function parseNumber(number) {
  const m = /^CN-(\d{4})-(\d{4,})$/.exec(String(number || '').trim());
  return m ? { year: parseInt(m[1], 10), seq: parseInt(m[2], 10) } : null;
}

// ── how much went back ───────────────────────────────────────────────────────
// Reads only the payment object the caller re-fetched from Mollie, never a
// webhook body. Both cumulative counters are added: a payment can be partly
// refunded by us and then charged back for the rest, and both halves are money
// the customer no longer paid. Capped at what was invoiced, because a credit
// note for more than the invoice is a document nobody can book.
//
// The fallback matters. A chargeback event does not always carry a populated
// amountChargedBack on the payment (it is settled asynchronously), and a
// `refunded` status without counters means the whole thing went back. Answering
// zero there would leave the customer with an invoice for money he does not
// have, which is the state this module exists to end.
function reversedCentsOf(payment, record) {
  const p = payment || {};
  const status = String(p.status || '');
  const cap = invoice.centsOf(record && record.amount_gross);
  const capped = Number.isFinite(cap) ? cap : 0;
  const read = (amount) => {
    const c = invoice.centsOf(amount && amount.value);
    return Number.isFinite(c) ? c : 0;
  };
  let cents = read(p.amountRefunded) + read(p.amountChargedBack);
  const full = status === 'chargeback' || status === 'charged_back' || status === 'refunded';
  if (cents <= 0 && full) cents = capped;
  return Math.max(0, Math.min(cents, capped));
}

// Is there anything here that asks for a credit note at all. Kept next to the
// amount so the relay has one place to ask, rather than repeating a list of
// Mollie statuses at the call site.
function isReversal(payment) {
  const p = payment || {};
  const status = String(p.status || '');
  if (status === 'chargeback' || status === 'charged_back' || status === 'refunded') return true;
  const refunded = invoice.centsOf(p.amountRefunded && p.amountRefunded.value);
  const back = invoice.centsOf(p.amountChargedBack && p.amountChargedBack.value);
  return (Number.isFinite(refunded) && refunded > 0) || (Number.isFinite(back) && back > 0);
}

function reasonOf(payment) {
  const status = String((payment || {}).status || '');
  if (status === 'chargeback' || status === 'charged_back') return 'chargeback';
  const back = invoice.centsOf((payment || {}).amountChargedBack && payment.amountChargedBack.value);
  if (Number.isFinite(back) && back > 0) return 'chargeback';
  return 'refund';
}

// ── the record ───────────────────────────────────────────────────────────────
// Seller and buyer are COPIED FROM THE ORIGINAL DOCUMENT, not rebuilt from
// today's configuration. A credit note reverses a specific invoice, and it has
// to state the same parties that invoice stated even if the customer has since
// changed his company address.
function describe(original) {
  return `Credit for ${original.description || 'a paid plan'} (invoice ${original.number})`;
}

function buildRecord({ number, original, amounts, reason, payment, now, partial }) {
  const issued = now instanceof Date ? now : new Date();
  const forInvoice = original.kind === 'invoice';
  return {
    number,
    kind: 'credit_note',
    series: 'CN',
    title: forInvoice ? 'Credit note' : 'Refund receipt',
    note: forInvoice ? '' : CREDIT_RECEIPT_NOTE,
    credits_kind: original.kind,
    issued_at: issued.toISOString(),
    invoice_date: issued.toISOString().slice(0, 10),
    account_id: original.account_id,
    payment_id: (payment && payment.id) || original.payment_id,
    payment_method: original.payment_method || null,
    credit_for: original.number,
    credit_for_date: original.invoice_date,
    reason,
    partial: !!partial,
    product: original.product,
    plan: original.plan,
    interval: original.interval,
    description: describe(original),
    service_period_end: original.service_period_end || null,
    currency: original.currency || 'EUR',
    vat_rate: original.vat_rate,
    amount_net: invoice.money(-amounts.net_cents),
    amount_vat: invoice.money(-amounts.vat_cents),
    amount_gross: invoice.money(-amounts.gross_cents),
    seller: Object.assign({}, original.seller),
    buyer: Object.assign({}, original.buyer),
  };
}

// ── what has already been given back ─────────────────────────────────────────
// One small JSON blob per invoice: the running totals and the numbers of the
// notes that produced them. It is what makes a second partial refund credit the
// delta instead of the whole amount again, and it is the only place a reader
// has to look to answer "is this invoice fully credited".
async function creditedAgainst(number, redis) {
  const empty = { gross_cents: 0, net_cents: 0, vat_cents: 0, notes: [] };
  if (!redis || !number) return empty;
  try {
    const raw = await redis.get(CK.against(number));
    if (!raw) return empty;
    const parsed = JSON.parse(raw);
    return {
      gross_cents: parsed.gross_cents || 0,
      net_cents: parsed.net_cents || 0,
      vat_cents: parsed.vat_cents || 0,
      notes: Array.isArray(parsed.notes) ? parsed.notes : [],
    };
  } catch { return empty; }
}

// ── issuing ──────────────────────────────────────────────────────────────────
// `redis` is anything with get / set / incr / rPush / lRange, so the unit tests
// drive a Map and the route tests drive a real server, exactly as invoice.js
// does. Never throws and never blocks the webhook: a customer whose money went
// back must not see the webhook fail over paperwork either.
//
// Returns { result, number, record, fully_credited }:
//   'issued'      a credit note exists for this reversal
//   'existing'    this reversal already has one; record is that one
//   'none'        nothing to credit (no invoice, or already credited in full)
//   'deferred'    another attempt holds the claim right now; try again later
//   'unavailable' no redis, or nothing could be written
async function issueCreditNote({ payment, original, now }, redis) {
  if (!redis) return { result: 'unavailable', reason: 'no_redis' };
  if (!payment || !payment.id) return { result: 'unavailable', reason: 'no_payment' };

  // The invoice being credited. Passed in by the tests, looked up from the
  // payment id in production: a chargeback arrives on the same tr_ id as the
  // payment it reverses, and the claim key is the index from one to the other.
  const invoiceRecord = original || await invoice.recordForPayment(payment.id, redis);
  if (!invoiceRecord || !invoiceRecord.number) return { result: 'none', reason: 'no_invoice' };

  const issued = now instanceof Date ? now : new Date();
  const grossCents = invoice.centsOf(invoiceRecord.amount_gross);
  if (!Number.isFinite(grossCents) || grossCents <= 0) return { result: 'none', reason: 'bad_invoice_amount' };

  const targetGross = reversedCentsOf(payment, invoiceRecord);
  if (targetGross <= 0) return { result: 'none', reason: 'nothing_reversed' };

  // Step 1: claim the reversal. The id is the payment PLUS the cumulative
  // amount, which is what makes this both idempotent and able to follow a
  // second partial refund: a repeat webhook reports the same total and hits the
  // same claim, a further refund reports a higher total and is a new one.
  const reversalId = `${payment.id}:${targetGross}`;
  const claimKey = CK.claim(reversalId);
  const pendingValue = `pending:${issued.getTime()}`;
  let claimed = false;
  try {
    claimed = !!(await redis.set(claimKey, pendingValue, { NX: true }));
  } catch (e) {
    return { result: 'unavailable', reason: `claim_failed:${e.message}` };
  }
  if (!claimed) {
    let held = null;
    try { held = await redis.get(claimKey); } catch { held = null; }
    if (held && held.startsWith('CN-')) {
      let record = null;
      try { record = JSON.parse((await redis.get(invoice.K.doc(held))) || 'null'); } catch { record = null; }
      return { result: 'existing', number: held, record };
    }
    const started = parseInt(String(held || '').split(':')[1] || '0', 10);
    if (!(started && issued.getTime() - started > PENDING_TAKEOVER_MS)) {
      return { result: 'deferred', reason: 'claim_pending' };
    }
    // Older than the takeover window: the previous attempt is not coming back.
  }

  // Step 2: how much of that total is new. Read under the claim, so two
  // reversals of the same payment cannot both read the same starting point.
  const already = await creditedAgainst(invoiceRecord.number, redis);
  const target = invoice.splitVat(invoice.money(targetGross), invoiceRecord.vat_rate);
  if (!target) return { result: 'unavailable', reason: 'bad_amount' };
  const amounts = {
    gross_cents: target.gross_cents - already.gross_cents,
    net_cents: target.net_cents - already.net_cents,
    vat_cents: target.vat_cents - already.vat_cents,
  };
  if (amounts.gross_cents <= 0) {
    // Everything this reversal asks for is already on a credit note. Release
    // the claim so a LATER, larger reversal of the same payment is not blocked
    // by a claim that produced nothing.
    try { await redis.set(claimKey, 'none'); } catch { /* best effort */ }
    return { result: 'none', reason: 'already_credited', fully_credited: already.gross_cents >= grossCents };
  }

  // Step 3: draw the number. Only ever reached for a reversal that has no
  // document yet, which is what keeps the CN series gapless.
  const year = issued.getUTCFullYear();
  let seq;
  try { seq = await redis.incr(CK.seq(year)); }
  catch (e) { return { result: 'unavailable', reason: `seq_failed:${e.message}` }; }
  const number = formatNumber(year, seq);

  const record = buildRecord({
    number,
    original: invoiceRecord,
    amounts,
    reason: reasonOf(payment),
    payment,
    now: issued,
    partial: targetGross < grossCents,
  });

  // Step 4: the record first, then the claim, then the running total, then the
  // lists. A crash leaves at worst a document nobody has indexed yet, never a
  // claim pointing at a number that has no document, and never a running total
  // counting a note that was never written.
  try {
    await redis.set(invoice.K.doc(number), JSON.stringify(record));
    await redis.set(claimKey, number);
    await redis.set(CK.against(invoiceRecord.number), JSON.stringify({
      invoice: invoiceRecord.number,
      gross_cents: target.gross_cents,
      net_cents: target.net_cents,
      vat_cents: target.vat_cents,
      notes: already.notes.concat([number]),
      updated_at: issued.toISOString(),
    }));
    if (invoiceRecord.account_id) await redis.rPush(invoice.K.byAcct(invoiceRecord.account_id), number);
    await redis.rPush(invoice.K.all, number);
  } catch (e) {
    return { result: 'unavailable', reason: `store_failed:${e.message}`, number };
  }

  // Back-reference on the invoice, best effort. Not the record of the credit
  // (that is CK.against and the note itself); it is so that anyone who opens
  // only the invoice, PDF included, is told which document reversed it and for
  // how much. A failure here must never undo a credit note that exists.
  try {
    const raw = await redis.get(invoice.K.doc(invoiceRecord.number));
    if (raw) {
      const rec = JSON.parse(raw);
      const notes = Array.isArray(rec.credit_notes) ? rec.credit_notes : [];
      if (!notes.includes(number)) notes.push(number);
      rec.credit_notes = notes;
      rec.credited_gross = invoice.money(target.gross_cents);
      await redis.set(invoice.K.doc(invoiceRecord.number), JSON.stringify(rec));
    }
  } catch { /* the credit note stands on its own */ }

  return {
    result: 'issued',
    number,
    record,
    credited: invoiceRecord.number,
    fully_credited: target.gross_cents >= grossCents,
  };
}

// Every credit note issued against one invoice, oldest first. Reading is by
// number through the shared document keyspace, so nothing here can serve a
// document belonging to another account that the caller has not already checked.
async function notesAgainst(number, redis) {
  const state = await creditedAgainst(number, redis);
  const out = [];
  for (const n of state.notes) {
    try {
      const raw = await redis.get(invoice.K.doc(n));
      if (raw) out.push(JSON.parse(raw));
    } catch { /* one unreadable note must not hide the rest */ }
  }
  return out;
}

module.exports = {
  CK, CREDIT_RECEIPT_NOTE, PENDING_TAKEOVER_MS,
  formatNumber, parseNumber, describe, buildRecord,
  reversedCentsOf, isReversal, reasonOf,
  creditedAgainst, issueCreditNote, notesAgainst,
};
