'use strict';
// The document a customer gets after paying. Until this module existed the
// money moved, the entitlement moved, and nothing was ever written down: no
// number, no VAT split, no record. A Dutch office that spends EUR 603.79 needs
// an invoice it can put in its books, and so does ours.
//
// WHAT THE LAW ASKS FOR (Wet OB art. 35a, the minimum set):
//   - the date the invoice was issued
//   - a sequential number, unique, from one or more series
//   - the supplier's name and address
//   - the supplier's VAT identification number
//   - the customer's name and address
//   - a description of what was supplied
//   - the amount excluding VAT, per rate
//   - the VAT rate and the VAT amount
//   - the total
// The KvK number is not required by art. 35a; it is on the document anyway
// because a Dutch B.V. must state it on outgoing commercial documents
// (Handelsregisterwet art. 25).
//
// THREE RULES THIS MODULE ENFORCES.
//
// 1. ONE DOCUMENT PER PAYMENT. Mollie retries a webhook for about a day, and
//    the relay itself re-runs the handler on a retry after a redis flush. A
//    second document for the same tr_ id would be a second invoice for money
//    that came in once, which is worse than no invoice at all. The payment id
//    is claimed BEFORE a number is drawn, so an ordinary retry never even
//    reaches the counter.
//
// 2. A NUMBER IS NEVER REUSED AND NEVER SKIPPED. Per year, INCR on one redis
//    key. INCR is atomic, so two webhooks in the same millisecond get two
//    numbers. Claiming the payment first is what keeps the sequence gapless:
//    a number is only ever drawn for a payment that has no document yet, and
//    the number that was drawn is written back onto the claim, so a crash
//    between the draw and the record hands the SAME number to the retry
//    instead of burning it. (The one gap this cannot close is a crash between
//    INCR and the write-back; the takeover path below narrows it to a 60s
//    window and the all-list makes such a gap visible.)
//
// 3. AMOUNTS COME FROM THE CATALOG AND THE PAYMENT, NEVER FROM A REQUEST.
//    Same rule the webhook already applies before granting. The gross is the
//    amount Mollie says was actually paid, which processPayment has already
//    checked against the catalog price; the split into net and VAT is done
//    here, in integer cents.
//
// NOT HERE, ON PURPOSE:
//   - a credit note for a chargeback. A reversal writes a marker (see
//     recordReversal) so the record is not silently wrong, but a numbered
//     credit note with its own series is a separate piece of work.
//   - reverse charge / VAT-MOSS. Every catalog price is 21% Dutch VAT and that
//     is what was actually charged, so that is what the document states. An
//     EU customer outside NL with a VAT number is charged the same 21% today;
//     changing that is a pricing decision, not a formatting one.

const CATALOG_VAT_RATE = 21;

// ── redis key shapes ─────────────────────────────────────────────────────────
// None of these ever get a TTL. Dutch bookkeeping retention is seven years
// (AWR art. 52), and an invoice record that expires is an invoice that was
// never kept.
const K = {
  claim:    (paymentId) => `paramant:billing:invoice:for:${paymentId}`,
  seq:      (year)      => `paramant:billing:invoice:seq:${year}`,
  doc:      (number)    => `paramant:billing:invoice:doc:${number}`,
  byAcct:   (accountId) => `paramant:billing:invoice:list:${accountId}`,
  all:                     'paramant:billing:invoice:list:all',
  reversed: (number)    => `paramant:billing:invoice:reversed:${number}`,
};

// How long a half-finished claim blocks a retry before it is taken over. Long
// enough that two webhooks racing the same payment cannot both pass it, short
// enough that a crashed attempt does not cost the customer his invoice.
const PENDING_TAKEOVER_MS = 60_000;

// ── seller ───────────────────────────────────────────────────────────────────
// Configuration, not code: the address and the VAT id are deployment facts.
// The name and the KvK number have defaults because they are already public and
// unchanging (Paramantis Solutions B.V., KvK 42115132); the VAT id has none,
// because guessing a VAT number onto an invoice is the one error here that
// costs a customer his deduction.
// Takes an injectable env object (the pattern lib/entitlements.js and
// lib/developer-gate.js use) so the unit tests can build a seller with and
// without a VAT id without touching process.env.
function sellerFromEnv(envIn) {
  const env = envIn || process.env;
  return {
    name:    (env.BILLING_SELLER_NAME || 'Paramantis Solutions B.V.').trim(),
    address: (env.BILLING_SELLER_ADDRESS || '').trim(),
    kvk:     (env.BILLING_SELLER_KVK || '42115132').trim(),
    vat:     (env.BILLING_SELLER_VAT || '').trim(),
  };
}

// With no VAT id configured the document may not call itself an invoice: an
// invoice without the supplier's VAT number is not one, and a customer who
// files it cannot deduct. It goes out as a payment receipt that says an invoice
// follows, so the customer has proof of payment on the day he paid and knows
// the real document is coming.
function documentKind(seller) {
  return seller && seller.vat ? 'invoice' : 'receipt';
}

function documentTitle(kind) {
  return kind === 'invoice' ? 'Invoice' : 'Payment receipt';
}

const RECEIPT_NOTE = 'Invoice with VAT number follows.';

// ── money ────────────────────────────────────────────────────────────────────
// Integer cents throughout. Catalog prices are gross (VAT included), which is
// what the payment link charges, so the split runs backwards: net is the gross
// divided by 1 + rate, and VAT is whatever is left. Doing it the other way
// round (net * rate, rounded) can leave the two halves failing to add up to the
// amount that was actually collected, and an invoice whose total is not the
// amount paid is a wrong invoice.
function centsOf(value) {
  const m = /^(\d+)(?:\.(\d{1,2})\d*)?$/.exec(String(value == null ? '' : value).trim());
  if (!m) return NaN;
  return parseInt(m[1], 10) * 100 + parseInt((m[2] || '0').padEnd(2, '0'), 10);
}

function money(cents) {
  const sign = cents < 0 ? '-' : '';
  const abs = Math.abs(cents);
  return `${sign}${Math.floor(abs / 100)}.${String(abs % 100).padStart(2, '0')}`;
}

function splitVat(grossValue, ratePercent) {
  const rate = Number.isFinite(ratePercent) ? ratePercent : CATALOG_VAT_RATE;
  const gross = centsOf(grossValue);
  if (!Number.isFinite(gross)) return null;
  const net = Math.round(gross / (1 + rate / 100));
  return { rate, gross_cents: gross, net_cents: net, vat_cents: gross - net };
}

// ── numbering ────────────────────────────────────────────────────────────────
// PS-2026-0001. One series, restarted per calendar year, which is the shape a
// Dutch bookkeeper expects and what Moneybird imports without argument. Four
// digits is not a cap: the padding stops at four and the number keeps counting.
function formatNumber(year, seq) {
  return `PS-${year}-${String(seq).padStart(4, '0')}`;
}

function parseNumber(number) {
  const m = /^PS-(\d{4})-(\d{4,})$/.exec(String(number || '').trim());
  return m ? { year: parseInt(m[1], 10), seq: parseInt(m[2], 10) } : null;
}

// ── the record ───────────────────────────────────────────────────────────────
// Everything the PDF, the mail and a future Moneybird export need, in one flat
// JSON blob. Seller and buyer are COPIED in, not referenced: an invoice states
// what was true on the day it was issued, and a later address change must not
// rewrite history.
function describe(order) {
  const product = order.product === 'parasign' ? 'ParaSign' : 'ParaSend';
  const plan = String(order.plan || '').replace(/^./, (c) => c.toUpperCase());
  const interval = order.interval === 'yearly' ? 'yearly' : 'monthly';
  return `Paramant ${product} ${plan}, ${interval} plan`;
}

function buildRecord({ number, kind, seller, buyer, order, payment, split, now, periodEnd }) {
  const issued = now instanceof Date ? now : new Date();
  return {
    number,
    kind,
    title: documentTitle(kind),
    note: kind === 'invoice' ? '' : RECEIPT_NOTE,
    issued_at: issued.toISOString(),
    invoice_date: issued.toISOString().slice(0, 10),
    account_id: order.accountId,
    payment_id: payment.id,
    payment_method: (payment.method || '') || null,
    paid_at: payment.paidAt || issued.toISOString(),
    product: order.product,
    plan: order.plan,
    interval: order.interval,
    description: describe(order),
    service_period_end: periodEnd || null,
    currency: order.currency || 'EUR',
    vat_rate: split.rate,
    amount_net: money(split.net_cents),
    amount_vat: money(split.vat_cents),
    amount_gross: money(split.gross_cents),
    seller: { name: seller.name, address: seller.address, kvk: seller.kvk, vat: seller.vat },
    buyer: {
      email: buyer.email || '',
      company: buyer.company || '',
      address: buyer.address || '',
      vat: buyer.vat || '',
    },
  };
}

// The line the document carries when the account never filled in company
// details. Says what is missing and where to fix it, instead of printing a
// blank address block and hoping the reader works it out.
const BUYER_HINT = 'Add your company details on your account page to have them on the invoice';

function buyerIsComplete(buyer) {
  return !!(buyer && buyer.company && buyer.address);
}

// ── issuing ──────────────────────────────────────────────────────────────────
// `redis` is anything with get / set / incr / rPush / lRange, so the unit tests
// drive a Map and the route tests drive a real server. A missing or unready
// client is not an error here: it returns 'unavailable' and the caller logs it,
// because a customer who paid must never see his webhook fail over paperwork.
//
// Returns { result, number, record }:
//   'issued'      a new document exists
//   'existing'    this payment already has one; record is that one
//   'deferred'    another attempt holds the claim right now; try again later
//   'unavailable' no redis; nothing was written
async function issueDocument({ payment, order, seller, buyer, now, periodEnd }, redis) {
  if (!redis) return { result: 'unavailable', reason: 'no_redis' };
  if (!payment || !payment.id) return { result: 'unavailable', reason: 'no_payment' };

  const issued = now instanceof Date ? now : new Date();
  const claimKey = K.claim(payment.id);

  // Step 1: claim the payment. NX, so the winner is decided by redis and not by
  // who read first. Everything after this point happens at most once per
  // payment under normal operation.
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
    if (held && held.startsWith('PS-')) {
      let record = null;
      try { record = JSON.parse((await redis.get(K.doc(held))) || 'null'); } catch { record = null; }
      return { result: 'existing', number: held, record };
    }
    // A `pending:` value means an earlier attempt drew no number and died, or
    // is running right now. Wait it out rather than risk a second document;
    // Mollie retries, and the reissue path below picks it up.
    const started = parseInt(String(held || '').split(':')[1] || '0', 10);
    if (!(started && issued.getTime() - started > PENDING_TAKEOVER_MS)) {
      return { result: 'deferred', reason: 'claim_pending' };
    }
    // Older than the takeover window: the previous attempt is not coming back.
  }

  // Step 2: draw the number. Only ever reached for a payment that holds no
  // document, which is what keeps the series gapless.
  const year = issued.getUTCFullYear();
  let seq;
  try { seq = await redis.incr(K.seq(year)); }
  catch (e) { return { result: 'unavailable', reason: `seq_failed:${e.message}` }; }
  const number = formatNumber(year, seq);

  const split = splitVat(payment.amount && payment.amount.value, CATALOG_VAT_RATE);
  if (!split) return { result: 'unavailable', reason: 'bad_amount' };

  const kind = documentKind(seller);
  const record = buildRecord({ number, kind, seller, buyer, order, payment, split, now: issued, periodEnd });

  // Step 3: the record first, then the claim, then the lists. In that order a
  // crash leaves at worst a document nobody has indexed yet, never a claim
  // pointing at a number that has no document.
  try {
    await redis.set(K.doc(number), JSON.stringify(record));
    await redis.set(claimKey, number);
    if (order.accountId) await redis.rPush(K.byAcct(order.accountId), number);
    await redis.rPush(K.all, number);
  } catch (e) {
    return { result: 'unavailable', reason: `store_failed:${e.message}`, number };
  }
  return { result: 'issued', number, record };
}

// A chargeback takes the money back on the SAME tr_ id as the payment. There is
// no credit note yet (see the header), so the least dishonest thing available
// is a marker on the invoice that was reversed: the document keeps its number
// and its place in the series, and every reader can see the money went back.
// Never issues a new number.
async function recordReversal({ payment, now }, redis) {
  if (!redis || !payment || !payment.id) return { result: 'unavailable' };
  let number = null;
  try { number = await redis.get(K.claim(payment.id)); } catch { number = null; }
  if (!number || !number.startsWith('PS-')) return { result: 'none' };
  const at = (now instanceof Date ? now : new Date()).toISOString();
  try {
    await redis.set(K.reversed(number), JSON.stringify({ number, payment_id: payment.id, reversed_at: at }));
    const raw = await redis.get(K.doc(number));
    if (raw) {
      const rec = JSON.parse(raw);
      rec.reversed_at = at;
      await redis.set(K.doc(number), JSON.stringify(rec));
    }
  } catch (e) {
    return { result: 'unavailable', reason: e.message };
  }
  return { result: 'reversed', number };
}

// ── reading ──────────────────────────────────────────────────────────────────
// Only ever the account's own documents. listFor reads the per-account list,
// getFor reads one document and re-checks the account on the record itself, so
// a guessed number from another account's series answers 404 and not a stranger
// his invoice.
async function listFor(accountId, redis, limit = 200) {
  if (!redis || !accountId) return [];
  let numbers = [];
  try { numbers = (await redis.lRange(K.byAcct(accountId), -limit, -1)) || []; } catch { return []; }
  const out = [];
  for (const n of numbers.slice().reverse()) {
    try {
      const raw = await redis.get(K.doc(n));
      if (!raw) continue;
      const rec = JSON.parse(raw);
      if (rec && rec.account_id === accountId) out.push(rec);
    } catch { /* one unreadable record must not hide the rest */ }
  }
  return out;
}

async function getFor(accountId, number, redis) {
  if (!redis || !accountId || !parseNumber(number)) return null;
  try {
    const raw = await redis.get(K.doc(number));
    if (!raw) return null;
    const rec = JSON.parse(raw);
    return rec && rec.account_id === accountId ? rec : null;
  } catch { return null; }
}

module.exports = {
  CATALOG_VAT_RATE, K, BUYER_HINT, RECEIPT_NOTE, PENDING_TAKEOVER_MS,
  sellerFromEnv, documentKind, documentTitle, buyerIsComplete,
  centsOf, money, splitVat, formatNumber, parseNumber, describe, buildRecord,
  issueDocument, recordReversal, listFor, getFor,
};
