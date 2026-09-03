'use strict';
// One chronological list of everything that has happened to a customer's money
// and to his term, built from records that already exist.
//
// WHAT WAS WRONG. /account has a "Billing history" block, and it said "No
// billing events yet" to a customer who had paid, been invoiced, and watched
// his term run out. The only feed behind it was the admin audit log, which
// records plan_changed for an ADMIN action and knows nothing about a
// self-serve Mollie payment. So the one page a paying customer looks at when he
// wonders what he was charged showed him nothing at all.
//
// NO NEW STORAGE. Everything below is derived:
//   - payments and refunds  -> the invoice and credit-note records
//                              (lib/invoice.js, lib/credit-note.js)
//   - a term that ended     -> the paid period on those same records, cross-read
//                              against the plan-expiry index and its "already
//                              told him" markers (lib/plan-expiry.js)
// Adding a third store for "billing events" would mean a fourth thing that can
// disagree with the other three. A derived list cannot drift from the documents
// it is derived from.
//
// WHY A TERM END IS NOT SIMPLY "service_period_end IS IN THE PAST".
// A renewal bought before the period ran out EXTENDS it (lib/billing.js
// extendFrom), so the earlier period end is not a moment anything ended: the
// customer never lost access and never saw a mail. A period end is a real end
// only when no later period was bought on or before it. Renew late, after a
// lapse, and both ends are real, and both belong in the list, which is exactly
// what a customer reading his own history needs to see.
//
// The plan-expiry marker is read but never required. It says a mail went out
// (and when), which is worth showing; a term that ended while the mailer was
// unconfigured still ended, and still gets its line.

const invoice = require('./invoice');
const planExpiry = require('./plan-expiry');
const entitlements = require('./entitlements');

const PRODUCT_NAME = Object.freeze({ parasign: 'ParaSign', parasend: 'ParaSend' });

function productName(product) {
  return PRODUCT_NAME[product] || product || 'plan';
}

function tierName(tier) {
  const t = String(tier || '');
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : '';
}

// ── the money rows ───────────────────────────────────────────────────────────
// One row per document, in both series. The amount is the document's own total,
// so a credit note is negative and the column adds up to what the customer
// actually paid over the whole list.
function documentRow(rec) {
  const isCredit = rec.kind === 'credit_note';
  const label = isCredit
    ? `${rec.title || 'Credit note'} for invoice ${rec.credit_for}${rec.partial ? ' (partial)' : ''}`
    : rec.description || rec.title || 'Payment';
  return {
    ts: rec.issued_at,
    type: isCredit ? 'credit_note' : 'invoice',
    label,
    detail: isCredit
      ? (rec.reason === 'chargeback' ? 'Charged back' : 'Refunded')
      : (rec.kind === 'invoice' ? 'Paid' : 'Paid, receipt issued'),
    amount: rec.amount_gross,
    currency: rec.currency || 'EUR',
    document: rec.number,
    document_kind: rec.kind,
    credit_for: isCredit ? rec.credit_for : null,
    reversed_at: (!isCredit && rec.reversed_at) || null,
    pdf_url: `/v2/billing/invoices/${rec.number}.pdf`,
  };
}

// ── the term rows ────────────────────────────────────────────────────────────
// Candidate ends per product, from the documents that bought them. Sorted by
// the period end so "was this one renewed" is a scan and not a nested search.
function termEndsFromDocuments(records, nowMs) {
  const byProduct = new Map();
  for (const rec of records) {
    if (!rec || rec.kind === 'credit_note') continue;
    if (!rec.product || !rec.service_period_end) continue;
    // A fully reversed payment bought no term. Leaving it in would tell a
    // customer his plan ended on a date it never started.
    if (rec.reversed_at) continue;
    const end = Date.parse(rec.service_period_end);
    const issued = Date.parse(rec.issued_at);
    if (Number.isNaN(end)) continue;
    const list = byProduct.get(rec.product) || [];
    list.push({ end, issued: Number.isNaN(issued) ? end : issued, plan: rec.plan, iso: rec.service_period_end });
    byProduct.set(rec.product, list);
  }
  const out = [];
  for (const [product, list] of byProduct) {
    list.sort((a, b) => a.end - b.end);
    for (const term of list) {
      // Renewed: some other period reaches further AND was bought before this
      // one ran out, so nothing ended here.
      const renewed = list.some((other) => other.end > term.end && other.issued <= term.end);
      if (renewed) continue;
      if (term.end > nowMs) continue;
      out.push({ product, endsAt: term.end, iso: term.iso, tier: term.plan });
    }
  }
  return out;
}

// The plan-expiry index knows about periods that no document did: a plan set by
// an admin, or one granted before the invoice module existed. Two keyed reads,
// one per product, never a scan.
async function termEndFromIndex(accountId, redis, nowMs) {
  const out = [];
  for (const product of entitlements.PRODUCTS) {
    let meta = null;
    try { meta = JSON.parse(await redis.hGet(planExpiry.META_HASH, planExpiry.memberOf(accountId, product)) || 'null'); }
    catch { meta = null; }
    if (!meta || !meta.paid_until) continue;
    const at = Date.parse(meta.paid_until);
    if (Number.isNaN(at) || at > nowMs) continue;
    out.push({ product, endsAt: at, iso: meta.paid_until, tier: meta.tier });
  }
  return out;
}

// Did the customer get the "your plan has ended" mail for this exact period,
// and when. The marker name carries the period, so it is constructed and read
// by key; nothing is scanned.
async function endedNoticeAt(accountId, product, iso, redis) {
  try {
    const raw = await redis.get(planExpiry.noticeKey('ended', accountId, product, iso));
    const ms = parseInt(String(raw || ''), 10);
    return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : null;
  } catch { return null; }
}

function termRow({ product, endsAt, tier, notifiedAt }) {
  const plan = `${productName(product)} ${tierName(tier)}`.trim();
  return {
    ts: new Date(endsAt).toISOString(),
    type: 'term_ended',
    label: `${plan} term ended`,
    detail: 'Account back on Community',
    amount: null,
    currency: null,
    document: null,
    notified_at: notifiedAt || null,
  };
}

// ── the list ─────────────────────────────────────────────────────────────────
// Never throws and never half-answers: a redis that drops out mid-read costs
// the rows it had not reached, and the customer still sees the rest. `limit`
// caps what goes over the wire; the documents themselves stay complete in the
// invoice list beside it.
async function build({ accountId, redis, now, limit = 100 } = {}) {
  if (!accountId || !redis) return [];
  const nowMs = (now instanceof Date ? now : new Date()).getTime();
  let records = [];
  try { records = await invoice.listFor(accountId, redis); } catch { records = []; }

  const rows = [];
  for (const rec of records) {
    try { rows.push(documentRow(rec)); } catch { /* one bad record must not empty the list */ }
  }

  // Both sources of a term end, deduplicated on the period itself: the index
  // holds the CURRENT period, which is usually the same one the last document
  // bought, and showing it twice would read as two lapses.
  const ends = termEndsFromDocuments(records, nowMs);
  let indexed = [];
  try { indexed = await termEndFromIndex(accountId, redis, nowMs); } catch { indexed = []; }
  const seen = new Set(ends.map((e) => `${e.product}|${e.endsAt}`));
  for (const e of indexed) {
    if (seen.has(`${e.product}|${e.endsAt}`)) continue;
    seen.add(`${e.product}|${e.endsAt}`);
    ends.push(e);
  }
  for (const e of ends) {
    rows.push(termRow({ ...e, notifiedAt: await endedNoticeAt(accountId, e.product, e.iso, redis) }));
  }

  rows.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
  return rows.slice(0, limit);
}

module.exports = { build, documentRow, termRow, termEndsFromDocuments, termEndFromIndex, productName, tierName };
