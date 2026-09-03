'use strict';
// The books, for one period, in one download.
//
// WHY THIS FILE EXISTS. lib/invoice.js and lib/credit-note.js write every
// document as a flat JSON record in redis and never throw one away. That is the
// archive; it is not a bookkeeping export. Until now the only way to get a
// quarter of invoices out of the relay was to read them one account at a time
// through /v2/billing/invoices, or to type them over into an accounting
// package. Typing over an invoice is how a VAT return ends up not matching the
// bank.
//
// So: one admin route, one period, every document that period holds, in the two
// shapes an accountant actually accepts. CSV for a spreadsheet, JSON for a
// script, and a zip of the PDFs for the folder that has to survive seven years
// (AWR art. 52). This layer is READ ONLY. It draws no numbers, changes no
// record, and cannot make a document exist or stop existing.
//
// THE CSV IS FOR EXCEL IN THE NETHERLANDS, and that decides three things that
// look like details and are not:
//   - the separator is a semicolon. A Dutch Excel splits on the list separator
//     of the locale, which is ';', and a comma-separated file opens as one
//     column per row.
//   - the file starts with a UTF-8 BOM. Without it Excel reads the bytes as the
//     ANSI code page and a customer called "Kraüs B.V." arrives mangled.
//   - amounts use a comma as the decimal mark. "603,79" is a number in a Dutch
//     Excel; "603.79" is text, and text does not add up.
// The JSON does the opposite on all three counts, on purpose: a dot, no BOM,
// and the same field names the stored record uses.
//
// WHAT A ROW IS. One document: an invoice (PS), a payment receipt (PS without a
// seller VAT id) or a credit note (CN). A credit note carries NEGATIVE net, VAT
// and gross, exactly as the record stores them, and names the invoice it
// credits. Nothing is netted off and nothing is summarised away: the reader is
// a bookkeeper who has to see both documents.

const invoice = require('./invoice');

// A guard, not a page size. The global list holds every document ever issued;
// reading it whole is one round trip plus one GET per number, and this is the
// point past which that stops being a sensible thing to do in a request.
const MAX_DOCUMENTS = 20000;

// ── dates ────────────────────────────────────────────────────────────────────
// The period is compared on `invoice_date`, the YYYY-MM-DD the document itself
// carries, and not on issued_at. A document states one date and that is the one
// the bookkeeper files it under; a timezone that moves a 23:50 invoice into the
// next month would move it out of the VAT return it belongs to.
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function isDate(value) {
  if (!DATE_RE.test(String(value || ''))) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

// Both ends inclusive. A quarter is 2026-07-01 to 2026-09-30 and both of those
// days have invoices on them.
function inPeriod(date, from, to) {
  const d = String(date || '');
  if (!DATE_RE.test(d)) return false;
  return d >= from && d <= to;
}

// ── money ────────────────────────────────────────────────────────────────────
// The records store amounts as strings, and a credit note stores them negative
// ("-603.79"). invoice.centsOf is deliberately unsigned (it parses a Mollie
// amount, which never is), so the sign is handled here rather than loosened
// there.
function signedCents(value) {
  const s = String(value == null ? '' : value).trim();
  const neg = s.startsWith('-');
  const cents = invoice.centsOf(neg ? s.slice(1) : s);
  if (!Number.isFinite(cents)) return NaN;
  return neg ? -cents : cents;
}

// "603.79" -> "603,79", "-603.79" -> "-603,79". Only ever applied on the way
// into the CSV; the JSON keeps the dot.
function commaDecimal(value) {
  return String(value == null ? '' : value).replace('.', ',');
}

// ── a row ────────────────────────────────────────────────────────────────────
// Twelve columns and one derived one. `type` is the record's own kind
// ('invoice', 'receipt' or 'credit_note') rather than a label, because that is
// the field a script would filter on, and the difference between an invoice and
// a receipt is a real one here (a receipt has no seller VAT id and may not be
// deducted from).
//
// customer_name is the company when the account filled one in and the email
// address when it did not, so the column is never empty on a document that has
// a buyer at all. The email keeps its own column either way.
const COLUMNS = [
  'number', 'date', 'type', 'customer_name', 'customer_email', 'customer_vat',
  'description', 'amount_net', 'vat_rate', 'amount_vat', 'amount_gross',
  'currency', 'payment_id', 'credit_for', 'moneybird_id',
];

const MONEY_COLUMNS = new Set(['amount_net', 'amount_vat', 'amount_gross']);

function rowOf(record) {
  const buyer = (record && record.buyer) || {};
  return {
    number: record.number || '',
    date: record.invoice_date || '',
    type: record.kind || '',
    customer_name: buyer.company || buyer.email || '',
    customer_email: buyer.email || '',
    customer_vat: buyer.vat || '',
    description: record.description || '',
    amount_net: record.amount_net || '',
    vat_rate: record.vat_rate == null ? '' : String(record.vat_rate),
    amount_vat: record.amount_vat || '',
    amount_gross: record.amount_gross || '',
    currency: record.currency || 'EUR',
    payment_id: record.payment_id || '',
    credit_for: record.credit_for || '',
    moneybird_id: record.moneybird_id || '',
  };
}

// ── CSV ──────────────────────────────────────────────────────────────────────
const BOM = '\uFEFF';
const SEP = ';';
// CRLF, which is what RFC 4180 says and what Excel writes itself. A lone LF is
// read fine by Excel and badly by half the older tools an accountant uses.
const EOL = '\r\n';

// A field is quoted when it holds the separator, a quote or a line break, and a
// quote inside a quoted field is doubled. Nothing else is escaped: a formula
// injection guard belongs on a file that is executed, and every value here is a
// number, a date or a name that came out of our own record.
function csvField(value) {
  const s = String(value == null ? '' : value);
  if (s.includes(SEP) || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function toCsv(rows) {
  const lines = [COLUMNS.map(csvField).join(SEP)];
  for (const r of rows) {
    lines.push(COLUMNS.map((c) => csvField(MONEY_COLUMNS.has(c) ? commaDecimal(r[c]) : r[c])).join(SEP));
  }
  return BOM + lines.join(EOL) + EOL;
}

// ── totals ───────────────────────────────────────────────────────────────────
// The three sums a VAT return asks for, over the period, with credit notes
// counted negative because that is how they are stored. Returned as the same
// dotted strings the rows use, so a reader never has to know these were cents.
function totalsOf(rows) {
  let net = 0; let vat = 0; let gross = 0;
  for (const r of rows) {
    const n = signedCents(r.amount_net); const v = signedCents(r.amount_vat); const g = signedCents(r.amount_gross);
    if (Number.isFinite(n)) net += n;
    if (Number.isFinite(v)) vat += v;
    if (Number.isFinite(g)) gross += g;
  }
  return { amount_net: invoice.money(net), amount_vat: invoice.money(vat), amount_gross: invoice.money(gross) };
}

// ── reading ──────────────────────────────────────────────────────────────────
// The global append-only list of every number ever drawn, both series, oldest
// first. Documents are then loaded one by one and filtered on their own date. A
// number in the list with no document behind it is the gap lib/invoice.js
// documents (a crash between INCR and the write-back); it is counted and
// reported rather than skipped in silence, because a hole in the sequence is
// exactly what an audit looks for.
async function collect({ from, to, redis, limit = MAX_DOCUMENTS }) {
  const out = { rows: [], records: [], missing: [], scanned: 0 };
  if (!redis) return out;
  let numbers = [];
  try { numbers = (await redis.lRange(invoice.K.all, -limit, -1)) || []; } catch { return out; }
  out.scanned = numbers.length;
  for (const n of numbers) {
    let rec = null;
    try { rec = JSON.parse((await redis.get(invoice.K.doc(n))) || 'null'); } catch { rec = null; }
    if (!rec) { out.missing.push(n); continue; }
    if (!inPeriod(rec.invoice_date, from, to)) continue;
    out.records.push(rec);
    out.rows.push(rowOf(rec));
  }
  // By date, then by number, so an export of the same period is byte-identical
  // whichever order the documents happened to be written in. Numbers are
  // fixed-width per series and per year, so a plain string compare orders them.
  const key = (r) => `${r.date}|${r.number}`;
  const order = new Map(out.rows.map((r, i) => [r, i]));
  out.rows.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : order.get(a) - order.get(b)));
  const byNumber = new Map(out.records.map((r) => [r.number, r]));
  out.records = out.rows.map((r) => byNumber.get(r.number)).filter(Boolean);
  return out;
}

// The whole export, in the shape the route serves. Never throws on a document
// it cannot read: one unreadable record must not cost the accountant the other
// three hundred.
async function build({ from, to, redis, limit }) {
  if (!isDate(from) || !isDate(to)) return { error: 'bad_period' };
  if (from > to) return { error: 'bad_period' };
  const found = await collect({ from, to, redis, limit });
  return {
    from,
    to,
    count: found.rows.length,
    scanned: found.scanned,
    missing: found.missing,
    totals: totalsOf(found.rows),
    columns: COLUMNS.slice(),
    rows: found.rows,
    records: found.records,
  };
}

// ── the zip ──────────────────────────────────────────────────────────────────
// One PDF per document, rendered from the stored record exactly as the customer
// download route renders it, plus the ledger file itself so the archive is
// complete on its own. The renderer is injected (relay.js passes
// lib/invoice-pdf.render) so this module stays free of the PDF layer and the
// test can drive a stub.
//
// A document whose PDF fails to render is LISTED in a failures file inside the
// archive rather than dropped: a zip that is quietly one invoice short is worse
// than one that says which invoice is missing and why.
function fileBase(from, to) {
  return `paramant-billing-${from}_${to}`;
}

function buildZipEntries(exported, { render, format = 'csv', now } = {}) {
  const base = fileBase(exported.from, exported.to);
  const stamp = now instanceof Date ? now : new Date();
  const entries = [];
  const failures = [];
  for (const rec of exported.records || []) {
    let pdf = null;
    try { pdf = typeof render === 'function' ? render(rec, { buyerHint: invoice.BUYER_HINT }) : null; }
    catch (e) { failures.push(`${rec.number}: ${e.message}`); continue; }
    if (!pdf) { failures.push(`${rec.number}: not_rendered`); continue; }
    entries.push({ name: `${base}/${rec.number}.pdf`, data: pdf, date: new Date(rec.issued_at || stamp) });
  }
  const ledger = format === 'json'
    ? { name: `${base}/${base}.json`, data: Buffer.from(JSON.stringify(asJson(exported), null, 2), 'utf8'), date: stamp }
    : { name: `${base}/${base}.csv`, data: Buffer.from(toCsv(exported.rows), 'utf8'), date: stamp };
  entries.unshift(ledger);
  if (failures.length) {
    entries.push({
      name: `${base}/RENDER-FAILURES.txt`,
      data: Buffer.from(`${failures.join('\n')}\n`, 'utf8'),
      date: stamp,
    });
  }
  return { entries, failures };
}

// The JSON body. `records` is dropped: the rows are the export, and the raw
// records carry the seller and buyer blocks of every customer in the period,
// which is more than a ledger line needs to be.
function asJson(exported) {
  return {
    ok: true,
    from: exported.from,
    to: exported.to,
    count: exported.count,
    totals: exported.totals,
    columns: exported.columns,
    missing: exported.missing,
    rows: exported.rows,
  };
}

module.exports = {
  MAX_DOCUMENTS, COLUMNS, BOM, SEP, EOL,
  isDate, inPeriod, signedCents, commaDecimal, rowOf, csvField, toCsv,
  totalsOf, collect, build, asJson, fileBase, buildZipEntries,
};
