'use strict';
// Putting the documents this relay issues into Moneybird, without anybody
// typing them over.
//
// WHY EXTERNAL SALES INVOICES AND NOT SALES INVOICES. Moneybird has two shapes
// for outgoing revenue. A *sales invoice* is one Moneybird itself creates: it
// draws the number from a workflow, it fills the invoice date when the document
// is SENT, and it renders its own PDF. Everything about that fights this relay,
// which has already drawn PS-2026-0001 from its own gapless series
// (lib/invoice.js), already stamped the date, already rendered the PDF and
// already mailed it to the customer. Pushing it as a sales invoice would give
// the same money a second number and risk Moneybird mailing the customer again.
//
// An *external sales invoice* is Moneybird's word for exactly our case: "an
// invoice created in another system that you want to import for a complete
// overview of your revenue". It has no workflow and no numbering; our number
// goes in `reference`, it lands in the books straight away without a send step,
// and the PDF we already made is attached to it. So that is what this pushes.
//
// THE RULES THIS MODULE HOLDS TO.
//
// 1. THE PUSH IS AFTERCARE, NEVER A GATE. A payment is granted, the entitlement
//    moves and the invoice is issued whether or not Moneybird is configured,
//    reachable, or having a good day. Nothing here is awaited on the webhook
//    path in a way that can fail it, nothing here throws to a caller, and a
//    Moneybird outage costs a bookkeeping line, never a customer his plan.
//
// 2. ONCE PER DOCUMENT. The Moneybird id is written back onto the stored record
//    (`moneybird_id`), and a record that has one is never pushed again. The
//    check is done against redis at push time and not against the copy in
//    memory, so a retry that races the first attempt reads what the first
//    attempt wrote.
//
// 3. A FAILED PUSH IS REMEMBERED, NOT SWALLOWED. The document number goes into
//    a redis sorted set scored by the time of its next attempt, and a six-hour
//    sweep (same lock-and-interval pattern as lib/plan-expiry.js, against the
//    same redis, so five containers make one attempt between them) works
//    through what is due. Nothing is ever dropped from that set for being old:
//    a document that never reached the books has to stay visible.
//
// 4. AMOUNTS ARE SENT GROSS, TAX INCLUSIVE. The gross is the amount Mollie
//    actually collected and the amount that hit the bank; net and VAT on our
//    document are derived FROM it (net = round(gross / 1.21), VAT = the
//    remainder, see lib/invoice.js). Sending the net and letting Moneybird
//    multiply back up can differ by a cent on some amounts. Sending the gross
//    with `prices_are_incl_tax` asks Moneybird to do the same division we did,
//    so the two agree by construction, and the answer is checked against our
//    own totals afterwards anyway (see AMOUNT_TOLERANCE_CENTS).
//
// 5. NOTHING IS SENT THAT WAS NOT ASKED FOR. Without MONEYBIRD_TOKEN and
//    MONEYBIRD_ADMINISTRATION_ID this module does nothing at all: no request,
//    no queue entry, no log line per payment. Customer data leaving the relay
//    for a third party is a decision an operator makes on purpose.
//
// THE API, as of the v2 documentation (developer.moneybird.com):
//   POST /api/v2/{administration}/contacts.json
//   GET  /api/v2/{administration}/contacts.json?query=<email>
//   GET  /api/v2/{administration}/tax_rates.json?filter=percentage:21,tax_rate_type:sales_invoice
//   POST /api/v2/{administration}/external_sales_invoices.json
//   POST /api/v2/{administration}/external_sales_invoices/{id}/attachment.json
// Bearer token in the Authorization header. Ids come back as decimal strings
// that do not survive a JSON number, so they are kept as strings throughout.

const https = require('https');
const invoice = require('./invoice');

// Hard-coded, exactly as lib/mollie.js hard-codes api.mollie.com: the caller
// never supplies a URL, so there is no SSRF surface here at all.
const MONEYBIRD_HOST = 'moneybird.com';
const API_PREFIX = '/api/v2';

// Moneybird allows 150 requests per five minutes per IP. A push is three or
// four requests and the sweep is the only thing that ever makes them in a
// batch, so the ceiling below is what keeps one sweep from spending the whole
// window and starving the next.
const SWEEP_BATCH = 20;

// Six hours, plus one pass shortly after boot. The same numbers and the same
// reasoning as lib/plan-expiry.js: long enough that five containers are not
// hammering one redis, short enough that a document that failed this morning
// is in the books today.
const SWEEP_INTERVAL_MS = 6 * 3600000;
const LOCK_TTL_MS = 10 * 60000;

// Backoff between attempts, doubling from fifteen minutes and stopping at a
// day. A Moneybird that is down for an afternoon costs four attempts; one that
// is misconfigured costs one a day and a log line a day, until somebody fixes
// it. Nothing is ever given up on.
const RETRY_BASE_MS = 15 * 60000;
const RETRY_MAX_MS = 24 * 3600000;

// Past this many attempts the log line goes from warn to error. It does not
// stop the retries: a document that is not in the books is not less wrong for
// having been wrong for a week.
const LOUD_AFTER_ATTEMPTS = 8;

// How far the total Moneybird computed may differ from ours before it is worth
// a line in the log. Zero: the two do the same division on the same gross, and
// a cent of difference means one of the two assumptions above is wrong and
// somebody should know.
const AMOUNT_TOLERANCE_CENTS = 0;

const HTTP_TIMEOUT_MS = 10000;

// What Moneybird shows as the origin of the document, next to `origin: api`.
const SOURCE = 'PARAMANT relay';

// The rate every catalog price carries (lib/invoice.js: CATALOG_VAT_RATE). The
// id behind it is looked up per administration, because it is Mick's own
// bookkeeping and nobody else can know the number.
const TAX_RATE_TYPE = 'sales_invoice';

// ── redis layout ─────────────────────────────────────────────────────────────
// The pending set has no TTL, for the same reason the documents have none: an
// unbooked invoice does not become acceptable by ageing. The two caches DO
// expire, because they hold ids that live in somebody else's system.
const K = {
  pending:  'paramant:billing:moneybird:pending',      // ZSET number -> next attempt (epoch ms)
  attempts: 'paramant:billing:moneybird:attempts',     // HASH number -> attempt count
  lock:     'paramant:billing:moneybird:lock',
  contact:  (email) => `paramant:billing:moneybird:contact:${String(email).toLowerCase()}`,
  taxRate:  (pct) => `paramant:billing:moneybird:tax_rate:${pct}`,
};

const CONTACT_TTL_S = 30 * 86400;
const TAX_RATE_TTL_S = 86400;

// ── configuration ────────────────────────────────────────────────────────────
// Takes an injectable env object, the pattern lib/invoice.js and
// lib/entitlements.js use, so the tests build a configuration without touching
// process.env.
//
// The administration id is checked to be digits before it is ever put in a
// path. It comes from the environment and it is the only part of any URL this
// module builds that is not a literal; a value with a slash or a query string
// in it would otherwise aim our authenticated requests at a different endpoint
// than the one the code reads.
function configFromEnv(envIn) {
  const env = envIn || process.env;
  const token = (env.MONEYBIRD_TOKEN || '').trim();
  const administrationId = (env.MONEYBIRD_ADMINISTRATION_ID || '').trim();
  return { token, administrationId, valid: /^\d{1,32}$/.test(administrationId) };
}

function configured(cfg) {
  return !!(cfg && cfg.token && cfg.administrationId && cfg.valid);
}

// ── the wire ─────────────────────────────────────────────────────────────────
// One request, JSON in and JSON out, or a multipart body for the one endpoint
// that takes a file. Injectable as `http` everywhere below so the tests drive a
// stub and never open a socket; the shape of what it returns is exactly what
// this returns.
function httpsRequest({ method, path, token, json, multipart }) {
  return new Promise((resolve, reject) => {
    let body = null;
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (multipart) {
      body = multipart.body;
      headers['Content-Type'] = `multipart/form-data; boundary=${multipart.boundary}`;
      headers['Content-Length'] = body.length;
    } else if (json !== undefined && json !== null) {
      body = Buffer.from(JSON.stringify(json), 'utf8');
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = body.length;
    }
    const req = https.request({ host: MONEYBIRD_HOST, port: 443, method, path, headers, timeout: HTTP_TIMEOUT_MS }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }
        resolve({ status: res.statusCode, body: parsed, text, headers: res.headers });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('moneybird_timeout')));
    if (body) req.write(body);
    req.end();
  });
}

function apiPath(cfg, tail) {
  return `${API_PREFIX}/${cfg.administrationId}/${tail}`;
}

// A multipart/form-data body with one file field, built by hand. The single
// alternative is a dependency, and this is the only multipart request the relay
// makes anywhere.
function multipartFile(fieldName, filename, contentType, data) {
  const boundary = `----paramant${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  const head = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n` +
    `Content-Type: ${contentType}\r\n\r\n`, 'utf8');
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  return { boundary, body: Buffer.concat([head, data, tail]) };
}

// Moneybird answers a validation failure with 422 and a per-field object, and a
// bad parameter with 400 and a `symbolic` block. Both are worth having in one
// log line and neither is worth a stack trace.
function errorOf(res) {
  if (!res) return 'no_response';
  const b = res.body;
  if (b && typeof b.error === 'string') return b.error;
  if (b && b.error && typeof b.error === 'object') {
    return Object.entries(b.error).map(([k, v]) => `${k}: ${[].concat(v).join(', ')}`).join('; ');
  }
  if (typeof b === 'string') return b;
  return `http_${res.status}`;
}

// A 401, a 403 or a 422 is a configuration or a data problem: retrying it on a
// timer changes nothing until a human changes something. It is still queued (a
// token can be replaced without a deploy), it just says so in the log.
function isPermanent(status) {
  return status === 401 || status === 403 || status === 404 || status === 422;
}

// ── contacts ─────────────────────────────────────────────────────────────────
// Moneybird's ?query= is a substring search across a dozen fields, so a query
// for "a@b.test" can come back with contacts that merely mention it. The exact
// comparison is done here, against both address fields Moneybird keeps, and a
// near-miss is treated as no match: creating a second contact is recoverable,
// booking revenue against the wrong customer is not.
function contactMatches(contact, email) {
  const want = String(email || '').trim().toLowerCase();
  if (!want) return false;
  const fields = [contact && contact.email, contact && contact.send_invoices_to_email];
  for (const f of fields) {
    if (!f) continue;
    if (String(f).toLowerCase().split(',').map((s) => s.trim()).includes(want)) return true;
  }
  return false;
}

// The relay stores the buyer address as one free-text block, because that is
// what the customer typed on his account page. Moneybird wants it in fields. A
// line that has the shape of a Dutch postcode plus a place becomes zipcode and
// city; everything else is passed through in address1 and address2 unchanged.
// A heuristic, deliberately: it can only ever move text between fields on the
// contact card, and it never blocks a push.
const NL_POSTCODE = /^(\d{4}\s?[A-Za-z]{2})\s+(.+)$/;

function addressFields(block) {
  const lines = String(block || '').split('\n').map((l) => l.trim()).filter(Boolean);
  const out = { address1: '', address2: '', zipcode: '', city: '' };
  const rest = [];
  for (const line of lines) {
    const m = !out.zipcode && NL_POSTCODE.exec(line);
    if (m) { out.zipcode = m[1].toUpperCase(); out.city = m[2]; continue; }
    rest.push(line);
  }
  out.address1 = rest.shift() || '';
  out.address2 = rest.join(', ');
  return out;
}

// Moneybird refuses a contact with no name at all, so a buyer who never filled
// in a company falls back to the address we do have. It is what the account is
// known by here, and it keeps the contact card findable.
function contactPayload(buyer) {
  const b = buyer || {};
  const addr = addressFields(b.address);
  const contact = {
    company_name: (b.company || b.email || '').trim(),
    address1: addr.address1,
    address2: addr.address2,
    zipcode: addr.zipcode,
    city: addr.city,
  };
  // `email` is NOT writable on a Moneybird contact: the readable `email` field
  // is derived from the invoice address. Sending it would be silently dropped.
  if (b.email) contact.send_invoices_to_email = b.email;
  if (b.vat) contact.tax_number = b.vat;
  return { contact };
}

// The contact for this document's buyer: from the cache, else looked up on the
// email address, else created. Returns { id, created } or throws an Error whose
// `permanent` says whether a retry could ever help.
async function ensureContact({ cfg, buyer, redis, http }) {
  const email = String((buyer && buyer.email) || '').trim();
  if (redis && email) {
    try {
      const cached = await redis.get(K.contact(email));
      if (cached) return { id: cached, created: false, cached: true };
    } catch { /* a cache that cannot be read is a cache that is not used */ }
  }

  if (email) {
    const found = await http({
      method: 'GET', token: cfg.token,
      path: apiPath(cfg, `contacts.json?query=${encodeURIComponent(email)}`),
    });
    if (found.status === 200 && Array.isArray(found.body)) {
      const hit = found.body.find((c) => contactMatches(c, email));
      if (hit && hit.id) {
        const id = String(hit.id);
        if (redis) { try { await redis.set(K.contact(email), id, { EX: CONTACT_TTL_S }); } catch { /* best effort */ } }
        return { id, created: false, cached: false };
      }
    } else if (found.status !== 200) {
      const e = new Error(`contact_lookup_failed: ${errorOf(found)}`);
      e.permanent = isPermanent(found.status);
      throw e;
    }
  }

  const created = await http({
    method: 'POST', token: cfg.token,
    path: apiPath(cfg, 'contacts.json'),
    json: contactPayload(buyer),
  });
  if (created.status !== 201 || !created.body || !created.body.id) {
    const e = new Error(`contact_create_failed: ${errorOf(created)}`);
    e.permanent = isPermanent(created.status);
    throw e;
  }
  const id = String(created.body.id);
  if (redis && email) { try { await redis.set(K.contact(email), id, { EX: CONTACT_TTL_S }); } catch { /* best effort */ } }
  return { id, created: true, cached: false };
}

// ── the tax rate ─────────────────────────────────────────────────────────────
// Moneybird keeps one rate record per percentage PER TYPE, so filtering on the
// percentage alone returns the sales rate and the purchase rate and picking the
// wrong one books the VAT on the wrong side. Both halves of the filter are
// therefore mandatory, and the answer's percentage (which comes back as the
// string "21.0") is checked again here.
async function findTaxRateId({ cfg, percentage, redis, http }) {
  const pct = Number(percentage);
  if (!Number.isFinite(pct)) return null;
  const key = K.taxRate(pct);
  if (redis) {
    try { const cached = await redis.get(key); if (cached) return cached; } catch { /* not fatal */ }
  }
  const res = await http({
    method: 'GET', token: cfg.token,
    path: apiPath(cfg, `tax_rates.json?filter=${encodeURIComponent(`percentage:${pct},tax_rate_type:${TAX_RATE_TYPE}`)}`),
  });
  if (res.status !== 200 || !Array.isArray(res.body)) {
    const e = new Error(`tax_rate_lookup_failed: ${errorOf(res)}`);
    e.permanent = isPermanent(res.status);
    throw e;
  }
  const hit = res.body.find((r) => r && r.active !== false
    && r.tax_rate_type === TAX_RATE_TYPE
    && Math.abs(parseFloat(r.percentage) - pct) < 0.001);
  if (!hit || !hit.id) {
    // Not an error worth retrying on a timer: the administration does not have
    // a 21% sales rate, and no number of retries will conjure one. The push
    // goes ahead WITHOUT the rate id, and Moneybird applies the default of the
    // administration, which is the same rate in every ordinary setup.
    return null;
  }
  const id = String(hit.id);
  if (redis) { try { await redis.set(key, id, { EX: TAX_RATE_TTL_S }); } catch { /* best effort */ } }
  return id;
}

// ── the document ─────────────────────────────────────────────────────────────
// One detail line, because one document here is always one plan for one term.
// The description is the record's own, so what Moneybird shows is word for word
// what the PDF the customer holds shows.
//
// `period` is the term the money bought (invoice date to the end of the paid
// period), in Moneybird's YYYYMMDD..YYYYMMDD form. It is what lets the revenue
// be recognised over the year it covers rather than all in the month it was
// paid, which for a yearly plan is the difference between a sensible profit and
// loss and a spike.
function periodOf(record) {
  const start = String(record.invoice_date || '').replace(/-/g, '');
  const endIso = record.service_period_end ? String(record.service_period_end).slice(0, 10) : '';
  const end = endIso.replace(/-/g, '');
  if (!/^\d{8}$/.test(start) || !/^\d{8}$/.test(end) || end <= start) return null;
  return `${start}..${end}`;
}

function invoicePayload({ record, contactId, taxRateId }) {
  const detail = {
    description: record.description || record.title || record.number,
    price: record.amount_gross,
    amount: '1',
  };
  if (taxRateId) detail.tax_rate_id = taxRateId;
  const period = periodOf(record);
  if (period) detail.period = period;
  return {
    external_sales_invoice: {
      contact_id: contactId,
      reference: record.number,
      date: record.invoice_date,
      currency: record.currency || 'EUR',
      // The gross, tax inclusive. See rule 4 at the top of this file.
      prices_are_incl_tax: true,
      source: SOURCE,
      details_attributes: [detail],
    },
  };
}

// ── one push ─────────────────────────────────────────────────────────────────
// Deps:
//   record     the stored document (invoice, receipt or credit note)
//   redis      node-redis v4 client, or a stand-in with the same five commands
//   http       the request function above, or a stub
//   env        injectable environment
//   renderPdf  (record) -> Buffer, or omitted to push without an attachment
//   log        (level, event, fields)
//   now        Date, injectable
//
// Returns, and never throws:
//   { result: 'pushed',   id }        it is in Moneybird now
//   { result: 'existing', id }        it already was; nothing was sent
//   { result: 'disabled' }            no token or no administration id
//   { result: 'failed', reason, permanent, retry_at }   queued for the sweep
async function pushDocument(deps) {
  const d = deps || {};
  const log = typeof d.log === 'function' ? d.log : () => {};
  const now = d.now instanceof Date ? d.now : new Date();
  const cfg = d.cfg || configFromEnv(d.env);
  const http = typeof d.http === 'function' ? d.http : httpsRequest;
  const redis = d.redis || null;

  if (!configured(cfg)) {
    // One warning, and only when something IS set: a half-configured Moneybird
    // is a mistake somebody wants to hear about, an unconfigured one is the
    // documented default.
    if (cfg && (cfg.token || cfg.administrationId)) {
      log('warn', 'moneybird_not_configured', {
        token: !!cfg.token,
        administration: !!cfg.administrationId,
        administration_valid: !!cfg.valid,
      });
    }
    return { result: 'disabled' };
  }

  let record = d.record;
  if (!record || !record.number) return { result: 'failed', reason: 'no_record', permanent: true };

  // Rule 2: the freshest copy decides, not the one the caller is holding. A
  // sweep and a webhook can reach the same document at the same moment.
  if (redis) {
    try {
      const raw = await redis.get(invoice.K.doc(record.number));
      if (raw) record = JSON.parse(raw);
    } catch { /* the caller's copy is still a document */ }
  }
  if (record.moneybird_id) return { result: 'existing', id: String(record.moneybird_id) };

  try {
    const contact = await ensureContact({ cfg, buyer: record.buyer, redis, http });
    const taxRateId = await findTaxRateId({ cfg, percentage: record.vat_rate, redis, http });

    const created = await http({
      method: 'POST', token: cfg.token,
      path: apiPath(cfg, 'external_sales_invoices.json'),
      json: invoicePayload({ record, contactId: contact.id, taxRateId }),
    });
    if (created.status === 400 && redis && record.buyer && record.buyer.email) {
      // The one 400 worth reacting to: a cached contact id that Moneybird no
      // longer has. Drop the cache so the retry looks the contact up again
      // instead of failing on the same stale id every six hours.
      try { await redis.del(K.contact(record.buyer.email)); } catch { /* best effort */ }
    }
    if (created.status !== 201 || !created.body || !created.body.id) {
      const e = new Error(`invoice_create_failed: ${errorOf(created)}`);
      e.permanent = isPermanent(created.status);
      throw e;
    }
    const id = String(created.body.id);

    // What Moneybird made of our amount, checked against what the customer was
    // charged. A difference here means the tax assumption is wrong for this
    // administration, and it is worth a line long before it is worth a quarter
    // of wrong VAT returns.
    const ours = Math.abs(centsOfSigned(record.amount_gross));
    const theirs = Math.abs(centsOfSigned(created.body.total_price_incl_tax));
    if (Number.isFinite(ours) && Number.isFinite(theirs) && Math.abs(ours - theirs) > AMOUNT_TOLERANCE_CENTS) {
      log('warn', 'moneybird_amount_mismatch', {
        number: record.number, ours: record.amount_gross, moneybird: created.body.total_price_incl_tax,
      });
    }

    // The PDF, best effort and after the fact. A document that is in the books
    // without its attachment is a document that is in the books; failing the
    // whole push over it would queue a retry that creates a SECOND external
    // sales invoice for the same money.
    let attached = false;
    if (typeof d.renderPdf === 'function') {
      try {
        const pdf = d.renderPdf(record);
        if (pdf && pdf.length) {
          const part = multipartFile('file', `${record.number}.pdf`, 'application/pdf', pdf);
          const res = await http({
            method: 'POST', token: cfg.token,
            path: apiPath(cfg, `external_sales_invoices/${encodeURIComponent(id)}/attachment.json`),
            multipart: part,
          });
          attached = res.status >= 200 && res.status < 300;
          if (!attached) log('warn', 'moneybird_attachment_failed', { number: record.number, id, reason: errorOf(res) });
        }
      } catch (e) {
        log('warn', 'moneybird_attachment_failed', { number: record.number, id, err: e.message });
      }
    }

    // The write-back is what makes rule 2 true. It happens BEFORE the queue is
    // cleared, so a crash in between leaves a queued document that the next
    // sweep finds already pushed and simply drops.
    await writeBack({ redis, record, id, contactId: contact.id, attached, now });
    await clearPending({ redis, number: record.number });

    log('info', 'moneybird_pushed', {
      number: record.number, id, contact: contact.id, contact_created: contact.created, attached,
    });
    return { result: 'pushed', id, contact_id: contact.id, contact_created: contact.created, attached };
  } catch (e) {
    const queued = await queuePending({ redis, number: record.number, now, permanent: !!e.permanent });
    log(queued.attempts >= LOUD_AFTER_ATTEMPTS ? 'error' : 'warn', 'moneybird_push_failed', {
      number: record.number, reason: e.message, permanent: !!e.permanent,
      attempts: queued.attempts, retry_at: queued.retryAt,
    });
    return { result: 'failed', reason: e.message, permanent: !!e.permanent, attempts: queued.attempts, retry_at: queued.retryAt };
  }
}

// The record amounts are strings and a credit note's are negative, which
// invoice.centsOf (written for a Mollie amount) does not accept. Same helper as
// lib/billing-export.js has, kept local rather than shared because loosening
// centsOf itself would loosen it on the invoicing path too.
function centsOfSigned(value) {
  const s = String(value == null ? '' : value).trim();
  const neg = s.startsWith('-');
  const cents = invoice.centsOf(neg ? s.slice(1) : s);
  if (!Number.isFinite(cents)) return NaN;
  return neg ? -cents : cents;
}

// Read, stamp, write. Read again rather than stamping the copy in hand: between
// the push starting and finishing, the credit-note path may have added a
// `credit_notes` back-reference to this same record, and writing a stale copy
// would erase it.
async function writeBack({ redis, record, id, contactId, attached, now }) {
  if (!redis) return false;
  try {
    const raw = await redis.get(invoice.K.doc(record.number));
    const rec = raw ? JSON.parse(raw) : Object.assign({}, record);
    rec.moneybird_id = id;
    rec.moneybird_contact_id = contactId || null;
    rec.moneybird_pushed_at = (now instanceof Date ? now : new Date()).toISOString();
    rec.moneybird_attachment = !!attached;
    await redis.set(invoice.K.doc(record.number), JSON.stringify(rec));
    return true;
  } catch { return false; }
}

// ── the queue ────────────────────────────────────────────────────────────────
function backoffMs(attempts) {
  const n = Math.max(1, attempts);
  return Math.min(RETRY_BASE_MS * Math.pow(2, n - 1), RETRY_MAX_MS);
}

async function queuePending({ redis, number, now, permanent }) {
  const at = (now instanceof Date ? now : new Date()).getTime();
  if (!redis) return { attempts: 0, retryAt: null };
  let attempts = 0;
  try {
    attempts = await redis.hIncrBy(K.attempts, number, 1);
  } catch { attempts = 1; }
  // A permanent failure (a bad token, a rejected field) is retried on the SLOW
  // end of the backoff from the start. It stays queued, because the fix for
  // most of them is a value in .env and no redeploy.
  const wait = permanent ? RETRY_MAX_MS : backoffMs(attempts);
  const retryAt = at + wait;
  try { await redis.zAdd(K.pending, [{ score: retryAt, value: number }]); } catch { /* best effort */ }
  return { attempts, retryAt: new Date(retryAt).toISOString() };
}

async function clearPending({ redis, number }) {
  if (!redis) return;
  try { await redis.zRem(K.pending, number); } catch { /* best effort */ }
  try { await redis.hDel(K.attempts, number); } catch { /* best effort */ }
}

// Everything waiting, oldest first, whether or not it is due yet. Read-only,
// for the operator who wants to know what is not in the books.
async function pending(redis, limit = 200) {
  if (!redis) return [];
  try { return (await redis.zRange(K.pending, 0, Math.max(0, limit - 1))) || []; } catch { return []; }
}

// ── the sweep ────────────────────────────────────────────────────────────────
// The lock is SET NX PX with a token that is checked before the release, taken
// straight from lib/plan-expiry.js: five relay containers run this line against
// one redis and exactly one of them may be pushing at a time, or the same
// document gets two external sales invoices.
function lockToken() {
  return `${process.pid}:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`;
}

async function acquireLock(redis, ttlMs, token) {
  const ok = await redis.set(K.lock, token, { NX: true, PX: ttlMs || LOCK_TTL_MS });
  return ok === 'OK' || ok === true;
}

async function releaseLock(redis, token) {
  const held = await redis.get(K.lock);
  if (held !== token) return false;
  await redis.del(K.lock);
  return true;
}

// Returns { ran, pushed, existing, failed, reason }.
async function runSweep(deps) {
  const d = deps || {};
  const redis = d.redis;
  const log = typeof d.log === 'function' ? d.log : () => {};
  const now = d.now instanceof Date ? d.now : new Date();
  const cfg = d.cfg || configFromEnv(d.env);
  const out = { ran: false, pushed: 0, existing: 0, failed: 0, reason: null };
  if (!configured(cfg)) { out.reason = 'disabled'; return out; }
  if (!redis || (redis.isReady === false)) { out.reason = 'no_redis'; return out; }

  const token = lockToken();
  let got = false;
  try { got = await acquireLock(redis, d.lockTtlMs || LOCK_TTL_MS, token); }
  catch (e) { out.reason = 'lock_error'; log('warn', 'moneybird_lock_failed', { err: e.message }); return out; }
  // On five containers this is the expected answer four times out of five.
  if (!got) { out.reason = 'locked'; return out; }
  out.ran = true;

  try {
    let due = [];
    try { due = (await redis.zRangeByScore(K.pending, 0, now.getTime())) || []; } catch { due = []; }
    for (const number of due.slice(0, d.batch || SWEEP_BATCH)) {
      let record = null;
      try { record = JSON.parse((await redis.get(invoice.K.doc(number))) || 'null'); } catch { record = null; }
      if (!record) {
        // A queued number with no document behind it can never be pushed. Drop
        // it from the queue and say so once, rather than retrying a hole every
        // six hours forever.
        log('warn', 'moneybird_retry_no_document', { number });
        await clearPending({ redis, number });
        continue;
      }
      const r = await pushDocument({ ...d, cfg, record, redis, now });
      if (r.result === 'pushed') out.pushed++;
      else if (r.result === 'existing') { out.existing++; await clearPending({ redis, number }); }
      else out.failed++;
    }
  } catch (e) {
    out.reason = 'sweep_error';
    log('warn', 'moneybird_sweep_failed', { err: e.message });
  } finally {
    try { await releaseLock(redis, token); } catch { /* the PX expiry is the backstop */ }
  }
  return out;
}

// One pass a short random delay after boot, then one every six hours. The
// timers are unref'd: this must never be the reason a process refuses to exit.
// Nothing at all is started when Moneybird is not configured.
function startMoneybirdPlanner(deps) {
  const d = deps || {};
  const log = typeof d.log === 'function' ? d.log : () => {};
  const cfg = d.cfg || configFromEnv(d.env);
  if (!configured(cfg)) return null;
  const intervalMs = d.intervalMs || SWEEP_INTERVAL_MS;
  const bootDelayMs = typeof d.bootDelayMs === 'number' ? d.bootDelayMs : 45000 + Math.floor(Math.random() * 30000);
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const r = await runSweep({ ...d, cfg, now: new Date() });
      if (r.ran && (r.pushed || r.failed || r.existing)) log('info', 'moneybird_sweep', r);
    } catch (e) {
      log('warn', 'moneybird_sweep_failed', { err: e.message });
    } finally { running = false; }
  };
  const boot = setTimeout(tick, bootDelayMs);
  const timer = setInterval(tick, intervalMs);
  if (boot.unref) boot.unref();
  if (timer.unref) timer.unref();
  log('info', 'moneybird_planner_started', { administration: cfg.administrationId, interval_ms: intervalMs });
  return { tick, stop() { clearTimeout(boot); clearInterval(timer); } };
}

module.exports = {
  MONEYBIRD_HOST, API_PREFIX, K, SOURCE, TAX_RATE_TYPE,
  SWEEP_INTERVAL_MS, LOCK_TTL_MS, SWEEP_BATCH, RETRY_BASE_MS, RETRY_MAX_MS, LOUD_AFTER_ATTEMPTS,
  configFromEnv, configured, httpsRequest, apiPath, multipartFile, errorOf, isPermanent,
  contactMatches, addressFields, contactPayload, ensureContact, findTaxRateId,
  periodOf, invoicePayload, centsOfSigned, writeBack,
  backoffMs, queuePending, clearPending, pending,
  acquireLock, releaseLock, pushDocument, runSweep, startMoneybirdPlanner,
};
