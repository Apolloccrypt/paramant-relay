'use strict';
// The Moneybird push: contact, external sales invoice, PDF attachment, the id
// written back, and what happens when any of it fails.
//
// NO NETWORK. lib/moneybird.js takes its HTTP layer as an injected `http`
// function with exactly the shape of its own httpsRequest, on the pattern
// lib/billing-recurring.js uses for the Mollie client, so every request below
// is answered by a script in this file and the real one is never called. There
// is no Moneybird token anywhere in this repo and there is not meant to be.
//
// Run: node --test relay/test/moneybird.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const invoice = require('../lib/invoice');
const moneybird = require('../lib/moneybird');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('moneybird', checks));

const CFG_ENV = { MONEYBIRD_TOKEN: 'mbt_demo_token', MONEYBIRD_ADMINISTRATION_ID: '123456789' };

// ── a redis stand-in ─────────────────────────────────────────────────────────
// The commands lib/moneybird.js uses: get/set/del, the sorted set behind the
// retry queue, and the hash behind the attempt counter. SET honours NX and
// ignores EX/PX, which is enough: nothing here asserts on expiry, and the lock
// is taken and released inside one sweep.
function fakeRedis() {
  const kv = new Map();
  const zsets = new Map();
  const hashes = new Map();
  const zset = (k) => { if (!zsets.has(k)) zsets.set(k, new Map()); return zsets.get(k); };
  const hash = (k) => { if (!hashes.has(k)) hashes.set(k, new Map()); return hashes.get(k); };
  return {
    kv, zsets, hashes, isReady: true,
    async get(k) { return kv.has(k) ? kv.get(k) : null; },
    async set(k, v, opts) {
      if (opts && opts.NX && kv.has(k)) return null;
      kv.set(k, String(v));
      return 'OK';
    },
    async del(k) { return kv.delete(k) ? 1 : 0; },
    async zAdd(k, entries) {
      for (const e of [].concat(entries)) zset(k).set(e.value, e.score);
      return 1;
    },
    async zRem(k, member) { return zset(k).delete(member) ? 1 : 0; },
    async zRange(k, start, stop) {
      const sorted = [...zset(k).entries()].sort((a, b) => a[1] - b[1]).map((e) => e[0]);
      return sorted.slice(start, stop + 1);
    },
    async zRangeByScore(k, min, max) {
      return [...zset(k).entries()].filter(([, s]) => s >= min && s <= max)
        .sort((a, b) => a[1] - b[1]).map((e) => e[0]);
    },
    async hIncrBy(k, field, by) {
      const n = (parseInt(hash(k).get(field) || '0', 10) || 0) + by;
      hash(k).set(field, String(n));
      return n;
    },
    async hDel(k, field) { return hash(k).delete(field) ? 1 : 0; },
  };
}

// ── a Moneybird stand-in ─────────────────────────────────────────────────────
// One scripted answer per (method, path prefix). Every call is recorded, so the
// assertions can read what was actually sent rather than what was meant to be.
function fakeApi(script = {}) {
  const calls = [];
  const http = async ({ method, path, token, json, multipart }) => {
    calls.push({ method, path, token, json, multipart });
    const key = Object.keys(script).find((k) => {
      const [m, p] = k.split(' ');
      return m === method && path.startsWith(p);
    });
    if (!key) throw new Error(`unscripted request: ${method} ${path}`);
    const answer = script[key];
    return typeof answer === 'function' ? answer({ method, path, json, multipart, calls }) : answer;
  };
  http.calls = calls;
  http.of = (method, prefix) => calls.filter((c) => c.method === method && c.path.startsWith(prefix));
  return http;
}

const CONTACT_LIST = '/api/v2/123456789/contacts.json?query=';
const CONTACT_CREATE = '/api/v2/123456789/contacts.json';
const TAX_RATES = '/api/v2/123456789/tax_rates.json';
const ESI = '/api/v2/123456789/external_sales_invoices.json';
const ATTACH = '/api/v2/123456789/external_sales_invoices/';

// The happy script: no contact found, one 21% sales rate, the document created,
// the attachment accepted.
function happyScript(over = {}) {
  return Object.assign({
    [`GET ${CONTACT_LIST}`]: { status: 200, body: [] },
    [`POST ${CONTACT_CREATE}`]: { status: 201, body: { id: '497268131056584640' } },
    [`GET ${TAX_RATES}`]: {
      status: 200,
      body: [{ id: '497268115859571850', name: '21% btw', percentage: '21.0', tax_rate_type: 'sales_invoice', active: true }],
    },
    [`POST ${ESI}`]: ({ json }) => ({
      status: 201,
      body: {
        id: '497268140000000001',
        reference: json.external_sales_invoice.reference,
        total_price_incl_tax: json.external_sales_invoice.details_attributes[0].price,
      },
    }),
    [`POST ${ATTACH}`]: { status: 200, body: null },
  }, over);
}

// ── the documents ────────────────────────────────────────────────────────────
function invoiceRecord(over = {}) {
  return Object.assign({
    number: 'PS-2026-0001',
    kind: 'invoice',
    title: 'Invoice',
    issued_at: '2026-09-04T10:00:00.000Z',
    invoice_date: '2026-09-04',
    account_id: 'acct_demo',
    payment_id: 'tr_demo1',
    product: 'parasign', plan: 'pro', interval: 'yearly',
    description: 'Paramant ParaSign Pro, yearly plan',
    service_period_end: '2027-09-04T10:00:00.000Z',
    currency: 'EUR',
    vat_rate: 21,
    amount_net: '499.00', amount_vat: '104.79', amount_gross: '603.79',
    seller: { name: 'Paramantis Solutions B.V.', address: 'Example Street 1', kvk: '42115132', vat: 'NL863456789B01' },
    buyer: {
      email: 'office@example.test', company: 'Acme B.V.',
      address: 'Example Road 12\n1015 BR Example City', vat: 'NL812345678B01',
    },
  }, over);
}

function creditRecord(over = {}) {
  return Object.assign(invoiceRecord(), {
    number: 'CN-2026-0001',
    kind: 'credit_note',
    title: 'Credit note',
    invoice_date: '2026-09-20',
    credit_for: 'PS-2026-0001',
    reason: 'chargeback',
    description: 'Credit for Paramant ParaSign Pro, yearly plan (invoice PS-2026-0001)',
    amount_net: '-499.00', amount_vat: '-104.79', amount_gross: '-603.79',
    service_period_end: null,
  }, over);
}

function store(redis, ...records) {
  for (const r of records) redis.kv.set(invoice.K.doc(r.number), JSON.stringify(r));
  return records[0];
}

const NOW = new Date('2026-09-05T08:00:00.000Z');
const PDF = Buffer.from('%PDF-1.4 demo\n', 'latin1');

function push(extra) {
  return moneybird.pushDocument(Object.assign({ env: CFG_ENV, now: NOW, renderPdf: () => PDF }, extra));
}

// ── configuration ────────────────────────────────────────────────────────────

test('M1 without a token and an administration id nothing is sent at all', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  const r = await push({ env: {}, record: rec, redis, http });
  assert.equal(r.result, 'disabled');
  assert.equal(http.calls.length, 0, 'no request leaves the relay');
  assert.equal(JSON.parse(redis.kv.get(invoice.K.doc(rec.number))).moneybird_id, undefined);
  assert.equal(await redis.zRange(moneybird.K.pending, 0, 10).then((l) => l.length), 0, 'and nothing is queued either');
  did();
});

test('M2 an administration id that is not a plain number is refused before it reaches a URL', async () => {
  assert.equal(moneybird.configured(moneybird.configFromEnv(CFG_ENV)), true);
  assert.equal(moneybird.configured(moneybird.configFromEnv({ ...CFG_ENV, MONEYBIRD_ADMINISTRATION_ID: '1/../../x' })), false);
  assert.equal(moneybird.configured(moneybird.configFromEnv({ ...CFG_ENV, MONEYBIRD_ADMINISTRATION_ID: '' })), false);
  assert.equal(moneybird.configured(moneybird.configFromEnv({ MONEYBIRD_ADMINISTRATION_ID: '1' })), false);
  did();
});

// ── the contact ──────────────────────────────────────────────────────────────

test('M3 an existing contact is found on the email address and no second one is made', async () => {
  const http = fakeApi(happyScript({
    [`GET ${CONTACT_LIST}`]: {
      status: 200,
      body: [
        { id: '111', email: 'someone.else@example.test' },
        { id: '222', email: 'office@example.test', company_name: 'Acme B.V.' },
      ],
    },
  }));
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  const r = await push({ record: rec, redis, http });
  assert.equal(r.result, 'pushed');
  assert.equal(r.contact_id, '222');
  assert.equal(r.contact_created, false);
  assert.equal(http.of('POST', CONTACT_CREATE).length, 0, 'nothing was created');
  const sent = http.of('POST', ESI)[0].json.external_sales_invoice;
  assert.equal(sent.contact_id, '222');
  did();
});

test('M4 a near miss on the query is not a match: the search is a substring search', async () => {
  const http = fakeApi(happyScript({
    // Moneybird's ?query= searches a dozen fields, so it can answer with a
    // contact that merely mentions the address. Booking revenue against the
    // wrong customer is worse than a duplicate contact.
    [`GET ${CONTACT_LIST}`]: { status: 200, body: [{ id: '333', email: 'not-office@example.test.other' }] },
  }));
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  const r = await push({ record: rec, redis, http });
  assert.equal(r.contact_created, true);
  assert.equal(r.contact_id, '497268131056584640');
  did();
});

test('M5 a created contact carries the company, the address, the VAT number and the invoice address', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  await push({ record: store(redis, invoiceRecord()), redis, http });
  const { contact } = http.of('POST', CONTACT_CREATE)[0].json;
  assert.equal(contact.company_name, 'Acme B.V.');
  assert.equal(contact.address1, 'Example Road 12');
  assert.equal(contact.zipcode, '1015 BR');
  assert.equal(contact.city, 'Example City');
  assert.equal(contact.tax_number, 'NL812345678B01');
  assert.equal(contact.send_invoices_to_email, 'office@example.test');
  // `email` is not a writable field on a Moneybird contact; sending it would be
  // dropped without a word.
  assert.ok(!('email' in contact));
  did();
});

test('M6 a buyer with no company still makes a contact Moneybird will accept', () => {
  const { contact } = moneybird.contactPayload({ email: 'two@example.test', company: '', address: '', vat: '' });
  assert.equal(contact.company_name, 'two@example.test');
  assert.deepEqual(moneybird.addressFields('Example Road 12\n1015 BR Example City'),
    { address1: 'Example Road 12', address2: '', zipcode: '1015 BR', city: 'Example City' });
  assert.deepEqual(moneybird.addressFields('Some Street 4\nBuilding B\nSomewhere Else'),
    { address1: 'Some Street 4', address2: 'Building B, Somewhere Else', zipcode: '', city: '' });
  did();
});

test('M7 the contact id is cached, so a second document for the same customer costs one request', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  await push({ record: store(redis, invoiceRecord()), redis, http });
  const afterFirst = http.calls.length;
  await push({ record: store(redis, invoiceRecord({ number: 'PS-2026-0002', payment_id: 'tr_demo2' })), redis, http });
  assert.equal(http.of('GET', CONTACT_LIST).length, 1, 'the contact is looked up once');
  assert.equal(http.of('POST', CONTACT_CREATE).length, 1);
  assert.equal(http.of('GET', TAX_RATES).length, 1, 'and so is the tax rate');
  assert.ok(http.calls.length > afterFirst);
  did();
});

// ── the document ─────────────────────────────────────────────────────────────

test('M8 the external sales invoice carries our number, our date and the gross tax-inclusive', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  await push({ record: store(redis, invoiceRecord()), redis, http });
  const sent = http.of('POST', ESI)[0].json.external_sales_invoice;
  assert.equal(sent.reference, 'PS-2026-0001', 'our own number is what Moneybird files it under');
  assert.equal(sent.date, '2026-09-04');
  assert.equal(sent.currency, 'EUR');
  assert.equal(sent.prices_are_incl_tax, true);
  assert.equal(sent.source, moneybird.SOURCE);
  assert.equal(sent.details_attributes.length, 1);
  const detail = sent.details_attributes[0];
  assert.equal(detail.description, 'Paramant ParaSign Pro, yearly plan');
  assert.equal(detail.price, '603.79');
  assert.equal(detail.amount, '1');
  assert.equal(detail.tax_rate_id, '497268115859571850');
  assert.equal(detail.period, '20260904..20270904', 'a yearly plan is revenue over that year');
  did();
});

test('M9 a credit note goes over as the same document with a negative price', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  await push({ record: store(redis, creditRecord()), redis, http });
  const sent = http.of('POST', ESI)[0].json.external_sales_invoice;
  assert.equal(sent.reference, 'CN-2026-0001');
  assert.equal(sent.date, '2026-09-20');
  assert.equal(sent.details_attributes[0].price, '-603.79');
  assert.equal(sent.details_attributes[0].period, undefined, 'a credit note has no term of its own');
  did();
});

test('M10 the tax rate is looked up by percentage AND by type, and the answer is re-checked', async () => {
  const http = fakeApi(happyScript({
    [`GET ${TAX_RATES}`]: {
      status: 200,
      body: [
        { id: '900', percentage: '21.0', tax_rate_type: 'purchase_invoice', active: true },
        { id: '901', percentage: '9.0', tax_rate_type: 'sales_invoice', active: true },
        { id: '902', percentage: '21.0', tax_rate_type: 'sales_invoice', active: true },
      ],
    },
  }));
  const redis = fakeRedis();
  await push({ record: store(redis, invoiceRecord()), redis, http });
  const path = http.of('GET', TAX_RATES)[0].path;
  assert.ok(path.includes(encodeURIComponent('percentage:21,tax_rate_type:sales_invoice')), path);
  assert.equal(http.of('POST', ESI)[0].json.external_sales_invoice.details_attributes[0].tax_rate_id, '902');
  did();
});

test('M11 an administration with no matching rate is still pushed, on the administration default', async () => {
  const http = fakeApi(happyScript({ [`GET ${TAX_RATES}`]: { status: 200, body: [] } }));
  const redis = fakeRedis();
  const r = await push({ record: store(redis, invoiceRecord()), redis, http });
  assert.equal(r.result, 'pushed');
  assert.equal(http.of('POST', ESI)[0].json.external_sales_invoice.details_attributes[0].tax_rate_id, undefined);
  did();
});

test('M12 the PDF is attached as multipart, under the document number', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  const r = await push({ record: store(redis, invoiceRecord()), redis, http });
  assert.equal(r.attached, true);
  const call = http.of('POST', ATTACH)[0];
  assert.equal(call.path, '/api/v2/123456789/external_sales_invoices/497268140000000001/attachment.json');
  const body = call.multipart.body.toString('latin1');
  assert.ok(body.includes(`--${call.multipart.boundary}`));
  assert.ok(body.includes('name="file"; filename="PS-2026-0001.pdf"'));
  assert.ok(body.includes('Content-Type: application/pdf'));
  assert.ok(body.includes('%PDF-1.4 demo'));
  did();
});

test('M13 an attachment that will not upload does not undo a document that is in the books', async () => {
  const http = fakeApi(happyScript({ [`POST ${ATTACH}`]: { status: 400, body: { error: 'too big' } } }));
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  const r = await push({ record: rec, redis, http });
  assert.equal(r.result, 'pushed', 'a retry would create a SECOND external sales invoice for the same money');
  assert.equal(r.attached, false);
  assert.equal(JSON.parse(redis.kv.get(invoice.K.doc(rec.number))).moneybird_attachment, false);
  did();
});

// ── idempotency ──────────────────────────────────────────────────────────────

test('M14 the Moneybird id is written back onto the stored record', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  const r = await push({ record: rec, redis, http });
  assert.equal(r.result, 'pushed');
  assert.equal(r.id, '497268140000000001');
  const stored = JSON.parse(redis.kv.get(invoice.K.doc(rec.number)));
  assert.equal(stored.moneybird_id, '497268140000000001');
  assert.equal(stored.moneybird_contact_id, '497268131056584640');
  assert.equal(stored.moneybird_pushed_at, NOW.toISOString());
  assert.equal(stored.moneybird_attachment, true);
  // Everything the document said before is still what it says.
  assert.equal(stored.amount_gross, '603.79');
  assert.equal(stored.number, 'PS-2026-0001');
  did();
});

test('M15 a second push of the same document sends nothing', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  await push({ record: rec, redis, http });
  const afterFirst = http.calls.length;
  const again = await push({ record: rec, redis, http });
  assert.equal(again.result, 'existing');
  assert.equal(again.id, '497268140000000001');
  assert.equal(http.calls.length, afterFirst, 'not one extra request');
  did();
});

test('M16 the check is made against redis, not against the copy the caller holds', async () => {
  const http = fakeApi(happyScript());
  const redis = fakeRedis();
  const rec = invoiceRecord();
  // The caller's copy predates the push; the stored one already has the id,
  // which is what a sweep racing a webhook looks like.
  store(redis, Object.assign({}, rec, { moneybird_id: '497268140000000009' }));
  const r = await push({ record: rec, redis, http });
  assert.equal(r.result, 'existing');
  assert.equal(r.id, '497268140000000009');
  assert.equal(http.calls.length, 0);
  did();
});

test('M17 the write-back does not erase a change another path made while the push ran', async () => {
  const redis = fakeRedis();
  const rec = invoiceRecord();
  store(redis, rec);
  // The credit-note path adds a back-reference to the invoice; it must survive
  // a Moneybird push that started before it.
  const meanwhile = Object.assign({}, rec, { credit_notes: ['CN-2026-0001'] });
  redis.kv.set(invoice.K.doc(rec.number), JSON.stringify(meanwhile));
  await moneybird.writeBack({ redis, record: rec, id: '777', contactId: '888', attached: true, now: NOW });
  const stored = JSON.parse(redis.kv.get(invoice.K.doc(rec.number)));
  assert.deepEqual(stored.credit_notes, ['CN-2026-0001']);
  assert.equal(stored.moneybird_id, '777');
  did();
});

// ── failure and the retry ────────────────────────────────────────────────────

test('M18 a failed push is queued with a backoff and never marks the record pushed', async () => {
  const http = fakeApi(happyScript({ [`POST ${ESI}`]: { status: 500, body: { error: 'boom' } } }));
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  const r = await push({ record: rec, redis, http });
  assert.equal(r.result, 'failed');
  assert.ok(r.reason.includes('invoice_create_failed'), r.reason);
  assert.equal(r.permanent, false);
  assert.equal(r.attempts, 1);
  assert.equal(JSON.parse(redis.kv.get(invoice.K.doc(rec.number))).moneybird_id, undefined);
  assert.deepEqual(await moneybird.pending(redis), ['PS-2026-0001']);
  assert.equal(new Date(r.retry_at).getTime(), NOW.getTime() + moneybird.RETRY_BASE_MS);
  did();
});

test('M19 a rejected field says so, and the backoff doubles per attempt up to a day', async () => {
  const http = fakeApi(happyScript({
    [`POST ${ESI}`]: { status: 422, body: { error: { reference: ["can't be blank"], date: ['is not a valid date'] } } },
  }));
  const redis = fakeRedis();
  const r = await push({ record: store(redis, invoiceRecord()), redis, http });
  assert.equal(r.permanent, true, 'a validation error is not fixed by trying again in a quarter of an hour');
  assert.ok(r.reason.includes("reference: can't be blank"), r.reason);
  assert.ok(r.reason.includes('date: is not a valid date'), r.reason);
  assert.equal(moneybird.backoffMs(1), moneybird.RETRY_BASE_MS);
  assert.equal(moneybird.backoffMs(2), moneybird.RETRY_BASE_MS * 2);
  assert.equal(moneybird.backoffMs(40), moneybird.RETRY_MAX_MS);
  did();
});

test('M20 the sweep retries what is due, pushes it, and clears the queue', async () => {
  const redis = fakeRedis();
  const rec = store(redis, invoiceRecord());
  // First attempt: Moneybird is down.
  const down = fakeApi(happyScript({ [`POST ${ESI}`]: { status: 503, body: 'unavailable' } }));
  await push({ record: rec, redis, http: down });
  assert.deepEqual(await moneybird.pending(redis), ['PS-2026-0001']);

  // Not due yet: the sweep runs and touches nothing.
  const early = fakeApi(happyScript());
  const nothing = await moneybird.runSweep({
    env: CFG_ENV, redis, http: early, renderPdf: () => PDF, now: new Date(NOW.getTime() + 60000),
  });
  assert.equal(nothing.ran, true);
  assert.equal(nothing.pushed, 0);
  assert.equal(early.calls.length, 0);

  // Due: the sweep pushes it, writes the id back and empties the queue.
  const later = fakeApi(happyScript());
  const swept = await moneybird.runSweep({
    env: CFG_ENV, redis, http: later, renderPdf: () => PDF,
    now: new Date(NOW.getTime() + moneybird.RETRY_BASE_MS + 1000),
  });
  assert.equal(swept.ran, true);
  assert.equal(swept.pushed, 1);
  assert.equal(swept.failed, 0);
  assert.equal(JSON.parse(redis.kv.get(invoice.K.doc('PS-2026-0001'))).moneybird_id, '497268140000000001');
  assert.deepEqual(await moneybird.pending(redis), []);
  did();
});

test('M21 a sweep that fails again leaves the document queued, with the attempt counted', async () => {
  const redis = fakeRedis();
  store(redis, invoiceRecord());
  const down = fakeApi(happyScript({ [`POST ${ESI}`]: { status: 500, body: { error: 'still down' } } }));
  await push({ record: invoiceRecord(), redis, http: down });
  const swept = await moneybird.runSweep({
    env: CFG_ENV, redis, http: down, renderPdf: () => PDF,
    now: new Date(NOW.getTime() + moneybird.RETRY_BASE_MS + 1000),
  });
  assert.equal(swept.failed, 1);
  assert.equal(swept.pushed, 0);
  assert.deepEqual(await moneybird.pending(redis), ['PS-2026-0001']);
  assert.equal(redis.hashes.get(moneybird.K.attempts).get('PS-2026-0001'), '2');
  did();
});

test('M22 only one container sweeps at a time', async () => {
  const redis = fakeRedis();
  const token = 'held-by-another-container';
  await redis.set(moneybird.K.lock, token, { NX: true, PX: 60000 });
  const http = fakeApi(happyScript());
  const out = await moneybird.runSweep({ env: CFG_ENV, redis, http, now: NOW });
  assert.equal(out.ran, false);
  assert.equal(out.reason, 'locked');
  assert.equal(http.calls.length, 0);
  assert.equal(redis.kv.get(moneybird.K.lock), token, 'and it does not release a lock it never held');
  did();
});

test('M23 a queued number whose document is gone leaves the queue instead of failing forever', async () => {
  const redis = fakeRedis();
  await redis.zAdd(moneybird.K.pending, [{ score: 1, value: 'PS-2026-0404' }]);
  const http = fakeApi(happyScript());
  const out = await moneybird.runSweep({ env: CFG_ENV, redis, http, now: NOW });
  assert.equal(out.ran, true);
  assert.equal(out.pushed, 0);
  assert.equal(http.calls.length, 0);
  assert.deepEqual(await moneybird.pending(redis), []);
  did();
});

test('M24 the sweep and the planner do nothing when Moneybird is not configured', async () => {
  const redis = fakeRedis();
  const out = await moneybird.runSweep({ env: {}, redis, now: NOW });
  assert.equal(out.ran, false);
  assert.equal(out.reason, 'disabled');
  assert.equal(moneybird.startMoneybirdPlanner({ env: {}, redis }), null, 'no timer is even created');
  const planner = moneybird.startMoneybirdPlanner({ env: CFG_ENV, redis, http: fakeApi(happyScript()) });
  assert.ok(planner && typeof planner.stop === 'function');
  planner.stop();
  did();
});

test('M25 a stale cached contact is dropped when Moneybird rejects it, so the retry looks it up again', async () => {
  const redis = fakeRedis();
  await redis.set(moneybird.K.contact('office@example.test'), '999');
  const rejects = fakeApi(happyScript({
    [`POST ${ESI}`]: { status: 400, body: { error: 'Contact ID is invalid', symbolic: { external_sales_invoice: { contact_id: 'contact_invalid' } } } },
  }));
  const r = await push({ record: store(redis, invoiceRecord()), redis, http: rejects });
  assert.equal(r.result, 'failed');
  assert.ok(r.reason.includes('Contact ID is invalid'), r.reason);
  assert.equal(redis.kv.has(moneybird.K.contact('office@example.test')), false);

  const ok = fakeApi(happyScript());
  const second = await moneybird.runSweep({
    env: CFG_ENV, redis, http: ok, renderPdf: () => PDF,
    now: new Date(NOW.getTime() + moneybird.RETRY_MAX_MS + 1000),
  });
  assert.equal(second.pushed, 1);
  assert.equal(ok.of('GET', CONTACT_LIST).length, 1, 'it went and looked the contact up again');
  did();
});

test('M26 a total that comes back different from what the customer paid is reported', async () => {
  const lines = [];
  const http = fakeApi(happyScript({
    [`POST ${ESI}`]: { status: 201, body: { id: '1', total_price_incl_tax: '603.78' } },
  }));
  const redis = fakeRedis();
  const r = await push({
    record: store(redis, invoiceRecord()), redis, http,
    log: (level, event, fields) => lines.push([level, event, fields]),
  });
  assert.equal(r.result, 'pushed');
  const warn = lines.find((l) => l[1] === 'moneybird_amount_mismatch');
  assert.ok(warn, 'a cent of difference is a wrong VAT return waiting to happen');
  assert.equal(warn[2].ours, '603.79');
  assert.equal(warn[2].moneybird, '603.78');
  did();
});
