'use strict';
// The document a payment produces: its number, its VAT split, its idempotency,
// and whether every field Dutch law requires is really on the PDF.
//
// No redis and no network. The store is a Map behind the five commands
// lib/invoice.js uses (get, set with NX, incr, rPush, lRange), which is enough
// to drive the exact ordering the real client would see and lets these run in
// the plain unit job. The route half (auth, listing, PDF download) lives in
// test/route-billing-invoices.test.js and needs a real redis.
//
// Run: node --test relay/test/invoice.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const invoice = require('../lib/invoice');
const invoicePdf = require('../lib/invoice-pdf');
const catalog = require('../lib/billing-catalog');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('invoice', checks));

// ── a redis stand-in ─────────────────────────────────────────────────────────
// Only the commands lib/invoice.js calls, with the semantics that matter: SET
// with NX returns null when the key exists, INCR starts at 1, rPush appends,
// lRange takes negative indices. Anything this fake gets wrong would show up in
// the route suite, which runs the same code against a real server.
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
  };
}

const SELLER_WITH_VAT = {
  name: 'Paramantis Solutions B.V.',
  address: 'Example Street 1\n1234 AB Example City\nNetherlands',
  kvk: '42115132',
  vat: 'NL863456789B01',
};
const SELLER_NO_VAT = Object.assign({}, SELLER_WITH_VAT, { vat: '' });

const BUYER = {
  email: 'office@example.test',
  company: 'Acme B.V.',
  address: 'Example Road 12\n1015 BR Example City',
  vat: 'NL812345678B01',
};

// A payment as Mollie hands it back from GET /v2/payments/:id, reduced to the
// three fields the invoice path reads.
function payment(id, value = '603.79') {
  return {
    id, status: 'paid', method: 'ideal',
    amount: { value, currency: 'EUR' },
    metadata: { accountId: 'acct_demo', product: 'parasign', plan: 'pro', interval: 'yearly' },
  };
}

function orderOf(p) {
  const md = p.metadata;
  return Object.assign({ accountId: md.accountId }, catalog.resolveOrder(md));
}

const issue = (redis, p, seller = SELLER_WITH_VAT, extra = {}) => invoice.issueDocument(Object.assign({
  payment: p, order: orderOf(p), seller, buyer: BUYER,
  now: new Date('2026-09-03T12:00:00Z'),
  periodEnd: '2027-09-03T12:00:00Z',
}, extra), redis);

// ── 1. the VAT split, against the real catalog ───────────────────────────────
// Every price in the catalog is a gross amount that has to come apart into a
// round net amount and 21% VAT. If one of them does not, the invoice for that
// plan states a total that is not what the customer was charged, or a net
// amount his bookkeeper cannot reconcile.

test('every catalog price splits into an exact net amount and 21% VAT', () => {
  const expected = {
    '18.15': '15.00', '181.50': '150.00',
    '59.29': '49.00', '603.79': '499.00',
    '361.79': '299.00', '3617.90': '2990.00',
    // Firm: 29 and 290 excl. btw. Both land on the cent, which is what let the
    // plan be priced at 29 rather than at a number that splits badly.
    '35.09': '29.00', '350.90': '290.00',
  };
  for (const [product, plans] of Object.entries(catalog.CATALOG)) {
    for (const [plan, intervals] of Object.entries(plans)) {
      for (const [interval, gross] of Object.entries(intervals)) {
        const s = invoice.splitVat(gross, 21);
        assert.ok(s, `${product}/${plan}/${interval} splits`);
        assert.strictEqual(invoice.money(s.net_cents), expected[gross],
          `${product} ${plan} ${interval}: net of ${gross}`);
        assert.strictEqual(s.net_cents + s.vat_cents, s.gross_cents,
          `${gross}: net + VAT is exactly the amount paid`);
      }
    }
  }
  did();
});

test('the split never loses or invents a cent', () => {
  // Amounts that do not divide cleanly by 1.21. The invariant is not that the
  // net is pretty; it is that the two halves add back up to what was collected.
  for (const gross of ['0.01', '1.00', '10.00', '99.99', '123.45', '1000.00']) {
    const s = invoice.splitVat(gross, 21);
    assert.strictEqual(s.net_cents + s.vat_cents, s.gross_cents, `${gross} adds up`);
  }
  assert.strictEqual(invoice.splitVat('not-money', 21), null, 'unparseable amount yields no split');
  did();
});

// ── 2. one document per payment ──────────────────────────────────────────────

test('the same webhook twice issues exactly one document', async () => {
  const redis = fakeRedis();
  const p = payment('tr_once');
  const first = await issue(redis, p);
  assert.strictEqual(first.result, 'issued');
  assert.strictEqual(first.number, 'PS-2026-0001');

  const second = await issue(redis, p);
  assert.strictEqual(second.result, 'existing', 'the repeat is recognised');
  assert.strictEqual(second.number, 'PS-2026-0001', 'and points at the same document');

  const list = await invoice.listFor('acct_demo', redis);
  assert.strictEqual(list.length, 1, 'one document on the account');
  assert.strictEqual(await redis.get(invoice.K.seq(2026)), '1', 'the counter moved once');
  did();
});

test('a repeat does not burn a number, so the series stays gapless', async () => {
  const redis = fakeRedis();
  await issue(redis, payment('tr_a'));
  await issue(redis, payment('tr_a'));   // retry
  await issue(redis, payment('tr_a'));   // and again
  const second = await issue(redis, payment('tr_b'));
  assert.strictEqual(second.number, 'PS-2026-0002', 'the next real payment gets 0002, not 0004');
  did();
});

test('two payments get consecutive numbers', async () => {
  const redis = fakeRedis();
  const a = await issue(redis, payment('tr_1'));
  const b = await issue(redis, payment('tr_2'));
  const c = await issue(redis, payment('tr_3'));
  assert.deepStrictEqual([a.number, b.number, c.number],
    ['PS-2026-0001', 'PS-2026-0002', 'PS-2026-0003']);
  const list = await invoice.listFor('acct_demo', redis);
  assert.deepStrictEqual(list.map(r => r.number),
    ['PS-2026-0003', 'PS-2026-0002', 'PS-2026-0001'], 'newest first');
  did();
});

test('the year is the series, so 2027 starts at 0001 again', async () => {
  const redis = fakeRedis();
  await issue(redis, payment('tr_2026'));
  const next = await issue(redis, payment('tr_2027'), SELLER_WITH_VAT, { now: new Date('2027-01-04T09:00:00Z') });
  assert.strictEqual(next.number, 'PS-2027-0001');
  did();
});

test('a claim left half-finished by a crash is taken over, not duplicated', async () => {
  const redis = fakeRedis();
  const p = payment('tr_crashed');
  // What a process that died between claiming and drawing a number leaves.
  await redis.set(invoice.K.claim(p.id), `pending:${Date.now() - 5 * 60_000}`);
  const out = await issue(redis, p, SELLER_WITH_VAT, { now: new Date() });
  assert.strictEqual(out.result, 'issued', 'a stale claim does not block the customer forever');

  // A claim from a second ago is a webhook that is running right now.
  const fresh = payment('tr_racing');
  await redis.set(invoice.K.claim(fresh.id), `pending:${Date.now()}`);
  const held = await issue(redis, fresh, SELLER_WITH_VAT, { now: new Date() });
  assert.strictEqual(held.result, 'deferred', 'a live claim is left alone');
  did();
});

// ── 3. chargeback ────────────────────────────────────────────────────────────

test('a chargeback issues no second document, it marks the first reversed', async () => {
  const redis = fakeRedis();
  const p = payment('tr_taken_back');
  const issued = await issue(redis, p);
  assert.strictEqual(issued.number, 'PS-2026-0001');

  const rev = await invoice.recordReversal({ payment: Object.assign({}, p, { status: 'chargeback' }) }, redis);
  assert.strictEqual(rev.result, 'reversed');
  assert.strictEqual(rev.number, 'PS-2026-0001', 'the same document, not a new number');
  assert.strictEqual(await redis.get(invoice.K.seq(2026)), '1', 'the counter did not move');

  const list = await invoice.listFor('acct_demo', redis);
  assert.strictEqual(list.length, 1, 'still one document');
  assert.ok(list[0].reversed_at, 'and it says the money went back');

  // KNOWN GAP, asserted so it cannot be forgotten: there is no numbered credit
  // note. A reversal marks the invoice; it does not produce a document with its
  // own number in a credit series, which is what a bookkeeper eventually needs.
  assert.strictEqual(await redis.get(invoice.K.doc('PS-2026-0002')), null,
    'no credit note exists yet (see lib/invoice.js header)');
  did();
});

test('a reversal of a payment that never had a document does nothing', async () => {
  const redis = fakeRedis();
  const rev = await invoice.recordReversal({ payment: payment('tr_unknown') }, redis);
  assert.strictEqual(rev.result, 'none');
  did();
});

// ── 4. no VAT number configured ──────────────────────────────────────────────

test('without BILLING_SELLER_VAT the document is a receipt and says so', async () => {
  const redis = fakeRedis();
  const out = await issue(redis, payment('tr_no_vat'), SELLER_NO_VAT);
  assert.strictEqual(out.result, 'issued');
  assert.strictEqual(out.record.kind, 'receipt');
  assert.strictEqual(out.record.title, 'Payment receipt');
  assert.strictEqual(out.record.note, invoice.RECEIPT_NOTE);
  assert.match(out.record.note, /Invoice with VAT number follows/);

  const text = invoicePdf.render(out.record, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('Payment receipt'), 'the PDF is titled a receipt');
  assert.ok(!/\(Invoice\) Tj/.test(text), 'and never calls itself an invoice');
  assert.ok(text.includes('Invoice with VAT number follows'), 'and says the invoice follows');
  assert.ok(text.includes('VAT number: not yet issued'), 'and does not print a blank VAT line');
  did();
});

test('sellerFromEnv reads the four variables and defaults the two that are public', () => {
  const bare = invoice.sellerFromEnv({});
  assert.strictEqual(bare.name, 'Paramantis Solutions B.V.');
  assert.strictEqual(bare.kvk, '42115132');
  assert.strictEqual(bare.vat, '', 'a VAT number is never guessed');
  assert.strictEqual(invoice.documentKind(bare), 'receipt');

  const full = invoice.sellerFromEnv({
    BILLING_SELLER_NAME: 'Other B.V.', BILLING_SELLER_ADDRESS: 'Street 1\nCity',
    BILLING_SELLER_KVK: '11111111', BILLING_SELLER_VAT: 'NL999999999B01',
  });
  assert.strictEqual(full.name, 'Other B.V.');
  assert.strictEqual(full.address, 'Street 1\nCity');
  assert.strictEqual(invoice.documentKind(full), 'invoice');
  did();
});

// ── 5. the PDF carries every field the law asks for ──────────────────────────
// The content stream is uncompressed on purpose (see lib/invoice-pdf.js), so
// the text of the document is readable straight out of the bytes. That is what
// makes this assertion possible without a PDF parser.

test('the PDF carries every field Wet OB art. 35a requires', async () => {
  const redis = fakeRedis();
  const out = await issue(redis, payment('tr_legal'));
  const pdf = invoicePdf.render(out.record, { buyerHint: invoice.BUYER_HINT });
  const text = pdf.toString('latin1');

  assert.ok(text.startsWith('%PDF-1.4'), 'it is a PDF');
  assert.ok(text.trimEnd().endsWith('%%EOF'), 'with a complete trailer');

  const required = {
    'a: invoice date':            '2026-09-03',
    'b: sequential number':       'PS-2026-0001',
    'c: supplier name':           'Paramantis Solutions B.V.',
    'c: supplier address':        '1234 AB Example City',
    'd: supplier VAT number':     'NL863456789B01',
    'e: customer name':           'Acme B.V.',
    'e: customer address':        '1015 BR Example City',
    'f: description':             'Paramant ParaSign Pro, yearly plan',
    'g: amount excluding VAT':    '499.00',
    'h: VAT rate':                '21%',
    'h: VAT amount':              '104.79',
    'i: total':                   '603.79',
    'extra: KvK number':          '42115132',
  };
  for (const [what, value] of Object.entries(required)) {
    assert.ok(text.includes(value), `${what} is on the document (${value})`);
  }
  // The words too, not only the numbers: an amount with no label is not a
  // statement about VAT.
  for (const label of ['Invoice', 'Invoice date', 'Invoice number', 'Billed to', 'Subtotal excl. VAT', 'Total']) {
    assert.ok(text.includes(label), `the document is labelled: ${label}`);
  }
  did();
});

test('an account with no company details still gets a document, and is told why', async () => {
  const redis = fakeRedis();
  const out = await invoice.issueDocument({
    payment: payment('tr_bare'),
    order: orderOf(payment('tr_bare')),
    seller: SELLER_WITH_VAT,
    buyer: { email: 'solo@example.test', company: '', address: '', vat: '' },
    now: new Date('2026-09-03T12:00:00Z'),
  }, redis);
  assert.strictEqual(out.result, 'issued');
  assert.strictEqual(invoice.buyerIsComplete(out.record.buyer), false);

  const text = invoicePdf.render(out.record, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('solo@example.test'), 'the email stands in as the addressee');
  assert.ok(text.includes('Add your company details on your account page'),
    'and the document says how to fix it');
  did();
});

test('a name outside latin-1 does not break the document', () => {
  const record = invoice.buildRecord({
    number: 'PS-2026-0009', kind: 'invoice', seller: SELLER_WITH_VAT,
    buyer: { email: 'a@b.test', company: 'Acme 東京 (B.V.)', address: 'Straat 1', vat: '' },
    order: { accountId: 'acct_x', product: 'parasign', plan: 'pro', interval: 'monthly', currency: 'EUR' },
    payment: { id: 'tr_utf', amount: { value: '59.29', currency: 'EUR' } },
    split: invoice.splitVat('59.29', 21),
    now: new Date('2026-09-03T12:00:00Z'),
  });
  const text = invoicePdf.render(record, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('PS-2026-0009'), 'it still renders');
  assert.ok(text.includes('\\(B.V.\\)'), 'and the parentheses in the name are escaped, not left to break the stream');
  did();
});

// ── 6. an account only ever sees its own ─────────────────────────────────────

test('listFor and getFor never cross accounts', async () => {
  const redis = fakeRedis();
  const mine = payment('tr_mine');
  const theirs = payment('tr_theirs');
  theirs.metadata = Object.assign({}, theirs.metadata, { accountId: 'acct_other' });
  await issue(redis, mine);
  await issue(redis, theirs);

  assert.deepStrictEqual((await invoice.listFor('acct_demo', redis)).map(r => r.number), ['PS-2026-0001']);
  assert.deepStrictEqual((await invoice.listFor('acct_other', redis)).map(r => r.number), ['PS-2026-0002']);
  assert.strictEqual(await invoice.getFor('acct_demo', 'PS-2026-0002', redis), null,
    'guessing the neighbour number gets you nothing');
  assert.ok(await invoice.getFor('acct_other', 'PS-2026-0002', redis));
  assert.strictEqual(await invoice.getFor('acct_demo', 'not-a-number', redis), null);
  did();
});

// ── 7. no redis is not a failed payment ──────────────────────────────────────

test('without redis nothing is written and nothing throws', async () => {
  const out = await issue(null, payment('tr_no_redis'));
  assert.strictEqual(out.result, 'unavailable');
  assert.strictEqual(out.reason, 'no_redis');
  assert.deepStrictEqual(await invoice.listFor('acct_demo', null), []);
  assert.strictEqual(await invoice.getFor('acct_demo', 'PS-2026-0001', null), null);
  did();
});

test('a record is kept whole, so a later reprint is the same document', async () => {
  const redis = fakeRedis();
  const out = await issue(redis, payment('tr_keep'));
  const stored = JSON.parse(await redis.get(invoice.K.doc(out.number)));
  assert.deepStrictEqual(stored.seller, SELLER_WITH_VAT, 'the seller as it was on the day');
  assert.deepStrictEqual(stored.buyer, BUYER, 'the buyer as it was on the day');
  assert.strictEqual(stored.payment_id, 'tr_keep');
  assert.strictEqual(stored.amount_gross, '603.79');
  assert.strictEqual(stored.service_period_end, '2027-09-03T12:00:00Z');
  did();
});
