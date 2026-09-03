'use strict';
// The invoice routes on a really booted relay, against a really running redis.
//
// WHAT THIS COVERS THAT test/invoice.test.js CANNOT. That suite drives the
// module against a Map: it proves the numbering and the document. This one
// proves the half that lives in relay.js and can only be wrong on the wire:
// that /v2/billing/invoices needs a key, that it answers with THIS account's
// documents and no one else's, that the PDF really comes back as a PDF, and
// that the company details a customer saves are the ones the next document
// carries.
//
// WHAT IT DELIBERATELY DOES NOT DO. It does not drive the Mollie webhook.
// lib/mollie.js hard-codes api.mollie.com with no override (see the note in
// route-billing-entitlements.test.js), so the write path cannot be reached
// offline without intercepting HTTPS. The documents here are therefore issued
// through lib/invoice against the same redis the relay reads, which is exactly
// what the webhook does one function call later; the webhook's own branch is
// covered by test/billing.test.js and by the unit suite.
//
// Needs a throwaway redis. Any port; the suite is told which through REDIS_URL:
//   docker run -d --rm -p 6398:6379 --name invoice-test-redis redis:alpine
//   REDIS_URL=redis://127.0.0.1:6398 node --test test/route-billing-invoices.test.js
// Without one it FAILS, unless the runner declared redis absent
// (RELAY_TEST_SKIP=redis). See test/_requires.js for why.

const { test, before, after } = require('node:test');
const assert = require('assert');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const invoice = require('../lib/invoice');

const KEY_A = 'pgp_invoice_account_a';
const KEY_B = 'pgp_invoice_account_b';
const ACCT_A = 'acct_demo_a';
const ACCT_B = 'acct_demo_b';

const SELLER = {
  BILLING_SELLER_NAME: 'Paramantis Solutions B.V.',
  BILLING_SELLER_ADDRESS: 'Example Street 1\n1234 AB Example City\nNetherlands',
  BILLING_SELLER_KVK: '42115132',
  BILLING_SELLER_VAT: 'NL863456789B01',
};

let redis = null;
let srv = null;
let checks = 0;
const did = () => { checks++; };

// Every key this suite writes carries the run's own prefix in the account id,
// so a redis someone else is also using cannot make it green or red by
// accident, and nothing has to be flushed.
const RUN = `${process.pid}_${Date.now().toString(36)}`;
const acct = (base) => `${base}_${RUN}`;

before(async () => {
  redis = await requireRedis('redis://127.0.0.1:6398');
  if (!redis) return;
  srv = await boot({
    tag: 'billing-invoices',
    // usersFile, not USERS_JSON: the restart test below re-boots on the same
    // scratch dir, and a relay that carried its keys in an env var comes back
    // with none.
    usersFile: true,
    users: {
      api_keys: [
        { key: KEY_A, plan: 'community', active: true, parasign: true, account_id: acct(ACCT_A), email: 'one@example.test' },
        { key: KEY_B, plan: 'community', active: true, parasign: true, account_id: acct(ACCT_B), email: 'two@example.test' },
      ],
    },
    env: { ...SELLER, RELAY_REDIS_URL: redis.options.url, REDIS_URL: redis.options.url },
  });
});

after(async () => {
  await killAll();
  if (redis) { try { await redis.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-billing-invoices', checks);
});

const asA = { headers: { 'X-Api-Key': KEY_A } };
const asB = { headers: { 'X-Api-Key': KEY_B } };

// Issue a document straight into the shared redis, the way the webhook does.
async function issueFor(accountId, paymentId, value, opts = {}) {
  return invoice.issueDocument({
    payment: {
      id: paymentId, status: 'paid', method: 'ideal',
      amount: { value, currency: 'EUR' },
      metadata: { accountId, product: 'parasign', plan: 'pro', interval: 'yearly' },
    },
    order: { accountId, product: 'parasign', plan: 'pro', interval: 'yearly', currency: 'EUR' },
    seller: invoice.sellerFromEnv(SELLER),
    buyer: opts.buyer || { email: 'one@example.test', company: '', address: '', vat: '' },
    now: opts.now,
  }, redis);
}

// The relay caches nothing about invoices in memory, so a document written to
// redis after boot is visible to the next request. Nothing to wait for.

test('the routes need a key', async (t) => {
  if (!srv) return t.skip('no redis');
  for (const p of ['/v2/billing/invoices', '/v2/billing/invoices/PS-2026-0001.pdf', '/v2/billing/profile']) {
    const r = await srv.get(p);
    assert.strictEqual(r.status, 401, `${p} is closed without a key`);
  }
  did();
});

test('an account with no payments gets an empty list, not an error', async (t) => {
  if (!srv) return t.skip('no redis');
  const r = await srv.get('/v2/billing/invoices', asB);
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(r.json.invoices, []);
  did();
});

test('a document written by the billing path is listed and downloadable', async (t) => {
  if (!srv) return t.skip('no redis');
  const out = await issueFor(acct(ACCT_A), `tr_route_${RUN}_1`, '603.79', {
    buyer: { email: 'one@example.test', company: 'Acme One B.V.', address: 'Example Road 12\n1015 BR Example City', vat: 'NL812345678B01' },
  });
  assert.strictEqual(out.result, 'issued');

  const list = await srv.get('/v2/billing/invoices', asA);
  assert.strictEqual(list.status, 200);
  const row = list.json.invoices.find((i) => i.number === out.number);
  assert.ok(row, 'the document is in the account listing');
  assert.strictEqual(row.amount_gross, '603.79');
  assert.strictEqual(row.amount_net, '499.00');
  assert.strictEqual(row.amount_vat, '104.79');
  assert.strictEqual(row.vat_rate, 21);
  assert.strictEqual(row.kind, 'invoice');
  assert.strictEqual(row.pdf_url, `/v2/billing/invoices/${out.number}.pdf`);
  // The listing is a summary. Seller and buyer blocks belong on the document.
  assert.strictEqual(row.seller, undefined);
  assert.strictEqual(row.buyer, undefined);

  const pdf = await srv.get(row.pdf_url, asA);
  assert.strictEqual(pdf.status, 200);
  assert.strictEqual(pdf.headers['content-type'], 'application/pdf');
  assert.match(pdf.headers['content-disposition'], new RegExp(`filename="${out.number}\\.pdf"`));
  assert.strictEqual(pdf.headers['cache-control'], 'private, no-store');
  const text = pdf.buf.toString('latin1');
  assert.ok(text.startsWith('%PDF-'), 'the body is a PDF');
  assert.ok(text.includes(out.number), 'with its own number on it');
  assert.ok(text.includes('NL863456789B01'), 'the seller VAT number from the relay env');
  assert.ok(text.includes('Acme One B.V.'), 'and the customer it was issued to');
  did();
});

test('an account cannot read another account its document', async (t) => {
  if (!srv) return t.skip('no redis');
  const mine = await issueFor(acct(ACCT_A), `tr_route_${RUN}_2`, '59.29');
  const listB = await srv.get('/v2/billing/invoices', asB);
  assert.ok(!listB.json.invoices.some((i) => i.number === mine.number),
    'it is not in the other account listing');
  const stolen = await srv.get(`/v2/billing/invoices/${mine.number}.pdf`, asB);
  assert.strictEqual(stolen.status, 404, 'and the number alone gets you nothing');
  did();
});

test('a malformed number is refused before anything is looked up', async (t) => {
  if (!srv) return t.skip('no redis');
  for (const bad of ['nope.pdf', '../../etc/passwd', 'PS-26-1.pdf', 'PS-2026-0001x.pdf']) {
    const r = await srv.get(`/v2/billing/invoices/${encodeURIComponent(bad)}`, asA);
    assert.strictEqual(r.status, 400, `${bad} is refused`);
  }
  const missing = await srv.get('/v2/billing/invoices/PS-1999-9999.pdf', asA);
  assert.strictEqual(missing.status, 404, 'a well-formed number that does not exist is a 404');
  did();
});

test('company details are saved on the account and land on the NEXT document', async (t) => {
  if (!srv) return t.skip('no redis');
  const before = await srv.get('/v2/billing/profile', asB);
  assert.strictEqual(before.status, 200);
  assert.strictEqual(before.json.email, 'two@example.test', 'the email always comes from the account');
  assert.strictEqual(before.json.company, '');

  const saved = await srv.post('/v2/billing/profile', {
    headers: asB.headers,
    body: { company: 'Acme Two B.V.', address: 'Example Lane 40\n1015 CS Example City', vat: 'NL823456789B01' },
  });
  assert.strictEqual(saved.status, 200);
  assert.strictEqual(saved.json.company, 'Acme Two B.V.');

  const readBack = await srv.get('/v2/billing/profile', asB);
  assert.strictEqual(readBack.json.address, 'Example Lane 40\n1015 CS Example City');
  assert.strictEqual(readBack.json.vat, 'NL823456789B01');

  // A profile is in redis and not in users.json on purpose: the relay that
  // serves the account page and the relay nginx routes the Mollie webhook to
  // are different containers with different /data volumes.
  const raw = await redis.get(`paramant:billing:profile:${acct(ACCT_B)}`);
  assert.ok(raw && JSON.parse(raw).company === 'Acme Two B.V.', 'stored in the shared redis');
  did();
});

test('a saved profile survives a restart of the relay', async (t) => {
  if (!srv) return t.skip('no redis');
  srv = await srv.restart();
  const after = await srv.get('/v2/billing/profile', asB);
  assert.strictEqual(after.status, 200);
  assert.strictEqual(after.json.company, 'Acme Two B.V.');
  did();
});

test('a profile with an absurd address is refused, not truncated into nonsense', async (t) => {
  if (!srv) return t.skip('no redis');
  const r = await srv.post('/v2/billing/profile', {
    headers: asA.headers,
    body: { company: 'X', address: 'a\nb\nc\nd\ne\nf\ng', vat: '' },
  });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.json.error, 'address_too_many_lines');
  did();
});

test('numbers issued through the relay redis run consecutively', async (t) => {
  if (!srv) return t.skip('no redis');
  // Its own year, so a redis shared with another run of this suite cannot make
  // the sequence look broken.
  const year = new Date('2031-05-05T10:00:00Z');
  await redis.del(invoice.K.seq(2031));
  const first = await issueFor(acct(ACCT_A), `tr_seq_${RUN}_1`, '59.29', { now: year });
  const second = await issueFor(acct(ACCT_A), `tr_seq_${RUN}_2`, '59.29', { now: year });
  const repeat = await issueFor(acct(ACCT_A), `tr_seq_${RUN}_1`, '59.29', { now: year });
  assert.strictEqual(first.number, 'PS-2031-0001');
  assert.strictEqual(second.number, 'PS-2031-0002');
  assert.strictEqual(repeat.result, 'existing');
  assert.strictEqual(repeat.number, 'PS-2031-0001', 'a retry gets its own document back');

  const list = await srv.get('/v2/billing/invoices', asA);
  const numbers = list.json.invoices.map((i) => i.number).filter((n) => n.startsWith('PS-2031-'));
  assert.deepStrictEqual(numbers, ['PS-2031-0002', 'PS-2031-0001'], 'newest first, no duplicate');
  did();
});
