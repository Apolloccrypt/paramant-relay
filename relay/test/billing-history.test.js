'use strict';
// The one list a customer reads when he wonders what he was charged.
//
// /account carried a "Billing history" block that said "No billing events yet"
// to an account that had paid, been invoiced and watched its term run out. This
// suite drives the module that fills it, and the assertion that matters most is
// the one about renewals: a period end that was extended by a renewal is NOT a
// moment anything ended, and putting it in the list would tell a paying customer
// he had lapsed on a day he never lost access.
//
// No redis and no network: the same Map stand-in the invoice and credit-note
// suites use, plus the two hash reads lib/plan-expiry.js's index needs.
//
// Run: node --test relay/test/billing-history.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const invoice = require('../lib/invoice');
const credit = require('../lib/credit-note');
const planExpiry = require('../lib/plan-expiry');
const history = require('../lib/billing-history');
const catalog = require('../lib/billing-catalog');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('billing-history', checks));

function fakeRedis() {
  const kv = new Map();
  const lists = new Map();
  const hashes = new Map();
  return {
    kv, lists, hashes,
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
    async hSet(h, f, v) { const m = hashes.get(h) || new Map(); m.set(f, String(v)); hashes.set(h, m); return 1; },
    async hGet(h, f) { const m = hashes.get(h); return m && m.has(f) ? m.get(f) : null; },
  };
}

const SELLER = {
  name: 'Paramantis Solutions B.V.',
  address: 'Example Street 1\n1234 AB Example City\nNetherlands',
  kvk: '42115132',
  vat: 'NL863456789B01',
};
const BUYER = { email: 'office@example.test', company: 'Acme B.V.', address: 'Example Road 12', vat: '' };
const ACCT = 'acct_demo';
const NOW = new Date('2027-03-01T00:00:00Z');

function payment(id, plan = 'pro', interval = 'yearly') {
  const order = catalog.resolveOrder({ product: 'parasign', plan, interval });
  return {
    id, status: 'paid', method: 'ideal',
    amount: { value: order.amount, currency: order.currency },
    metadata: { accountId: ACCT, product: 'parasign', plan, interval },
  };
}

// One payment, on a date, buying a term that runs to another date. Both are
// injected, because everything this module decides is a comparison of those two
// against each other and against now.
async function pay(redis, id, { at, until, plan = 'pro', interval = 'yearly' }) {
  const p = payment(id, plan, interval);
  return invoice.issueDocument({
    payment: p,
    order: Object.assign({ accountId: ACCT }, catalog.resolveOrder(p.metadata)),
    seller: SELLER, buyer: BUYER,
    now: new Date(at),
    periodEnd: until,
  }, redis);
}

const build = (redis) => history.build({ accountId: ACCT, redis, now: NOW });
const typesOf = (rows) => rows.map((r) => r.type);

// ── 1. the money ─────────────────────────────────────────────────────────────

test('a paid invoice becomes a row with its number, its total and a download', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_one', { at: '2026-09-03T12:00:00Z', until: '2027-09-03T12:00:00Z' });
  const rows = await build(redis);
  assert.strictEqual(rows.length, 1, 'a paid account is not "no billing events yet"');
  const row = rows[0];
  assert.strictEqual(row.type, 'invoice');
  assert.strictEqual(row.document, 'PS-2026-0001');
  assert.strictEqual(row.amount, '603.79');
  assert.strictEqual(row.currency, 'EUR');
  assert.strictEqual(row.label, 'Paramant ParaSign Pro, yearly plan');
  assert.strictEqual(row.detail, 'Paid');
  assert.strictEqual(row.pdf_url, '/v2/billing/invoices/PS-2026-0001.pdf');
  assert.strictEqual(row.ts, '2026-09-03T12:00:00.000Z');
  did();
});

test('a credit note is its own row, negative, naming the invoice it credits', async () => {
  const redis = fakeRedis();
  const paid = await pay(redis, 'tr_back', { at: '2026-09-03T12:00:00Z', until: '2027-09-03T12:00:00Z' });
  assert.strictEqual(paid.result, 'issued');
  await credit.issueCreditNote({
    payment: Object.assign(payment('tr_back'), { status: 'chargeback', amountChargedBack: { value: '603.79', currency: 'EUR' } }),
    now: new Date('2026-09-20T09:00:00Z'),
  }, redis);
  const rows = await build(redis);
  assert.deepStrictEqual(typesOf(rows), ['credit_note', 'invoice'], 'newest first');
  assert.strictEqual(rows[0].document, 'CN-2026-0001');
  assert.strictEqual(rows[0].amount, '-603.79');
  assert.strictEqual(rows[0].credit_for, 'PS-2026-0001');
  assert.strictEqual(rows[0].label, 'Credit note for invoice PS-2026-0001');
  assert.strictEqual(rows[0].detail, 'Charged back');
  assert.strictEqual(rows[0].pdf_url, '/v2/billing/invoices/CN-2026-0001.pdf');
  did();
});

test('a partial credit says it is partial, and the invoice row stays', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_part', { at: '2026-09-03T12:00:00Z', until: '2027-09-03T12:00:00Z' });
  await credit.issueCreditNote({
    payment: Object.assign(payment('tr_part'), { amountRefunded: { value: '100.00', currency: 'EUR' } }),
    now: new Date('2026-10-01T09:00:00Z'),
  }, redis);
  const rows = await build(redis);
  assert.strictEqual(rows[0].label, 'Credit note for invoice PS-2026-0001 (partial)');
  assert.strictEqual(rows[0].detail, 'Refunded');
  assert.strictEqual(rows[0].amount, '-100.00');
  assert.strictEqual(rows[1].amount, '603.79', 'the invoice still says what was charged');
  did();
});

// ── 2. the terms ─────────────────────────────────────────────────────────────

test('a term that has run out is a row of its own, on the day it ended', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_gone', { at: '2026-01-10T12:00:00Z', until: '2026-02-10T12:00:00Z', interval: 'monthly' });
  const rows = await build(redis);
  assert.deepStrictEqual(typesOf(rows), ['term_ended', 'invoice']);
  assert.strictEqual(rows[0].ts, '2026-02-10T12:00:00.000Z');
  assert.strictEqual(rows[0].label, 'ParaSign Pro term ended');
  assert.strictEqual(rows[0].detail, 'Account back on Community');
  assert.strictEqual(rows[0].amount, null, 'nothing was charged for it ending');
  assert.strictEqual(rows[0].notified_at, null, 'and no mail is claimed that never went out');
  did();
});

test('a term still running is not in the list at all', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_live', { at: '2027-02-01T12:00:00Z', until: '2028-02-01T12:00:00Z' });
  const rows = await build(redis);
  assert.deepStrictEqual(typesOf(rows), ['invoice'], 'a plan that has not ended has not ended');
  did();
});

test('a renewal bought in time is one term, not two', async () => {
  // The whole point. The first period ends on 2026-09-03, and a renewal bought
  // in August extends it (lib/billing.js extendFrom) rather than starting a
  // second one. Listing that first end would tell a customer who never lost a
  // day of access that his plan had lapsed.
  const redis = fakeRedis();
  await pay(redis, 'tr_r1', { at: '2025-09-03T12:00:00Z', until: '2026-09-03T12:00:00Z' });
  await pay(redis, 'tr_r2', { at: '2026-08-20T12:00:00Z', until: '2027-09-03T12:00:00Z' });
  const rows = await build(redis);
  assert.deepStrictEqual(typesOf(rows), ['invoice', 'invoice'], 'two payments, no lapse');
  did();
});

test('a lapse and a later restart are two real term ends', async () => {
  // Paid a month, let it go, came back four months later, let that go too.
  // Both ends really happened and the customer really was on Community in
  // between, so both belong in his own history.
  const redis = fakeRedis();
  await pay(redis, 'tr_l1', { at: '2026-01-10T12:00:00Z', until: '2026-02-10T12:00:00Z', interval: 'monthly' });
  await pay(redis, 'tr_l2', { at: '2026-06-10T12:00:00Z', until: '2026-07-10T12:00:00Z', interval: 'monthly' });
  const rows = await build(redis);
  assert.deepStrictEqual(typesOf(rows), ['term_ended', 'invoice', 'term_ended', 'invoice']);
  assert.deepStrictEqual(rows.filter((r) => r.type === 'term_ended').map((r) => r.ts),
    ['2026-07-10T12:00:00.000Z', '2026-02-10T12:00:00.000Z']);
  did();
});

test('a term the customer was mailed about carries when he was told', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_told', { at: '2026-01-10T12:00:00Z', until: '2026-02-10T12:00:00Z', interval: 'monthly' });
  // The marker lib/plan-expiry.js writes when the "your plan has ended" mail
  // really went out. Its name carries the period, so it is read by key.
  await redis.set(
    planExpiry.noticeKey('ended', ACCT, 'parasign', '2026-02-10T12:00:00Z'),
    String(Date.parse('2026-02-10T18:00:00Z')));
  const rows = await build(redis);
  assert.strictEqual(rows[0].type, 'term_ended');
  assert.strictEqual(rows[0].notified_at, '2026-02-10T18:00:00.000Z');
  did();
});

test('a period no invoice ever bought still ends, via the plan-expiry index', async () => {
  // An admin-set plan, or one granted before the invoice module existed. The
  // expiry index is the only record of it, and it is two keyed reads away.
  const redis = fakeRedis();
  await redis.hSet(planExpiry.META_HASH, planExpiry.memberOf(ACCT, 'parasend'), JSON.stringify({
    email: 'office@example.test', tier: 'business', paid_until: '2026-05-01T00:00:00.000Z',
  }));
  const rows = await build(redis);
  assert.deepStrictEqual(typesOf(rows), ['term_ended']);
  assert.strictEqual(rows[0].label, 'ParaSend Business term ended');
  assert.strictEqual(rows[0].ts, '2026-05-01T00:00:00.000Z');
  did();
});

test('the index and the invoice do not produce the same ending twice', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_dup', { at: '2026-01-10T12:00:00Z', until: '2026-02-10T12:00:00Z', interval: 'monthly' });
  await redis.hSet(planExpiry.META_HASH, planExpiry.memberOf(ACCT, 'parasign'), JSON.stringify({
    email: 'office@example.test', tier: 'pro', paid_until: '2026-02-10T12:00:00.000Z',
  }));
  const rows = await build(redis);
  assert.strictEqual(rows.filter((r) => r.type === 'term_ended').length, 1, 'one ending, one row');
  did();
});

test('a fully reversed payment bought no term, so none ended', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_rev', { at: '2026-01-10T12:00:00Z', until: '2026-02-10T12:00:00Z', interval: 'monthly' });
  await invoice.recordReversal({ payment: { id: 'tr_rev' }, now: new Date('2026-01-15T00:00:00Z') }, redis);
  const rows = await build(redis);
  assert.strictEqual(rows.filter((r) => r.type === 'term_ended').length, 0,
    'a plan that was charged back never ran to a term end');
  assert.strictEqual(rows[0].reversed_at, '2026-01-15T00:00:00.000Z', 'and the invoice row says it was reversed');
  did();
});

// ── 3. the empty and broken cases ────────────────────────────────────────────

test('an account that never paid gets an empty list, not an error', async () => {
  const rows = await build(fakeRedis());
  assert.deepStrictEqual(rows, []);
  did();
});

test('no account and no redis answer empty rather than throw', async () => {
  assert.deepStrictEqual(await history.build({ accountId: ACCT, redis: null }), []);
  assert.deepStrictEqual(await history.build({ accountId: '', redis: fakeRedis() }), []);
  assert.deepStrictEqual(await history.build({}), []);
  did();
});

test('the whole list is one chronology, newest first', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_c1', { at: '2026-01-10T12:00:00Z', until: '2026-02-10T12:00:00Z', interval: 'monthly' });
  await pay(redis, 'tr_c2', { at: '2026-06-10T12:00:00Z', until: '2026-07-10T12:00:00Z', interval: 'monthly' });
  await credit.issueCreditNote({
    payment: Object.assign(payment('tr_c2', 'pro', 'monthly'), { status: 'chargeback' }),
    now: new Date('2026-06-15T09:00:00Z'),
  }, redis);
  const rows = await build(redis);
  const stamps = rows.map((r) => Date.parse(r.ts));
  for (let i = 1; i < stamps.length; i++) {
    assert.ok(stamps[i - 1] >= stamps[i], `row ${i} is not out of order`);
  }
  assert.ok(rows.some((r) => r.type === 'credit_note'), 'the credit note is in the same list');
  assert.ok(rows.some((r) => r.type === 'invoice'), 'so are the payments');
  did();
});

test('no em-dash reaches the customer from anything this module writes', async () => {
  const redis = fakeRedis();
  await pay(redis, 'tr_style', { at: '2026-01-10T12:00:00Z', until: '2026-02-10T12:00:00Z', interval: 'monthly' });
  await credit.issueCreditNote({
    payment: Object.assign(payment('tr_style', 'pro', 'monthly'), { status: 'chargeback' }),
    now: new Date('2026-01-20T09:00:00Z'),
  }, redis);
  const rows = await build(redis);
  assert.ok(rows.length >= 3);
  for (const row of rows) {
    for (const field of ['label', 'detail']) {
      assert.ok(!String(row[field] || '').includes('\u2014'), `${row.type}.${field} has no em-dash`);
    }
  }
  did();
});
