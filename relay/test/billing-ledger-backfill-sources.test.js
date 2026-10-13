'use strict';
// Herreview #560, M3. The backfill read only paid_by_<product> and the
// paramant:billing:done:* markers. Markers written before the TTL was dropped
// still expire after 60 days, so the deploy needed a PERSIST on them first.
// The invoice claims (paramant:billing:invoice:for:<id>) carry no TTL and are
// written only after a grant: the backfill now reads them too.
// Plus the LAAG point from the same review: a chargeback that the webhook
// records while the backfill runs must not be overwritten with 'granted'.
const { test, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { BillingLedger, backfillLedger } = require('../lib/billing-ledger');
const { summary } = require('./_requires');

let checks = 0;
after(() => summary('billing-ledger-backfill-sources', checks));

function fakeRedis(kv, { onGet } = {}) {
  return {
    isReady: true,
    async *scanIterator({ MATCH }) {
      const pre = MATCH.replace(/\*$/, '');
      yield Object.keys(kv).filter((k) => k.startsWith(pre));
    },
    async get(k) { if (onGet) await onGet(k); return kv[k] ?? null; },
  };
}
function tmpLedger() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledgerbf-'));
  return new BillingLedger(path.join(dir, 'billing-processed.jsonl'));
}
function lines(ledger) {
  return fs.readFileSync(ledger.file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

test('invoice claims land in the ledger as granted, a revoked marker keeps its value, a second run adds nothing', async () => {
  const kv = {
    'paramant:billing:invoice:for:tr_oldInvoice1': 'PS-2026-000001',
    'paramant:billing:invoice:for:tr_pendingClaim': 'pending:1700000000000',
    'paramant:billing:invoice:for:tr_revokedOne': 'PS-2026-000002',
    'paramant:billing:done:tr_revokedOne': 'revoked',
    'paramant:billing:invoice:seq:2026': '2',
  };
  const ledger = tmpLedger();
  const r1 = await backfillLedger(ledger, { redis: fakeRedis(kv), records: [], products: [] });
  assert.strictEqual(ledger.status('tr_oldInvoice1'), 'granted');
  assert.strictEqual(ledger.status('tr_pendingClaim'), 'granted');
  assert.strictEqual(ledger.status('tr_revokedOne'), 'revoked');
  assert.strictEqual(r1.added, 3);
  const r2 = await backfillLedger(ledger, { redis: fakeRedis(kv), records: [], products: [] });
  assert.strictEqual(r2.added, 0);
  assert.strictEqual(lines(ledger).length, 3);
  // A fresh process reads the same file and backfills nothing either.
  const reloaded = new BillingLedger(ledger.file).load();
  assert.strictEqual((await backfillLedger(reloaded, { redis: fakeRedis(kv), records: [], products: [] })).added, 0);
  checks += 3;
});

test('a chargeback recorded during the backfill is not overwritten with granted', async () => {
  const ledger = tmpLedger();
  const kv = {
    'paramant:billing:done:tr_slowMarker': 'granted',
    'paramant:billing:invoice:for:tr_raced': 'PS-2026-000009',
  };
  // tr_raced is queued from its paid_by pointer. While the backfill is still
  // reading a done-marker, the webhook records the chargeback for it.
  const records = [{ paid_by_parasign: 'tr_raced' }];
  const redis = fakeRedis(kv, { onGet: async () => { await ledger.record('tr_raced', 'revoked'); } });
  await backfillLedger(ledger, { redis, records, products: ['parasign'] });
  assert.strictEqual(ledger.status('tr_raced'), 'revoked');
  assert.strictEqual(lines(ledger).filter((l) => l.id === 'tr_raced').length, 1);
  checks += 1;
});
