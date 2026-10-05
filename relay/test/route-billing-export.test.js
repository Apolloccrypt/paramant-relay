'use strict';
// GET /v2/admin/billing/export on a really booted relay, against a really
// running redis.
//
// WHAT THIS COVERS THAT test/billing-export.test.js CANNOT. That suite drives
// the module against a Map: it proves the rows, the CSV and the zip. This one
// proves the half that lives in relay.js and can only be wrong on the wire:
// that the route is closed to a customer key and open only to ADMIN_TOKEN, that
// the CSV really arrives as bytes with a BOM and a filename, that ?pdfs=1
// really answers with a zip a reader can open, and that a malformed period is a
// 400 rather than an empty file somebody files as a quiet quarter.
//
// Needs a throwaway redis. Any port; the suite is told which through REDIS_URL:
//   docker run -d --rm -p 6398:6379 --name export-test-redis redis:alpine
//   REDIS_URL=redis://127.0.0.1:6398 node --test test/route-billing-export.test.js
// Without one it FAILS, unless the runner declared redis absent
// (RELAY_TEST_SKIP=redis). See test/_requires.js for why.

const { test, before, after } = require('node:test');
const assert = require('assert');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const invoice = require('../lib/invoice');
const exporter = require('../lib/billing-export');

const EXPORT_KEY = 'pgp_export_customer_key';
const EXPORT_ADMIN = 'export-suite-admin-token';
// The boot helper proves it is talking to OUR relay by calling
// /v2/admin/entitlements/..., which sits behind X-Internal-Auth as well as the
// admin token. Without this the handshake reads as a port clash.
const EXPORT_INTERNAL = 'export-suite-internal-token';

let exportRedis = null;
let exportSrv = null;
let exportChecks = 0;
const exportDid = () => { exportChecks++; };

// The redis this suite shares with every other route suite carries ONE global
// list of document numbers, so the period is what keeps the runs apart: these
// documents are dated in a year nothing else in the repo issues into, and the
// account id carries the run's own prefix.
const EXPORT_RUN = `${process.pid}_${Date.now().toString(36)}`;
const EXPORT_FROM = '2019-03-01';
const EXPORT_TO = '2019-03-31';
const EXPORT_NUMBERS = {
  one: `PS-2019-${String(process.pid % 9000 + 1000)}`,
  two: `PS-2019-${String(process.pid % 9000 + 1001)}`,
  credit: `CN-2019-${String(process.pid % 9000 + 1000)}`,
  outside: `PS-2019-${String(process.pid % 9000 + 1002)}`,
};

function exportRecord(over) {
  return Object.assign({
    number: EXPORT_NUMBERS.one,
    kind: 'invoice',
    title: 'Invoice',
    issued_at: '2019-03-04T10:00:00.000Z',
    invoice_date: '2019-03-04',
    account_id: `acct_export_${EXPORT_RUN}`,
    payment_id: `tr_export_${EXPORT_RUN}_1`,
    payment_method: 'ideal',
    product: 'parasign', plan: 'pro', interval: 'yearly',
    description: 'Paramant ParaSign Pro, yearly plan',
    currency: 'EUR',
    vat_rate: 21,
    amount_net: '499.00', amount_vat: '104.79', amount_gross: '603.79',
    seller: { name: 'Paramantis Solutions B.V.', address: 'Example Street 1', kvk: '42115132', vat: 'NL863456789B01' },
    buyer: { email: 'office@example.test', company: 'Acme B.V.', address: 'Example Road 12\n1015 BR Example City', vat: 'NL812345678B01' },
  }, over || {});
}

// Straight into the keyspace lib/invoice.js writes, which is what the webhook
// does one function call later. Doing it through issueDocument would date every
// document today and make the period untestable.
async function putExportDocument(record) {
  await exportRedis.set(invoice.K.doc(record.number), JSON.stringify(record));
  await exportRedis.rPush(invoice.K.all, record.number);
  return record;
}

before(async () => {
  exportRedis = await requireRedis('redis://127.0.0.1:6398');
  if (!exportRedis) return;
  await putExportDocument(exportRecord());
  await putExportDocument(exportRecord({
    number: EXPORT_NUMBERS.two,
    issued_at: '2019-03-11T09:00:00.000Z',
    invoice_date: '2019-03-11',
    payment_id: `tr_export_${EXPORT_RUN}_2`,
    product: 'parasend', plan: 'pro', interval: 'monthly',
    description: 'Paramant ParaSend Pro, monthly plan',
    amount_net: '15.00', amount_vat: '3.15', amount_gross: '18.15',
    buyer: { email: 'two@example.test', company: '', address: '', vat: '' },
  }));
  await putExportDocument(exportRecord({
    number: EXPORT_NUMBERS.credit,
    kind: 'credit_note',
    title: 'Credit note',
    issued_at: '2019-03-20T09:00:00.000Z',
    invoice_date: '2019-03-20',
    credit_for: EXPORT_NUMBERS.one,
    credit_for_date: '2019-03-04',
    reason: 'chargeback',
    description: `Credit for Paramant ParaSign Pro, yearly plan (invoice ${EXPORT_NUMBERS.one})`,
    amount_net: '-499.00', amount_vat: '-104.79', amount_gross: '-603.79',
  }));
  await putExportDocument(exportRecord({
    number: EXPORT_NUMBERS.outside,
    issued_at: '2019-04-01T09:00:00.000Z',
    invoice_date: '2019-04-01',
    payment_id: `tr_export_${EXPORT_RUN}_4`,
  }));

  exportSrv = await boot({
    tag: 'billing-export',
    users: { api_keys: [{ key: EXPORT_KEY, plan: 'community', active: true, account_id: `acct_export_${EXPORT_RUN}`, email: 'office@example.test' }] },
    env: {
      ADMIN_TOKEN: EXPORT_ADMIN,
      INTERNAL_AUTH_TOKEN: EXPORT_INTERNAL,
      RELAY_REDIS_URL: exportRedis.options.url,
      REDIS_URL: exportRedis.options.url,
    },
  });
});

after(async () => {
  await killAll();
  if (exportRedis) {
    // Take this run's documents back out of the shared list, so a redis that is
    // reused does not grow one dead number per test run.
    try {
      for (const n of Object.values(EXPORT_NUMBERS)) {
        await exportRedis.lRem(invoice.K.all, 0, n);
        await exportRedis.del(invoice.K.doc(n));
      }
    } catch (_) { /* a cleanup that fails must not fail the suite */ }
    try { await exportRedis.disconnect(); } catch (_) { /* already gone */ }
  }
  summary('route-billing-export', exportChecks);
});

const exportAdmin = { headers: { 'X-Admin-Token': EXPORT_ADMIN } };
const exportPeriod = `from=${EXPORT_FROM}&to=${EXPORT_TO}`;

test('X1 the export is an admin route: a customer key and no key are both 401', async () => {
  if (!exportSrv) return;
  const anon = await exportSrv.get(`/v2/admin/billing/export?${exportPeriod}`);
  assert.equal(anon.status, 401);
  const asCustomer = await exportSrv.get(`/v2/admin/billing/export?${exportPeriod}`, { headers: { 'X-Api-Key': EXPORT_KEY } });
  assert.equal(asCustomer.status, 401);
  assert.equal(asCustomer.json.error, 'ADMIN_TOKEN required for admin endpoints');
  exportDid();
});

test('X2 the JSON export carries this period and nobody else', async () => {
  if (!exportSrv) return;
  const r = await exportSrv.get(`/v2/admin/billing/export?${exportPeriod}&format=json`, exportAdmin);
  assert.equal(r.status, 200);
  assert.equal(r.json.ok, true);
  const numbers = r.json.rows.map((x) => x.number);
  assert.deepEqual(numbers, [EXPORT_NUMBERS.one, EXPORT_NUMBERS.two, EXPORT_NUMBERS.credit]);
  assert.ok(!numbers.includes(EXPORT_NUMBERS.outside), 'an April invoice is not March business');
  assert.deepEqual(r.json.totals, { amount_net: '15.00', amount_vat: '3.15', amount_gross: '18.15' });
  assert.deepEqual(r.json.columns, exporter.COLUMNS);
  exportDid();
});

test('X3 the CSV comes back as a downloadable file with a BOM, semicolons and comma decimals', async () => {
  if (!exportSrv) return;
  const r = await exportSrv.get(`/v2/admin/billing/export?${exportPeriod}`, exportAdmin);
  assert.equal(r.status, 200);
  assert.ok(String(r.headers['content-type']).startsWith('text/csv'), r.headers['content-type']);
  assert.equal(r.headers['content-disposition'], `attachment; filename="paramant-billing-${EXPORT_FROM}_${EXPORT_TO}.csv"`);
  assert.equal(r.headers['cache-control'], 'private, no-store');
  assert.equal(r.buf.subarray(0, 3).toString('hex'), 'efbbbf', 'the BOM is what makes Excel read UTF-8');
  const lines = r.buf.subarray(3).toString('utf8').split('\r\n').filter(Boolean);
  assert.equal(lines[0].split(';')[0], 'number');
  assert.equal(lines.length, 4, 'a header and three documents');
  assert.ok(lines[1].includes(';603,79;'), lines[1]);
  assert.ok(lines[3].includes(';-603,79;'), lines[3]);
  assert.ok(!r.text.includes('603.79'), 'no dotted amount survives into the CSV');
  exportDid();
});

test('X4 a malformed or reversed period is a 400, never a quietly empty export', async () => {
  if (!exportSrv) return;
  for (const q of ['from=01-03-2019&to=2019-03-31', 'from=2019-03-01', 'from=2019-03-31&to=2019-03-01', '']) {
    const r = await exportSrv.get(`/v2/admin/billing/export?${q}`, exportAdmin);
    assert.equal(r.status, 400, q);
    assert.equal(r.json.error, 'bad_period');
  }
  const bad = await exportSrv.get(`/v2/admin/billing/export?${exportPeriod}&format=xml`, exportAdmin);
  assert.equal(bad.status, 400);
  assert.equal(bad.json.error, 'bad_format');
  exportDid();
});

test('X5 pdfs=1 answers with a zip holding the ledger and one PDF per document', async () => {
  if (!exportSrv) return;
  const r = await exportSrv.get(`/v2/admin/billing/export?${exportPeriod}&pdfs=1`, exportAdmin);
  assert.equal(r.status, 200);
  assert.equal(r.headers['content-type'], 'application/zip');
  assert.equal(r.headers['content-disposition'], `attachment; filename="paramant-billing-${EXPORT_FROM}_${EXPORT_TO}.zip"`);
  assert.equal(r.buf.readUInt32LE(0), 0x04034b50, 'a local file header, so it is a zip');
  const eocd = r.buf.length - 22;
  assert.equal(r.buf.readUInt32LE(eocd), 0x06054b50);
  assert.equal(r.buf.readUInt16LE(eocd + 10), 4, 'the CSV plus three PDFs');
  // The names are readable straight out of the central directory.
  const text = r.buf.toString('latin1');
  for (const n of [EXPORT_NUMBERS.one, EXPORT_NUMBERS.two, EXPORT_NUMBERS.credit]) {
    assert.ok(text.includes(`${n}.pdf`), `${n}.pdf is in the archive`);
  }
  assert.ok(!text.includes(`${EXPORT_NUMBERS.outside}.pdf`));
  assert.ok(text.includes('%PDF-'), 'and the PDFs are stored, not compressed');
  exportDid();
});
