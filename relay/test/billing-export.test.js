'use strict';
// The period export: the CSV a Dutch Excel opens as numbers, the JSON a script
// reads, and the zip that holds the PDFs of one month.
//
// No redis and no network. The store is the same Map-behind-five-commands
// stand-in relay/test/invoice.test.js uses, so these run in the plain unit job.
// The route half (admin auth, the headers, the zip over the wire) is exercised
// by the booted relay in test/route-billing-invoices.test.js.
//
// Run: node --test relay/test/billing-export.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const invoice = require('../lib/invoice');
const invoicePdf = require('../lib/invoice-pdf');
const exporter = require('../lib/billing-export');
const zipStore = require('../lib/zip-store');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('billing-export', checks));

// ── a redis stand-in ─────────────────────────────────────────────────────────
// get, set (with NX), incr, rPush, lRange with negative indices: the five
// commands lib/invoice.js and lib/billing-export.js call between them.
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

const SELLER = {
  name: 'Paramantis Solutions B.V.',
  address: 'Example Street 1\n1234 AB Example City\nNetherlands',
  kvk: '42115132',
  vat: 'NL863456789B01',
};

// A stored document, written straight into the keyspace lib/invoice.js uses.
// Building them by hand rather than through issueDocument keeps the dates under
// the test's control: a period filter that is only ever asked about today is a
// period filter nobody has tested.
function putDocument(redis, rec) {
  redis.kv.set(invoice.K.doc(rec.number), JSON.stringify(rec));
  const all = redis.lists.get(invoice.K.all) || [];
  all.push(rec.number);
  redis.lists.set(invoice.K.all, all);
  return rec;
}

function invoiceRecord(over = {}) {
  return Object.assign({
    number: 'PS-2026-0001',
    kind: 'invoice',
    title: 'Invoice',
    issued_at: '2026-09-04T10:00:00.000Z',
    invoice_date: '2026-09-04',
    account_id: 'acct_demo',
    payment_id: 'tr_demo1',
    payment_method: 'ideal',
    product: 'parasign',
    plan: 'pro',
    interval: 'yearly',
    description: 'Paramant ParaSign Pro, yearly plan',
    currency: 'EUR',
    vat_rate: 21,
    amount_net: '499.00',
    amount_vat: '104.79',
    amount_gross: '603.79',
    seller: Object.assign({}, SELLER),
    buyer: { email: 'office@example.test', company: 'Acme B.V.', address: 'Example Road 12\n1015 BR Example City', vat: 'NL812345678B01' },
  }, over);
}

function creditRecord(over = {}) {
  return Object.assign(invoiceRecord(), {
    number: 'CN-2026-0001',
    kind: 'credit_note',
    series: 'CN',
    title: 'Credit note',
    issued_at: '2026-09-20T10:00:00.000Z',
    invoice_date: '2026-09-20',
    credit_for: 'PS-2026-0001',
    credit_for_date: '2026-09-04',
    reason: 'chargeback',
    partial: false,
    description: 'Credit for Paramant ParaSign Pro, yearly plan (invoice PS-2026-0001)',
    amount_net: '-499.00',
    amount_vat: '-104.79',
    amount_gross: '-603.79',
  }, over);
}

// The three documents every case below reads: two invoices in September and one
// credit note against the first, plus one invoice in August that must never
// appear in a September export.
async function septemberStore() {
  const redis = fakeRedis();
  putDocument(redis, invoiceRecord());
  putDocument(redis, invoiceRecord({
    number: 'PS-2026-0002',
    issued_at: '2026-09-11T09:00:00.000Z',
    invoice_date: '2026-09-11',
    payment_id: 'tr_demo2',
    product: 'parasend', plan: 'pro', interval: 'monthly',
    description: 'Paramant ParaSend Pro, monthly plan',
    amount_net: '15.00', amount_vat: '3.15', amount_gross: '18.15',
    buyer: { email: 'two@example.test', company: '', address: '', vat: '' },
  }));
  putDocument(redis, creditRecord());
  putDocument(redis, invoiceRecord({
    number: 'PS-2026-0000',
    issued_at: '2026-08-31T23:50:00.000Z',
    invoice_date: '2026-08-31',
    payment_id: 'tr_august',
  }));
  return redis;
}

const SEPT = { from: '2026-09-01', to: '2026-09-30' };

// ── the period ───────────────────────────────────────────────────────────────

test('E1 the export holds exactly the documents of the period, both series', async () => {
  const redis = await septemberStore();
  const out = await exporter.build({ ...SEPT, redis });
  assert.equal(out.count, 3);
  assert.deepEqual(out.rows.map((r) => r.number), ['PS-2026-0001', 'PS-2026-0002', 'CN-2026-0001']);
  assert.ok(!out.rows.some((r) => r.number === 'PS-2026-0000'), 'an August invoice is not September business');
  did();
});

test('E2 both ends of the period are inclusive', () => {
  assert.ok(exporter.inPeriod('2026-09-01', '2026-09-01', '2026-09-30'));
  assert.ok(exporter.inPeriod('2026-09-30', '2026-09-01', '2026-09-30'));
  assert.ok(!exporter.inPeriod('2026-08-31', '2026-09-01', '2026-09-30'));
  assert.ok(!exporter.inPeriod('2026-10-01', '2026-09-01', '2026-09-30'));
  did();
});

test('E3 a malformed or reversed period is refused, not silently emptied', async () => {
  const redis = await septemberStore();
  assert.equal((await exporter.build({ from: '01-09-2026', to: '2026-09-30', redis })).error, 'bad_period');
  assert.equal((await exporter.build({ from: '2026-09-01', to: '', redis })).error, 'bad_period');
  assert.equal((await exporter.build({ from: '2026-09-30', to: '2026-09-01', redis })).error, 'bad_period');
  assert.equal((await exporter.build({ from: '2026-02-30', to: '2026-09-01', redis })).error, 'bad_period');
  did();
});

// ── the CSV ──────────────────────────────────────────────────────────────────

test('E4 the CSV is semicolon-separated, starts with a UTF-8 BOM, and ends its lines with CRLF', async () => {
  const redis = await septemberStore();
  const csv = exporter.toCsv((await exporter.build({ ...SEPT, redis })).rows);
  assert.equal(csv.charCodeAt(0), 0xfeff, 'the BOM is what makes Excel read UTF-8');
  assert.equal(Buffer.from(csv, 'utf8').subarray(0, 3).toString('hex'), 'efbbbf');
  const lines = csv.slice(1).split('\r\n').filter(Boolean);
  assert.equal(lines.length, 4, 'a header and three documents');
  assert.equal(lines[0].split(';')[0], 'number');
  assert.equal(lines[0].split(';').length, exporter.COLUMNS.length);
  assert.ok(!csv.includes(',;'), 'no stray comma-separated field');
  did();
});

test('E5 amounts carry a comma as the decimal mark, and a credit note carries the minus', async () => {
  const redis = await septemberStore();
  const csv = exporter.toCsv((await exporter.build({ ...SEPT, redis })).rows);
  const rows = csv.slice(1).split('\r\n').filter(Boolean).slice(1).map((l) => l.split(';'));
  const col = (name) => exporter.COLUMNS.indexOf(name);
  assert.equal(rows[0][col('amount_net')], '499,00');
  assert.equal(rows[0][col('amount_vat')], '104,79');
  assert.equal(rows[0][col('amount_gross')], '603,79');
  assert.equal(rows[1][col('amount_gross')], '18,15');
  assert.equal(rows[2][col('amount_gross')], '-603,79');
  assert.ok(!csv.includes('603.79'), 'no dotted amount survives into the CSV');
  did();
});

test('E6 every column a bookkeeper needs is on the row', async () => {
  const redis = await septemberStore();
  const out = await exporter.build({ ...SEPT, redis });
  const first = out.rows[0];
  assert.equal(first.number, 'PS-2026-0001');
  assert.equal(first.date, '2026-09-04');
  assert.equal(first.type, 'invoice');
  assert.equal(first.customer_name, 'Acme B.V.');
  assert.equal(first.customer_email, 'office@example.test');
  assert.equal(first.customer_vat, 'NL812345678B01');
  assert.equal(first.description, 'Paramant ParaSign Pro, yearly plan');
  assert.equal(first.vat_rate, '21');
  assert.equal(first.currency, 'EUR');
  assert.equal(first.payment_id, 'tr_demo1');
  assert.equal(first.credit_for, '');
  // No company on file: the name column falls back to the address we do have,
  // so it is never blank on a document that has a buyer.
  assert.equal(out.rows[1].customer_name, 'two@example.test');
  // The credit note names the invoice it reverses, which is the field that
  // makes it bookable at all.
  assert.equal(out.rows[2].type, 'credit_note');
  assert.equal(out.rows[2].credit_for, 'PS-2026-0001');
  did();
});

test('E7 a value holding the separator or a quote is quoted, and a quote is doubled', () => {
  assert.equal(exporter.csvField('Acme B.V.'), 'Acme B.V.');
  assert.equal(exporter.csvField('Acme; B.V.'), '"Acme; B.V."');
  assert.equal(exporter.csvField('Acme "the" B.V.'), '"Acme ""the"" B.V."');
  assert.equal(exporter.csvField('line\nbreak'), '"line\nbreak"');
  did();
});

test('E8 the totals add the credit note back off, in whole cents', async () => {
  const redis = await septemberStore();
  const out = await exporter.build({ ...SEPT, redis });
  // 603.79 + 18.15 - 603.79 = 18.15 gross, and the same arithmetic on the halves.
  assert.deepEqual(out.totals, { amount_net: '15.00', amount_vat: '3.15', amount_gross: '18.15' });
  did();
});

// ── the JSON ─────────────────────────────────────────────────────────────────

test('E9 the JSON body keeps dots, carries no BOM, and never ships the seller and buyer blocks', async () => {
  const redis = await septemberStore();
  const body = exporter.asJson(await exporter.build({ ...SEPT, redis }));
  const text = JSON.stringify(body);
  assert.equal(text.charCodeAt(0), '{'.charCodeAt(0));
  assert.equal(body.rows[0].amount_gross, '603.79');
  assert.equal(body.count, 3);
  assert.deepEqual(body.columns, exporter.COLUMNS);
  assert.ok(!('records' in body), 'the rows are the export; the raw records are not');
  assert.ok(!text.includes('Example Road 12'), 'no customer address rides along in a ledger line');
  did();
});

test('E10 a number in the list with no document behind it is reported, not skipped', async () => {
  const redis = await septemberStore();
  const all = redis.lists.get(invoice.K.all);
  all.push('PS-2026-0009');           // a number drawn whose record never landed
  const out = await exporter.build({ ...SEPT, redis });
  assert.deepEqual(out.missing, ['PS-2026-0009']);
  assert.equal(out.count, 3, 'the gap does not become a row');
  did();
});

// ── the zip ──────────────────────────────────────────────────────────────────

test('E11 the zip holds one PDF per document plus the ledger file', async () => {
  const redis = await septemberStore();
  const out = await exporter.build({ ...SEPT, redis });
  const built = exporter.buildZipEntries(out, { render: invoicePdf.render, format: 'csv' });
  assert.deepEqual(built.failures, []);
  const names = built.entries.map((e) => e.name);
  const base = exporter.fileBase(SEPT.from, SEPT.to);
  assert.deepEqual(names, [
    `${base}/${base}.csv`,
    `${base}/PS-2026-0001.pdf`,
    `${base}/PS-2026-0002.pdf`,
    `${base}/CN-2026-0001.pdf`,
  ]);
  for (const e of built.entries.slice(1)) {
    assert.ok(e.data.subarray(0, 5).toString('latin1') === '%PDF-', `${e.name} is a real PDF`);
  }
  did();
});

test('E12 the archive is a readable store-only zip: signatures, entry count, and the bytes come back', async () => {
  const redis = await septemberStore();
  const out = await exporter.build({ ...SEPT, redis });
  const built = exporter.buildZipEntries(out, { render: invoicePdf.render, format: 'csv' });
  const zip = zipStore.buildZip(built.entries);

  assert.equal(zip.readUInt32LE(0), 0x04034b50, 'starts with a local file header');
  // The end of central directory is the last 22 bytes (no archive comment).
  const eocd = zip.length - 22;
  assert.equal(zip.readUInt32LE(eocd), 0x06054b50);
  assert.equal(zip.readUInt16LE(eocd + 10), built.entries.length);
  const cdOffset = zip.readUInt32LE(eocd + 16);
  assert.equal(zip.readUInt32LE(cdOffset), 0x02014b50, 'the central directory is where the EOCD says it is');

  // Walk the local headers and read every entry back out, which is what an
  // unzip does. Method 0 means the bytes in the file ARE the bytes we put in.
  let at = 0;
  for (const entry of built.entries) {
    assert.equal(zip.readUInt32LE(at), 0x04034b50);
    assert.equal(zip.readUInt16LE(at + 8), 0, 'method 0, stored');
    const crc = zip.readUInt32LE(at + 14);
    const size = zip.readUInt32LE(at + 18);
    assert.equal(size, zip.readUInt32LE(at + 22), 'compressed and uncompressed size agree');
    const nameLen = zip.readUInt16LE(at + 26);
    const extraLen = zip.readUInt16LE(at + 28);
    const name = zip.subarray(at + 30, at + 30 + nameLen).toString('utf8');
    const data = zip.subarray(at + 30 + nameLen + extraLen, at + 30 + nameLen + extraLen + size);
    assert.equal(name, entry.name);
    assert.equal(size, entry.data.length);
    assert.ok(data.equals(entry.data), `${name} comes back byte for byte`);
    assert.equal(crc, zipStore.crc32(entry.data), 'the checksum is the one a reader will verify');
    at += 30 + nameLen + extraLen + size;
  }
  assert.equal(at, cdOffset, 'the entries end exactly where the central directory begins');
  did();
});

test('E13 the CSV inside the zip is the CSV the route serves', async () => {
  const redis = await septemberStore();
  const out = await exporter.build({ ...SEPT, redis });
  const built = exporter.buildZipEntries(out, { render: invoicePdf.render, format: 'csv' });
  assert.equal(built.entries[0].data.toString('utf8'), exporter.toCsv(out.rows));
  const asJson = exporter.buildZipEntries(out, { render: invoicePdf.render, format: 'json' });
  assert.ok(asJson.entries[0].name.endsWith('.json'));
  assert.deepEqual(JSON.parse(asJson.entries[0].data.toString('utf8')).rows, out.rows);
  did();
});

test('E14 a document whose PDF will not render is named in the archive, not dropped from it', async () => {
  const redis = await septemberStore();
  const out = await exporter.build({ ...SEPT, redis });
  const built = exporter.buildZipEntries(out, {
    format: 'csv',
    render: (rec) => {
      if (rec.number === 'PS-2026-0002') throw new Error('render_boom');
      return invoicePdf.render(rec, { buyerHint: invoice.BUYER_HINT });
    },
  });
  assert.deepEqual(built.failures, ['PS-2026-0002: render_boom']);
  const names = built.entries.map((e) => e.name);
  assert.ok(!names.some((n) => n.endsWith('PS-2026-0002.pdf')));
  assert.ok(names.some((n) => n.endsWith('RENDER-FAILURES.txt')));
  const note = built.entries.find((e) => e.name.endsWith('RENDER-FAILURES.txt'));
  assert.ok(note.data.toString('utf8').includes('PS-2026-0002: render_boom'));
  did();
});

test('E15 the two CRC-32 implementations agree, and a name cannot escape the extraction directory', () => {
  for (const s of ['', 'a', 'the quick brown fox', 'x'.repeat(1000)]) {
    const buf = Buffer.from(s, 'utf8');
    assert.equal(zipStore.crc32(buf), zipStore.crc32Fallback(buf), `crc32 agrees on ${JSON.stringify(s.slice(0, 12))}`);
  }
  assert.equal(zipStore.crc32Fallback(Buffer.from('123456789')), 0xcbf43926, 'the IEEE check value');
  assert.equal(zipStore.safeName('../../etc/passwd'), 'etc/passwd');
  assert.equal(zipStore.safeName('/absolute/path.pdf'), 'absolute/path.pdf');
  assert.equal(zipStore.safeName('a\\b.pdf'), 'a/b.pdf');
  assert.throws(() => zipStore.buildZip([{ name: '../..', data: Buffer.alloc(1) }]), /zip_bad_entry_name/);
  did();
});
