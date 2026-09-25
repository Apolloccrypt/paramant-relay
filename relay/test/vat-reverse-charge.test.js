'use strict';
// Reverse charge, piece by piece: the decision (lib/vat.js), the VIES answer,
// the amount, the marker on the payment, the webhook's amount check, the
// renewal, the invoice record, the PDF, the mail, the credit note, Moneybird,
// and the one compose line that lets the seller's VAT number reach a relay.
//
// No redis and no network. VIES is always a fake here; the route half, with a
// booted relay, a fake Mollie and a fake VIES, is test/route-billing-vat.test.js.
//
// Run: node --test relay/test/vat-reverse-charge.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const vat = require('../lib/vat');
const invoice = require('../lib/invoice');
const invoicePdf = require('../lib/invoice-pdf');
const billing = require('../lib/billing');
const recurring = require('../lib/billing-recurring');
const billingMail = require('../lib/billing-mail');
const creditNote = require('../lib/credit-note');
const moneybird = require('../lib/moneybird');
const catalog = require('../lib/billing-catalog');
const exporter = require('../lib/billing-export');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('vat-reverse-charge', checks));

// Example values only; the real seller number is deployment configuration.
const SELLER_VAT = 'NL000099998B01';
const SELLER = {
  name: 'Acme Seller B.V.',
  address: 'Example Street 1\n1234 AB Example City\nNetherlands',
  kvk: '00000000',
  vat: SELLER_VAT,
};
const EU_VAT = 'BE0999000001';
const NOW = new Date('2026-09-25T10:00:00Z');

// A VIES that answers what the test says and remembers what it was asked.
function fakeCheck(answer) {
  const calls = [];
  const check = async (q) => {
    calls.push(q);
    if (answer instanceof Error) throw answer;
    return typeof answer === 'function' ? answer(q) : answer;
  };
  check.calls = calls;
  return check;
}
const VALID = {
  result: 'valid', requestDate: '2026-09-25T10:00:01Z', requestIdentifier: 'WAPIAAAAWZ0000001',
  countryCode: 'BE', name: 'ACME BE SRL', address: 'EXAMPLE STREET 2\n1000 EXAMPLE CITY',
};
// The account as it stands at the checkout: name and address filled in, the
// address in the country the VAT number is from.
const ACME = { buyerCompany: 'Acme BE SRL', buyerAddress: 'Example Street 2\n1000 Example City\nBelgium' };

// The commands lib/invoice.js, lib/credit-note.js and lib/moneybird.js call,
// with the semantics that matter (SET NX, INCR from 1, negative lRange).
function fakeRedis() {
  const kv = new Map();
  const lists = new Map();
  const ttls = new Map();
  return {
    kv, ttls,
    async get(k) { return kv.has(k) ? kv.get(k) : null; },
    async set(k, v, opts) {
      if (opts && opts.NX && kv.has(k)) return null;
      kv.set(k, String(v));
      if (opts && opts.EX) ttls.set(k, opts.EX); else ttls.delete(k);
      return 'OK';
    },
    async persist(k) { return ttls.delete(k) ? 1 : 0; },
    async ttl(k) { return kv.has(k) ? (ttls.has(k) ? ttls.get(k) : -1) : -2; },
    async del(k) { return kv.delete(k) ? 1 : 0; },
    async incr(k) { const n = (parseInt(kv.get(k) || '0', 10) || 0) + 1; kv.set(k, String(n)); return n; },
    async rPush(k, v) { const l = lists.get(k) || []; l.push(v); lists.set(k, l); return l.length; },
    async lRange(k, start, stop) {
      const l = lists.get(k) || [];
      const a = start < 0 ? Math.max(0, l.length + start) : start;
      const b = stop < 0 ? l.length + stop : stop;
      return l.slice(a, b + 1);
    },
    async zAdd() { return 1; },
    async zRem() { return 0; },
    async hIncrBy() { return 1; },
    async hDel() { return 0; },
  };
}

const FIRM = { product: 'firm', plan: 'firm', interval: 'monthly' };
const RC_TERMS = { treatment: 'reverse_charge', vatId: EU_VAT, country: 'BE', checkedAt: VALID.requestDate, consultation: VALID.requestIdentifier };

function paymentOf(id, value, md = {}) {
  return {
    id, status: 'paid', method: 'creditcard',
    amount: { value, currency: 'EUR' },
    metadata: Object.assign({ accountId: 'acct_demo', ...FIRM }, md),
  };
}

function issue(redis, p, buyer) {
  const md = p.metadata;
  return invoice.issueDocument({
    payment: p,
    order: Object.assign({ accountId: md.accountId }, catalog.resolveOrder(md)),
    seller: SELLER,
    buyer: buyer || { email: 'office@example.test', company: 'Acme BE SRL', address: 'Example Street 2\n1000 Example City\nBelgium', vat: 'be 0999.000.001' },
    now: NOW,
    vat: vat.termsFromMetadata(md),
  }, redis);
}

// ── the decision ─────────────────────────────────────────────────────────────

test('a VAT number is read the way people write it', () => {
  assert.deepStrictEqual(vat.parseVatId('be 0999.000.001'), { country: 'BE', number: '0999000001', id: EU_VAT });
  assert.deepStrictEqual(vat.parseVatId(' DE-999000002 '), { country: 'DE', number: '999000002', id: 'DE999000002' });
  assert.strictEqual(vat.parseVatId('GR999000003').id, 'EL999000003', 'a Greek number carries EL');
  assert.strictEqual(vat.parseVatId(''), null);
  assert.strictEqual(vat.parseVatId('0999000001'), null, 'no country code, no country');
  assert.strictEqual(vat.EU_PREFIXES.length, 27);
  assert.ok(!vat.EU_PREFIXES.includes('XI') && !vat.EU_PREFIXES.includes('GB'));
  did();
});

test('a Dutch business, a private buyer and a business outside the EU pay 21%, and VIES is not asked', async () => {
  const check = fakeCheck(VALID);
  const cases = [
    ['', 'no_vat_id'],
    ['NL000099997B01', 'dutch'],
    ['GB999000004', 'outside_eu'],
    ['XI999000005', 'outside_eu'],
    ['CHE999000006', 'outside_eu'],
    ['BE', 'unreadable'],
    ['0999000001', 'unreadable'],
  ];
  for (const [buyerVat, reason] of cases) {
    const t = await vat.decide({ buyerVat, sellerVat: SELLER_VAT, now: NOW }, { check });
    assert.strictEqual(t.treatment, 'standard', buyerVat);
    assert.strictEqual(t.reason, reason, buyerVat);
    assert.strictEqual(vat.chargeAmount(catalog.resolveOrder(FIRM), t), '35.09', buyerVat);
  }
  assert.strictEqual(check.calls.length, 0);
  did();
});

test('without the seller VAT number there is no reverse charge and no VIES call', async () => {
  const check = fakeCheck(VALID);
  const t = await vat.decide({ buyerVat: EU_VAT, sellerVat: '', now: NOW }, { check });
  assert.strictEqual(t.treatment, 'standard');
  assert.strictEqual(t.reason, 'no_seller_vat');
  assert.strictEqual(t.level, 'warn');
  assert.strictEqual(check.calls.length, 0);
  did();
});

test('a number VIES confirms is reverse charged, and the seller asks as itself', async () => {
  const check = fakeCheck(VALID);
  const t = await vat.decide({ buyerVat: 'be 0999.000.001', sellerVat: SELLER_VAT, now: NOW, ...ACME }, { check });
  assert.deepStrictEqual(check.calls, [{
    countryCode: 'BE', vatNumber: '0999000001',
    requesterMemberStateCode: 'NL', requesterNumber: '000099998B01',
  }]);
  assert.strictEqual(t.treatment, 'reverse_charge');
  assert.strictEqual(t.reason, 'vies_valid');
  assert.strictEqual(t.vatId, EU_VAT);
  assert.strictEqual(t.country, 'BE');
  assert.strictEqual(t.checkedAt, VALID.requestDate);
  assert.strictEqual(t.consultation, VALID.requestIdentifier);
  assert.strictEqual(t.viesName, VALID.name, 'what VIES holds for the number is kept');
  assert.strictEqual(t.viesAddress, VALID.address);
  assert.strictEqual(vat.chargeAmount(catalog.resolveOrder(FIRM), t), '29.00');
  did();
});

test('VIES saying invalid, or not answering, is 21% and a warning', async () => {
  const invalid = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...ACME }, { check: fakeCheck({ result: 'invalid', detail: 'not_valid' }) });
  assert.strictEqual(invalid.treatment, 'standard');
  assert.strictEqual(invalid.reason, 'vies_invalid');
  assert.strictEqual(invalid.level, 'warn');
  assert.strictEqual(invalid.country, 'BE');

  const down = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...ACME }, { check: fakeCheck({ result: 'unavailable', detail: 'MS_UNAVAILABLE' }) });
  assert.strictEqual(down.treatment, 'standard');
  assert.strictEqual(down.reason, 'vies_unavailable');
  assert.strictEqual(down.level, 'warn');
  assert.strictEqual(down.detail, 'MS_UNAVAILABLE');

  const threw = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...ACME }, { check: fakeCheck(new Error('socket hang up')) });
  assert.strictEqual(threw.treatment, 'standard');
  assert.strictEqual(threw.reason, 'vies_unavailable');

  // VIES refusing OUR number as the requester means the seller VAT number on
  // every invoice is suspect: louder than a buyer's number failing.
  const refusedUs = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...ACME }, { check: fakeCheck({ result: 'unavailable', detail: 'INVALID_REQUESTER_INFO' }) });
  assert.strictEqual(refusedUs.treatment, 'standard');
  assert.strictEqual(refusedUs.level, 'error');
  did();
});

test('a number alone is not enough: without a company name and an address it is 21%, and VIES is not asked', async () => {
  // Review probe R2: an account with nothing but somebody else's valid number.
  const check = fakeCheck(VALID);
  for (const who of [{}, { buyerCompany: 'Acme BE SRL' }, { buyerAddress: ACME.buyerAddress }, { buyerCompany: '  ', buyerAddress: ' ' }]) {
    const t = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...who }, { check });
    assert.strictEqual(t.treatment, 'standard', JSON.stringify(who));
    assert.strictEqual(t.reason, 'incomplete_profile');
    assert.strictEqual(t.level, 'warn');
    assert.strictEqual(vat.chargeAmount(catalog.resolveOrder(FIRM), t), '35.09');
  }
  assert.strictEqual(check.calls.length, 0);
  did();
});

test('VIES naming another company or country, or the address naming another country, is 21%', async () => {
  const decideWith = (answer, who = ACME) => vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...who }, { check: fakeCheck(answer) });

  const other = await decideWith({ ...VALID, name: 'GLOBEX NV' });
  assert.strictEqual(other.treatment, 'standard');
  assert.strictEqual(other.reason, 'name_mismatch');
  assert.strictEqual(other.level, 'warn');
  assert.ok(!JSON.stringify(other).includes('GLOBEX') && !JSON.stringify(other).includes('0999000001'), 'no name and no number in what gets logged');

  const elsewhere = await decideWith({ ...VALID, countryCode: 'DE' });
  assert.strictEqual(elsewhere.reason, 'country_mismatch');

  const check = fakeCheck(VALID);
  const dutchAddress = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, buyerCompany: 'Acme BE SRL', buyerAddress: 'Example Road 1\n1011 AA Example City\nNederland' }, { check });
  assert.strictEqual(dutchAddress.reason, 'country_mismatch');
  assert.strictEqual(dutchAddress.detail, 'address_NL');
  assert.strictEqual(check.calls.length, 0, 'an address in another country is refused before VIES is asked');

  // Not a clear difference, so reverse charged: VIES keeps the name to itself,
  // or writes it differently, or the address names no country at all.
  assert.strictEqual((await decideWith({ ...VALID, name: '---', address: '---' })).treatment, 'reverse_charge');
  assert.strictEqual((await decideWith({ ...VALID, name: 'ACME' })).treatment, 'reverse_charge');
  assert.strictEqual((await decideWith(VALID, { buyerCompany: 'Acme', buyerAddress: 'Example Street 2, 1000 Example City, Belgique' })).treatment, 'reverse_charge');
  assert.strictEqual((await decideWith(VALID, { buyerCompany: 'Acme BE', buyerAddress: 'Example Street 2\n1000 Example City' })).treatment, 'reverse_charge');
  did();
});

test('a valid answer without a consultation number is not accepted in silence: 21% and a warning', async () => {
  for (const requestIdentifier of ['', '  ', undefined]) {
    const t = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...ACME }, { check: fakeCheck({ ...VALID, requestIdentifier }) });
    assert.strictEqual(t.treatment, 'standard');
    assert.strictEqual(t.reason, 'vies_no_consultation');
    assert.strictEqual(t.level, 'warn');
  }
  did();
});

test('".", "-", "BV" or "NV" is not a name or an address: 21%, and VIES is not asked', async () => {
  // Review round 2: somebody else's valid number with a placeholder next to it.
  const check = fakeCheck(VALID);
  const cases = [];
  for (const junk of ['.', '-', 'BV', 'NV', ' . ', 'B.V.']) {
    cases.push({ buyerCompany: junk, buyerAddress: ACME.buyerAddress });
    cases.push({ buyerCompany: ACME.buyerCompany, buyerAddress: junk });
    cases.push({ buyerCompany: junk, buyerAddress: junk });
  }
  for (const who of cases) {
    const t = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...who }, { check });
    assert.strictEqual(t.treatment, 'standard', JSON.stringify(who));
    assert.strictEqual(t.reason, 'incomplete_profile', JSON.stringify(who));
    assert.strictEqual(vat.chargeAmount(catalog.resolveOrder(FIRM), t), '35.09');
  }
  assert.strictEqual(check.calls.length, 0);
  assert.strictEqual(vat.namesClearlyDiffer('.', 'ACME BE SRL'), true, 'no word never matches a name VIES gives');
  did();
});

test('a word many companies share does not make two names the same', async () => {
  const smith = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, buyerCompany: 'Global Consulting', buyerAddress: ACME.buyerAddress },
    { check: fakeCheck({ ...VALID, name: 'SMITH CONSULTING BV' }) });
  assert.strictEqual(smith.treatment, 'standard');
  assert.strictEqual(smith.reason, 'name_mismatch');
  for (const [mine, theirs] of [['Global Services Group', 'SMITH SERVICES'], ['Acme Holding', 'GLOBEX HOLDING NV'], ['Acme International Trading', 'GLOBEX TRADING']]) {
    assert.strictEqual(vat.namesClearlyDiffer(mine, theirs), true, `${mine} / ${theirs}`);
  }
  assert.strictEqual(vat.namesClearlyDiffer('Acme Consulting', 'ACME CONSULTING BV'), false, 'the distinctive word still matches');
  const generic = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, buyerCompany: 'Consulting Services BV', buyerAddress: ACME.buyerAddress }, { check: fakeCheck(VALID) });
  assert.strictEqual(generic.reason, 'incomplete_profile', 'a name made of shared words only says nothing');
  did();
});

test('the proof of a checkout is kept thirty days, and for good once its invoice exists', async () => {
  assert.strictEqual(vat.PROOF_TTL_DAYS, 30);
  const redis = fakeRedis();
  const t = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, now: NOW, ...ACME }, { check: fakeCheck(VALID) });
  assert.deepStrictEqual(await vat.saveProof(t, redis, { accountId: 'acct_demo' }), { ok: true });
  const key = vat.PROOF_KEY(VALID.requestIdentifier);
  assert.strictEqual(await redis.ttl(key), 30 * 86400, 'a checkout that is never paid leaves nothing behind for long');
  assert.deepStrictEqual(await vat.keepProof(VALID.requestIdentifier, redis), { ok: true });
  assert.strictEqual(await redis.ttl(key), -1, 'kept with the invoice');
  assert.deepStrictEqual(await vat.keepProof(VALID.requestIdentifier, redis), { ok: true }, 'a renewal may do it again');
  const broken = Object.assign(fakeRedis(), { async set() { throw new Error('READONLY'); } });
  assert.strictEqual((await vat.saveProof(t, broken)).ok, false, 'a store that refuses is no proof');
  // /privacy says the same number.
  for (const [rel, words] of [['privacy.html', 'na 30 dagen'], ['en/privacy.html', 'after 30 days']]) {
    const html = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', rel), 'utf8');
    assert.ok(html.includes(words), `${rel} names the ${vat.PROOF_TTL_DAYS}-day term`);
  }
  did();
});

test('the VIES request gives up after its timeout, and that is a 21% sale', async () => {
  assert.strictEqual(vat.VIES_TIMEOUT_MS, 6000);
  let asked = null;
  await vat.checkVies({ countryCode: 'BE', vatNumber: '0999000001' }, { request: async (req) => { asked = req; return { status: 200, body: { valid: false } }; } });
  assert.strictEqual(asked.timeoutMs, 6000, 'the relay asks with the six-second limit');

  // The real request function, pointed at a local server that takes the
  // question and never answers. Only the port and the transport differ from
  // what the relay does; the timeout code is the one that runs in production.
  const silent = http.createServer(() => { /* never answers */ });
  await new Promise((r) => silent.listen(0, '127.0.0.1', r));
  const started = Date.now();
  try {
    await assert.rejects(
      vat.httpsJson({ host: '127.0.0.1', port: silent.address().port, transport: http, path: '/x', body: {}, timeoutMs: 150 }),
      /vies_timeout/);
    assert.ok(Date.now() - started < 3000, 'gave up at the limit, not after it');
    const out = await vat.checkVies({ countryCode: 'BE', vatNumber: '0999000001' }, {
      request: (req) => vat.httpsJson({ ...req, host: '127.0.0.1', port: silent.address().port, transport: http, timeoutMs: 150 }),
    });
    assert.strictEqual(out.result, 'unavailable');
    assert.match(out.detail, /vies_timeout/);
  } finally {
    silent.closeAllConnections();
    await new Promise((r) => silent.close(r));
  }
  const t = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, ...ACME }, { check: fakeCheck({ result: 'unavailable', detail: 'request_failed:vies_timeout' }) });
  assert.strictEqual(t.treatment, 'standard');
  assert.strictEqual(t.reason, 'vies_unavailable');
  did();
});

test('the proof is kept under the consultation number and reaches the invoice', async () => {
  const redis = fakeRedis();
  const t = await vat.decide({ buyerVat: EU_VAT, sellerVat: SELLER_VAT, now: NOW, ...ACME }, { check: fakeCheck(VALID) });
  assert.deepStrictEqual(await vat.saveProof(t, redis, { accountId: 'acct_demo', company: ACME.buyerCompany, address: ACME.buyerAddress }), { ok: true });
  const proof = JSON.parse(await redis.get(vat.PROOF_KEY(VALID.requestIdentifier)));
  assert.deepStrictEqual(proof, {
    source: 'VIES', consultation: VALID.requestIdentifier, checked_at: VALID.requestDate,
    vat_id: EU_VAT, country: 'BE', name: VALID.name, address: VALID.address,
    account_id: 'acct_demo', account_company: ACME.buyerCompany, account_address: ACME.buyerAddress,
  });
  assert.deepStrictEqual(await vat.loadProof(VALID.requestIdentifier, redis), proof);
  assert.strictEqual((await vat.saveProof({ ...t, consultation: '' }, redis)).ok, false, 'no consultation number, nothing to keep it under');
  assert.strictEqual((await vat.saveProof(t, null)).ok, false, 'no store, no proof');
  assert.strictEqual(await vat.loadProof('../../etc', redis), null);

  // The webhook's half: terms from the payment, name and address from the proof.
  const md = vat.metadataOf(t);
  const terms = Object.assign(vat.termsFromMetadata(md), { viesName: proof.name, viesAddress: proof.address });
  const out = await invoice.issueDocument({
    payment: paymentOf('tr_proof', '29.00', md),
    order: Object.assign({ accountId: 'acct_demo' }, catalog.resolveOrder(FIRM)),
    seller: SELLER, buyer: { email: 'office@example.test', company: ACME.buyerCompany, address: ACME.buyerAddress, vat: EU_VAT },
    now: NOW, vat: terms,
  }, redis);
  assert.deepStrictEqual(out.record.vat_check, { source: 'VIES', checked_at: VALID.requestDate, consultation: VALID.requestIdentifier, name: VALID.name, address: VALID.address });
  did();
});

test('the VIES answer is read from its body, not from its status code', async () => {
  const ask = (res) => vat.checkVies({ countryCode: 'BE', vatNumber: '0999000001' }, {
    request: async (req) => {
      assert.strictEqual(req.host, 'ec.europa.eu');
      assert.strictEqual(req.path, '/taxation_customs/vies/rest-api/check-vat-number');
      if (res instanceof Error) throw res;
      return res;
    },
  });
  // The shapes the real service answers with (its test service, 2026-09-25).
  const valid = await ask({ status: 200, body: { valid: true, requestDate: '2026-09-25T10:25:49.269Z', requestIdentifier: '' } });
  assert.strictEqual(valid.result, 'valid');
  assert.strictEqual((await ask({ status: 200, body: { valid: false } })).result, 'invalid');
  const unavailable = await ask({ status: 200, body: { actionSucceed: false, errorWrappers: [{ error: 'MS_UNAVAILABLE' }] } });
  assert.deepStrictEqual(unavailable, { result: 'unavailable', detail: 'MS_UNAVAILABLE' });
  assert.strictEqual((await ask({ status: 200, body: { actionSucceed: false, errorWrappers: [{ error: 'INVALID_INPUT' }] } })).result, 'invalid');
  assert.strictEqual((await ask({ status: 500, body: { valid: true } })).result, 'unavailable', 'a 500 is never valid');
  assert.strictEqual((await ask({ status: 200, body: null })).result, 'unavailable', 'no JSON, no answer');
  assert.strictEqual((await ask({ status: 200, body: { valid: 'true' } })).result, 'unavailable', 'only the boolean true counts');
  assert.strictEqual((await ask(new Error('vies_timeout'))).result, 'unavailable');
  did();
});

// ── the amount and the marker ────────────────────────────────────────────────

test('every catalog price is charged at its fixed net amount under reverse charge', async () => {
  // Written out by hand, not computed: gross / 1.21, each one checked to come
  // out whole. A price change or a rounding change has to be made here too.
  const NET = {
    'parasend/pro/monthly': '15.00', 'parasend/pro/yearly': '150.00',
    'parasign/pro/monthly': '49.00', 'parasign/pro/yearly': '499.00',
    'parasign/business/monthly': '299.00', 'parasign/business/yearly': '2990.00',
    'firm/firm/monthly': '29.00', 'firm/firm/yearly': '290.00',
  };
  const seen = [];
  for (const [product, plans] of Object.entries(catalog.CATALOG)) {
    for (const [plan, intervals] of Object.entries(plans)) {
      for (const interval of Object.keys(intervals)) {
        const key = `${product}/${plan}/${interval}`;
        seen.push(key);
        const order = catalog.resolveOrder({ product, plan, interval });
        assert.strictEqual(vat.chargeAmount(order, RC_TERMS), NET[key], key);
        assert.strictEqual(vat.chargeAmount(order, { treatment: 'standard' }), order.amount);
        assert.strictEqual(vat.chargeAmount(order, undefined), order.amount);
      }
    }
  }
  assert.deepStrictEqual(seen.sort(), Object.keys(NET).sort(), 'every price in the catalog has its net written here');
  did();
});

test('the marker on the payment round-trips, and anything less reads as 21%', () => {
  assert.deepStrictEqual(vat.metadataOf({ treatment: 'standard' }), {}, 'a standard payment carries nothing new');
  const md = vat.metadataOf(RC_TERMS);
  assert.deepStrictEqual(md, { vat: 'reverse_charge', vatId: EU_VAT, vatCheckedAt: VALID.requestDate, vatConsultation: VALID.requestIdentifier });
  assert.ok(JSON.stringify(md).length < 200, 'well inside what Mollie keeps as metadata');
  assert.deepStrictEqual(vat.termsFromMetadata(md), RC_TERMS);
  assert.strictEqual(vat.termsFromMetadata({}).treatment, 'standard');
  assert.strictEqual(vat.termsFromMetadata({ vat: 'reverse_charge' }).treatment, 'standard', 'no number, no reverse charge');
  assert.strictEqual(vat.termsFromMetadata({ vat: 'reverse_charge', vatId: 'NL000099997B01' }).treatment, 'standard', 'never for a Dutch number');
  did();
});

test('the webhook grants a reverse-charged payment at the net amount, and refuses every other mix', async () => {
  const grants = [];
  const deps = { setProductPlan: async (...a) => { grants.push(a); return { ok: true }; }, now: NOW };
  const rcMd = vat.metadataOf(RC_TERMS);

  const ok = await billing.processPayment(paymentOf('tr_rc_net', '29.00', rcMd), deps);
  assert.strictEqual(ok.result, 'granted', ok.reason);

  const gross = await billing.processPayment(paymentOf('tr_rc_gross', '35.09', rcMd), deps);
  assert.strictEqual(gross.result, 'refused');
  assert.match(gross.reason, /amount_mismatch paid=35\.09\/EUR expected=29\.00\/EUR/);

  const netNoMarker = await billing.processPayment(paymentOf('tr_std_net', '29.00'), deps);
  assert.strictEqual(netNoMarker.result, 'refused', 'nobody pays net without the marker our checkout set');
  assert.match(netNoMarker.reason, /expected=35\.09/);

  const std = await billing.processPayment(paymentOf('tr_std', '35.09'), deps);
  assert.strictEqual(std.result, 'granted');
  did();
});

test('a reverse-charged plan renews net, with the marker on every collection; a standard one is unchanged', () => {
  const order = catalog.resolveOrder(FIRM);
  const base = { order, paidUntil: '2026-10-25T10:00:00Z', accountId: 'acct_demo', webhookUrl: 'https://paramant.app/v2/billing/webhook', mollieInterval: () => '1 month', now: NOW };
  const rc = recurring.subscriptionPayload(Object.assign({ vatTerms: RC_TERMS }, base)).payload;
  assert.deepStrictEqual(rc.amount, { currency: 'EUR', value: '29.00' });
  assert.strictEqual(rc.metadata.vat, 'reverse_charge');
  assert.strictEqual(rc.metadata.vatId, EU_VAT);
  const std = recurring.subscriptionPayload(base).payload;
  assert.deepStrictEqual(std.amount, { currency: 'EUR', value: '35.09' });
  assert.deepStrictEqual(std.metadata, { accountId: 'acct_demo', product: 'firm', plan: 'firm', interval: 'monthly' });
  did();
});

// ── the documents ────────────────────────────────────────────────────────────

test('a reverse-charged invoice: 0%, no VAT, the confirmed number, in the one series with the rest', async () => {
  const redis = fakeRedis();
  const a = await issue(redis, paymentOf('tr_a', '35.09'), { email: 'nl@example.test', company: 'Acme NL B.V.', address: 'Example Road 1', vat: 'NL000099997B01' });
  const b = await issue(redis, paymentOf('tr_b', '29.00', vat.metadataOf(RC_TERMS)));
  const c = await issue(redis, paymentOf('tr_c', '35.09'), { email: 'private@example.test' });
  assert.deepStrictEqual([a.number, b.number, c.number], ['PS-2026-0001', 'PS-2026-0002', 'PS-2026-0003'], 'one series, no gap');

  const rc = b.record;
  assert.strictEqual(rc.kind, 'invoice');
  assert.strictEqual(rc.vat_rate, 0);
  assert.strictEqual(rc.amount_net, '29.00');
  assert.strictEqual(rc.amount_vat, '0.00');
  assert.strictEqual(rc.amount_gross, '29.00', 'the total is what was paid');
  assert.strictEqual(rc.vat_treatment, 'reverse_charge');
  assert.strictEqual(rc.buyer.vat, EU_VAT, 'the number VIES confirmed, not the spelling in the profile');
  assert.strictEqual(rc.buyer.country, 'BE');
  assert.deepStrictEqual(rc.vat_check, { source: 'VIES', checked_at: VALID.requestDate, consultation: VALID.requestIdentifier, name: '', address: '' });
  assert.strictEqual(rc.seller.vat, SELLER_VAT);

  for (const std of [a.record, c.record]) {
    assert.strictEqual(std.vat_rate, 21);
    assert.strictEqual(std.amount_vat, '6.09');
    assert.ok(!('vat_treatment' in std) && !('vat_check' in std), 'a standard record keeps its old shape');
  }
  assert.strictEqual(a.record.buyer.vat, 'NL000099997B01');
  did();
});

test('the PDF says Btw verlegd and VAT reverse charged, next to both VAT numbers', async () => {
  const redis = fakeRedis();
  const rc = (await issue(redis, paymentOf('tr_pdf_rc', '29.00', vat.metadataOf(RC_TERMS)))).record;
  const text = invoicePdf.render(rc, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('Btw verlegd / VAT reverse charged'));
  assert.ok(text.includes(`Customer VAT ${EU_VAT} - Supplier VAT ${SELLER_VAT}`));
  assert.ok(text.includes('Article 196, Directive 2006/112/EC'));
  assert.ok(!text.includes('VAT 0%'), 'no rate line pretending a 0% Dutch rate');

  const std = (await issue(redis, paymentOf('tr_pdf_std', '35.09'), { email: 'private@example.test' })).record;
  const stdText = invoicePdf.render(std, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(stdText.includes('VAT 21%'));
  assert.ok(!/verlegd|reverse charged/i.test(stdText), 'a 21% invoice says nothing about reverse charge');
  did();
});

test('the mail says it in both languages, and a 21% mail is unchanged', async () => {
  const redis = fakeRedis();
  const rc = (await issue(redis, paymentOf('tr_mail_rc', '29.00', vat.metadataOf(RC_TERMS)))).record;
  const { text } = billingMail.invoiceMail(rc);
  assert.ok(text.includes(`Totaal: EUR 29.00 (btw verlegd, btw-nummer afnemer ${EU_VAT})`), text);
  assert.ok(text.includes(`Total: EUR 29.00 (VAT reverse charged, customer VAT number ${EU_VAT})`), text);

  const std = (await issue(redis, paymentOf('tr_mail_std', '35.09'), { email: 'private@example.test' })).record;
  const stdText = billingMail.invoiceMail(std).text;
  assert.ok(stdText.includes('Totaal: EUR 35.09 (incl. 21% btw, EUR 6.09)'));
  assert.ok(stdText.includes('Total: EUR 35.09 (incl. 21% VAT, EUR 6.09)'));
  did();
});

test('a credit note for a reverse-charged invoice is reverse charged too', async () => {
  const redis = fakeRedis();
  const p = paymentOf('tr_cn_rc', '29.00', vat.metadataOf(RC_TERMS));
  await issue(redis, p);
  const back = Object.assign({}, p, { amountRefunded: { value: '29.00', currency: 'EUR' } });
  const out = await creditNote.issueCreditNote({ payment: back, now: NOW }, redis);
  assert.strictEqual(out.result, 'issued', out.reason);
  const cn = out.record;
  assert.strictEqual(cn.vat_rate, 0);
  assert.strictEqual(cn.amount_gross, '-29.00');
  assert.strictEqual(cn.amount_vat, '0.00');
  assert.strictEqual(cn.vat_treatment, 'reverse_charge');
  assert.strictEqual(cn.buyer.vat, EU_VAT);
  const text = invoicePdf.render(cn, { buyerHint: invoice.BUYER_HINT }).toString('latin1');
  assert.ok(text.includes('Btw verlegd / VAT reverse charged'));
  assert.ok(billingMail.creditNoteMail(cn).text.includes('btw verlegd'));
  did();
});

test('Moneybird does not book a reverse-charged document at a guessed rate', async () => {
  const redis = fakeRedis();
  const rc = (await issue(redis, paymentOf('tr_mb_rc', '29.00', vat.metadataOf(RC_TERMS)))).record;
  const calls = [];
  const lines = [];
  const out = await moneybird.pushDocument({
    record: rc, redis, now: NOW,
    env: { MONEYBIRD_TOKEN: 'token_for_the_stub', MONEYBIRD_ADMINISTRATION_ID: '123456789' },
    http: async (req) => { calls.push(req); throw new Error('no request may leave for this document'); },
    log: (level, event, fields) => lines.push({ level, event, fields }),
  });
  assert.strictEqual(out.result, 'skipped');
  assert.strictEqual(out.reason, 'reverse_charge_not_mapped');
  assert.strictEqual(calls.length, 0);
  assert.ok(lines.some((l) => l.level === 'warn' && l.event === 'moneybird_skipped'));
  did();
});

test('ensureSubscription hands the terms of the first payment to the renewal', async () => {
  // The wiring itself, not only the payload builder: a subscription created
  // after a reverse-charged first payment collects net and carries the marker.
  const created = [];
  const mollie = {
    mollieInterval: (i) => (i === 'monthly' ? '1 month' : '12 months'),
    validMandates: async () => [{ id: 'mdt_demo', status: 'valid' }],
    createSubscription: async (mode, customerId, payload) => { created.push(payload); return { id: 'sub_demo' }; },
  };
  const first = Object.assign(paymentOf('tr_first', '29.00', vat.metadataOf(RC_TERMS)), { sequenceType: 'first', customerId: 'cst_demo' });
  const out = await recurring.ensureSubscription(first,
    { account: 'acct_demo', product: 'firm', paidUntil: '2026-10-25T10:00:00Z' },
    { recurring: true, mode: 'test', webhookUrl: 'https://paramant.app/v2/billing/webhook', mollie, getAccount: async () => ({}), saveSubscription: async () => {}, now: NOW });
  assert.strictEqual(out.result, 'created', out.reason);
  assert.deepStrictEqual(created[0].amount, { currency: 'EUR', value: '29.00' });
  assert.strictEqual(created[0].metadata.vat, 'reverse_charge');
  assert.strictEqual(created[0].metadata.vatConsultation, VALID.requestIdentifier);
  did();
});

test('the export carries the treatment, the country and the consultation number for the ICP return', async () => {
  assert.deepStrictEqual(exporter.COLUMNS.slice(-3), ['vat_treatment', 'customer_country', 'vat_consultation']);
  const redis = fakeRedis();
  const rc = (await issue(redis, paymentOf('tr_exp_rc', '29.00', vat.metadataOf(RC_TERMS)))).record;
  const std = (await issue(redis, paymentOf('tr_exp_std', '35.09'), { email: 'private@example.test' })).record;
  const r = exporter.rowOf(rc);
  assert.strictEqual(r.vat_treatment, 'reverse_charge');
  assert.strictEqual(r.customer_country, 'BE');
  assert.strictEqual(r.vat_consultation, VALID.requestIdentifier);
  assert.strictEqual(r.customer_vat, EU_VAT);
  assert.strictEqual(r.vat_rate, '0');
  const s21 = exporter.rowOf(std);
  assert.deepStrictEqual([s21.vat_treatment, s21.customer_country, s21.vat_consultation], ['standard', '', '']);
  const csv = exporter.toCsv([r, s21]).replace(/^\uFEFF/, '').split('\r\n');
  assert.ok(csv[0].endsWith(';vat_treatment;customer_country;vat_consultation'));
  assert.ok(csv[1].endsWith(`;reverse_charge;BE;${VALID.requestIdentifier}`));
  did();
});

test('an unquoted \\n in the seller address is a line break, as a quoted one is', () => {
  // docker compose passes BILLING_SELLER_ADDRESS=Street 1\\nCity through as a
  // backslash and an n; the PDF splits on a real line break.
  assert.strictEqual(invoice.sellerFromEnv({ BILLING_SELLER_ADDRESS: 'Example Street 1\\n1234 AB Example City' }).address, 'Example Street 1\n1234 AB Example City');
  assert.strictEqual(invoice.sellerFromEnv({ BILLING_SELLER_ADDRESS: 'Example Street 1\n1234 AB Example City' }).address, 'Example Street 1\n1234 AB Example City');
  did();
});

test('docker-compose passes the seller variables to every relay', () => {
  const compose = fs.readFileSync(path.join(__dirname, '..', '..', 'docker-compose.yml'), 'utf8');
  const start = compose.indexOf('x-relay-env: &relay-env');
  assert.ok(start >= 0, 'the shared relay environment block is where it was');
  // The block ends at the next line that starts in the first column.
  const rest = compose.slice(start + 1);
  const end = rest.search(/\n\S/);
  const block = end >= 0 ? rest.slice(0, end) : rest;
  for (const k of ['BILLING_SELLER_NAME', 'BILLING_SELLER_ADDRESS', 'BILLING_SELLER_KVK', 'BILLING_SELLER_VAT']) {
    assert.match(block, new RegExp(`^  ${k}: "\\$\\{${k}:-\\}"$`, 'm'), `${k} reaches the relays`);
  }
  did();
});
