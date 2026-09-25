'use strict';
// Reverse charge on a really booted relay: the checkout, the payment at a fake
// Mollie, the webhook, the invoice and the renewal, against a fake VIES.
//
// THE RULE UNDER TEST. A business in another EU member state with a VAT number
// that VIES says is valid pays the amount without VAT, and its invoice says
// "Btw verlegd" / "VAT reverse charged" and carries both VAT numbers. Everyone
// else pays 21% Dutch VAT: a Dutch business with a VAT number, a private buyer,
// and any buyer whose number VIES calls invalid or cannot check right now.
//
// NOTHING HERE REACHES A REAL SERVICE. tests/helpers/mollie-intercept.cjs is
// preloaded into the relay and sends api.mollie.com to the fake Mollie and
// ec.europa.eu to the fake VIES below. The fake Mollie's own webhook calls are
// switched off; this suite posts the webhook itself, so every step happens in
// the order the test says and not when a timer fires.
//
// Needs a throwaway redis, like the other route suites:
//   REDIS_URL=redis://127.0.0.1:6398 node --test test/route-billing-vat.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const http = require('http');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const fakeMollie = require('../../tests/helpers/fake-mollie.cjs');

const INTERCEPT = path.join(__dirname, '..', '..', 'tests', 'helpers', 'mollie-intercept.cjs');

// Example values only. The seller's real VAT number lives in the deployment's
// BILLING_SELLER_VAT and nowhere in the repo.
const SELLER = {
  BILLING_SELLER_NAME: 'Acme Seller B.V.',
  BILLING_SELLER_ADDRESS: 'Example Street 1\n1234 AB Example City\nNetherlands',
  BILLING_SELLER_KVK: '00000000',
  BILLING_SELLER_VAT: 'NL000099998B01',
};

// What the fake VIES answers, per VAT number, in the shapes the real service
// uses (checked against its test service on 2026-09-25): 200 with valid true or
// false, and 200 with errorWrappers when a member state cannot be reached. A
// valid answer carries the name and address VIES holds, and a consultation
// number of its own per question, so parallel runs never share a proof.
const VAT = {
  nl: 'NL000099997B01',
  eu: 'BE0999000001',
  invalid: 'DE999000002',
  down: 'FR99999000003',
};
const vies = { calls: [], override: new Map(), n: 0 };
function viesAnswer(q) {
  const id = `${q.countryCode}${q.vatNumber}`;
  const mode = vies.override.get(id) || (id === VAT.eu ? 'valid' : id === VAT.invalid ? 'invalid' : 'down');
  const base = { countryCode: q.countryCode, vatNumber: q.vatNumber, requestDate: new Date().toISOString() };
  if (mode === 'valid') return { ...base, valid: true, requestIdentifier: `WAPI-${RUN}-${++vies.n}`, name: 'ACME BE SRL', address: 'EXAMPLE STREET 2\n1000 EXAMPLE CITY' };
  if (mode === 'invalid') return { ...base, valid: false, requestIdentifier: '', name: '---', address: '---' };
  return { actionSucceed: false, errorWrappers: [{ error: 'MS_UNAVAILABLE' }] };
}
const viesServer = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let q = {};
    try { q = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { q = {}; }
    vies.calls.push({ path: req.url, method: req.method, body: q });
    const body = JSON.stringify(viesAnswer(q));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  });
});

let redis = null;
let srv = null;
let mollie = null;
let mollieOrigin = '';
let checks = 0;
const did = () => { checks++; };

const RUN = `${process.pid}_${Date.now().toString(36)}`;
// Five accounts, not more: an unlicensed relay refuses the sixth with a 402.
const WHO = ['nl', 'private', 'eu', 'invalid', 'down'];
const keyOf = (who) => `pgp_vat_${who}_${RUN}`;
const acctOf = (who) => `acct_demo_vat_${who}_${RUN}`;
const as = (who) => ({ headers: { 'X-Api-Key': keyOf(who) } });

before(async () => {
  redis = await requireRedis('redis://127.0.0.1:6398');
  if (!redis) return;
  mollie = fakeMollie.create();
  mollieOrigin = await mollie.listen();
  await new Promise((r) => viesServer.listen(0, '127.0.0.1', r));
  const viesOrigin = `http://127.0.0.1:${viesServer.address().port}`;
  // This suite posts every webhook itself.
  await fetch(`${mollieOrigin}/_ctl/webhook-off`, { method: 'POST', body: JSON.stringify({ off: true }) });
  srv = await boot({
    tag: 'billing-vat',
    usersFile: true,
    captureLog: true,
    users: {
      api_keys: WHO.map((w) => ({
        key: keyOf(w), plan: 'community', active: true, parasign: true,
        account_id: acctOf(w), email: `${w}@example.test`,
      })),
    },
    env: {
      ...SELLER,
      RELAY_REDIS_URL: redis.options.url,
      REDIS_URL: redis.options.url,
      NODE_OPTIONS: `--require ${INTERCEPT}`,
      FAKE_MOLLIE_URL: mollieOrigin,
      FAKE_VIES_URL: viesOrigin,
      MOLLIE_TEST_API_KEY: 'test_dummy_key_for_the_fake',
      // By hand, as production will: the mandate and subscription layer runs,
      // so a renewal can be collected and checked too.
      BILLING_MODE: 'test',
    },
  });
  const profiles = {
    nl: { company: 'Acme NL B.V.', address: 'Example Road 1\n1011 AA Example City\nNetherlands', vat: VAT.nl },
    eu: { company: 'Acme BE SRL', address: 'Example Street 2\n1000 Example City\nBelgium', vat: 'be 0999.000.001' },
    invalid: { company: 'Acme DE GmbH', address: 'Example Street 3\n10115 Example City\nGermany', vat: VAT.invalid },
    down: { company: 'Acme FR SAS', address: 'Example Street 4\n75001 Example City\nFrance', vat: VAT.down },
  };
  for (const [who, p] of Object.entries(profiles)) {
    const r = await srv.post('/v2/billing/profile', { ...as(who), body: p });
    assert.strictEqual(r.status, 200, `profile for ${who} saved`);
  }
});

after(async () => {
  await killAll();
  if (mollie) await mollie.close();
  await new Promise((r) => viesServer.close(r));
  if (redis) { try { await redis.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-billing-vat', checks);
});

// ── the buyer's path, one step at a time ───────────────────────────────────
async function checkout(who, plan = { product: 'firm', plan: 'firm', interval: 'monthly' }) {
  const r = await srv.post('/v2/billing/checkout', { ...as(who), body: plan });
  assert.strictEqual(r.status, 200, `checkout for ${who}: ${r.text}`);
  const all = await (await fetch(`${mollieOrigin}/_ctl/payments`)).json();
  const payment = all.find((p) => p.id === r.json.payment_id);
  assert.ok(payment, 'the payment exists at the fake Mollie');
  return payment;
}

async function payAndNotify(paymentId) {
  const paid = await fetch(`${mollieOrigin}/checkout/${paymentId}`, {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'outcome=paid',
  });
  assert.strictEqual(paid.status, 302, 'the fake Mollie took the payment');
  return notify(paymentId);
}

async function notify(paymentId) {
  const hook = await srv.post('/v2/billing/webhook', {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `id=${paymentId}`,
  });
  assert.strictEqual(hook.status, 200, `webhook for ${paymentId}: ${hook.text}`);
}

async function invoices(who) {
  const r = await srv.get('/v2/billing/invoices', as(who));
  assert.strictEqual(r.status, 200);
  return r.json.invoices;
}

const viesCallsFor = (id) => vies.calls.filter((c) => `${c.body.countryCode}${c.body.vatNumber}` === id);
const logLines = () => srv.log().split('\n').filter((l) => l.startsWith('{')).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);

// ── the cases ──────────────────────────────────────────────────────────────

test('a Dutch business with a VAT number pays 21% and VIES is not asked', async (t) => {
  if (!srv) return t.skip('no redis');
  const p = await checkout('nl');
  assert.strictEqual(p.amount.value, '35.09', 'charged the catalog price, VAT included');
  assert.strictEqual(p.metadata.vat, undefined, 'no reverse-charge marker on the payment');
  await payAndNotify(p.id);
  const [inv] = await invoices('nl');
  assert.ok(inv, 'an invoice was issued');
  assert.strictEqual(inv.vat_rate, 21);
  assert.strictEqual(inv.amount_net, '29.00');
  assert.strictEqual(inv.amount_vat, '6.09');
  assert.strictEqual(inv.amount_gross, '35.09');
  assert.strictEqual(viesCallsFor(VAT.nl).length, 0, 'a Dutch number is never sent to VIES');
  did();
});

test('a private buyer without a VAT number pays 21%', async (t) => {
  if (!srv) return t.skip('no redis');
  const p = await checkout('private');
  assert.strictEqual(p.amount.value, '35.09');
  assert.strictEqual(p.metadata.vat, undefined);
  await payAndNotify(p.id);
  const [inv] = await invoices('private');
  assert.strictEqual(inv.vat_rate, 21);
  assert.strictEqual(inv.amount_vat, '6.09');
  assert.strictEqual(inv.amount_gross, '35.09');
  did();
});

test('an EU business with a valid VAT number pays the net amount, and the invoice says the VAT is reverse charged', async (t) => {
  if (!srv) return t.skip('no redis');
  const p = await checkout('eu');
  assert.strictEqual(p.amount.value, '29.00', 'charged without VAT');
  assert.strictEqual(p.metadata.vat, 'reverse_charge');
  assert.strictEqual(p.metadata.vatId, VAT.eu, 'the number as VIES confirmed it, normalised');
  const asked = viesCallsFor(VAT.eu);
  assert.strictEqual(asked.length, 1, 'VIES was asked once');
  assert.strictEqual(asked[0].path, '/taxation_customs/vies/rest-api/check-vat-number');
  assert.strictEqual(asked[0].body.requesterMemberStateCode, 'NL', 'the seller asks as itself');
  assert.strictEqual(asked[0].body.requesterNumber, '000099998B01');
  assert.match(p.metadata.vatConsultation, /^WAPI-/, 'the consultation number rides on the payment');

  // The proof, kept before the payment existed: what VIES said, and what the
  // account said at that moment.
  const proof = JSON.parse(await redis.get(`paramant:billing:vat:proof:${p.metadata.vatConsultation}`));
  assert.strictEqual(proof.vat_id, VAT.eu);
  assert.strictEqual(proof.name, 'ACME BE SRL');
  assert.strictEqual(proof.address, 'EXAMPLE STREET 2\n1000 EXAMPLE CITY');
  assert.strictEqual(proof.account_company, 'Acme BE SRL');

  // Review probe R1: VIES changes its mind between the checkout and the
  // webhook. What was charged decides, and VIES is not asked again.
  vies.override.set(VAT.eu, 'invalid');
  try { await payAndNotify(p.id); } finally { vies.override.delete(VAT.eu); }
  assert.strictEqual(viesCallsFor(VAT.eu).length, 1, 'the webhook does not ask VIES again');
  const [inv] = await invoices('eu');
  assert.ok(inv, 'an invoice was issued');
  assert.strictEqual(inv.kind, 'invoice');
  assert.strictEqual(inv.vat_rate, 0);
  assert.strictEqual(inv.amount_net, '29.00');
  assert.strictEqual(inv.amount_vat, '0.00');
  assert.strictEqual(inv.amount_gross, '29.00', 'the invoice total is what the buyer paid');
  const stored = JSON.parse(await redis.get(`paramant:billing:invoice:doc:${inv.number}`));
  assert.strictEqual(stored.vat_check.consultation, p.metadata.vatConsultation);
  assert.strictEqual(stored.vat_check.name, 'ACME BE SRL', 'the invoice keeps the name VIES gave');
  assert.strictEqual(stored.vat_check.address, 'EXAMPLE STREET 2\n1000 EXAMPLE CITY');

  const pdf = await srv.get(`/v2/billing/invoices/${inv.number}.pdf`, as('eu'));
  assert.strictEqual(pdf.status, 200);
  const text = pdf.buf.toString('latin1');
  assert.ok(text.includes('Btw verlegd'), 'the Dutch mention is on the invoice');
  assert.ok(text.includes('VAT reverse charged'), 'the English mention is on the invoice');
  assert.ok(text.includes(VAT.eu), 'the buyer VAT number is on the invoice');
  assert.ok(text.includes(SELLER.BILLING_SELLER_VAT), 'the seller VAT number is on the invoice');

  // The paid plan is granted: the net amount is the right amount, not a mismatch.
  const alarms = logLines().filter((l) => l.msg === 'billing_webhook' && l.payment_id === p.id);
  assert.ok(alarms.length && alarms.every((l) => l.result === 'granted'), `granted, got ${JSON.stringify(alarms)}`);
  did();
});

test('the renewal of a reverse-charged plan is collected net and invoiced the same way', async (t) => {
  if (!srv) return t.skip('no redis');
  const subs = await (await fetch(`${mollieOrigin}/_ctl/subscriptions`)).json();
  const sub = subs.find((s) => s.metadata && s.metadata.accountId === acctOf('eu'));
  assert.ok(sub, 'a subscription was created after the first payment');
  assert.strictEqual(sub.amount.value, '29.00', 'the subscription collects without VAT');
  assert.strictEqual(sub.metadata.vat, 'reverse_charge');
  assert.strictEqual(sub.metadata.vatId, VAT.eu);

  const renewal = await (await fetch(`${mollieOrigin}/_ctl/recurring`, {
    method: 'POST', body: JSON.stringify({ subscriptionId: sub.id }),
  })).json();
  await notify(renewal.id);
  const list = await invoices('eu');
  assert.strictEqual(list.length, 2, 'the renewal has its own invoice');
  const [latest] = list;
  assert.strictEqual(latest.vat_rate, 0);
  assert.strictEqual(latest.amount_gross, '29.00');
  assert.strictEqual(latest.amount_vat, '0.00');
  did();
});

test('VIES cannot be reached: 21%, and the log says why', async (t) => {
  if (!srv) return t.skip('no redis');
  const p = await checkout('down');
  assert.strictEqual(p.amount.value, '35.09', 'the safe side: Dutch VAT');
  assert.strictEqual(p.metadata.vat, undefined);
  assert.strictEqual(viesCallsFor(VAT.down).length, 1, 'VIES was asked');
  const line = logLines().find((l) => l.msg === 'billing_vat' && l.account === acctOf('down').slice(0, 12) && l.reason === 'vies_unavailable');
  assert.ok(line, 'a billing_vat line with reason vies_unavailable');
  assert.strictEqual(line.level, 'warn');
  assert.strictEqual(line.country, 'FR');
  assert.ok(!JSON.stringify(line).includes(VAT.down.slice(2)), 'the log names the country, not the number');
  await payAndNotify(p.id);
  const [inv] = await invoices('down');
  assert.strictEqual(inv.vat_rate, 21);
  assert.strictEqual(inv.amount_gross, '35.09');
  did();
});

test('VIES says the number is invalid: 21%, and the log says why', async (t) => {
  if (!srv) return t.skip('no redis');
  const p = await checkout('invalid');
  assert.strictEqual(p.amount.value, '35.09');
  assert.strictEqual(p.metadata.vat, undefined);
  const line = logLines().find((l) => l.msg === 'billing_vat' && l.account === acctOf('invalid').slice(0, 12) && l.reason === 'vies_invalid');
  assert.ok(line, 'a billing_vat line with reason vies_invalid');
  assert.strictEqual(line.level, 'warn');
  did();
});

test('an invoice issued before a reverse-charged one keeps its number and its VAT', async (t) => {
  if (!srv) return t.skip('no redis');
  // The private buyer above already has a 21% invoice. He now enters a valid
  // EU VAT number and buys again. The first document must stay what it was.
  const [before21] = await invoices('private');
  assert.ok(before21, 'the earlier 21% invoice is there');
  const stored = await redis.get(`paramant:billing:invoice:doc:${before21.number}`);
  assert.ok(stored);

  const saved = await srv.post('/v2/billing/profile', { ...as('private'), body: { company: 'Acme BE SRL', address: 'Example Street 2\n1000 Example City\nBelgium', vat: VAT.eu } });
  assert.strictEqual(saved.status, 200);
  const second = await checkout('private', { product: 'firm', plan: 'firm', interval: 'yearly' });
  assert.strictEqual(second.amount.value, '290.00', 'yearly Firm without VAT');
  await payAndNotify(second.id);
  const list = await invoices('private');
  assert.strictEqual(list.length, 2);
  const [rc, old] = list;
  assert.strictEqual(rc.vat_rate, 0);
  assert.strictEqual(rc.amount_gross, '290.00');
  assert.match(rc.number, /^PS-\d{4}-\d{4,}$/, 'the same series as every other invoice');
  assert.ok(Number(rc.number.slice(8)) > Number(old.number.slice(8)), 'numbered after the earlier one');
  assert.strictEqual(old.number, before21.number);
  assert.strictEqual(old.vat_rate, 21);
  assert.strictEqual(await redis.get(`paramant:billing:invoice:doc:${old.number}`), stored, 'the stored record is untouched');
  did();
});

test("somebody else's valid number: without a name and an address, or under another name, 21%", async (t) => {
  if (!srv) return t.skip('no redis');
  const acct = acctOf('down').slice(0, 12);
  const before = viesCallsFor(VAT.eu).length;
  // Review probe R2: nothing on the account but a number that is valid for
  // somebody else.
  await srv.post('/v2/billing/profile', { ...as('down'), body: { company: '', address: '', vat: VAT.eu } });
  const bare = await checkout('down');
  assert.strictEqual(bare.amount.value, '35.09', 'the safe side: Dutch VAT');
  assert.strictEqual(bare.metadata.vat, undefined);
  assert.strictEqual(viesCallsFor(VAT.eu).length, before, 'no name and no address, so VIES is not even asked');
  assert.ok(logLines().some((l) => l.msg === 'billing_vat' && l.account === acct && l.reason === 'incomplete_profile' && l.level === 'warn'));

  // A name and an address, but not the company VIES holds for that number.
  await srv.post('/v2/billing/profile', { ...as('down'), body: { company: 'Globex SRL', address: 'Example Street 9\n1000 Example City\nBelgium', vat: VAT.eu } });
  const other = await checkout('down');
  assert.strictEqual(other.amount.value, '35.09');
  assert.strictEqual(other.metadata.vat, undefined);
  assert.strictEqual(viesCallsFor(VAT.eu).length, before + 1, 'VIES was asked this time');
  const line = logLines().find((l) => l.msg === 'billing_vat' && l.account === acct && l.reason === 'name_mismatch');
  assert.ok(line, 'a billing_vat line with reason name_mismatch');
  assert.strictEqual(line.level, 'warn');
  const raw = JSON.stringify(line);
  assert.ok(!raw.includes(VAT.eu.slice(2)) && !raw.includes('Globex') && !raw.includes('ACME'), 'no number and no name in the log');
  did();
});
