'use strict';
// What a buyer gets and reads after paying, on a really booted relay against
// the fake Mollie. Rows 1, 4, 6 and 8 of the betaaltest of 05-10-2026.
//
//   1  Business granted ParaSign alone. The customer kept ParaSend Community
//      (one recipient, one hour), /parashare told him "with Firm you send to
//      30", and Firm was refused because Business was running. Business is
//      more than Firm now (besluit 05-10): it carries ParaSend Pro.
//   4  Mollie's redirect carries no payment id, so the dashboard said "being
//      confirmed" after a cancelled payment too. The relay remembers the last
//      checkout and says what Mollie says became of it.
//   6  A buyer from /en/pricing came back to the Dutch /dashboard.
//   8  After Firm then Business, ParaSign Pro was moved behind Business and
//      ParaSend Pro ran out on the old day: two end dates for one purchase.
// Run: REDIS_URL=redis://127.0.0.1:6398 node --test test/route-betalen-duidelijk.test.js
const { test, before, after } = require('node:test');
const assert = require('assert');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const fakeMollie = require('../../tests/helpers/fake-mollie.cjs');

const INTERCEPT = path.join(__dirname, '..', '..', 'tests', 'helpers', 'mollie-intercept.cjs');
const RUN = `${process.pid}_${Date.now().toString(36)}`;
const BIZ = `pgp_demo_biz_${RUN}`;
const UP = `pgp_demo_up_${RUN}`;
const RET = `pgp_demo_ret_${RUN}`;
const DAY = 86400000;
const ADMIN_TOKEN = 'admin-token-for-betalen-duidelijk';
const INTERNAL = 'internal-token-for-betalen-duidelijk';

let redis = null; let srv = null; let mollie = null; let mollieOrigin = '';
let checks = 0;
const did = () => { checks++; };

before(async () => {
  redis = await requireRedis('redis://127.0.0.1:6398');
  if (!redis) return;
  mollie = fakeMollie.create();
  mollieOrigin = await mollie.listen();
  await fetch(`${mollieOrigin}/_ctl/webhook-off`, { method: 'POST', body: JSON.stringify({ off: true }) });
  srv = await boot({
    tag: 'betalen-duidelijk', usersFile: true, captureLog: true,
    users: { api_keys: [BIZ, UP, RET].map((key) => ({
      key, plan: 'community', active: true, parasign: true, account_id: key.replace('pgp_', 'acct_'), email: `${key}@example.test`,
    })) },
    env: {
      RELAY_REDIS_URL: redis.options.url, REDIS_URL: redis.options.url,
      NODE_OPTIONS: `--require ${INTERCEPT}`, FAKE_MOLLIE_URL: mollieOrigin,
      MOLLIE_TEST_API_KEY: 'test_dummy_key_for_the_fake',
      ADMIN_TOKEN, INTERNAL_AUTH_TOKEN: INTERNAL,
    },
  });
});
after(async () => {
  await killAll();
  if (mollie) await mollie.close();
  if (redis) { try { await redis.disconnect(); } catch (_) { /* gone */ } }
  summary('route-betalen-duidelijk', checks);
});

async function checkout(key, order) {
  const r = await srv.post('/v2/billing/checkout', { headers: { 'X-Api-Key': key }, body: order });
  assert.strictEqual(r.status, 200, r.text);
  return r.json.payment_id;
}
async function pay(id, outcome = 'paid') {
  const r = await fetch(`${mollieOrigin}/checkout/${id}`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `outcome=${outcome}` });
  assert.strictEqual(r.status, 302);
  return r.headers.get('location');
}
async function hook(id) {
  const h = await srv.post('/v2/billing/webhook', { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `id=${id}` });
  assert.strictEqual(h.status, 200, h.text);
}
async function buy(key, order) { const id = await checkout(key, order); await pay(id); await hook(id); return id; }
async function record(key, until) {
  let rec = null;
  for (let i = 0; i < 40; i++) {
    rec = srv.readUsersFile().api_keys.find((k) => k.key === key);
    if (rec && until(rec)) return rec;
    await new Promise((r) => setTimeout(r, 100));
  }
  return rec;
}

test('row 1: Business carries ParaSend Pro, so /parashare never sends a Business customer to Firm', async (t) => {
  if (!srv) return t.skip('no redis');
  await buy(BIZ, { product: 'parasign', plan: 'business', interval: 'monthly' });
  const rec = await record(BIZ, (r) => r.plan_parasend === 'pro');
  assert.strictEqual(rec.plan_parasign, 'business');
  assert.strictEqual(rec.plan_parasend, 'pro', 'the Business payment wrote the ParaSend half too');
  assert.strictEqual(rec.paid_until_parasend, rec.paid_until_parasign, 'one term, one end date for both halves');
  // What /parashare reads to decide the recipient cap and the upsell line.
  const ck = await srv.get('/v2/check-key', { headers: { 'X-Api-Key': BIZ } });
  assert.strictEqual(ck.status, 200, ck.text);
  assert.strictEqual(Number(ck.json.max_recipients), 30, `a Business account sends to 30: ${ck.text}`);
  assert.strictEqual(Number(ck.json.link_ttl_ms), DAY, `and its links live 24 hours: ${ck.text}`);
  did();
});

test('row 8: Firm then Business pauses both halves of Firm, so both end on one day', async (t) => {
  if (!srv) return t.skip('no redis');
  await buy(UP, { product: 'firm', plan: 'firm', interval: 'monthly' });
  const firm = await record(UP, (r) => r.plan_parasend === 'pro');
  const firmEnd = Date.parse(firm.paid_until_parasend);
  await buy(UP, { product: 'parasign', plan: 'business', interval: 'monthly' });
  const rec = await record(UP, (r) => r.terms_parasign && r.terms_parasign.pro
    && Date.parse(r.terms_parasign.pro.until) - firmEnd > 25 * DAY
    && Date.parse(r.paid_until_parasend) - firmEnd > 25 * DAY);
  const signProEnd = Date.parse(rec.terms_parasign.pro.until);
  const sendEnd = Date.parse(rec.paid_until_parasend);
  assert.ok(signProEnd - firmEnd > 25 * DAY, 'the ParaSign half of Firm waits behind Business');
  assert.ok(sendEnd - firmEnd > 25 * DAY, 'and so does the ParaSend half');
  assert.ok(Math.abs(sendEnd - signProEnd) < 60_000,
    `one end date for what is left of Firm: ParaSign ${rec.terms_parasign.pro.until}, ParaSend ${rec.paid_until_parasend}`);
  assert.strictEqual(rec.bundle_parasend, 'firm', 'the last day is still the end of his Firm, so the expiry mail names Firm');
  // The projection /account reads: one line per product.
  const keys = await srv.get('/v2/admin/keys?reveal=1', { headers: { 'X-Admin-Token': ADMIN_TOKEN, 'X-Internal-Auth': INTERNAL } });
  assert.strictEqual(keys.status, 200, keys.text);
  const row = keys.json.keys.find((k) => k.key === UP);
  assert.deepStrictEqual(row.terms_parasign.map((x) => x.tier), ['business', 'pro'], 'highest first, then what takes over');
  assert.deepStrictEqual(row.terms_parasend.map((x) => x.tier), ['pro']);
  assert.strictEqual(row.terms_parasend[0].until, row.terms_parasign[1].until, 'and they end on the same day');
  did();
});

test('rows 4 and 6: the buyer comes back in his language, and the relay says what became of the payment', async (t) => {
  if (!srv) return t.skip('no redis');
  const as = { headers: { 'X-Api-Key': RET } };
  const none = await srv.get('/v2/billing/last-payment', as);
  assert.strictEqual(none.status, 200, none.text);
  assert.strictEqual(none.json.payment, null, 'no checkout yet, nothing to say');

  const en = await checkout(RET, { product: 'firm', plan: 'firm', interval: 'monthly', lang: 'en' });
  assert.match(await pay(en, 'canceled'), /\/en\/dashboard\?billing=return$/, 'English buyer back on the English dashboard');
  let last = await srv.get('/v2/billing/last-payment', as);
  assert.strictEqual(last.json.payment.status, 'canceled', last.text);
  assert.deepStrictEqual([last.json.payment.product, last.json.payment.plan, last.json.payment.interval], ['firm', 'firm', 'monthly']);
  await hook(en);
  const rec = srv.readUsersFile().api_keys.find((k) => k.key === RET);
  assert.notStrictEqual(rec.plan_parasign, 'pro', 'a cancelled payment grants nothing');

  for (const outcome of ['failed', 'expired']) {
    const id = await checkout(RET, { product: 'firm', plan: 'firm', interval: 'yearly' });
    assert.match(await pay(id, outcome), /[^n]\/dashboard\?billing=return$/, 'without lang: the Dutch dashboard');
    last = await srv.get('/v2/billing/last-payment', as);
    assert.strictEqual(last.json.payment.status, outcome, last.text);
    assert.strictEqual(last.json.payment.interval, 'yearly');
  }
  const odd = await checkout(RET, { product: 'firm', plan: 'firm', interval: 'monthly', lang: '//evil.example' });
  assert.match(await pay(odd), /^https?:\/\/[^/]+\/dashboard\?billing=return$/, 'only "en" moves the redirect; nothing else from the request reaches it');
  last = await srv.get('/v2/billing/last-payment', as);
  assert.strictEqual(last.json.payment.status, 'paid');
  const anon = await srv.get('/v2/billing/last-payment');
  assert.strictEqual(anon.status, 401, 'never without an account');
  did();
});
