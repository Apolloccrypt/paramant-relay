'use strict';
// A replayed Mollie payment id, and a chargeback on the second month, on a
// really booted relay against the fake Mollie.
//
// WHY (sweep-acct, findings 1 and 8).
//   1. The idempotency marker lived 60 days in redis, and on disk only the
//      LAST payment per product was remembered (paid_by_<product>). After a
//      second purchase plus a redis flush (or 60 days), POST /v2/billing/webhook
//      with the first tr_ id -- printed on the invoice, the webhook is public --
//      granted another month for free.
//   2. A chargeback on month 2 floored the product and cleared paid_until, so
//      the paid month 1 went with it.
// Run: REDIS_URL=redis://127.0.0.1:6398 node --test test/route-billing-replay.test.js
const { test, before, after } = require('node:test');
const assert = require('assert');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const fakeMollie = require('../../tests/helpers/fake-mollie.cjs');
const entitlements = require('../lib/entitlements');

const INTERCEPT = path.join(__dirname, '..', '..', 'tests', 'helpers', 'mollie-intercept.cjs');
const RUN = `${process.pid}_${Date.now().toString(36)}`;
const KEY = `pgp_replay_${RUN}`;
const ACCT = `acct_demo_replay_${RUN}`;
const KEY2 = `pgp_upgrade_${RUN}`;
const ACCT2 = `acct_demo_upgrade_${RUN}`;
const PAID = entitlements.PRODUCT_PAID_UNTIL_FIELD.parasign;
const DAY = 86400000;

let redis = null; let srv = null; let mollie = null; let mollieOrigin = ''; let env = null;
let checks = 0;
const did = () => { checks++; };

before(async () => {
  redis = await requireRedis('redis://127.0.0.1:6398');
  if (!redis) return;
  mollie = fakeMollie.create();
  mollieOrigin = await mollie.listen();
  await fetch(`${mollieOrigin}/_ctl/webhook-off`, { method: 'POST', body: JSON.stringify({ off: true }) });
  env = {
    RELAY_REDIS_URL: redis.options.url, REDIS_URL: redis.options.url,
    NODE_OPTIONS: `--require ${INTERCEPT}`, FAKE_MOLLIE_URL: mollieOrigin,
    MOLLIE_TEST_API_KEY: 'test_dummy_key_for_the_fake',
  };
  srv = await boot({
    tag: 'billing-replay', usersFile: true, captureLog: true,
    users: { api_keys: [
      { key: KEY, plan: 'community', active: true, parasign: true, account_id: ACCT, email: 'replay@example.test' },
      { key: KEY2, plan: 'community', active: true, parasign: true, account_id: ACCT2, email: 'upgrade@example.test' },
    ] },
    env,
  });
});
after(async () => {
  await killAll();
  if (mollie) await mollie.close();
  if (redis) { try { await redis.disconnect(); } catch (_) { /* gone */ } }
  summary('route-billing-replay', checks);
});

const as = { headers: { 'X-Api-Key': KEY } };
async function buy(key = KEY, order = { product: 'firm', plan: 'firm', interval: 'monthly' }) {
  const r = await srv.post('/v2/billing/checkout', { headers: { 'X-Api-Key': key }, body: order });
  assert.strictEqual(r.status, 200, r.text);
  const id = r.json.payment_id;
  const paid = await fetch(`${mollieOrigin}/checkout/${id}`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'outcome=paid' });
  assert.strictEqual(paid.status, 302);
  await hook(id);
  return id;
}
async function hook(id) {
  const h = await srv.post('/v2/billing/webhook', { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `id=${id}` });
  assert.strictEqual(h.status, 200, h.text);
}
async function paidUntil(key = KEY) {
  await new Promise((r) => setTimeout(r, 150)); // users.json write is queued
  const rec = srv.readUsersFile().api_keys.find((k) => k.key === key);
  return { tier: rec.plan_parasign, until: rec[PAID] ? new Date(rec[PAID]).getTime() : null };
}
async function flushMarkers() {
  for await (const k of redis.scanIterator({ MATCH: 'paramant:billing:done:*' })) {
    for (const key of [].concat(k)) await redis.del(key);
  }
}

test('an old payment id replayed after a second purchase and a redis flush grants nothing', async (t) => {
  if (!srv) return t.skip('no redis');
  const p1 = await buy();
  const after1 = await paidUntil();
  assert.strictEqual(after1.tier, 'pro');
  const p2 = await buy();
  const after2 = await paidUntil();
  assert.ok(after2.until - after1.until > 25 * DAY, 'second month extends');

  await flushMarkers();
  await hook(p1);
  assert.strictEqual((await paidUntil()).until, after2.until, 'replay of month 1 after a redis flush: no extra month');

  // And after a restart too: the ledger is on disk.
  srv = await srv.restart();
  await flushMarkers();
  await hook(p1);
  await hook(p2);
  assert.strictEqual((await paidUntil()).until, after2.until, 'replay after restart + flush: still nothing');
  did();

  // Chargeback on month 2 takes back month 2, not month 1.
  const cb = await fetch(`${mollieOrigin}/_ctl/chargeback`, { method: 'POST', body: JSON.stringify({ id: p2 }) });
  assert.ok(cb.ok, 'fake Mollie charged back');
  await hook(p2);
  const afterCb = await paidUntil();
  assert.strictEqual(afterCb.tier, 'pro', 'month 1 is still paid for');
  assert.ok(Math.abs(afterCb.until - after1.until) < 2 * DAY, `term ends where month 1 ended (${new Date(afterCb.until).toISOString()} vs ${new Date(after1.until).toISOString()})`);
  did();
});

test('upgrade Firm -> ParaSign Business is self-service and pauses the Pro term', async (t) => {
  if (!srv) return t.skip('no redis');
  await buy(KEY2);
  const firm = await paidUntil(KEY2);
  assert.strictEqual(firm.tier, 'pro');
  await buy(KEY2, { product: 'parasign', plan: 'business', interval: 'monthly' });
  const rec = srv.readUsersFile().api_keys.find((k) => k.key === KEY2);
  assert.strictEqual(rec.plan_parasign, 'business', 'Business runs on top');
  const proEnd = new Date(rec.terms_parasign.pro.until).getTime();
  assert.ok(proEnd - firm.until > 25 * DAY, 'the Pro month under Business is paused, not lost');
  const down = await srv.post('/v2/billing/checkout', { headers: { 'X-Api-Key': KEY2 }, body: { product: 'firm', plan: 'firm', interval: 'yearly' } });
  assert.strictEqual(down.status, 200, 'renewing the Pro tier that holds a term is fine');
  did();
});
