'use strict';
// Review #555, H3: webhook registrations sat in the shared redis without a
// TTL and without a cap on device_id. Redis runs with noeviction, so one Pro
// key filled it (5000 registrations in a second, 20 MB) and every write of
// every customer failed. Now: a cap per account, a cap in total, a short list
// per device, a TTL on every key and a bounded url.
// Needs a redis. Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-webhook-caps.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

let checks = 0; let rc = null;
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } summary('route-webhook-caps', checks); });
const key = () => 'pgp_' + crypto.randomBytes(32).toString('hex');
const pro = (k, acct) => ({ key: k, plan: 'pro', plan_parasend: 'pro', active: true, email: acct + '@example.test', account_id: acct });

test('per account: the 21st device id is refused, every key has a TTL, a long url is refused', async (t) => {
  rc = await requireRedis('redis://127.0.0.1:6399');
  if (!rc) return t.skip('no redis');
  const K = key(); const acct = 'acct_whcap_' + crypto.randomBytes(4).toString('hex');
  const srv = await boot({ tag: 'whcap', env: { REDIS_URL: rc.options.url, MAIL_PROVIDER: 'dryrun' }, users: { api_keys: [pro(K, acct)] } });
  const statuses = [];
  for (let i = 0; i < 25; i++) {
    const r = await srv.post('/v2/webhook', { headers: { 'X-Api-Key': K }, body: { device_id: 'd' + i, url: 'https://hooks.example.com/h' + i } });
    statuses.push(r.status);
    if (i === 20) assert.strictEqual(r.json && r.json.error, 'webhook_device_limit', r.text);
  }
  assert.strictEqual(statuses.filter((s) => s === 200).length, 20, statuses.join(','));
  assert.ok(statuses.slice(20).every((s) => s === 429), statuses.join(','));
  // A device already registered may register again (the list stays short).
  for (let i = 0; i < 8; i++) {
    const r = await srv.post('/v2/webhook', { headers: { 'X-Api-Key': K }, body: { device_id: 'd0', url: 'https://hooks.example.com/again' + i } });
    assert.strictEqual(r.status, 200, r.text);
  }
  const listKey = 'paramant:webhooks:' + crypto.createHash('sha256').update('d0:' + acct).digest('hex').slice(0, 40);
  assert.ok(await rc.lLen(listKey) <= 5, 'the per-device list is short');
  const ttl = await rc.ttl(listKey);
  assert.ok(ttl > 0, 'a registration expires: ttl ' + ttl);
  const long = await srv.post('/v2/webhook', { headers: { 'X-Api-Key': K }, body: { device_id: 'd1', url: 'https://hooks.example.com/' + 'a'.repeat(600) } });
  assert.strictEqual(long.status, 400, long.text);
  await srv.stop();
  checks++;
});

test('in total: over all accounts the store stops at its cap', async (t) => {
  if (!rc) return t.skip('no redis');
  const now = Date.now();
  const before = await rc.zCount('paramant:webhooks:all', now, '+inf');
  const keys = Array.from({ length: 4 }, () => [key(), 'acct_whtot_' + crypto.randomBytes(4).toString('hex')]);
  const srv = await boot({ tag: 'whtot', env: { REDIS_URL: rc.options.url, MAIL_PROVIDER: 'dryrun', WEBHOOK_TOTAL_MAX: String(before + 3) },
    users: { api_keys: keys.map(([k, a]) => pro(k, a)) } });
  const out = [];
  for (const [k] of keys) {
    for (let i = 0; i < 2; i++) {
      const r = await srv.post('/v2/webhook', { headers: { 'X-Api-Key': k }, body: { device_id: 'tot' + i, url: 'https://hooks.example.com/t' + i } });
      out.push(r.status + ':' + ((r.json && r.json.error) || ''));
    }
  }
  assert.ok(out.some((x) => x === '429:webhook_store_full'), out.join(','));
  assert.ok(out.filter((x) => x.startsWith('200')).length <= 3, out.join(','));
  await srv.stop();
  checks++;
});
