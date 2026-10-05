'use strict';
// API-26-K: webhook registrations were an in-memory Map, gone after a restart
// and not shared between sector relays. They are kept in redis now.
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
let checks = 0; let rc = null;
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } summary('route-webhook-persist', checks); });

test('a webhook survives a relay restart', async (t) => {
  rc = await requireRedis('redis://127.0.0.1:6398');
  if (!rc) return t.skip('no redis');
  const env = { REDIS_URL: rc.options.url, MAIL_PROVIDER: 'dryrun' };
  const host = 'persist-' + crypto.randomBytes(4).toString('hex') + '.example.invalid';
  let srv = await boot({ tag: 'whpersist', usersFile: true, captureLog: true, env,
    users: { api_keys: [{ key: KEY, plan: 'pro', plan_parasend: 'pro', active: true, email: 'w@example.test', account_id: 'acct_wh_' + crypto.randomBytes(4).toString('hex') }] } });
  const reg = await srv.post('/v2/webhook', { headers: { 'X-Api-Key': KEY }, body: { device_id: 'devp', url: `https://${host}/hook` } });
  assert.strictEqual(reg.status, 200, reg.text);
  srv = await srv.restart();
  const payload = crypto.randomBytes(512);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const up = await srv.post('/v2/inbound', { headers: { 'X-Api-Key': KEY }, body: { hash, payload: payload.toString('base64'), meta: { device_id: 'devp' } } });
  assert.strictEqual(up.status, 200, up.text);
  await new Promise((r) => setTimeout(r, 600));
  assert.match(srv.log(), new RegExp(`webhook_fail[^\\n]*${host.split('.')[0]}`), 'the registration from before the restart was used');
  await srv.stop();
  checks++;
});
