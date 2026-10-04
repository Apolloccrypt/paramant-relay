'use strict';
// Admin panel, fase 1 P11:
//   ADMIN-06-H  /admin/users handed every account's FULL pgp_ key to the browser
//               (key_id); it carries the kid now and the routes resolve it.
//   ADMIN-16    resend-setup only accepted X-Admin-Token; the panel sends X-Session.
//   ADMIN-55    /admin/user-detail/:key compared against the masked key: always 404.
//   ADMIN-19-B  change-plan offered 'trial', which no relay accepts.
//   + New key   a key made with an address got no setup mail and no user:meta.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
const KID = 'k_' + crypto.randomBytes(6).toString('hex');
let rc = null; let srv = null; let relay = null; let SID = null;
before(async () => {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
  const { createClient } = require('redis');
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); } catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": ${e.message}`);
  }
  rc = c;
  const state = defaultRelayState([{ key: KEY, kid: KID, email: 'owner@example.test', plan: 'pro', active: true }]);
  state.route = (method, p, h, body) => {
    if (method === 'POST' && p === '/v2/admin/keys') return { status: 200, body: { ok: true, key: body.key } };
    if (p.startsWith('/v2/admin/keys/') || p === '/v2/reload-users') return { status: 200, body: { ok: true, entitlements: {} } };
    if (p.startsWith('/v2/admin/entitlements')) return { status: 200, body: {} };
    return null;
  };
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay, env: { RELAY_MAIN: relay.base, RELAY_LEGAL: relay.base, RELAY_FINANCE: relay.base, RELAY_IOT: relay.base } });
  SID = crypto.randomBytes(16).toString('hex');
  await rc.set(`paramant:admin:session:${SID}`, '1', { EX: 600 });
});
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

const H = () => ({ 'X-Session': SID, 'Content-Type': 'application/json' });

test('the user list carries no full key; the kid works on the detail route', async () => {
  if (!srv) return;
  const r = await fetch(`${srv.base}/api/admin/users`, { headers: H() });
  const txt = await r.text();
  assert.strictEqual(r.status, 200, txt);
  assert.ok(!txt.includes(KEY), 'a full pgp_ key reached the browser');
  const u = JSON.parse(txt).users[0];
  assert.strictEqual(u.key_id, KID);
  const d = await fetch(`${srv.base}/api/admin/user-detail/${KID}`, { headers: H() });
  assert.strictEqual(d.status, 200, 'user-detail with the handle');
  const d2 = await fetch(`${srv.base}/api/admin/user-detail/${KEY}`, { headers: H() });
  assert.strictEqual(d2.status, 200, 'user-detail with the full key (was always 404)');
  const dj = await d2.json();
  assert.notStrictEqual(dj.key, KEY, 'the detail answer names the key masked');
  assert.ok(!('_full' in dj));
});

test('resend-setup works with the panel session and a { key } body', async () => {
  if (!srv) return;
  const r = await fetch(`${srv.base}/api/admin/resend-setup`, { method: 'POST', headers: H(), body: JSON.stringify({ key: KID }) });
  // No mail carrier in tests: the route gets past auth and lookup, then the
  // send fails (500). What matters is that it is not 401 and not 400.
  assert.notStrictEqual(r.status, 401, 'the panel session was refused');
  assert.notStrictEqual(r.status, 400, 'the { key } body was not understood');
});

test('change-plan maps trial to community instead of a plan no relay takes', async () => {
  if (!srv) return;
  const r = await fetch(`${srv.base}/api/admin/change-plan`, { method: 'POST', headers: H(), body: JSON.stringify({ key: KID, new_plan: 'trial', notify: false }) });
  assert.notStrictEqual(r.status, 400);
  const call = relay.state.calls.find((c) => c.path === '/v2/admin/keys/update-plan');
  assert.ok(call && call.body.plan === 'community', JSON.stringify(call && call.body));
});

test('+ New key with an address records user:meta and tries the setup mail', async () => {
  if (!srv) return;
  const r = await fetch(`${srv.base}/api/keys/all`, { method: 'POST', headers: H(), body: JSON.stringify({ label: 'x', plan: 'pro', email: 'nieuw@posteo.de' }) });
  const j = await r.json();
  assert.ok(j.created && j.created.length >= 1, JSON.stringify(j));
  assert.ok('setup_email_sent' in j, 'the answer says whether the setup mail went');
  const key = relay.state.calls.find((c) => c.method === 'POST' && c.path === '/v2/admin/keys').body.key;
  const meta = JSON.parse(await rc.get(`paramant:user:meta:${key}`));
  assert.strictEqual(meta.email, 'nieuw@posteo.de');
});
