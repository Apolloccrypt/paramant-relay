'use strict';
// ADMIN-F2-kidcache: the panel acts with a kid (k_<hex>), which the admin
// resolves to the key through a cache of the relay's key list. A kid the cache
// did not know got one fresh read, but at most one per second. So an account
// made in the panel and acted on right away, within a second of any other kid
// lookup, answered 404 unknown_key (fase-1 herrun P11, p11/probe-kid.mjs).
// A write to the key set now marks the cache stale.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const OLD = { key: 'pgp_' + crypto.randomBytes(32).toString('hex'), kid: 'k_' + crypto.randomBytes(6).toString('hex'), email: 'oud@example.test', plan: 'pro', active: true };
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
  const state = defaultRelayState([OLD]);
  state.route = (method, p) => {
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

const post = (p, body) => fetch(`${srv.base}/api${p}`, { method: 'POST', headers: { 'X-Session': SID, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('an account made in the panel can be acted on at once by its kid', async () => {
  if (!srv) return;
  // Warm the cache with a kid lookup, the way any earlier click in the panel does.
  const warm = await post('/admin/set-parasign', { key: OLD.kid, enabled: true });
  assert.strictEqual(warm.status, 200, 'warm-up on a known kid');
  // The stub answers every /v2/admin/keys call with its list, so the new
  // account is put on that list here, as the relay does on a create, and the
  // panel's create call is the key-set write the admin sees.
  const fresh = { key: 'pgp_' + crypto.randomBytes(32).toString('hex'), kid: 'k_' + crypto.randomBytes(6).toString('hex'), email: null, label: 'nieuw', plan: 'pro', active: true };
  relay.state.accounts.push(fresh);
  await post('/keys/all', { label: 'nieuw', plan: 'pro' });
  const r = await post('/admin/set-parasign', { key: fresh.kid, enabled: true });
  const j = await r.json().catch(() => ({}));
  assert.notStrictEqual(r.status, 404, 'a kid made a moment ago answered unknown_key: ' + JSON.stringify(j));
  assert.strictEqual(r.status, 200, JSON.stringify(j));
  assert.strictEqual(j.key, fresh.kid, 'the answer names the kid, never the full key');
});
