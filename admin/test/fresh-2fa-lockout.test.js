'use strict';
// Review #555, H2: the fresh second factor (delete account, passkey,
// signing key, backup codes) had no cap on the TOTP path. With a stolen
// session a thief could guess codes for as long as the session lived. The
// admin now asks the relay to count wrong codes per account (fresh_factor),
// the same counter and backoff as the signing-key routes, and passes the
// lockout on as 429. relay/test/route-fresh-factor-lockout.test.js holds the
// relay half against a real relay.
// Needs a redis (REDIS_URL), like the rest of this directory.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const DEFAULT_REDIS = 'redis://127.0.0.1:6379';
const SUFFIX = crypto.randomBytes(4).toString('hex');
const KEY = `pgp_f2l_${SUFFIX}`;
const EMAIL = `f2l-${SUFFIX}@example.test`;
const ORIGIN = 'http://127.0.0.1';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

let rc = null; let srv = null; let relay = null;

before(async () => {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  const { createClient } = require('redis');
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  rc = c;
  const state = defaultRelayState([{ key: KEY, email: EMAIL, active: true, plan: 'pro', created: '2026-01-02T03:04:05.000Z' }]);
  // The relay's per-account lock, as relay.js does it for fresh_factor: five
  // wrong codes free, then 429 totp_locked. A caller that does not ask for
  // the count is only throttled, never refused (the login path).
  let fails = 0;
  state.verify = (b) => {
    if (b.fresh_factor === true && fails >= 5) return { status: 429, body: { error: 'totp_locked', retry_after: 60 } };
    if (b.fresh_factor === true) fails++;
    return { valid: false };
  };
  state.route = () => null;
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay });
});
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

test('wrong TOTP codes as a fresh factor end in a lockout, not an endless 403', async () => {
  if (!rc) return;
  const token = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:user:session:${token}`, JSON.stringify({
    user_id: KEY, email: EMAIL, created_at: Date.now(), last_seen: Date.now(), ip: '203.0.113.9', ua: UA, primary_api_key: KEY,
  }), { EX: 3600 });
  const statuses = [];
  let retryAfter = null;
  for (let i = 0; i < 25; i++) {
    const r = await fetch(`${srv.base}/api/user/account`, {
      method: 'DELETE',
      headers: { Cookie: `paramant_user_session=${token}`, 'User-Agent': UA, Origin: ORIGIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp: String(100000 + i) }),
    });
    statuses.push(r.status);
    if (r.status === 429) { retryAfter = r.headers.get('retry-after'); break; }
  }
  assert.ok(statuses.includes(429), 'never locked: ' + statuses.join(','));
  assert.ok(statuses.length <= 6, 'locked only after ' + statuses.length + ' tries');
  assert.strictEqual(retryAfter, '60');
  const sent = relay.state.calls.filter((c) => c.path === '/v2/user/verify-totp');
  assert.ok(sent.length && sent.every((c) => c.body && c.body.fresh_factor === true), 'every fresh-factor check asks the relay to count');
  await rc.del(`paramant:user:session:${token}`);
});
