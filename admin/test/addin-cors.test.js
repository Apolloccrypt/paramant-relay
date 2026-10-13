'use strict';
// The Outlook add-in (https://addin.paramant.app) signs in with password + TOTP
// from inside Outlook, so the login routes answer CORS for exactly that origin,
// with credentials. No other origin, no other route.
const { test, before, after } = require('node:test');
const assert = require('assert');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

let srv = null;
before(async () => {
  const relay = await stubRelay(defaultRelayState([]));
  srv = await boot({ redisUrl: process.env.REDIS_URL || 'redis://127.0.0.1:6379', relay });
});
after(async () => { await killAll(); });

const ADDIN = 'https://addin.paramant.app';
test('preflight for login from the add-in: allowed, with credentials', async () => {
  const r = await fetch(`${srv.base}/api/user/login`, { method: 'OPTIONS', headers: { Origin: ADDIN, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
  assert.strictEqual(r.status, 204);
  assert.strictEqual(r.headers.get('access-control-allow-origin'), ADDIN);
  assert.strictEqual(r.headers.get('access-control-allow-credentials'), 'true');
});
test('another origin, or another route, gets no CORS', async () => {
  const evil = await fetch(`${srv.base}/api/user/login`, { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } });
  assert.strictEqual(evil.headers.get('access-control-allow-origin'), null);
  const other = await fetch(`${srv.base}/api/user/account`, { method: 'OPTIONS', headers: { Origin: ADDIN, 'Access-Control-Request-Method': 'POST' } });
  assert.strictEqual(other.headers.get('access-control-allow-origin'), null);
});
test('a login POST from the add-in reaches the route (not the CSRF refusal)', async () => {
  const r = await fetch(`${srv.base}/api/user/login`, { method: 'POST', headers: { Origin: ADDIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'x@example.org', totp: '000000' }) });
  assert.notStrictEqual(r.status, 403, 'refused as cross-site');
  assert.strictEqual(r.headers.get('access-control-allow-origin'), ADDIN);
});
