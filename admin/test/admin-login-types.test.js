'use strict';
// POST /api/auth/login with a token or code that is not a string. Buffer.from()
// on a number or an object threw, and express answered with a 500. The
// comparison now goes through safeEqual, and a wrong type is a 400 or 401.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/admin-login-types.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const ALT_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const ALT_TOKEN = 'admin-token-for-the-login-types-suite';

let altSrv = null;
let altRelay = null;
let altIp = 0;
const altNextIp = () => { altIp++; return `203.0.113.${altIp}`; };

before(async () => {
  const url = process.env.REDIS_URL || ALT_DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log('  SKIP [redis] - the "redis" module is not installed (declared via ADMIN_TEST_SKIP)');
      return;
    }
    throw new Error('unmet precondition "redis": the redis module is not installed; run npm ci in admin/');
  }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); await rc.disconnect(); }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log(`  SKIP [redis] - no reachable redis at ${url} (declared via ADMIN_TEST_SKIP)`);
      return;
    }
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  altRelay = await stubRelay(defaultRelayState());
  altSrv = await boot({ redisUrl: url, relay: altRelay, adminToken: ALT_TOKEN });
});

after(killAll);

function login(body) {
  return altSrv.post('/api/auth/login', { headers: { 'X-Real-IP': altNextIp() }, body });
}

const cases = [
  ['token is a number', { token: 12345, totp: '123456' }, 401],
  ['token is an object', { token: { length: 1 }, totp: '123456' }, 401],
  ['token is an array', { token: [ALT_TOKEN], totp: '123456' }, 401],
  ['token is true', { token: true, totp: '123456' }, 401],
  ['token missing', { totp: '123456' }, 401],
  ['totp is a number', { token: ALT_TOKEN, totp: 123456 }, 400],
  ['totp is an array', { token: ALT_TOKEN, totp: ['123456'] }, 400],
  ['wrong token string, same length', { token: ALT_TOKEN.replace(/.$/, 'X'), totp: '123456' }, 401],
  ['wrong token string, other length', { token: 'short', totp: '123456' }, 401],
];

for (const [name, body, want] of cases) {
  test(`admin login: ${name} gives ${want}, not 500`, async (t) => {
    if (!altSrv) return t.skip('redis unavailable (declared)');
    const r = await login(body);
    assert.equal(r.status, want, `body: ${r.text}`);
  });
}

test('admin login: the right token reaches the TOTP check at the relay', async (t) => {
  if (!altSrv) return t.skip('redis unavailable (declared)');
  const before = altRelay.state.calls.length;
  const r = await login({ token: ALT_TOKEN, totp: '123456' });
  // The stub has no /v2/admin/verify-mfa, so the code is refused; what matters
  // is that the token comparison passed and the relay was asked.
  assert.equal(r.status, 401, `body: ${r.text}`);
  const asked = altRelay.state.calls.slice(before).find((c) => c.path === '/v2/admin/verify-mfa');
  assert.ok(asked, 'the admin asked the relay to verify the code');
  assert.equal(asked.body.totp_code, '123456');
});
