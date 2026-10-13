'use strict';
// POST /v2/user/verify-totp with fresh_factor: wrong codes are counted per
// ACCOUNT, with the same counter and backoff as the signing-key routes
// (review #555, H2). The admin asks for this when a TOTP is the fresh second
// factor for deleting an account, a passkey, a signing key or new backup
// codes, so a stolen session cannot guess codes there for as long as it lives.
// The login path does not send the flag and is only throttled, never locked.
//
// Needs @paramant/core and a redis. Run:
//   REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-fresh-factor-lockout.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const INTERNAL = 'internal-token-for-the-fresh-factor-suite';
const MASTER = crypto.randomBytes(32).toString('base64');
const SUFFIX = crypto.randomBytes(6).toString('hex');
const USER = `usr_fresh_factor_${SUFFIX}`;
const LOGIN_USER = `usr_fresh_factor_login_${SUFFIX}`;

let rc = null;
let srv = null;
let secret = null;
let checks = 0;

function code(offsetSteps = 0) {
  const totp = require('../lib/totp');
  return totp.totpCode(secret, Math.floor(Date.now() / 30000) + offsetSteps, 'sha256');
}
function wrongCode(i = 0) {
  const ok = new Set([code(-1), code(0), code(1)]);
  for (let n = i; ; n++) { const c = String(100000 + n); if (!ok.has(c)) return c; }
}
const verify = (user, totp, extra = {}) => srv.post('/v2/user/verify-totp', {
  headers: { 'X-Internal-Auth': INTERNAL }, body: { user_id: user, totp, throttled_upstream: true, ...extra },
});

before(async () => {
  if (!requireEngine()) return;
  rc = await requireRedis(DEFAULT_REDIS);
  if (!rc) return;
  process.env.PARAMANT_TOTP_MASTER_KEY = MASTER;
  const userTotp = require('../lib/user-totp');
  secret = userTotp.generateTotpSecret();
  await userTotp.storeUserTotpSecret(rc, USER, secret);
  await userTotp.storeUserTotpSecret(rc, LOGIN_USER, secret);
  srv = await boot({
    tag: 'fresh-factor',
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS, INTERNAL_AUTH_TOKEN: INTERNAL, PARAMANT_TOTP_MASTER_KEY: MASTER },
  });
});

after(async () => {
  await killAll();
  if (rc) {
    for (const u of [USER, LOGIN_USER]) {
      await rc.del([`paramant:user:totp:${u}`, `paramant:user:totpfail:${u}`, `paramant:user:totplock:${u}`, `paramant:user:replay:${u}`, `paramant:user:signing_pk:${u}`]);
    }
    await rc.quit().catch(() => {});
  }
  summary('route-fresh-factor-lockout', checks);
});

test('fresh factor: the fifth wrong code locks the account, also for a right code and for the signing-key route', async () => {
  if (!srv) return;
  for (let i = 0; i < 4; i++) {
    const r = await verify(USER, wrongCode(i), { fresh_factor: true });
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.valid, false);
  }
  const fifth = await verify(USER, wrongCode(10), { fresh_factor: true });
  assert.strictEqual(fifth.status, 429, 'the fifth wrong code locks: ' + fifth.text);
  assert.strictEqual(fifth.json.error, 'totp_locked');
  const right = await verify(USER, code(), { fresh_factor: true });
  assert.strictEqual(right.status, 429, 'a right code during the lock is refused too');
  // One counter: the signing-key route sees the same lock.
  const sk = await srv.post('/v2/user/signing-key', {
    headers: { 'X-Internal-Auth': INTERNAL }, body: { user_id: USER, pk_b64: crypto.randomBytes(1952).toString('base64'), label: 't', totp: code() },
  });
  assert.strictEqual(sk.status, 429, 'the signing-key route shares the lock: ' + sk.text);
  checks++;
});

test('the login path (no fresh_factor) is never locked by wrong codes', async () => {
  if (!srv) return;
  for (let i = 0; i < 7; i++) {
    const r = await verify(LOGIN_USER, wrongCode(i));
    assert.strictEqual(r.status, 200, r.text);
  }
  assert.strictEqual(await rc.get(`paramant:user:totplock:${LOGIN_USER}`), null);
  checks++;
});
