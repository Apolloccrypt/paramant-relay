'use strict';
// POST/DELETE /v2/user/signing-key: wrong TOTP codes are counted per ACCOUNT
// (security review ronde 2, (b)). nginx limited per address only, so a stolen
// session could guess from many addresses at once. After five wrong codes the
// account is locked with a growing backoff, also for a right code, and a right
// code before that clears the count.
//
// Needs @paramant/core and a redis. Run:
//   REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-signing-key-totp-lockout.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const INTERNAL = 'internal-token-for-the-totp-lockout-suite';
const MASTER = crypto.randomBytes(32).toString('base64');
const SUFFIX = crypto.randomBytes(6).toString('hex');
const USER = `usr_totp_lockout_${SUFFIX}`;
const OTHER = `usr_totp_lockout_other_${SUFFIX}`;

let rc = null;
let srv = null;
let secret = null;
let checks = 0;

function code(offsetSteps = 0) {
  const totp = require('../lib/totp');
  return totp.totpCode(secret, Math.floor(Date.now() / 30000) + offsetSteps, 'sha256');
}
function wrongCode() {
  // Six digits that are none of the three codes the window accepts.
  const ok = new Set([code(-1), code(0), code(1)]);
  for (let i = 0; ; i++) { const c = String(100000 + i); if (!ok.has(c)) return c; }
}
const pk = () => crypto.randomBytes(1952).toString('base64');
const post = (user, totp) => srv.post('/v2/user/signing-key', {
  headers: { 'X-Internal-Auth': INTERNAL }, body: { user_id: user, pk_b64: pk(), label: 't', totp },
});

before(async () => {
  if (!requireEngine()) return;
  rc = await requireRedis(DEFAULT_REDIS);
  if (!rc) return;
  process.env.PARAMANT_TOTP_MASTER_KEY = MASTER;
  const userTotp = require('../lib/user-totp');
  secret = userTotp.generateTotpSecret();
  await userTotp.storeUserTotpSecret(rc, USER, secret);
  await userTotp.storeUserTotpSecret(rc, OTHER, secret);
  srv = await boot({
    tag: 'totp-lockout',
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS, INTERNAL_AUTH_TOKEN: INTERNAL, PARAMANT_TOTP_MASTER_KEY: MASTER },
  });
});

after(async () => {
  await killAll();
  if (rc) {
    for (const u of [USER, OTHER]) {
      await rc.del([`paramant:user:totp:${u}`, `paramant:user:totpfail:${u}`, `paramant:user:totplock:${u}`, `paramant:user:replay:${u}`, `paramant:user:signing_pk:${u}`]);
    }
    await rc.quit().catch(() => {});
  }
  summary('route-signing-key-totp-lockout', checks);
});

test('four wrong codes are refused one by one, a right code then clears the count', async () => {
  if (!srv) return;
  for (let i = 0; i < 4; i++) {
    const r = await post(USER, wrongCode());
    assert.strictEqual(r.status, 403, r.text);
    assert.strictEqual(r.json && r.json.error, 'invalid_totp');
  }
  const good = await post(USER, code());
  assert.strictEqual(good.status, 200, good.text);
  assert.strictEqual(await rc.get(`paramant:user:totpfail:${USER}`), null, 'a right code clears the count');
  checks++;
});

test('the fifth wrong code in a row locks the account, also for a right code', async () => {
  if (!srv) return;
  let last = null;
  for (let i = 0; i < 5; i++) last = await post(USER, wrongCode());
  assert.strictEqual(last.status, 429, last.text);
  assert.strictEqual(last.json.error, 'totp_locked');
  assert.ok(last.json.retry_after >= 50 && last.json.retry_after <= 60, String(last.json.retry_after));
  assert.ok(Number(last.headers['retry-after']) > 0);
  const right = await post(USER, code(1));
  assert.strictEqual(right.status, 429, 'locked means locked, even for the right code: ' + right.text);
  checks++;
});

test('the lock grows with every further wrong code (backoff)', async () => {
  if (!srv) return;
  await rc.del(`paramant:user:totplock:${USER}`);   // the minute passed
  const r = await post(USER, wrongCode());
  assert.strictEqual(r.status, 429);
  assert.ok(r.json.retry_after > 60 && r.json.retry_after <= 120, String(r.json.retry_after));
  checks++;
});

test('the count is per account: another account is not locked', async () => {
  if (!srv) return;
  const r = await post(OTHER, code());
  assert.strictEqual(r.status, 200, r.text);
  checks++;
});

test('DELETE counts on the same account and is locked too', async () => {
  if (!srv) return;
  const body = JSON.stringify({ user_id: USER, pk_hash_sha3: 'a'.repeat(64), totp: code() });
  const r = await srv.req('DELETE', '/v2/user/signing-key', {
    headers: { 'X-Internal-Auth': INTERNAL, 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)) }, body,
  });
  assert.strictEqual(r.status, 429, r.status + ' ' + r.text);
  checks++;
});
