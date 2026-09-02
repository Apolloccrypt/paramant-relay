'use strict';
// The lockout, attempted for real against a booted relay.
//
// WHY THIS SUITE EXISTS. The unit suites pin the decision (auth-throttle) and
// the guard (verify-totp), but the bug was never in either: it was in the
// WIRING. /v2/user/verify-totp incremented a per-account counter on the way in
// and answered 429 at ten, and the user_id it counted comes straight off the
// request body. So ten posts naming somebody else's account shut that account
// out of its own second factor for five minutes, no credentials needed, and the
// only thing that would have caught a fix that missed a call site is a request.
//
// This suite makes the attack and then tries to sign in over it, on a relay
// process with a real redis behind it. The property, in one line: after a
// stranger has burned any number of wrong codes against an account, the account
// holder's correct code still verifies.
//
// Run: node --test relay/test/route-user-mfa-lockout.test.js
//      (needs REDIS_URL, because the TOTP secret and the single-use guard both
//      live in redis; without it the relay has nowhere to store a secret)

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const net = require('net');
const { boot, killAll, freePort } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const totpLib = require('../lib/totp');

const MFA_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const MFA_INTERNAL = 'internal-token-for-the-mfa-lockout-suite';
// relay.js USER_MFA_MAX. Ten failures used to be a five-minute lockout.
const MFA_THRESHOLD = 10;

let mfaSrv = null;
let mfaRedis = null;
let mfaChecks = 0;
const mfaDid = () => { mfaChecks++; };

before(async () => {
  mfaRedis = await requireRedis(MFA_DEFAULT_REDIS);
  if (!mfaRedis) return;
  mfaSrv = await boot({
    tag: 'mfa-lockout',
    env: {
      INTERNAL_AUTH_TOKEN: MFA_INTERNAL,
      REDIS_URL: process.env.REDIS_URL || MFA_DEFAULT_REDIS,
      // The stored TOTP secret is encrypted at rest (lib/encryption.js), so the
      // relay refuses to enroll without a key. Test-only, fixed, 32 bytes.
      PARAMANT_TOTP_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
    },
  });
});

after(async () => {
  await killAll();
  if (mfaRedis) { try { await mfaRedis.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-user-mfa-lockout', mfaChecks);
});

// Enroll a throwaway account and hand back its TOTP secret.
async function mfaEnroll(srv) {
  const userId = `pgp_mfa_${crypto.randomBytes(6).toString('hex')}`;
  const res = await srv.post('/v2/user/setup-totp', {
    headers: { 'X-Internal-Auth': MFA_INTERNAL },
    body: { user_id: userId },
  });
  assert.equal(res.status, 200, `setup-totp must enroll the account: ${JSON.stringify(res.json)}`);
  assert.ok(res.json.secret, 'setup-totp must return a secret');
  return { userId, secret: res.json.secret };
}

function mfaVerify(srv, userId, code) {
  return srv.post('/v2/user/verify-totp', {
    headers: { 'X-Internal-Auth': MFA_INTERNAL },
    body: { user_id: userId, totp: code },
  });
}

// A code that is wrong in every slot of the window, under both algorithms.
function mfaWrongCode(secret, now = Date.now()) {
  const slot = Math.floor(now / 1000 / 30);
  const taken = new Set();
  for (const alg of ['sha256', 'sha1']) {
    for (let i = -2; i <= 2; i++) taken.add(totpLib.totpCode(secret, slot + i, alg));
  }
  for (let n = 0; n < 1000; n++) {
    const candidate = String(n).padStart(6, '0');
    if (!taken.has(candidate)) return candidate;
  }
  throw new Error('no wrong code available, which cannot happen');
}

test('a stranger cannot spend an account out of its own second factor', async (t) => {
  if (!mfaSrv) return t.skip('no redis');
  const { userId, secret } = await mfaEnroll(mfaSrv);

  // The attack: more wrong codes than the old ceiling allowed, all naming the
  // victim's account. Every one of these used to move a counter that refused
  // at ten; the eleventh through fifteenth used to be 429 and the account was
  // then shut for five minutes.
  const statuses = [];
  for (let i = 0; i < MFA_THRESHOLD + 5; i++) {
    const res = await mfaVerify(mfaSrv, userId, mfaWrongCode(secret));
    statuses.push(res.status);
    assert.equal(res.json.valid, false, `attempt ${i + 1} is a wrong code and must read as one`);
  }
  assert.ok(!statuses.includes(429),
    `no attempt may be refused on a caller-supplied user_id, got: ${statuses.join(',')}`);
  mfaDid();

  // The account holder, immediately afterwards, with the code their app shows.
  const good = await mfaVerify(mfaSrv, userId, totpLib.totpCode(secret, Math.floor(Date.now() / 1000 / 30), 'sha256'));
  assert.equal(good.status, 200, 'the owner must not meet a 429 built out of somebody else attempts');
  assert.equal(good.json.valid, true, 'and the correct code must verify');
  mfaDid();
});

test('the wrong-code score is dropped the moment the right code lands', async (t) => {
  if (!mfaSrv) return t.skip('no redis');
  const { userId, secret } = await mfaEnroll(mfaSrv);

  for (let i = 0; i < MFA_THRESHOLD + 2; i++) await mfaVerify(mfaSrv, userId, mfaWrongCode(secret));

  // Past the threshold each further attempt is delayed a little, so a success
  // that did NOT clear the bucket would leave the owner paying for the
  // attacker's score on every later sign-in. Measure the second sign-in: it has
  // to be quick, which is only true if the first one reset the count.
  const slot = () => Math.floor(Date.now() / 1000 / 30);
  const first = await mfaVerify(mfaSrv, userId, totpLib.totpCode(secret, slot(), 'sha256'));
  assert.equal(first.json.valid, true, 'the owner gets in');

  // A different slot, so the single-use guard does not refuse the same code.
  const nextSlot = slot() + 1;
  const t0 = Date.now();
  const second = await mfaVerify(mfaSrv, userId, totpLib.totpCode(secret, nextSlot, 'sha256'));
  const elapsed = Date.now() - t0;
  assert.equal(second.json.valid, true, 'and gets in again');
  assert.ok(elapsed < 250, `a cleared bucket costs no delay, took ${elapsed}ms`);
  mfaDid();
});

// A TCP pass-through in front of redis, so a test can take the store away from a
// running relay without touching the server everything else in this job shares.
// Killing the proxy is what an outage looks like from inside the relay: the
// socket dies and every queued command sits there unanswered.
function mfaRedisProxy(port, upstreamUrl) {
  const u = new URL(upstreamUrl);
  const sockets = new Set();
  const server = net.createServer((client) => {
    const upstream = net.connect(Number(u.port || 6379), u.hostname || '127.0.0.1');
    sockets.add(client); sockets.add(upstream);
    client.on('error', () => {}); upstream.on('error', () => {});
    client.pipe(upstream); upstream.pipe(client);
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({
      kill() {
        for (const sock of sockets) { try { sock.destroy(); } catch (_) { /* already gone */ } }
        sockets.clear();
        return new Promise((r) => server.close(r));
      },
    }));
  });
}

test('an unreachable replay store refuses the code and says 503, instead of accepting it or hanging', async (t) => {
  if (!mfaRedis) return t.skip('no redis');

  // Its own relay, behind a proxy this test is allowed to kill.
  const proxyPort = await freePort();
  const proxy = await mfaRedisProxy(proxyPort, process.env.REDIS_URL || MFA_DEFAULT_REDIS);
  const srv = await boot({
    tag: 'mfa-failclosed',
    env: {
      INTERNAL_AUTH_TOKEN: MFA_INTERNAL,
      REDIS_URL: `redis://127.0.0.1:${proxyPort}`,
      PARAMANT_TOTP_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
    },
  });

  const { userId, secret } = await mfaEnroll(srv);
  const slot = () => Math.floor(Date.now() / 1000 / 30);
  const before = await mfaVerify(srv, userId, totpLib.totpCode(secret, slot(), 'sha256'));
  assert.equal(before.json.valid, true, 'with the store up, a correct code verifies');

  await proxy.kill();

  // What this proves, exactly: with the store gone, the ENDPOINT decides, and it
  // decides against the code. Measured on origin/main the same request never
  // answered at all: the secret read in front of the guard queues forever
  // against a dead socket, so the fail-open catch behind it was never even
  // reached. That is why the bound on the read is part of this fix, and why the
  // guard's own fail-closed behaviour is pinned where it can be reached in
  // isolation, in verify-totp.test.js (a throwing store, a synchronously
  // throwing store, and a store that never answers).
  const t0 = Date.now();
  const during = await mfaVerify(srv, userId, totpLib.totpCode(secret, slot() + 1, 'sha256'));
  const elapsed = Date.now() - t0;
  assert.equal(during.status, 503, `an outage must answer 503, got ${during.status} ${during.text}`);
  assert.notEqual(during.json && during.json.valid, true, 'and must never report the code as valid');
  assert.ok(elapsed < 8000, `the answer has to arrive, took ${elapsed}ms`);
  assert.match(srv.log() || '', /totp_replay_store_unavailable/, 'and the outage is logged');
  mfaDid();

  srv.stop();
});

test('a used code is still refused, so the fix did not open a replay window', async (t) => {
  if (!mfaSrv) return t.skip('no redis');
  const { userId, secret } = await mfaEnroll(mfaSrv);
  const code = totpLib.totpCode(secret, Math.floor(Date.now() / 1000 / 30), 'sha256');

  const first = await mfaVerify(mfaSrv, userId, code);
  assert.equal(first.json.valid, true, 'first use of the code is accepted');
  const replay = await mfaVerify(mfaSrv, userId, code);
  assert.equal(replay.status, 200, 'a replay is a verification answer, not an outage');
  assert.equal(replay.json.valid, false, 'the same code inside the same slot is refused');
  mfaDid();
});
