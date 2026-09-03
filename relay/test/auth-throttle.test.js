'use strict';
// The per-account MFA limiter, after it stopped being a lockout.
//
// userMfaAttemptOk(user_id) counted ATTEMPTS: it incremented on the way in and
// refused with 429 once ten landed in five minutes, and only a success cleared
// it. user_id is request input, so ten posts naming somebody else's account shut
// that account out of /v2/user/verify-totp and /v2/user/consume-backup for the
// rest of the window. Same shape as the e-mail counter on the admin login, one
// layer down, and it would have kept that lockout alive after the admin fix.
//
// lib/auth-throttle.js counts failures, clears on success, and answers with a
// delay instead of a refusal. Deterministic: `now` is injected everywhere.
//
// Run: node --test relay/test/auth-throttle.test.js

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const throttle = require('../lib/auth-throttle');

test('counting is read-only until something actually fails', () => {
  const map = new Map();
  const t0 = 1_000_000;
  for (let i = 0; i < 50; i++) throttle.failureCount(map, 'pgp_victim', t0);
  assert.equal(throttle.failureCount(map, 'pgp_victim', t0), 0, 'fifty reads, zero failures');
  assert.equal(map.size, 0, 'and no bucket was created by looking');

  throttle.noteFailure(map, 'pgp_victim', throttle.WINDOW_MS, t0);
  assert.equal(throttle.failureCount(map, 'pgp_victim', t0), 1, 'a real failure counts');
});

test('the throttle never refuses, it only gets slower', () => {
  // Nothing in this module can return "denied". That is the point: any refusal
  // keyed on a caller-supplied user_id is a weapon aimed at the account.
  assert.equal(throttle.throttleDelayMs(0), 0);
  assert.equal(throttle.throttleDelayMs(throttle.FAIL_THRESHOLD), 0, 'the threshold itself is still free');
  assert.equal(throttle.throttleDelayMs(throttle.FAIL_THRESHOLD + 1), throttle.STEP_MS, 'one over costs one step');
  assert.equal(throttle.throttleDelayMs(throttle.FAIL_THRESHOLD + 4), 4 * throttle.STEP_MS, 'and it grows per failure');
  assert.equal(throttle.throttleDelayMs(throttle.FAIL_THRESHOLD + 10_000), throttle.MAX_DELAY_MS,
    'capped, so a request can never be parked indefinitely');
  assert.ok(throttle.MAX_DELAY_MS <= 5_000, 'the cap stays inside any honest client timeout');
});

test('an attacker score does not follow the owner into a correct code', () => {
  const map = new Map();
  const t0 = 1_000_000;
  const victim = 'pgp_victim';

  // Ten wrong codes against the victim's account id.
  for (let i = 0; i < 10; i++) throttle.noteFailure(map, victim, throttle.WINDOW_MS, t0 + i);
  assert.equal(throttle.failureCount(map, victim, t0), 10);
  assert.equal(throttle.throttleDelayMs(10, { threshold: 10 }), 0, 'ten failures still cost the owner nothing');

  // The owner's correct code lands: the bucket is dropped there and then.
  throttle.clearFailures(map, victim);
  assert.equal(throttle.failureCount(map, victim, t0), 0, 'a success wipes the score');
  assert.equal(map.size, 0);
});

test('buckets are per account and roll over with the window', () => {
  const map = new Map();
  const t0 = 1_000_000;
  for (let i = 0; i < 12; i++) throttle.noteFailure(map, 'a', throttle.WINDOW_MS, t0);
  assert.equal(throttle.failureCount(map, 'a', t0), 12);
  assert.equal(throttle.failureCount(map, 'b', t0), 0, 'one account cannot spend another account budget');

  assert.equal(throttle.failureCount(map, 'a', t0 + throttle.WINDOW_MS + 1), 0, 'the window expires the score');
  assert.equal(throttle.noteFailure(map, 'a', throttle.WINDOW_MS, t0 + throttle.WINDOW_MS + 1), 1,
    'and the first failure after it starts a fresh bucket');
});

test('sleep(0) does not defer, and a delay is awaited', async () => {
  const t0 = Date.now();
  await throttle.sleep(0);
  await throttle.sleep(-5);
  assert.ok(Date.now() - t0 < 20, 'no delay means no wait');
  const t1 = Date.now();
  await throttle.sleep(30);
  assert.ok(Date.now() - t1 >= 25, 'a delay is actually waited out');
});

test('relay.js uses the throttle and no longer refuses on a named user_id', () => {
  const relay = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

  // The old primitive, by name and by effect.
  assert.doesNotMatch(relay, /userMfaAttemptOk/, 'the attempt-counting gate must not come back');
  assert.doesNotMatch(relay, /error: "too_many_attempts"/,
    'no 429 may be keyed on a user_id the caller supplied');

  assert.match(relay, /userMfaNoteFailure/, 'failures are recorded');
  assert.match(relay, /userMfaAttemptReset/, 'and a success clears them');
  assert.match(relay, /authThrottle\.sleep\(userMfaDelayMs\(user_id\)\)/, 'the answer is a delay');

  // Both MFA endpoints go through it: verify-totp and consume-backup. The
  // second is the one where a wrong code costs argon2 work, so it needs the
  // throttle more than the first, not less.
  const hits = relay.match(/authThrottle\.sleep\(userMfaDelayMs\(user_id\)\)/g) || [];
  assert.equal(hits.length, 2, 'verify-totp and consume-backup are both throttled');
  const notes = relay.match(/(?<!function )userMfaNoteFailure\(user_id\)/g) || [];
  assert.equal(notes.length, 2, 'and both record their failures');
});

test('every replay-guarded route turns a store outage into a 503, not a 401', () => {
  const relay = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

  // lib/totp.js fails closed on a store error, which is only worth anything if
  // the routes tell that apart from a wrong code. A 401 here would read to the
  // user as "your code is bad" and to a monitor as nothing at all.
  const guards = relay.match(/totpLib\.REPLAY_STORE_UNAVAILABLE/g) || [];
  const calls = relay.match(/replayKey: `paramant:user:replay:\$\{user_id\}`/g) || [];
  assert.ok(calls.length >= 3, 'verify-totp plus both signing-key routes use the replay guard');
  assert.equal(guards.length, calls.length,
    'every call site that passes a replayKey must handle the outage it can now return');

  const outages = relay.match(/writeHead\(503[\s\S]{0,160}?replay_store_unavailable/g) || [];
  assert.ok(outages.length >= calls.length,
    `every guarded route answers 503 replay_store_unavailable, found ${outages.length} for ${calls.length} call sites`);

  // The verify path has one more: the secret read sits in front of the guard and
  // would otherwise queue forever against a dead redis, so the guard never gets
  // to fail closed at all.
  assert.match(relay, /redisDeadline\(userTotp\.getUserTotpSecret/,
    'the redis read in front of the guard must be bounded, or an outage hangs instead of deciding');
  assert.match(relay, /function redisDeadline/, 'and the bound has to exist');

  // Configurable per deployment, but never off: a value of zero or a non-number
  // has to fall back to the default, because an unbounded deadline is the
  // failure it exists to prevent. The declaration moved out of relay.js into
  // lib/redis-deadline when the bound stopped being one hand-wrapped read and
  // became a property of the client, so the pin follows it. Same env name,
  // still the only one: deploy/.env.example documents it and
  // tests/env-documented.test.mjs is what keeps that true.
  const bound = fs.readFileSync(path.join(__dirname, '..', 'lib', 'redis-deadline.js'), 'utf8');
  assert.match(bound, /process\.env\.PARAMANT_REDIS_DEADLINE_MS|env\.PARAMANT_REDIS_DEADLINE_MS/,
    'the deadline reads its environment');
  const decl = bound.slice(bound.indexOf('function redisDeadlineMs'), bound.indexOf('function withRedisDeadline'));
  assert.match(decl, /Number\.isFinite\(raw\) && raw > 0 \? raw : 1000/,
    'zero, a negative and a non-number must all fall back to the 1000 ms default');
  assert.match(relay, /log\("error", "totp_replay_store_unavailable"/,
    'an outage that nobody logs is an outage nobody fixes');
});
