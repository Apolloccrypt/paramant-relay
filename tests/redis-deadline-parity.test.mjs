// The redis bound exists twice. This is what keeps the two copies the same file.
//
// WHY THERE ARE TWO. relay/ and admin/ are separate npm projects on different
// major versions of the redis client (5.x and 6.x), and each Dockerfile copies
// only its own lib/ into the image:
//
//   relay/Dockerfile:83   COPY lib/ ./lib/
//   admin/Dockerfile:22   COPY lib/ lib/
//
// So a shared module one directory up would resolve in a checkout and be
// missing in the container, which is the worst of the three options: it works
// everywhere except production. Publishing it as a package for two files is
// the other extreme. Two copies and this test is the honest middle: the
// duplication is real, and it is watched.
//
// The module is written to be version-agnostic for exactly this reason -- it
// wraps whatever client it is handed and touches no version-specific API -- so
// there is never a good reason for the copies to differ.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const COPIES = ['relay/lib/redis-deadline.js', 'admin/lib/redis-deadline.js'];
const COUNTER_COPIES = ['relay/lib/redis-counter.js', 'admin/lib/redis-counter.js'];

const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const sha = (s) => createHash('sha256').update(s).digest('hex');

test('the relay and admin copies of lib/redis-deadline.js are the same file', () => {
  const [a, b] = COPIES.map(read);
  assert.equal(sha(a), sha(b),
    `${COPIES[0]} and ${COPIES[1]} have drifted. Copy the one you changed over ` +
    'the other; the module is deliberately version-agnostic, so a difference ' +
    'between them is a fix that only landed on one service.');
});

test('the relay and admin copies of lib/redis-counter.js are the same file', () => {
  const [a, b] = COUNTER_COPIES.map(read);
  assert.equal(sha(a), sha(b),
    `${COUNTER_COPIES[0]} and ${COUNTER_COPIES[1]} have drifted. Copy the one you ` +
    'changed over the other; a counter that expires on one service and not on ' +
    'the other is a permanent refusal on whichever one missed the fix.');
});

test('no limiter sets its expiry only on the first hit any more', () => {
  // The bug: INCR followed by `if (count === 1) await expire(...)`. If the INCR
  // outlives the redis deadline while the server still executes it, the expiry
  // is never sent, the next INCR returns 2, and the key is immortal. That is a
  // permanent 429 on a source address, a permanent proof-of-work bill on an
  // e-mail address, and a permanently exhausted monthly quota.
  //
  // Nothing may call INCR directly except the helper that repairs it.
  const files = [
    'relay/relay.js', 'relay/lib/quota.js',
    'admin/server.js', 'admin/lib/login-ratelimit.js', 'admin/lib/webauthn.js',
  ];
  const offenders = [];
  for (const f of files) {
    const src = read(f);
    src.split('\n').forEach((line, i) => {
      if (/^\s*\/\//.test(line)) return;          // a comment quoting the old shape
      if (/\.incr\(/.test(line)) offenders.push(`${f}:${i + 1} calls INCR directly`);
      if (/===\s*1\)\s*(await\s+)?\S*\.?expire\(/.test(line)) {
        offenders.push(`${f}:${i + 1} sets an expiry only on the first hit`);
      }
    });
  }
  assert.deepEqual(offenders, [],
    'Use incrInWindow from lib/redis-counter.js: it sets the expiry after every ' +
    'INCR, with NX, so a lost expiry survives one request instead of for ever.');
});

test('the admin charges the same throttle curve the relay does', () => {
  // The per-account delay moved from relay.js (where only an address WITH an
  // account could reach it, which is what made it an existence oracle) to the
  // admin, keyed on the hashed address. It is only a mirror while the three
  // numbers match, and they live in two files that cannot require each other.
  const relay = read('relay/lib/auth-throttle.js');
  const admin = read('admin/lib/login-ratelimit.js');
  const num = (src, name) => {
    const m = src.match(new RegExp(`^const ${name} = ([0-9_]+);`, 'm'));
    assert.ok(m, `${name} must be a plain constant so this test can read it`);
    return Number(m[1].replace(/_/g, ''));
  };
  assert.equal(num(admin, 'THROTTLE_THRESHOLD'), num(relay, 'FAIL_THRESHOLD'),
    'the admin must start charging at the same failure count as the relay');
  assert.equal(num(admin, 'THROTTLE_STEP_MS'), num(relay, 'STEP_MS'),
    'and step by the same amount');
  assert.equal(num(admin, 'THROTTLE_MAX_MS'), num(relay, 'MAX_DELAY_MS'),
    'and stop at the same ceiling');
});

test('both copies still export the whole contract', () => {
  // A rename that lands in one copy and not the other would pass the hash check
  // only if both were copied, so this is really about the export list not
  // quietly shrinking: relay.js, admin/lib/redis.js and admin/server.js each
  // depend on a different part of it.
  const required = [
    'RedisUnavailableError',
    'isRedisOutage',
    'redisDeadlineMs',
    'withRedisDeadline',
    'guardRedisClient',
    'redisClientBounds',
    'RESET_AFTER_BREACHES',
  ];
  for (const p of COPIES) {
    const src = read(p);
    for (const name of required) {
      assert.ok(new RegExp(`^\\s*${name},`, 'm').test(src),
        `${p} must export ${name}`);
    }
  }
});

test('both services actually use the bound rather than just carrying it', () => {
  // The module being present and identical is worth nothing if a client is
  // still built without it. There are exactly two createClient calls in the
  // request paths, and both have to be wrapped.
  const relay = read('relay/relay.js');
  assert.match(relay, /guardRedisClient\(\s*\n?\s*createClient\(/,
    'relay.js must wrap its client, or every route inherits the queue again');
  assert.match(relay, /redisClientBounds\(\)/,
    'and pass disableOfflineQueue, which is what stops a command being held during a reconnect');

  const adminRedis = read('admin/lib/redis.js');
  assert.match(adminRedis, /guardRedisClient\(createClient\(/, 'admin/lib/redis.js must wrap its client too');
  assert.match(adminRedis, /redisClientBounds\(\)/, 'with the same client options');

  // And the two error handlers that turn the bound into an honest status code.
  assert.match(relay, /function redisOutage503/,
    'relay.js needs the route-level translation, because it catches its own errors');
  assert.match(read('admin/server.js'), /isRedisOutage\(err\)[\s\S]{0,200}?status\(503\)/,
    'the admin error middleware must answer 503 for an outage, not 500');

  // And the relay must not charge the per-account delay a second time on the
  // one path where the admin has already charged it against the address.
  assert.match(relay, /if \(!throttled_upstream\) await authThrottle\.sleep\(/,
    'relay.js must honour throttled_upstream, or the account-keyed delay comes back');
  const admin = read('admin/server.js');
  const flagged = (admin.match(/throttled_upstream: true/g) || []).length;
  assert.equal(flagged, 2,
    'both login routes must send it: /user/login reaches verify-totp and ' +
    '/user/login-with-backup reaches consume-backup, and each has its own ' +
    'account-keyed delay to suppress');
});
