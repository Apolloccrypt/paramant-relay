// Redis can answer and still refuse. This test is the one that would have
// caught the outage of 07-09-2026.
//
// WHAT HAPPENED. /api/captcha/challenge answered 500 internal_error in
// production. Signup and password reset were dead, login survived. The route
// has its own catch that answers 'challenge_failed', and the error handler has
// a branch that answers 503 'redis_unavailable' when the store is down. Neither
// fired, because neither describes what was wrong: the store was reachable and
// answering, and it was refusing the write.
//
// isRedisOutage() only knew about connection failures -- closed clients, socket
// timeouts, ECONNREFUSED. A server-side refusal (MISCONF because the disk is
// full, OOM at maxmemory, NOPERM from an ACL, READONLY on a replica) arrives as
// a plain Error with the refusal word at the front of the message, matched
// nothing, and fell through to a bare 500 that named no cause.
//
// The line this test holds: a refusal is the store failing us and answers 503;
// a command this code got wrong is still a 500, because that is a bug and
// laundering it into 503 would hide it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const admin = require('../admin/lib/redis-deadline.js');
const relay = require('../relay/lib/redis-deadline.js');

const REFUSALS = [
  'MISCONF Redis is configured to save RDB snapshots, but is currently not able to persist on disk.',
  'OOM command not allowed when used memory > \'maxmemory\'.',
  'NOPERM this user has no permissions to run the \'set\' command',
  'READONLY You can\'t write against a read only replica.',
  'NOAUTH Authentication required.',
  'WRONGPASS invalid username-password pair or user is disabled.',
  'LOADING Redis is loading the dataset in memory',
  'BUSY Redis is busy running a script.',
  'CLUSTERDOWN The cluster is down',
  'TRYAGAIN Multiple keys request during rehashing of slot',
  'MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to no.',
];

// Mistakes in our own commands. These must stay 500.
const OUR_BUGS = [
  'WRONGTYPE Operation against a key holding the wrong kind of value',
  'ERR unknown command \'foo\'',
  'ERR wrong number of arguments for \'set\' command',
  'ERR value is not an integer or out of range',
  'NOSCRIPT No matching script.',
];

for (const [naam, mod] of [['admin', admin], ['relay', relay]]) {
  test(`${naam}: een weigering van de server is een storing`, () => {
    for (const msg of REFUSALS) {
      assert.equal(mod.isRedisOutage(new Error(msg)), true, msg);
      assert.equal(typeof mod.redisRefusal(new Error(msg)), 'string', msg);
    }
  });

  test(`${naam}: een fout commando van ons blijft een fout van ons`, () => {
    for (const msg of OUR_BUGS) {
      assert.equal(mod.isRedisOutage(new Error(msg)), false, msg);
      assert.equal(mod.redisRefusal(new Error(msg)), null, msg);
    }
  });

  test(`${naam}: de connectiefouten blijven werken`, () => {
    const e = new Error('connect ECONNREFUSED 127.0.0.1:6379');
    e.code = 'ECONNREFUSED';
    assert.equal(mod.isRedisOutage(e), true);
    assert.equal(mod.isRedisOutage(new mod.RedisUnavailableError('get', 'deadline')), true);
  });

  test(`${naam}: rommel binnen geeft geen uitzondering`, () => {
    for (const x of [null, undefined, 0, '', 'MISCONF', {}, { message: 42 }]) {
      assert.equal(mod.isRedisOutage(x), false);
    }
  });
}

test('de weigering wordt bij naam genoemd, niet alleen geteld', () => {
  assert.equal(admin.redisRefusal(new Error('MISCONF Redis is configured...')), 'MISCONF');
  assert.equal(admin.redisRefusal(new Error('OOM command not allowed')), 'OOM');
  assert.equal(admin.redisRefusal(new Error('noperm lowercase from a proxy')), 'NOPERM');
});
