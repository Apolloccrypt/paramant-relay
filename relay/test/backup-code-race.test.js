'use strict';
// Review #555, M7: a back-up code was not single-use under concurrency.
// consumeBackupCode read the set, verified, then SREM'd and ignored the
// answer, so five parallel uses of one code were five times valid. The PR
// leans on it for the 2FA reset and the fresh second factor.
// Needs a redis and argon2. Run: REDIS_URL=redis://127.0.0.1:6399 node --test test/backup-code-race.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { requireRedis, summary } = require('./_requires');

let checks = 0; let rc = null;
const uid = 'usr_bc_race_' + crypto.randomBytes(5).toString('hex');
after(async () => {
  if (rc) { try { await rc.del([`paramant:user:backup_codes:${uid}`, `paramant:user:backup_codes_plaintext:${uid}`]); await rc.disconnect(); } catch (_) { /* gone */ } }
  summary('backup-code-race', checks);
});

test('one back-up code used five times in parallel is valid exactly once', async (t) => {
  let userTotp;
  try { userTotp = require('../lib/user-totp'); require('argon2'); } catch (e) { return t.skip('argon2 not installed'); }
  rc = await requireRedis('redis://127.0.0.1:6399');
  if (!rc) return t.skip('no redis');
  const codes = await userTotp.regenerateBackupCodes(rc, uid);
  const res = await Promise.all(Array.from({ length: 5 }, () => userTotp.consumeBackupCode(rc, uid, codes[0])));
  assert.strictEqual(res.filter((r) => r.valid).length, 1, JSON.stringify(res));
  assert.strictEqual(await rc.sCard(`paramant:user:backup_codes:${uid}`), codes.length - 1);
  checks++;
});
