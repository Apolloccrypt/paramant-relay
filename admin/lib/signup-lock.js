'use strict';
// Serializes account creation in signup-verify per e-mail address.
//
// Two concurrent verify clicks -- two different pending tokens for the same
// address, both issued while no account existed yet -- could both pass the
// "does the account exist" re-check before either had created the account,
// so one e-mail could end up with two keys (known-issues C1, TOCTOU).
// A Redis NX lock on the e-mail hash closes the window: the loser waits and
// re-runs the existence check, which then sees the winner's account.

const crypto = require('crypto');

const LOCK_TTL_S = 60;        // hard upper bound; normal hold time is <2s
const RETRIES = 4;
const RETRY_DELAY_MS = 700;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const lockKey = (email) =>
  'paramant:signup:creating:' +
  crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');

// Returns { acquired, release }. release() only deletes the lock when the
// stored value is still ours, so a lock that expired and was re-acquired by
// another request is never deleted from under that request. The get+del pair
// is not atomic, but with a 60s TTL against a <2s hold the value-match makes
// a misdelete require a 58s stall between two specific commands.
async function acquireSignupLock(redis, email, owner, opts = {}) {
  const retries = opts.retries ?? RETRIES;
  const delayMs = opts.delayMs ?? RETRY_DELAY_MS;
  const key = lockKey(email);
  for (let i = 0; i <= retries; i++) {
    const ok = await redis.set(key, owner, { NX: true, EX: LOCK_TTL_S });
    if (ok) {
      return {
        acquired: true,
        release: async () => {
          const cur = await redis.get(key).catch(() => null);
          if (cur === owner) await redis.del(key).catch(() => {});
        },
      };
    }
    if (i < retries) await sleep(delayMs);
  }
  return { acquired: false, release: async () => {} };
}

module.exports = { acquireSignupLock, lockKey, LOCK_TTL_S };
