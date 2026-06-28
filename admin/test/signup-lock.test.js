'use strict';
// signup-lock: serializes signup-verify account creation per e-mail (C1).
// Run: node admin/test/signup-lock.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const { acquireSignupLock, lockKey, LOCK_TTL_S } = require('../lib/signup-lock');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// Minimal in-memory stand-in for the node-redis v4 surface the lock uses.
function fakeRedis() {
  const store = new Map();
  return {
    async set(key, val, opts = {}) {
      if (opts.NX && store.has(key)) return null;
      store.set(key, String(val));
      return 'OK';
    },
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async del(key) { return store.delete(key) ? 1 : 0; },
    _store: store,
  };
}

(async () => {
  // lockKey: same address normalizes to the same key, different address differs
  assert.strictEqual(lockKey('A@B.com '), lockKey('a@b.com'), 'case/space-insensitive');
  assert.notStrictEqual(lockKey('a@b.com'), lockKey('c@d.com'), 'distinct per address');
  assert.ok(lockKey('a@b.com').startsWith('paramant:signup:creating:'), 'namespaced');
  assert.ok(!lockKey('a@b.com').includes('a@b.com'), 'address itself never in the key');
  ok('lockKey');

  // first caller acquires, NX blocks the second, release frees it
  const r = fakeRedis();
  const a = await acquireSignupLock(r, 'a@b.com', 'tok-A', { retries: 0 });
  assert.strictEqual(a.acquired, true, 'first acquire wins');
  const b = await acquireSignupLock(r, 'a@b.com', 'tok-B', { retries: 0 });
  assert.strictEqual(b.acquired, false, 'second acquire blocked while held');
  await a.release();
  const c = await acquireSignupLock(r, 'a@b.com', 'tok-C', { retries: 0 });
  assert.strictEqual(c.acquired, true, 'acquire succeeds after release');
  await c.release();
  ok('mutual exclusion + release');

  // different e-mail addresses do not contend
  const r2 = fakeRedis();
  const x = await acquireSignupLock(r2, 'x@y.com', 'tok-X', { retries: 0 });
  const y = await acquireSignupLock(r2, 'z@w.com', 'tok-Z', { retries: 0 });
  assert.strictEqual(x.acquired && y.acquired, true, 'independent addresses');
  ok('per-address scoping');

  // the loser retries and gets the lock once the winner releases
  const r3 = fakeRedis();
  const w = await acquireSignupLock(r3, 'a@b.com', 'tok-W', { retries: 0 });
  setTimeout(() => { w.release(); }, 30);
  const l = await acquireSignupLock(r3, 'a@b.com', 'tok-L', { retries: 5, delayMs: 20 });
  assert.strictEqual(l.acquired, true, 'retry wins after release');
  ok('retry until released');

  // release() of a stale handle never deletes someone else's lock
  const r4 = fakeRedis();
  const first = await acquireSignupLock(r4, 'a@b.com', 'tok-1', { retries: 0 });
  // simulate TTL expiry + re-acquire by another request
  r4._store.set(lockKey('a@b.com'), 'tok-2');
  await first.release();
  assert.strictEqual(await r4.get(lockKey('a@b.com')), 'tok-2', 'foreign lock survives stale release');
  ok('stale release is a no-op');

  // sanity: TTL bound exists so a crashed holder cannot deadlock signups
  assert.ok(LOCK_TTL_S > 0 && LOCK_TTL_S <= 300, 'bounded TTL');
  ok('bounded TTL');

  console.log(`signup-lock: ${passed} checks passed`);
})().catch((e) => { console.error(e); process.exit(1); });
