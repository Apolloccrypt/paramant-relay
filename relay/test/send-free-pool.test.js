'use strict';
// Herreview #560, M6: with a share per account, a handful of free accounts
// still filled the total for every paying customer. Free (community) sends now
// hold at most half of the total together, so a paid send always finds room.
// Read at load: total 8 MB, max send 2 MB, so the free pool is 4 MB and one
// free account may hold 2 MB.
process.env.SEND_TOTAL_MB = '8';
process.env.SEND_MAX_MB = '2';
delete process.env.SEND_ACCOUNT_MB;
delete process.env.SEND_FREE_POOL_MB;
delete process.env.SEND_FREE_ACCOUNT_MB;
const { test } = require('node:test');
const assert = require('assert');
const { createSendStore, SEND_FREE_POOL_MB, SEND_FREE_ACCOUNT_MB } = require('../lib/send');
const { sealedVoor } = require('./_sealed');

function nepStore() {
  const blobs = new Map(); const meta = new Map();
  return {
    async putBlob(id, buf) { blobs.set(id, Buffer.from(buf)); },
    async getBlob(id) { return blobs.get(id) || null; },
    async delBlob(id) { blobs.delete(id); },
    async putMeta(id, obj) { meta.set(id, JSON.parse(JSON.stringify(obj))); },
    async delMeta(id) { meta.delete(id); },
    async getMeta(id) { const r = meta.get(id); return r ? JSON.parse(JSON.stringify(r)) : null; },
  };
}

test('free accounts together cannot fill the store for paid plans', async () => {
  assert.strictEqual(SEND_FREE_POOL_MB, 4);
  assert.strictEqual(SEND_FREE_ACCOUNT_MB, 2);
  let nu = 1_000_000;
  const sends = createSendStore({ store: nepStore(), now: () => nu });
  const mb = (n) => Buffer.alloc(n * 1048576, 1);
  const who = (i) => [`p${i}@example.org`];
  const mk = (i, plan, accountId, size) => sends.create({ plan, blob: mb(size), addresses: who(i), sealed: sealedVoor(who(i)), ttlMs: 3600000, accountId });
  const free = [];
  for (let i = 0; i < 4; i++) free.push(await mk(i, 'free', 'acct_free' + i, 2));
  assert.deepStrictEqual(free.map((r) => r.ok), [true, true, false, false], 'the third and fourth free account hit the free pool');
  assert.strictEqual(free[2].reason, 'store_full');
  const paid = await mk(10, 'pro', 'acct_paid', 2);
  assert.strictEqual(paid.ok, true, 'a paid account still sends: ' + JSON.stringify(paid));
  nu += 3600001;
  assert.strictEqual((await mk(11, 'free', 'acct_free9', 2)).ok, true, 'expired free sends free the pool');
});

test('one free account holds at most one maximum-size send', async () => {
  const sends = createSendStore({ store: nepStore(), now: () => 1_000_000 });
  const who = (i) => [`q${i}@example.org`];
  const mk = (i) => sends.create({ plan: 'free', blob: Buffer.alloc(1048576, 1), addresses: who(i), sealed: sealedVoor(who(i)), ttlMs: 3600000, accountId: 'acct_one' });
  assert.strictEqual((await mk(1)).ok, true);
  assert.strictEqual((await mk(2)).ok, true);
  const third = await mk(3);
  assert.strictEqual(third.reason, 'account_store_full');
  assert.strictEqual(third.limit, 2);
});
