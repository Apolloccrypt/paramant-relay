'use strict';
// Review #555, M6: one bucket for every customer together. Six free 25 MB
// sends of one account closed ParaSend-op-naam for everybody else until they
// expired. Now an account has a share (default a quarter of the total, never
// less than one send of the maximum size) next to the total.
// Read at load, so set before the require: total 8 MB, max send 2 MB, which
// makes the default share max(2, 8/4) = 2 MB.
process.env.SEND_TOTAL_MB = '8';
process.env.SEND_MAX_MB = '2';
delete process.env.SEND_ACCOUNT_MB;
const { test } = require('node:test');
const assert = require('assert');
const { createSendStore, SEND_ACCOUNT_MB } = require('../lib/send');
const { sealedVoor } = require('./_sealed');

function nepStore() {
  const blobs = new Map(); const meta = new Map();
  return {
    blobs, meta,
    async putBlob(id, buf) { blobs.set(id, Buffer.from(buf)); },
    async getBlob(id) { return blobs.get(id) || null; },
    async delBlob(id) { blobs.delete(id); },
    async putMeta(id, obj) { meta.set(id, JSON.parse(JSON.stringify(obj))); },
    async delMeta(id) { meta.delete(id); },
    async getMeta(id) { const r = meta.get(id); return r ? JSON.parse(JSON.stringify(r)) : null; },
  };
}

test('one account cannot take the whole store; another account still sends', async () => {
  assert.strictEqual(SEND_ACCOUNT_MB, 2);
  let nu = 1_000_000;
  const store = nepStore();
  const sends = createSendStore({ store, now: () => nu });
  const mb = (n) => Buffer.alloc(n * 1048576, 1);
  const who = (i) => [`p${i}@example.org`];
  const mk = (i, accountId) => sends.create({ plan: 'business', blob: mb(1), addresses: who(i), sealed: sealedVoor(who(i)), ttlMs: 3600000, accountId });
  assert.strictEqual((await mk(1, 'acct_heavy')).ok, true);
  assert.strictEqual((await mk(2, 'acct_heavy')).ok, true);
  const third = await mk(3, 'acct_heavy');
  assert.strictEqual(third.ok, false, 'the third MB of one account is over its share');
  assert.strictEqual(third.reason, 'account_store_full');
  const other = await mk(4, 'acct_other');
  assert.strictEqual(other.ok, true, 'another account is not locked out');
  nu += 3600001;
  assert.strictEqual((await mk(5, 'acct_heavy')).ok, true, 'expired sends free the share');
});
