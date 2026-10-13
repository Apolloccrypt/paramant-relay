'use strict';
// One ceiling over every open send together (sweep-chaos 4). There was a
// ceiling per send and none over the lot: seven 25 MB sends filled redis and
// log-in, signing and envelopes all answered 503 for up to a week.
// SEND_TOTAL_MB is read at load, so it is set before the require.
process.env.SEND_TOTAL_MB = '2';
const { test } = require('node:test');
const assert = require('assert');
const { createSendStore } = require('../lib/send');
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

test('the total over open sends is enforced, and an expired send frees its share', async () => {
  let nu = 1_000_000;
  const store = nepStore();
  const sends = createSendStore({ store, now: () => nu });
  const mb = (n) => Buffer.alloc(n * 1048576, 1);
  const who = (i) => [`p${i}@example.org`];
  const a = await sends.create({ plan: 'business', blob: mb(1), addresses: who(1), sealed: sealedVoor(who(1)), ttlMs: 3600000 });
  assert.strictEqual(a.ok, true);
  const b = await sends.create({ plan: 'business', blob: mb(1), addresses: who(2), sealed: sealedVoor(who(2)), ttlMs: 3600000 });
  assert.strictEqual(b.ok, true);
  const c = await sends.create({ plan: 'business', blob: mb(1), addresses: who(3), sealed: sealedVoor(who(3)), ttlMs: 3600000 });
  assert.strictEqual(c.ok, false);
  assert.strictEqual(c.reason, 'store_full');
  assert.strictEqual(store.blobs.size, 2, 'nothing was written for the refused send');
  nu += 3600001;
  const d = await sends.create({ plan: 'business', blob: mb(1), addresses: who(4), sealed: sealedVoor(who(4)), ttlMs: 3600000 });
  assert.strictEqual(d.ok, true, 'expired sends no longer count');
});
