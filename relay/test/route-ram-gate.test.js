'use strict';
// The upload RAM gate counts the bytes this relay holds, not RSS.
// sweep-chaos 7 / SENDNAME-09-RAM: RSS does not come back down after a burst
// (the allocator keeps freed pages for reuse), so after one peak the gate
// answered 503 to every upload with 15 MB of blobs held. Here the limits are
// set below the bare process RSS: the old gate refuses the very first upload,
// the new one accepts it because nothing is held.
// Run: node --test relay/test/route-ram-gate.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
let checks = 0;
after(async () => { await killAll(); summary('route-ram-gate', checks); });

test('an empty relay whose RSS is above RAM_LIMIT_MB + RAM_RESERVE_MB still accepts an upload', async () => {
  const srv = await boot({ tag: 'ramgate', env: { RAM_LIMIT_MB: '24', RAM_RESERVE_MB: '24' },
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'r@example.test', account_id: 'acct_ram' }] } });
  const payload = crypto.randomBytes(1024);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const r = await srv.post('/v2/inbound', { headers: { 'X-Api-Key': KEY }, body: { hash, payload: payload.toString('base64') } });
  assert.strictEqual(r.status, 200, `refused by process RSS: ${r.status} ${r.text}`);
  await srv.stop();
  checks++;
});
