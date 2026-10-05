'use strict';
// Review #555, M5: the inv_ hand-over manifest. Any key could reject any
// inv_ id and wipe the sender's manifest, and any free key could fill the
// heap (5000 manifests x 100 000 tokens, rejections without a cap). Now
// /reject checks the owner of the running hand-over, and the manifests are
// bounded per manifest, per account and in total.
// Run: node --test relay/test/route-inv-manifest-bounds.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

let checks = 0;
after(async () => { await killAll(); summary('route-inv-manifest-bounds', checks); });
const A = 'pgp_' + crypto.randomBytes(32).toString('hex');
const B = 'pgp_' + crypto.randomBytes(32).toString('hex');
const inv = () => 'inv_' + crypto.randomBytes(16).toString('hex');
const users = { api_keys: [
  { key: A, plan: 'pro', active: true, email: 'a@example.test', account_id: 'acct_inv_sender' },
  { key: B, plan: 'community', active: true, email: 'b@example.test', account_id: 'acct_inv_stranger' },
] };

test('a stranger cannot reject a running hand-over; the sender can', async () => {
  const srv = await boot({ tag: 'invbounds', users });
  const id = inv();
  let r = await srv.post(`/v2/session/${id}/manifest`, { headers: { 'X-Api-Key': A }, body: { index: 0, total_chunks: 2, token: 'tokA0' } });
  assert.strictEqual(r.status, 200, r.text);
  r = await srv.post(`/v2/session/${id}/reject`, { headers: { 'X-Api-Key': B }, body: {} });
  assert.strictEqual(r.status, 403, 'stranger reject: ' + r.text);
  r = await srv.get(`/v2/session/${id}/manifest`);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.chunks.length, 1, 'the sender\'s manifest is still there');
  r = await srv.post(`/v2/session/${id}/reject`, { headers: { 'X-Api-Key': A }, body: {} });
  assert.strictEqual(r.status, 200, r.text);
  r = await srv.get(`/v2/session/${id}/manifest`);
  assert.strictEqual(r.status, 410);
  await srv.stop();
  checks++;
});

test('a manifest is bounded in blocks, and an account in live hand-overs', async () => {
  const srv = await boot({ tag: 'invbounds2', users });
  const big = await srv.post(`/v2/session/${inv()}/manifest`, { headers: { 'X-Api-Key': B }, body: { index: 0, total_chunks: 100000, token: 't0' } });
  assert.strictEqual(big.status, 400, '100 000 blocks: ' + big.text);
  const statuses = [];
  for (let i = 0; i < 7; i++) {
    const r = await srv.post(`/v2/session/${inv()}/manifest`, { headers: { 'X-Api-Key': B }, body: { index: 0, total_chunks: 3, token: 'tk' + i } });
    statuses.push(r.status);
  }
  assert.deepStrictEqual(statuses.slice(0, 5), [200, 200, 200, 200, 200]);
  assert.ok(statuses.slice(5).every((s) => s === 429), statuses.join(','));
  // Another account is not affected by B's cap.
  const other = await srv.post(`/v2/session/${inv()}/manifest`, { headers: { 'X-Api-Key': A }, body: { index: 0, total_chunks: 3, token: 'ta' } });
  assert.strictEqual(other.status, 200);
  await srv.stop();
  checks++;
});
