'use strict';
// SENDNAME-29-K: the live hand-over announced every block at
// /v2/session/inv_.../manifest and got 403 (pst_ token out of scope) and then
// 404 (the route only knew pss_ sessions); the receiver's keyless read got
// 401. Streaming was off and the relay held the whole file until `_ready`.
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');
const st = require('../lib/session-token');

const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
const OTHER = 'pgp_' + crypto.randomBytes(32).toString('hex');
let checks = 0;
after(async () => { await killAll(); summary('route-inv-manifest', checks); });

test('a pst_ token may announce blocks of a live hand-over', () => {
  const inv = 'inv_' + 'a'.repeat(32);
  assert.ok(st.scopeAllows('POST', `/v2/session/${inv}/manifest`), 'announce is in the ParaSend scope');
  assert.ok(!st.scopeAllows('POST', '/v2/session/inv_short/manifest'));
  checks++;
});

test('sender announces with his key, receiver reads without one, a stranger cannot write', async () => {
  const srv = await boot({ tag: 'invmf', users: { api_keys: [
    { key: KEY, plan: 'pro', active: true, email: 'a@example.test', account_id: 'acct_inv_a' },
    { key: OTHER, plan: 'pro', active: true, email: 'b@example.test', account_id: 'acct_inv_b' },
  ] } });
  const inv = 'inv_' + crypto.randomBytes(16).toString('hex');
  const empty = await srv.get(`/v2/session/${inv}/manifest`);
  assert.strictEqual(empty.status, 200, 'keyless read before anything: empty, not 401');
  assert.strictEqual(empty.json.total, 0);
  for (let i = 0; i < 3; i++) {
    const r = await srv.post(`/v2/session/${inv}/manifest`, { headers: { 'X-Api-Key': KEY }, body: { index: i, total_chunks: 3, token: 't' + i } });
    assert.strictEqual(r.status, 200, r.text);
  }
  const read = await srv.get(`/v2/session/${inv}/manifest`);
  assert.strictEqual(read.status, 200);
  assert.strictEqual(read.json.complete, true);
  assert.deepStrictEqual(read.json.chunks.map((c) => c.token), ['t0', 't1', 't2']);
  const anon = await srv.post(`/v2/session/${inv}/manifest`, { body: { index: 0, total_chunks: 3, token: 'x' } });
  assert.strictEqual(anon.status, 401);
  const stranger = await srv.post(`/v2/session/${inv}/manifest`, { headers: { 'X-Api-Key': OTHER }, body: { index: 0, total_chunks: 3, token: 'x' } });
  assert.strictEqual(stranger.status, 403);
  await srv.stop();
  checks++;
});

test('the sender says no: the receiver reading _ready or the manifest gets 410 handover_rejected', async () => {
  const srv = await boot({ tag: 'invrej', users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'a@example.test', account_id: 'acct_inv_a' }] } });
  const inv = 'inv_' + crypto.randomBytes(16).toString('hex');
  assert.ok(st.scopeAllows('POST', `/v2/session/${inv}/reject`), 'a pst_ token may say no');
  assert.strictEqual((await srv.post(`/v2/session/${inv}/reject`, { body: {} })).status, 401, 'not without a credential');
  const r = await srv.post(`/v2/session/${inv}/reject`, { headers: { 'X-Api-Key': KEY }, body: {} });
  assert.strictEqual(r.status, 200, r.text);
  const ready = await srv.get(`/v2/pubkey/${inv}_ready`);
  assert.strictEqual(ready.status, 410);
  assert.strictEqual(ready.json.error, 'handover_rejected');
  assert.strictEqual((await srv.get(`/v2/session/${inv}/manifest`)).status, 410);
  await srv.stop();
  checks++;
});
