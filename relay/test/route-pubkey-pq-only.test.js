'use strict';
// sweep-api finding 5: sdk-js 3.3 (wire format v1, ML-KEM only) registers
// kem_pub without ecdh_pub, and the relay answered every registration 400.
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
let checks = 0;
after(async () => { await killAll(); summary('route-pubkey-pq-only', checks); });

test('a post-quantum-only key registers and reads back; the inv_ rendezvous still needs ecdh_pub', async () => {
  const srv = await boot({ tag: 'pqonly', users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'p@example.test' }] } });
  const kem = crypto.randomBytes(1184).toString('hex');
  const r = await srv.post('/v2/pubkey', { headers: { 'X-Api-Key': KEY }, body: { device_id: 'sdk-device-1', kem_id: 2, kem_pub: kem, kyber_pub: kem, sig_pub: '', dsa_pub: '' } });
  assert.strictEqual(r.status, 200, r.text);
  const g = await srv.get('/v2/pubkey/sdk-device-1', { headers: { 'X-Api-Key': KEY } });
  assert.strictEqual(g.status, 200, g.text);
  assert.strictEqual(g.json.kyber_pub, kem);
  const inv = await srv.post('/v2/pubkey', { body: { device_id: 'inv_' + 'a'.repeat(32), kyber_pub: kem } });
  assert.strictEqual(inv.status, 400);
  const none = await srv.post('/v2/pubkey', { headers: { 'X-Api-Key': KEY }, body: { device_id: 'x' } });
  assert.strictEqual(none.status, 400);
  await srv.stop();
  checks++;
});
