'use strict';
// Review #555, M9: MAX_ACTIVE_KEYS = 50. Code keys bound before keys had an
// expiry stay active forever, so an account with fifty of them could not
// sign at all after the deploy (too_many_active_keys). At the ceiling the
// oldest active keys now lapse: not revoked, so old signatures still verify
// and the key still resolves; only the active count stays bounded.
// Run: node --test relay/test/signing-key-cap-lapse.test.js (no deps).
const { test } = require('node:test');
const assert = require('assert');
const us = require('../lib/user-signing');

function fakeRedis() {
  const kv = new Map();
  return {
    async get(k) { return kv.has(k) ? kv.get(k) : null; },
    async set(k, v) { kv.set(k, v); return 'OK'; },
    async del(k) { kv.delete(k); return 1; },
  };
}
const pkN = (n) => { const b = Buffer.alloc(us.ML_DSA_65_PK_LEN, 7); b.writeUInt32BE(n + 5000, 0); return b.toString('base64'); };

test('an account with fifty lasting keys can still bind a new one; the oldest lapses', async () => {
  const r = fakeRedis();
  const uid = 'usr_legacy_heavy';
  // Fifty legacy keys: no expires_at, as code keys were before they lapsed.
  for (let n = 0; n < us.MAX_ACTIVE_KEYS; n++) await us.storeSigningPk(r, uid, { pk_b64: pkN(n), label: 'old ' + n });
  const oldest = (await us.getSigningPks(r, uid))[0];
  const next = await us.storeSigningPk(r, uid, { pk_b64: pkN(999), expiresInMs: us.CODE_KEY_TTL_MS });
  assert.strictEqual(next.reenrolled, false, 'the new key is bound, not refused');
  assert.strictEqual((await us.getActiveSigningPks(r, uid)).length, us.MAX_ACTIVE_KEYS);
  const found = await us.lookupByPkHash(r, oldest.pk_hash_sha3);
  assert.ok(found, 'the lapsed key still resolves for its old signatures');
  assert.ok(!found.entry.revoked_at, 'lapsed, not revoked');
  assert.ok(us.isExpired(found.entry), 'the oldest key lapsed');
});
