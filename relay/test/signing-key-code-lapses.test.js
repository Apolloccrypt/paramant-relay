'use strict';
// 36-K: a signing key bound with a 6-digit code (relay POST /v2/user/signing-key)
// is made for ONE signature; the browser keeps no secret half, so it can never
// sign again. It used to stay active for ever, and after fifty signatures the
// ceiling (MAX_ACTIVE_KEYS) was a dead end: the next signature failed with
// too_many_active_keys and nothing on the account page could fix it except
// revoking fifty keys one by one with a code each.
// Now such a key lapses by itself after CODE_KEY_TTL_MS, does not count against
// the ceiling, cannot fill a signature slot, and stays as history.
// Run: node relay/test/signing-key-code-lapses.test.js (no deps).

const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const us = require('../lib/user-signing');

function fakeRedis() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async del(k) { return m.delete(k) ? 1 : 0; },
  };
}
const pkN = (n) => { const b = Buffer.alloc(us.ML_DSA_65_PK_LEN, 3); b.writeUInt32BE(n + 7, 0); return b.toString('base64'); };

test('a code-bound key carries expires_at and is active until then', async () => {
  const r = fakeRedis();
  const out = await us.storeSigningPk(r, 'u1', { pk_b64: pkN(1), label: 'code', expiresInMs: us.CODE_KEY_TTL_MS });
  assert.ok(out.entry.expires_at, 'expires_at is set');
  const lapse = Date.parse(out.entry.expires_at) - Date.parse(out.entry.enrolled_at);
  assert.strictEqual(lapse, us.CODE_KEY_TTL_MS);
  assert.strictEqual((await us.getActiveSigningPks(r, 'u1')).length, 1);
  assert.strictEqual(us.isActive(out.entry, Date.parse(out.entry.expires_at) - 1), true);
  assert.strictEqual(us.isActive(out.entry, Date.parse(out.entry.expires_at)), false);
});

test('a passkey or invite bind (no expiresInMs) does not lapse', async () => {
  const r = fakeRedis();
  const out = await us.storeSigningPk(r, 'u2', { pk_b64: pkN(2), label: 'passkey' });
  assert.strictEqual(out.entry.expires_at, undefined);
  assert.strictEqual(us.isActive(out.entry, Date.now() + 10 * 365 * 86400e3), true);
});

test('fifty lapsed code keys leave room: the ceiling is no dead end', async () => {
  const r = fakeRedis();
  for (let n = 0; n < us.MAX_ACTIVE_KEYS; n++) {
    await us.storeSigningPk(r, 'u3', { pk_b64: pkN(100 + n), label: 'sig ' + n, expiresInMs: us.CODE_KEY_TTL_MS });
  }
  // While they are fresh, the ceiling holds.
  await assert.rejects(() => us.storeSigningPk(r, 'u3', { pk_b64: pkN(999), expiresInMs: us.CODE_KEY_TTL_MS }), /too_many_active_keys/);
  // A day later every one of them has lapsed: put the clock forward by moving
  // expires_at into the past (same stored shape as a real lapse).
  const raw = JSON.parse(await r.get('paramant:user:signing_pk:u3'));
  for (const e of raw) e.expires_at = new Date(Date.now() - 1000).toISOString();
  await r.set('paramant:user:signing_pk:u3', JSON.stringify(raw));
  assert.strictEqual((await us.getActiveSigningPks(r, 'u3')).length, 0, 'lapsed keys are not active');
  const next = await us.storeSigningPk(r, 'u3', { pk_b64: pkN(999), expiresInMs: us.CODE_KEY_TTL_MS });
  assert.strictEqual(next.reenrolled, false);
  // History stays: all 51 still in the list, and a lapsed one still resolves.
  assert.strictEqual((await us.getSigningPks(r, 'u3')).length, us.MAX_ACTIVE_KEYS + 1);
  const found = await us.lookupByPkHash(r, raw[0].pk_hash_sha3);
  assert.ok(found && found.entry.expires_at, 'a lapsed key still resolves for old signatures');
});

test('the relay binds a key with a code as lapsing, and lists expired/active', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
  const start = src.indexOf('if (req.method === "POST" && path === "/v2/user/signing-key")');
  const end = src.indexOf('path === "/v2/user/signing-key/tofu"', start);
  assert.ok(start > 0 && end > start);
  assert.match(src.slice(start, end), /storeSigningPk\([^)]*expiresInMs: userSigning\.CODE_KEY_TTL_MS/);
  const get = src.indexOf('if (req.method === "GET" && path === "/v2/user/signing-key")');
  const getBody = src.slice(get, get + 1500);
  assert.match(getBody, /expired: userSigning\.isExpired/);
  assert.match(getBody, /active: userSigning\.isActive/);
});
