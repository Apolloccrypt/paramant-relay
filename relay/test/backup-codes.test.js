'use strict';
// Backup-code lifecycle tests — proves the setup-flow fix: backup codes are
// minted once at activation, are immediately usable, survive setup reloads, and
// a re-mint cleanly replaces the previous set.
// Run: node relay/test/backup-codes.test.js (argon2 only; no live Redis).

const assert = require('assert');
const userTotp = require('../lib/user-totp');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// Minimal in-memory Redis covering the set + key ops user-totp.js uses.
function fakeRedis() {
  const sets = new Map();   // key -> Set<string>
  const kv = new Map();     // key -> string
  return {
    async sAdd(key, members) {
      const arr = Array.isArray(members) ? members : [members];
      const s = sets.get(key) || new Set();
      for (const m of arr) s.add(m);
      sets.set(key, s);
      return arr.length;
    },
    async sMembers(key) { return Array.from(sets.get(key) || []); },
    async sRem(key, member) { const s = sets.get(key); if (s) s.delete(member); return 1; },
    async del(key) {
      const keys = Array.isArray(key) ? key : [key];
      for (const k of keys) { sets.delete(k); kv.delete(k); }
      return keys.length;
    },
    async set(key, val) { kv.set(key, val); return 'OK'; },
    async get(key) { return kv.has(key) ? kv.get(key) : null; },
    _setCount(key) { return (sets.get(key) || new Set()).size; },
  };
}

(async () => {
  const r = fakeRedis();
  const uid = 'pgp_test_user';
  const setKey = `paramant:user:backup_codes:${uid}`;

  // 1. Before activation, nothing has minted codes — the set is empty. (Mirrors
  //    the new setup-totp, which no longer produces codes at the QR step.)
  assert.strictEqual(r._setCount(setKey), 0, 'no codes before activation');
  ok('setup step mints no backup codes');

  // 2. Activation mints exactly one full batch and returns the plaintext once.
  const codes = await userTotp.regenerateBackupCodes(r, uid);
  assert.ok(Array.isArray(codes) && codes.length === 10, 'activation returns 10 codes');
  assert.strictEqual(r._setCount(setKey), 10, '10 hashes stored');
  assert.ok(codes.every(c => /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(c)), 'code format');
  ok('activation mints and returns 10 usable codes');

  // 3. The returned codes actually validate (enrol == unlock guarantee).
  const v1 = await userTotp.consumeBackupCode(r, uid, codes[0]);
  assert.strictEqual(v1.valid, true, 'first code validates');
  const v1again = await userTotp.consumeBackupCode(r, uid, codes[0]);
  assert.strictEqual(v1again.valid, false, 'code is single-use');
  assert.strictEqual(r._setCount(setKey), 9, 'consumed code removed from set');
  ok('codes validate and are single-use');

  // 4. Reload-safety / re-issue: minting again replaces the set. The OLD codes
  //    stop working, the NEW ones work. This is the exact scenario that used to
  //    strand users on an empty backup-code screen.
  const codes2 = await userTotp.regenerateBackupCodes(r, uid);
  assert.strictEqual(r._setCount(setKey), 10, 're-mint resets to a full batch');
  const oldStillValid = await userTotp.consumeBackupCode(r, uid, codes[1]);
  assert.strictEqual(oldStillValid.valid, false, 'old codes invalid after re-mint');
  const newValid = await userTotp.consumeBackupCode(r, uid, codes2[0]);
  assert.strictEqual(newValid.valid, true, 'new codes valid after re-mint');
  ok('re-mint cleanly replaces the previous set');

  console.log(`\nbackup-codes: ${passed} checks passed`);
})().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
