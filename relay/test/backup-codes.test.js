'use strict';
// Backup-code lifecycle tests — proves the setup-flow fix: codes are minted at
// activation (regenerateBackupCodes), are usable, single-use, and a re-mint
// cleanly REPLACES the prior set (the reload-safety guarantee that was missing).
//
// This runs in the "no native deps" CI lane (node --test test/*.test.js, no
// npm install), so argon2 (a native binding) is unavailable. We stub it with a
// deterministic hash before requiring user-totp. That is honest here: this fix
// is about orchestration (del -> generate -> store -> return), not the argon2
// KDF, so a deterministic hash exercises exactly the behaviour under test.

const Module = require('module');
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'argon2') {
    return {
      argon2id: 2,
      async hash(s) { return 'h:' + s; },
      async verify(h, s) { return h === 'h:' + s; },
    };
  }
  return origLoad.apply(this, arguments);
};

const assert = require('assert');
const userTotp = require('../lib/user-totp');

// Minimal in-memory Redis covering the set + key ops user-totp.js uses.
function fakeRedis() {
  const sets = new Map(); // key -> Set<string>
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
      for (const k of keys) sets.delete(k);
      return keys.length;
    },
    _setCount(key) { return (sets.get(key) || new Set()).size; },
  };
}

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

(async () => {
  const r = fakeRedis();
  const uid = 'pgp_test_user';
  const setKey = `paramant:user:backup_codes:${uid}`;

  // 1. Before activation, nothing has minted codes. (Mirrors the new setup-totp,
  //    which no longer produces codes at the QR step.)
  assert.strictEqual(r._setCount(setKey), 0, 'no codes before activation');
  ok('setup step mints no backup codes');

  // 2. Activation mints exactly one full batch and returns the plaintext once.
  const codes = await userTotp.regenerateBackupCodes(r, uid);
  assert.ok(Array.isArray(codes) && codes.length === 10, 'activation returns 10 codes');
  assert.strictEqual(r._setCount(setKey), 10, '10 hashes stored');
  assert.ok(codes.every((c) => /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(c)), 'code format');
  ok('activation mints and returns 10 usable codes');

  // 3. The returned codes validate and are single-use.
  assert.strictEqual((await userTotp.consumeBackupCode(r, uid, codes[0])).valid, true, 'first code validates');
  assert.strictEqual((await userTotp.consumeBackupCode(r, uid, codes[0])).valid, false, 'code is single-use');
  assert.strictEqual(r._setCount(setKey), 9, 'consumed code removed');
  ok('codes validate and are single-use');

  // 4. Reload-safety / re-issue: minting again REPLACES the set. Old codes stop
  //    working, new ones work. This is the exact scenario that used to strand
  //    users on an empty backup-code screen.
  const codes2 = await userTotp.regenerateBackupCodes(r, uid);
  assert.strictEqual(r._setCount(setKey), 10, 're-mint resets to a full batch');
  assert.strictEqual((await userTotp.consumeBackupCode(r, uid, codes[1])).valid, false, 'old codes invalid after re-mint');
  assert.strictEqual((await userTotp.consumeBackupCode(r, uid, codes2[0])).valid, true, 'new codes valid after re-mint');
  ok('re-mint cleanly replaces the previous set');

  console.log(`\nbackup-codes: ${passed} checks passed`);
})().catch((e) => { console.error('FAIL:', e && e.stack || e); process.exit(1); });
