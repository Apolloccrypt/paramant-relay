'use strict';
// Unit test for relay/lib/user-webauthn.js (ADR R018, PR-A): credential
// storage, user-handle minting/lookup, idempotent re-enroll, cross-account
// conflict, counter update, and revoke (index removal so revoked creds can no
// longer authenticate). Run: node relay/test/user-webauthn.test.js
// (no deps, non-zero exit on failure).

const assert = require('assert');
const wa = require('../lib/user-webauthn');

// ── in-memory redis double (get/set/del over a Map) ──
function fakeRedis() {
  const m = new Map();
  return {
    _m: m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async del(k) { return m.delete(k) ? 1 : 0; },
  };
}

const U1 = 'pgp_user_one';
const U2 = 'pgp_user_two';
const CRED = 'Y3JlZC1pZC1vbmU';   // base64url-ish
const PK = Buffer.from('cose-public-key-bytes').toString('base64url');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

async function main() {
  const r = fakeRedis();

  // user handle: mint once, stable, reverse-resolvable, no PII (not the userId)
  const h1 = await wa.getOrCreateUserHandle(r, U1);
  assert.ok(/^[A-Za-z0-9_-]{20,}$/.test(h1), 'handle is base64url');
  assert.notStrictEqual(h1, U1, 'handle is not the pgp_ user id');
  assert.strictEqual(await wa.getOrCreateUserHandle(r, U1), h1, 'handle is stable (idempotent)');
  assert.deepStrictEqual(await wa.lookupByHandle(r, h1), { userId: U1 }, 'handle resolves to user');
  assert.strictEqual(await wa.lookupByHandle(r, 'nonexistent'), null, 'unknown handle -> null');
  ok('user handle mint/lookup');

  // store credential
  const { entry, reenrolled } = await wa.storeCredential(r, U1, {
    credId: CRED, publicKey: PK, counter: 0, transports: ['internal'], prfSupported: true, aaguid: 'aaguid-x', label: 'MacBook',
  });
  assert.strictEqual(reenrolled, false, 'first store is a fresh enroll');
  assert.strictEqual(entry.prfSupported, true, 'prf flag persisted');
  assert.strictEqual((await wa.getActiveCredentials(r, U1)).length, 1, 'one active credential');
  assert.strictEqual(await wa.countActiveCredentials(r, U1), 1, 'count = 1 (for lockout guard)');
  ok('storeCredential new');

  // idempotent re-enroll updates counter/label, no duplicate
  const re = await wa.storeCredential(r, U1, { credId: CRED, publicKey: PK, counter: 5, label: 'MBP' });
  assert.strictEqual(re.reenrolled, true, 're-enroll detected');
  assert.strictEqual((await wa.getCredentials(r, U1)).length, 1, 'no duplicate entry');
  assert.strictEqual(re.entry.counter, 5, 'counter updated on re-enroll');
  ok('storeCredential idempotent re-enroll');

  // cross-account conflict: same credId for a different user is refused
  await assert.rejects(
    () => wa.storeCredential(r, U2, { credId: CRED, publicKey: PK }),
    /different account/, 'credId bound to another account is rejected');
  ok('storeCredential cross-account conflict');

  // lookup by credId resolves to user + entry
  const found = await wa.lookupByCredId(r, CRED);
  assert.ok(found && found.userId === U1 && found.entry.credId === CRED, 'lookupByCredId resolves');
  assert.strictEqual(await wa.lookupByCredId(r, 'unknown-cred'), null, 'unknown credId -> null');
  ok('lookupByCredId');

  // counter update persists + stamps last_used_at
  assert.strictEqual(await wa.updateCounter(r, U1, CRED, 9), true, 'updateCounter ok');
  assert.strictEqual((await wa.getCredentials(r, U1))[0].counter, 9, 'counter persisted');
  assert.ok((await wa.getCredentials(r, U1))[0].last_used_at, 'last_used_at stamped');
  ok('updateCounter');

  // revoke: history kept, but index removed so it can no longer authenticate
  const rev = await wa.revokeCredential(r, U1, CRED);
  assert.strictEqual(rev.revoked, true, 'revoke ok');
  assert.strictEqual(rev.remaining_active, 0, 'no active creds remain');
  assert.strictEqual(await wa.lookupByCredId(r, CRED), null, 'revoked cred no longer resolves for auth');
  assert.strictEqual((await wa.getCredentials(r, U1)).length, 1, 'history entry retained');
  assert.strictEqual(await wa.countActiveCredentials(r, U1), 0, 'active count back to 0');
  ok('revokeCredential removes auth path, keeps history');

  // re-enroll after revoke clears revoked_at and restores the index
  await wa.storeCredential(r, U1, { credId: CRED, publicKey: PK, counter: 0 });
  assert.ok(await wa.lookupByCredId(r, CRED), 're-enroll restores auth lookup');
  assert.strictEqual(await wa.countActiveCredentials(r, U1), 1, 'active again after re-enroll');
  ok('re-enroll after revoke');
}

main()
  .then(() => console.log(`\nuser-webauthn: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.message ? e.message : e); process.exit(1); });
