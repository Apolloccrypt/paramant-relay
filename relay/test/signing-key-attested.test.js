'use strict';
// Unit test for the invariants behind the TOTP-free, passkey-attested signing-
// key bind (relay POST /v2/user/signing-key/attested — the "your sign-in passkey
// IS your signing key" path). The route itself is thin HTTP glue; its SECURITY
// rests on lib-level invariants, asserted here against the same in-memory redis
// double the other relay tests use:
//   1. GATE — countActiveCredentials(user) is the passkey gate: 0 for a fresh
//      account (route -> 403 no_passkey_enrolled), >=1 once a passkey exists.
//      This is what stops a TOTP-less, passkey-less account from ever reaching a
//      TOTP-free bind.
//   2. BIND — after the gate, storeSigningPk enrols the pubkey and it shows up
//      active (the happy path the route returns), and re-binding is idempotent.
//   3. CONFLICT — storeSigningPk still refuses a pubkey already bound to another
//      account, so the attested path cannot graft a key onto someone else.
// Run: node relay/test/signing-key-attested.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const wa = require('../lib/user-webauthn');
const us = require('../lib/user-signing');

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
// A valid ML-DSA-65 public key is exactly 1952 bytes (FIPS 204); storeSigningPk
// validates the length, so the test keys must be exactly that size.
const PK1 = Buffer.alloc(us.ML_DSA_65_PK_LEN, 7).toString('base64');
const PK2 = Buffer.alloc(us.ML_DSA_65_PK_LEN, 9).toString('base64');
const CRED = 'Y3JlZC1pZC1hdHRlc3RlZA';   // base64url-ish

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

async function main() {
  const r = fakeRedis();

  // 1. GATE — a fresh account has no passkey, so the attested route would 403.
  assert.strictEqual(await wa.countActiveCredentials(r, U1), 0, 'fresh account: 0 passkeys -> attested bind refused');
  ok('gate: no passkey -> count 0 (route 403 no_passkey_enrolled)');

  // After registering a passkey, the gate opens (count >= 1).
  await wa.storeCredential(r, U1, { credId: CRED, publicKey: Buffer.from('cose').toString('base64url'), counter: 0, prfSupported: true });
  assert.strictEqual(await wa.countActiveCredentials(r, U1), 1, 'with a passkey -> attested bind allowed');
  ok('gate: passkey present -> count 1 (route proceeds)');

  // 2. BIND — the happy path the route runs after the gate + step-up verify.
  const res = await us.storeSigningPk(r, U1, { pk_b64: PK1, label: 'iPhone' });
  assert.ok(res && res.entry && /^[0-9a-f]{64}$/.test(res.entry.pk_hash_sha3), 'server computes a 64-hex pk_hash');
  assert.strictEqual(res.reenrolled, false, 'first bind is a fresh enroll');
  const active = await us.getActiveSigningPks(r, U1);
  assert.strictEqual(active.length, 1, 'the bound pubkey is active');
  assert.strictEqual(active[0].pk_b64, PK1, 'the active key is the one we bound');
  ok('bind: attested enroll stores the pubkey active');

  // Idempotent re-bind (same pk, same user) — matches the route's reenrolled:true
  // response when a device re-runs the one-tap setup.
  const again = await us.storeSigningPk(r, U1, { pk_b64: PK1, label: 'iPhone' });
  assert.strictEqual(again.reenrolled, true, 're-binding the same pubkey is idempotent');
  assert.strictEqual((await us.getActiveSigningPks(r, U1)).length, 1, 'no duplicate entry on re-bind');
  ok('bind: idempotent re-enroll');

  // 3. CONFLICT — a pubkey already bound to U1 cannot be attested onto U2, so the
  //    attested path can never graft someone else's key onto another account.
  await wa.storeCredential(r, U2, { credId: 'b3RoZXItY3JlZA', publicKey: Buffer.from('cose2').toString('base64url'), counter: 0, prfSupported: true });
  await assert.rejects(
    () => us.storeSigningPk(r, U2, { pk_b64: PK1, label: 'theft' }),
    /already enrolled to a different account/,
    'cross-account pubkey conflict is refused',
  );
  ok('conflict: cross-account pubkey bind refused');

  // A different pubkey for U2 is fine (independent accounts, independent keys).
  await us.storeSigningPk(r, U2, { pk_b64: PK2, label: 'ok' });
  assert.strictEqual((await us.getActiveSigningPks(r, U2)).length, 1, 'U2 binds its own distinct key');
  ok('conflict: distinct key per account allowed');

  console.log(`\n${passed} checks passed.`);
}

main().catch((e) => { console.error('FAIL:', (e && e.stack) || e); process.exit(1); });
