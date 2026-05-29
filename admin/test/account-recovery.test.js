'use strict';
// Lockout-prevention guard tests (ADR R018, mandatory gate before PR-A).
// Run: node admin/test/account-recovery.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const {
  loginFactorCount, emailRecoverable, assertNotLockedOut, assertCanRemoveFactor,
} = require('../lib/account-recovery');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };
const throwsCode = (fn, code, msg) => {
  assert.throws(fn, (e) => e && e.code === code, msg + ' (expected code ' + code + ')');
};

// loginFactorCount
assert.strictEqual(loginFactorCount({ totp: true }), 1, 'totp = 1');
assert.strictEqual(loginFactorCount({ backupCodes: 3 }), 1, 'backup codes = 1 factor');
assert.strictEqual(loginFactorCount({ backupCodes: 0 }), 0, 'no backup codes = 0');
assert.strictEqual(loginFactorCount({ passkeys: 2 }), 2, 'two passkeys = 2');
assert.strictEqual(loginFactorCount({ totp: true, passkeys: 1, backupCodes: 5 }), 3, 'sum of factors');
assert.strictEqual(loginFactorCount(null), 0, 'null account = 0');
ok('loginFactorCount');

// emailRecoverable
assert.strictEqual(emailRecoverable({ email: 'a@b.com' }), true, 'email present');
assert.strictEqual(emailRecoverable({}), false, 'no email');
ok('emailRecoverable');

// assertNotLockedOut
assert.strictEqual(assertNotLockedOut({ passkeys: 1 }, 'op'), true, 'one factor is safe');
assert.strictEqual(assertNotLockedOut({ email: 'a@b.com' }, 'op'), true, '0 factors but email recoverable');
throwsCode(() => assertNotLockedOut({ passkeys: 0 }, 'wipe'), 'lockout_no_factor', '0 factors + no email is a lockout');
ok('assertNotLockedOut');

// assertCanRemoveFactor — removing a non-last factor is always fine
assert.strictEqual(
  assertCanRemoveFactor({ totp: true }, 'passkey'),
  true, 'removing a passkey while TOTP remains is fine');
ok('assertCanRemoveFactor: other factors remain');

// removing the LAST factor with no email = hard lockout
throwsCode(
  () => assertCanRemoveFactor({ /* nothing left */ email: '' }, 'totp'),
  'lockout_last_factor', 'last factor + no email');
ok('assertCanRemoveFactor: last factor, no email');

// removing the last TOTP, email present -> OK (email reset restores TOTP)
assert.strictEqual(
  assertCanRemoveFactor({ email: 'a@b.com' }, 'totp'),
  true, 'last TOTP with email recovery is allowed');
ok('assertCanRemoveFactor: last TOTP recoverable by email');

// removing the last PASSKEY, email present but reset cannot re-enrol -> refused
throwsCode(
  () => assertCanRemoveFactor({ email: 'a@b.com' }, 'passkey', { emailResetCanEnrolPasskey: false }),
  'lockout_passkey_only_no_reenrol', 'passkey-only with no re-enrol path');
ok('assertCanRemoveFactor: last passkey blocked without re-enrol path');

// ...same, but once the email reset flow can enrol a passkey -> allowed
assert.strictEqual(
  assertCanRemoveFactor({ email: 'a@b.com' }, 'passkey', { emailResetCanEnrolPasskey: true }),
  true, 'last passkey allowed once email reset can re-enrol a passkey');
ok('assertCanRemoveFactor: last passkey allowed with re-enrol path');

console.log(`\naccount-recovery: ${passed} checks passed`);
