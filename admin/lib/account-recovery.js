'use strict';
// Lockout-prevention guard — mandatory gate before the WebAuthn/passkey work
// (ADR R018). The invariant: no interactive operation may strand a user such
// that they can never sign in again. PR-A (passkey login) and PR-B (PRF vault)
// MUST route their factor-mutating operations through these checks.
//
// An account's independent *login* factors:
//   - totp        : authenticator TOTP is active
//   - backupCodes : count of unused backup codes (>=1 counts as a factor)
//   - passkeys    : count of registered WebAuthn credentials
//
// Plus a *recovery channel*:
//   - email       : the account's verified email. The /auth reset flow can
//                   restore access through it. CRITICAL: for a passkey-only
//                   account that reset flow must be able to enrol a FRESH
//                   passkey (not merely reset TOTP) -- otherwise a lost device
//                   is terminal. That capability is signalled per-call by
//                   `emailResetCanEnrolPasskey` and is a PR-A acceptance
//                   criterion. Until it is true, removing the last passkey from
//                   a passkey-only account is refused.

function loginFactorCount(account) {
  const a = account || {};
  return (a.totp ? 1 : 0)
       + ((a.backupCodes | 0) > 0 ? 1 : 0)
       + Math.max(0, a.passkeys | 0);
}

function emailRecoverable(account) {
  return !!(account && account.email);
}

// Assert the account state (AFTER an operation has been applied) is not a
// lockout: it must retain at least one login factor, or an email recovery
// channel through which access can be re-established. Throws on violation.
function assertNotLockedOut(accountAfter, opLabel) {
  if (loginFactorCount(accountAfter) === 0 && !emailRecoverable(accountAfter)) {
    const e = new Error('lockout_no_factor');
    e.code = 'lockout_no_factor';
    e.opLabel = opLabel || null;
    throw e;
  }
  return true;
}

// Guard an interactive "remove this factor" operation. `accountAfter` is the
// projected account state once `factor` ('passkey' | 'totp' | 'backupCodes')
// is removed. Refuses to remove the LAST login factor unless email recovery
// remains AND, for the last passkey specifically, the email reset flow can
// re-enrol a passkey.
function assertCanRemoveFactor(accountAfter, factor, opts = {}) {
  if (loginFactorCount(accountAfter) > 0) return true;   // other factors remain
  if (!emailRecoverable(accountAfter)) {
    const e = new Error('lockout_last_factor');
    e.code = 'lockout_last_factor';
    e.factor = factor;
    throw e;
  }
  if (factor === 'passkey' && !opts.emailResetCanEnrolPasskey) {
    const e = new Error('lockout_passkey_only_no_reenrol');
    e.code = 'lockout_passkey_only_no_reenrol';
    e.factor = factor;
    throw e;
  }
  return true;   // 0 factors but email-recoverable for this class
}

module.exports = {
  loginFactorCount,
  emailRecoverable,
  assertNotLockedOut,
  assertCanRemoveFactor,
};
