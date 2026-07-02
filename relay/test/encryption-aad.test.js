'use strict';
// AAD-binding tests — proves the fail-closed fix: an AAD-bound (v2) secret can
// NEVER be decrypted under a different AAD, so a Redis-write attacker cannot lift
// user A's encrypted secret into user B's context. Legacy pre-AAD blobs (no v2
// prefix) stay decryptable for migration.

const { test } = require('node:test');
const assert = require('assert');

// 32-byte master key (base64) for the test process.
process.env.PARAMANT_TOTP_MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
const { encryptSecret, decryptSecret } = require('../lib/encryption');

test('aad-bound blob round-trips under the same aad', () => {
  const blob = encryptSecret('super-secret-totp', 'user:alice');
  assert.ok(blob.startsWith('v2:'), 'aad-bound blob carries v2 prefix');
  assert.strictEqual(decryptSecret(blob, 'user:alice'), 'super-secret-totp');
});

test('aad-bound blob FAILS CLOSED under a different aad (no unbound fallback)', () => {
  const blob = encryptSecret('alice-secret', 'user:alice');
  assert.throws(
    () => decryptSecret(blob, 'user:bob'),
    'lifting alice\'s v2 blob into bob\'s context must throw, not silently decrypt',
  );
});

test('aad-bound blob cannot be downgraded to unbound decryption', () => {
  const blob = encryptSecret('alice-secret', 'user:alice');
  assert.throws(() => decryptSecret(blob, undefined),
    'a v2 blob decrypted with no aad must throw');
});

test('legacy pre-aad blob (no v2 prefix) still decrypts, incl. unbound retry', () => {
  const legacy = encryptSecret('legacy-secret'); // no aad -> no prefix
  assert.ok(!legacy.startsWith('v2:'), 'unbound blob has no prefix');
  assert.strictEqual(decryptSecret(legacy), 'legacy-secret');
  // A caller that now passes aad against an old unbound blob still recovers it.
  assert.strictEqual(decryptSecret(legacy, 'user:alice'), 'legacy-secret');
});

test('malformed input throws', () => {
  assert.throws(() => decryptSecret('not-a-blob', 'x'));
  assert.throws(() => decryptSecret('v2:only:two', 'x'));
});
