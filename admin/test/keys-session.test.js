'use strict';
// Account-split stap 3 (admin side): the session carries the account's primary
// api-key, and admin-side relay auth + the /account/key reveal read it instead
// of the raw user_id. Pure-logic unit test for admin/lib/account-keys.js.
// Run: node admin/test/keys-session.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const { sessionKeyFields, proxyApiKey, revealKey } = require('../lib/account-keys');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// ── 1. login → the minted session carries primary_api_key ──────────────────────
// Every session-write site embeds sessionKeyFields(<authenticating key>). Today
// that key IS the account's primary, revealable api-key (1:1 seed), so the
// fields are behaviour-neutral.
assert.deepStrictEqual(
  sessionKeyFields('pgp_alice'),
  { primary_api_key: 'pgp_alice', legacy_revealable: true },
  'session carries primary_api_key + legacy_revealable');
ok('login: session carries primary_api_key (== user_id today)');

// A realistic minted session: user_id + the stap-3 fields spread in, exactly as
// the JSON.stringify call sites build it.
const freshSession = { user_id: 'pgp_alice', email: 'a@b.com', ...sessionKeyFields('pgp_alice') };
assert.strictEqual(freshSession.primary_api_key, 'pgp_alice', 'primary mirrors user_id at mint');
assert.strictEqual(freshSession.legacy_revealable, true, 'fresh session is revealable');
ok('login: minted session shape is correct');

// ── 2. GET /account/key returns the primary key, honouring legacy_revealable ────
assert.deepStrictEqual(
  revealKey(freshSession),
  { api_key: 'pgp_alice', revealable: true },
  'revealable session reveals the primary key');
ok('/account/key: reveals primary key for a revealable account');

// A session minted BEFORE stap 3 has no primary_api_key/legacy_revealable: must
// still reveal, falling back to user_id (no forced re-login).
assert.deepStrictEqual(
  revealKey({ user_id: 'pgp_legacy', email: 'l@b.com' }),
  { api_key: 'pgp_legacy', revealable: true },
  'pre-stap3 session falls back to user_id and stays revealable');
ok('/account/key: legacy session falls back to user_id');

// A non-revealable account (future acct_/non-primary key) yields no secret.
assert.deepStrictEqual(
  revealKey({ user_id: 'acct_bob', primary_api_key: 'pgp_bob', legacy_revealable: false }),
  { api_key: null, revealable: false },
  'non-revealable account returns no raw key');
ok('/account/key: non-revealable account is refused (no secret leak)');

// Null/garbage session never throws and never leaks.
assert.deepStrictEqual(revealKey(null), { api_key: null, revealable: false }, 'null session => no key');
assert.deepStrictEqual(revealKey(undefined), { api_key: null, revealable: false }, 'undefined session => no key');
ok('/account/key: null/undefined session is safe');

// ── 3. sector-proxy authenticates with the session's api-key (X-Api-Key) ────────
assert.strictEqual(proxyApiKey(freshSession), 'pgp_alice', 'proxy uses primary_api_key');
assert.strictEqual(
  proxyApiKey({ user_id: 'pgp_legacy' }), 'pgp_legacy',
  'pre-stap3 session falls back to user_id so the proxy keeps authenticating');
assert.strictEqual(proxyApiKey(null), null, 'null session => null (caller/relay rejects)');
assert.strictEqual(proxyApiKey({}), null, 'empty session => null');
ok('sector-proxy: X-Api-Key = primary_api_key || user_id');

// ── 4. the WHOLE point — stap 5 divergence: identity != usable api-key ──────────
// Once a session's user_id becomes an account id (acct_…) that the relay will
// NOT accept as an api-key, the proxy and the reveal must use primary_api_key.
// These assertions prove the call sites are already correct for that future.
const stap5Session = { user_id: 'acct_carol', primary_api_key: 'pgp_carol_real', legacy_revealable: true };
assert.strictEqual(proxyApiKey(stap5Session), 'pgp_carol_real',
  'proxy sends the real api-key, NOT the acct_ identity');
assert.notStrictEqual(proxyApiKey(stap5Session), stap5Session.user_id,
  'proxy must not send acct_ as X-Api-Key');
assert.deepStrictEqual(revealKey(stap5Session), { api_key: 'pgp_carol_real', revealable: true },
  'reveal returns the real api-key, not the acct_ identity');
ok('stap5-ready: identity (acct_) and api-key diverge cleanly');

console.log(`\nkeys-session: ${passed} groups passed`);
