'use strict';
// Account-split, admin side (stap 3). One place decides which api-key the admin
// plane uses on a logged-in user's behalf, so the SESSION — not the raw user_id
// — is the source of truth for relay auth (X-Api-Key) and the /account/key
// reveal.
//
// Backward-compatible by construction (mirrors relay/lib/keys-table.js
// parseAccountFields): today a session's user_id IS the account's primary,
// re-revealable api-key (the 1:1 seed account_id == key), so every function here
// is behaviour-neutral right now. The point is the plumbing: once stap 5 mints
// sessions whose identity (account_id, eventually acct_…) differs from a usable
// api-key, these call sites already read primary_api_key and keep working,
// untouched.
//
// Distinction this module enforces:
//   • X-Api-Key (a relay AUTH credential)  -> must be a real api-key  -> proxyApiKey()
//   • user_id in a request BODY (an account IDENTIFIER, e.g. signing-key enrol)
//     stays user_id and is NOT routed through here.

// Fields a freshly-minted session carries. `key` is the api-key the user just
// authenticated with — its account's primary today. legacy_revealable mirrors
// the seeded-primary default (a seeded primary stays revealable until the user
// rotates it); stap 5 will pass the real per-key flag here.
function sessionKeyFields(key) {
  return { primary_api_key: key, legacy_revealable: true };
}

// The api-key the admin plane presents to a relay on this session's behalf
// (X-Api-Key). primary_api_key when the session carries it (stap 3+), else the
// legacy user_id so sessions minted before stap 3 keep authenticating.
function proxyApiKey(session) {
  if (!session) return null;
  return session.primary_api_key || session.user_id || null;
}

// The GET /account/key reveal decision. The raw key is returned ONLY when the
// account is legacy_revealable; a non-revealable key (a future acct_/non-primary
// key) yields no secret. A session without the field (minted before stap 3) is
// treated as revealable, so existing sessions still see their key.
function revealKey(session) {
  const revealable = !!session && session.legacy_revealable !== false;
  if (!revealable) return { api_key: null, revealable: false };
  return { api_key: proxyApiKey(session), revealable: true };
}

module.exports = { sessionKeyFields, proxyApiKey, revealKey };
