'use strict';
// Account-split schema helpers (stap 1: additive, behaviour-neutral).
//
// Today one string means three things: session.user_id == "pgp_..." ==
// apiKeys.get(key). This module introduces the additive account layer that
// lets account_id, primary_api_key and N per-account keys diverge later,
// WITHOUT changing current behaviour: for an existing key the defaults make
// account_id == the key itself (1:1), so every downstream lookup is identical.
//
// Pure module: no I/O, no globals. Unit-tested in test/keys-table.test.js.
const crypto = require('crypto');

// Scopes are reserved now (every key is "full"); the relay does not yet gate on
// them. Kept as an allow-list so the enum stays stable for a non-breaking
// future migration to composite grants.
const VALID_SCOPES = new Set(['full', 'send-only', 'sign-only', 'read-only']);

// Non-secret, stable key identifier for URLs/listings (never the raw pgp_ key).
// 48 bits of SHA3-free SHA-256 prefix: collision-safe well past 10M keys.
function computeKid(key) {
  return 'k_' + crypto.createHash('sha256').update(String(key)).digest('hex').slice(0, 12);
}

// Parse the additive account fields off a raw users.json key record, with
// backward-compatible defaults. A record with no explicit account_id is its own
// account (account_id = key), is its own primary, full scope, and — being a
// seeded primary — stays re-revealable until the user rotates it.
function parseAccountFields(rawKey) {
  const hasAccountId = rawKey.account_id != null && rawKey.account_id !== '';
  const account_id = hasAccountId ? rawKey.account_id : rawKey.key;
  const is_primary = (rawKey.is_primary !== undefined) ? !!rawKey.is_primary : !hasAccountId;
  const scope = VALID_SCOPES.has(rawKey.scope) ? rawKey.scope : 'full';
  const legacy_revealable = (rawKey.legacy_revealable !== undefined)
    ? !!rawKey.legacy_revealable
    : (!hasAccountId && is_primary);
  return { account_id, is_primary, scope, legacy_revealable };
}

// Pick a kid not already present in `taken` (anything with a .has(kid) method:
// the live kidIndex Map, or a Set in tests). On the astronomically-unlikely
// 48-bit prefix collision at LOAD time we cannot regenerate an existing key, so
// we suffix the kid and warn. (At CREATE time the caller regenerates the key
// instead — see assignKid usage notes; not wired in stap 1.)
function assignKid(taken, key, log) {
  const base = computeKid(key);
  if (!taken.has(base)) return base;
  let n = 1, alt = `${base}_${n}`;
  while (taken.has(alt) && n < 1000) { n += 1; alt = `${base}_${n}`; }
  if (log) log('warn', 'kid_collision', { kid: base, resolved: alt, key_prefix: String(key).slice(0, 8) });
  return alt;
}

// Full rebuild of the account/index Maps from the live apiKeys Map. Idempotent:
// clears and re-derives on every call (used after load, trial-load and the
// reload atomic swap). Each apiKeys value must already carry account_id/
// is_primary/scope (set via parseAccountFields at load). Assigns each value a
// stable `kid`. First-writer fills the account record; an explicit primary key
// always wins primary_api_key.
function rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex, log) {
  accounts.clear();
  accountKeys.clear();
  kidIndex.clear();
  for (const [key, v] of apiKeys) {
    const account_id = v.account_id || key;
    if (!accounts.has(account_id)) {
      accounts.set(account_id, { account_id, plan: v.plan, email: v.email || '', primary_api_key: null, label: v.label || '' });
    }
    const acct = accounts.get(account_id);
    if (v.is_primary || !acct.primary_api_key) acct.primary_api_key = v.is_primary ? key : (acct.primary_api_key || key);
    if (!accountKeys.has(account_id)) accountKeys.set(account_id, new Set());
    accountKeys.get(account_id).add(key);
    const kid = assignKid(kidIndex, key, log);
    v.kid = kid;
    kidIndex.set(kid, key);
  }
  return { accounts, accountKeys, kidIndex };
}

// users.json v1 -> v2 migration. Pure: returns a NEW object, never mutates the
// input. Idempotent: a v2 input (schema_version >= 2) is returned unchanged, so
// running it twice is a no-op. Seeds account_id = key for every existing key.
function migrateUsersV2(data) {
  if (!data || !Array.isArray(data.api_keys)) throw new Error('invalid users.json: missing api_keys array');
  if ((data.schema_version | 0) >= 2) return data;
  const accounts = {};
  const api_keys = data.api_keys.map((k) => {
    const fields = parseAccountFields(k);
    const a = accounts[fields.account_id]
      || (accounts[fields.account_id] = { account_id: fields.account_id, plan: k.plan, email: k.email || '', primary_api_key: null, label: k.label || '' });
    if (fields.is_primary || !a.primary_api_key) a.primary_api_key = fields.is_primary ? k.key : (a.primary_api_key || k.key);
    return { ...k, ...fields };
  });
  return { ...data, schema_version: 2, accounts, api_keys };
}

module.exports = { VALID_SCOPES, computeKid, parseAccountFields, assignKid, rebuildKeyIndexes, migrateUsersV2 };
