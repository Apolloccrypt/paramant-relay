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

// Decide which keys are over a limit. Returns a Set<key> of over-limit keys
// (keys NOT in the set are within limits). Two orthogonal dimensions, OR'd
// (decision F):
//   per-account  — within each account, active keys are sorted primary-first
//                  then created-asc (missing created = oldest), insertion-order
//                  tiebreak; those at index >= the account's plan cap are over.
//   relay-total  — self-host community only (edition !== 'licensed'): active
//                  keys beyond licenseMaxKeys in insertion order are over.
// Pure: reads the Maps, mutates nothing. `capForPlan(plan)` returns the numeric
// per-account cap (Infinity for uncapped plans).
function computeOverLimit(apiKeys, accounts, accountKeys, opts) {
  const { capForPlan, licenseMaxKeys = Infinity, edition = 'community' } = opts || {};
  const over = new Set();

  const order = new Map();
  let i = 0;
  for (const key of apiKeys.keys()) order.set(key, i++);

  for (const [accountId, keySet] of accountKeys) {
    const acct = accounts.get(accountId);
    const cap = capForPlan ? capForPlan(acct ? acct.plan : 'community') : Infinity;
    if (!(cap < Infinity)) continue;
    const active = [...keySet].filter((k) => { const v = apiKeys.get(k); return v && v.active !== false; });
    active.sort((a, b) => {
      const va = apiKeys.get(a), vb = apiKeys.get(b);
      const pa = va.is_primary ? 0 : 1, pb = vb.is_primary ? 0 : 1;
      if (pa !== pb) return pa - pb;
      const ca = va.created ? (Date.parse(va.created) || 0) : 0;
      const cb = vb.created ? (Date.parse(vb.created) || 0) : 0;
      if (ca !== cb) return ca - cb;
      return order.get(a) - order.get(b);
    });
    active.forEach((k, idx) => { if (idx >= cap) over.add(k); });
  }

  if (edition !== 'licensed' && licenseMaxKeys !== Infinity) {
    let n = 0;
    for (const [key, v] of apiKeys) {
      if (v.active === false) continue;
      n += 1;
      if (n > licenseMaxKeys) over.add(key);
    }
  }

  return over;
}

// Designate `key` as the primary api-key of account `accountId` (stap 4). Mutates
// the live Maps in place: promotes the chosen key (is_primary=true), demotes every
// other member of the account, and repoints accounts[accountId].primary_api_key.
// Pure w.r.t. I/O — the caller persists to users.json and reads no globals.
// Throws (caller maps to 4xx) when the key is unknown, inactive, or not a member
// of the account, so a mismatched account_id can never silently move a primary.
// Returns { previous, current } (previous may be null on a fresh account).
function designatePrimary(apiKeys, accounts, accountKeys, accountId, key) {
  const v = apiKeys.get(key);
  if (!v) { const e = new Error('key_not_found'); e.code = 'key_not_found'; throw e; }
  if (v.active === false) { const e = new Error('key_inactive'); e.code = 'key_inactive'; throw e; }
  const acctOf = v.account_id || key;
  if (acctOf !== accountId) { const e = new Error('key_account_mismatch'); e.code = 'key_account_mismatch'; throw e; }
  const members = accountKeys.get(accountId) || new Set([key]);
  const previous = (accounts.get(accountId) && accounts.get(accountId).primary_api_key) || null;
  for (const m of members) { const mv = apiKeys.get(m); if (mv) mv.is_primary = (m === key); }
  v.is_primary = true;
  if (!accounts.has(accountId)) {
    accounts.set(accountId, { account_id: accountId, plan: v.plan, email: v.email || '', primary_api_key: key, label: v.label || '' });
  } else {
    accounts.get(accountId).primary_api_key = key;
  }
  return { previous, current: key };
}

module.exports = { VALID_SCOPES, computeKid, parseAccountFields, assignKid, rebuildKeyIndexes, migrateUsersV2, computeOverLimit, designatePrimary };
