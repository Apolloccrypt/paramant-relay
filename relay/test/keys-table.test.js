'use strict';
// Unit tests for the additive account-split schema (stap 1). Pure: imports the
// helper module only, never starts the relay server.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const kt = require('../lib/keys-table');

test('computeKid is deterministic and well-formed', () => {
  const a = kt.computeKid('pgp_deadbeef');
  assert.equal(a, kt.computeKid('pgp_deadbeef'));            // deterministic
  assert.match(a, /^k_[0-9a-f]{12}$/);                       // k_ + 48-bit hex
  assert.notEqual(a, kt.computeKid('pgp_other'));            // distinct inputs differ
});

test('parseAccountFields: v1 record (no account_id) is its own account+primary', () => {
  const f = kt.parseAccountFields({ key: 'pgp_seed', plan: 'community', email: 'a@b.c', active: true });
  assert.equal(f.account_id, 'pgp_seed');     // 1:1 — the behaviour-neutral guarantee
  assert.equal(f.is_primary, true);
  assert.equal(f.scope, 'full');
  assert.equal(f.legacy_revealable, true);    // seed primary stays re-revealable until rotated
});

test('parseAccountFields: v2 record preserves explicit fields', () => {
  const f = kt.parseAccountFields({ key: 'pgp_x', account_id: 'acct_1', is_primary: false, scope: 'send-only' });
  assert.equal(f.account_id, 'acct_1');
  assert.equal(f.is_primary, false);
  assert.equal(f.scope, 'send-only');
  assert.equal(f.legacy_revealable, false);   // not a seeded primary
});

test('parseAccountFields: unknown scope falls back to full', () => {
  assert.equal(kt.parseAccountFields({ key: 'pgp_x', scope: 'root' }).scope, 'full');
  assert.equal(kt.parseAccountFields({ key: 'pgp_x', scope: '' }).scope, 'full');
});

test('assignKid: no collision returns the base kid', () => {
  const kid = kt.assignKid(new Set(), 'pgp_a');
  assert.equal(kid, kt.computeKid('pgp_a'));
});

test('assignKid: collision suffixes and warns (load-time, never regenerates the key)', () => {
  const base = kt.computeKid('pgp_a');
  const events = [];
  const kid = kt.assignKid(new Set([base]), 'pgp_a', (lvl, ev, data) => events.push([lvl, ev, data]));
  assert.equal(kid, base + '_1');
  assert.equal(events.length, 1);
  assert.equal(events[0][1], 'kid_collision');
});

test('rebuildKeyIndexes: groups keys per account, resolves primary, indexes kids', () => {
  const apiKeys = new Map();
  const set = (key, raw) => apiKeys.set(key, { plan: raw.plan || 'community', label: raw.label || '', email: raw.email || '', active: true, ...kt.parseAccountFields({ ...raw, key }) });
  set('pgp_primary', { account_id: 'acct_1', is_primary: true, plan: 'pro', email: 'a@b.c' });
  set('pgp_second',  { account_id: 'acct_1', is_primary: false });
  set('pgp_solo',    {});                                   // v1-style: its own account

  const accounts = new Map(), accountKeys = new Map(), kidIndex = new Map();
  kt.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex);

  assert.equal(accounts.get('acct_1').primary_api_key, 'pgp_primary');
  assert.deepEqual([...accountKeys.get('acct_1')].sort(), ['pgp_primary', 'pgp_second']);
  assert.equal(accounts.get('pgp_solo').primary_api_key, 'pgp_solo');
  assert.equal(kidIndex.size, 3);                          // bijective: one kid per key
  assert.equal(kidIndex.get(apiKeys.get('pgp_solo').kid), 'pgp_solo');
  assert.equal(apiKeys.get('pgp_primary').kid, kt.computeKid('pgp_primary'));
});

test('rebuildKeyIndexes is idempotent (safe on reload)', () => {
  const apiKeys = new Map([
    ['pgp_a', { plan: 'community', ...kt.parseAccountFields({ key: 'pgp_a' }) }],
    ['pgp_b', { plan: 'community', ...kt.parseAccountFields({ key: 'pgp_b' }) }],
  ]);
  const accounts = new Map(), accountKeys = new Map(), kidIndex = new Map();
  kt.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex);
  const firstKids = [...kidIndex.keys()].sort();
  kt.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex);   // run again
  assert.equal(accounts.size, 2);
  assert.equal(kidIndex.size, 2);
  assert.deepEqual([...kidIndex.keys()].sort(), firstKids);
});

test('migrateUsersV2: v1 -> v2, additive, original fields preserved, input not mutated', () => {
  const v1 = { api_keys: [{ key: 'pgp_a', plan: 'community', label: 'Alice', email: 'a@b.c', active: true }] };
  const v2 = kt.migrateUsersV2(v1);
  assert.equal(v2.schema_version, 2);
  assert.equal(v2.api_keys[0].account_id, 'pgp_a');
  assert.equal(v2.api_keys[0].is_primary, true);
  assert.equal(v2.api_keys[0].scope, 'full');
  assert.equal(v2.api_keys[0].legacy_revealable, true);
  assert.equal(v2.api_keys[0].plan, 'community');          // original preserved
  assert.equal(v2.api_keys[0].label, 'Alice');
  assert.equal(v2.accounts['pgp_a'].primary_api_key, 'pgp_a');
  assert.equal(v1.api_keys[0].account_id, undefined);      // pure: input untouched
  assert.equal(v1.schema_version, undefined);
});

test('migrateUsersV2 is idempotent (second run is a no-op)', () => {
  const v1 = { api_keys: [{ key: 'pgp_a', plan: 'pro', active: true }] };
  const once = kt.migrateUsersV2(v1);
  const twice = kt.migrateUsersV2(once);
  assert.deepEqual(twice, once);
  assert.equal(twice.schema_version, 2);
});

test('migrateUsersV2 rejects malformed input', () => {
  assert.throws(() => kt.migrateUsersV2({}), /missing api_keys/);
  assert.throws(() => kt.migrateUsersV2(null), /missing api_keys/);
});

test('integration: migrate v1 file -> load -> rebuild produces consistent indexes', () => {
  const v1 = { api_keys: [
    { key: 'pgp_alice', plan: 'pro', email: 'alice@x.io', active: true },
    { key: 'pgp_bob',   plan: 'community', email: 'bob@x.io', active: true },
  ] };
  const v2 = kt.migrateUsersV2(v1);

  // simulate loadUsers: apiKeys carries the parsed fields
  const apiKeys = new Map();
  for (const k of v2.api_keys) apiKeys.set(k.key, { plan: k.plan, email: k.email, active: true, ...kt.parseAccountFields(k) });
  const accounts = new Map(), accountKeys = new Map(), kidIndex = new Map();
  kt.rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex);

  assert.equal(accounts.size, 2);                          // each key is its own account (1:1)
  assert.equal(accounts.get('pgp_alice').primary_api_key, 'pgp_alice');
  assert.equal(kidIndex.size, 2);
  assert.equal(apiKeys.get('pgp_bob').account_id, 'pgp_bob');
});
