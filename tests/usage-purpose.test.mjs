// Usage-purpose survey lib (relay/lib/usage-purpose.js) - the store behind
// POST /v2/user/usage-purpose. Dependency-injected pure units (no redis, no
// relay boot; same style as the sibling parasign lib tests).
//
// Covered:
//   * invalid / missing purpose -> 400, nothing stored
//   * unknown or revoked key    -> 404
//   * valid answer -> 200, in-memory record + users.json mutation get
//     usage_purpose + ISO timestamp
//   * 'skipped' is a first-class persisted value
//   * DOCUMENTED POLICY: a second answer OVERWRITES the first (last answer
//     wins; the dashboard only asks while the field is empty)
//   * users.json round-trip: keys-table parseAccountFields rehydrates the
//     field on relay reload
//
// NOT covered here (needs a booted relay + admin, reported honestly in the
// PR notes): the X-Internal-Auth gate on the relay endpoint and the cookie
// authUser gate on the admin proxy. Both reuse the exact gates of the
// existing /v2/user/* TOTP endpoints.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import usagePurpose from '../relay/lib/usage-purpose.js';
import keysTable from '../relay/lib/keys-table.js';

const KEY = 'pgp_' + 'ab'.repeat(16);

function makeDeps() {
  const apiKeys = new Map([[KEY, { plan: 'community', email: 'x@example.com', active: true, account_id: KEY }]]);
  const usersJson = { api_keys: [{ key: KEY, plan: 'community', email: 'x@example.com', active: true }] };
  const mutations = [];
  const mutateUsersJson = (fn) => { mutations.push(fn); fn(usersJson); return Promise.resolve(); };
  return { apiKeys, usersJson, mutations, deps: { apiKeys, mutateUsersJson, now: () => 1752994800000 } };
}

test('rejects an invalid purpose with 400 and stores nothing', () => {
  const { deps, apiKeys, mutations } = makeDeps();
  for (const bad of ['world_domination', '', null, undefined, 42]) {
    const out = usagePurpose.setUsagePurpose(deps, KEY, bad);
    assert.equal(out.status, 400);
    assert.equal(out.body.error, 'invalid_purpose');
  }
  assert.equal(apiKeys.get(KEY).usage_purpose, undefined);
  assert.equal(mutations.length, 0);
});

test('rejects a missing or unknown user', () => {
  const { deps } = makeDeps();
  assert.equal(usagePurpose.setUsagePurpose(deps, '', 'personal').status, 400);
  assert.equal(usagePurpose.setUsagePurpose(deps, 'pgp_' + 'ff'.repeat(16), 'personal').status, 404);
});

test('rejects a revoked key with 404', () => {
  const { deps, apiKeys } = makeDeps();
  apiKeys.get(KEY).active = false;
  assert.equal(usagePurpose.setUsagePurpose(deps, KEY, 'personal').status, 404);
});

test('stores a valid answer in memory AND in users.json with an ISO timestamp', () => {
  const { deps, apiKeys, usersJson } = makeDeps();
  const out = usagePurpose.setUsagePurpose(deps, KEY, 'organisation');
  assert.equal(out.status, 200);
  assert.equal(out.body.ok, true);
  assert.equal(out.body.usage_purpose, 'organisation');
  assert.match(out.body.usage_purpose_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  // in-memory record (feeds GET /v2/admin/keys and the admin users view)
  assert.equal(apiKeys.get(KEY).usage_purpose, 'organisation');
  assert.equal(apiKeys.get(KEY).usage_purpose_at, out.body.usage_purpose_at);
  // persisted users.json entry
  const entry = usersJson.api_keys.find((k) => k.key === KEY);
  assert.equal(entry.usage_purpose, 'organisation');
  assert.equal(entry.usage_purpose_at, out.body.usage_purpose_at);
  assert.ok(usersJson.updated);
});

test("'skipped' persists like an answer so the question never returns", () => {
  const { deps, apiKeys } = makeDeps();
  const out = usagePurpose.setUsagePurpose(deps, KEY, 'skipped');
  assert.equal(out.status, 200);
  assert.equal(apiKeys.get(KEY).usage_purpose, 'skipped');
});

test('policy: a second answer overwrites the first (last answer wins)', () => {
  const { deps, apiKeys, usersJson } = makeDeps();
  assert.equal(usagePurpose.setUsagePurpose(deps, KEY, 'personal').status, 200);
  const out2 = usagePurpose.setUsagePurpose(deps, KEY, 'organisation');
  assert.equal(out2.status, 200);
  assert.equal(apiKeys.get(KEY).usage_purpose, 'organisation');
  assert.equal(usersJson.api_keys[0].usage_purpose, 'organisation');
});

test('every VALID_PURPOSES value is accepted (allowlist and UI stay in sync)', () => {
  for (const p of usagePurpose.VALID_PURPOSES) {
    const { deps } = makeDeps();
    assert.equal(usagePurpose.setUsagePurpose(deps, KEY, p).status, 200, p);
  }
});

test('users.json round-trip: parseAccountFields rehydrates usage_purpose on reload', () => {
  const raw = {
    key: KEY, plan: 'community', active: true,
    usage_purpose: 'client_management', usage_purpose_at: '2026-07-20T08:00:00.000Z',
  };
  const fields = keysTable.parseAccountFields(raw);
  assert.equal(fields.usage_purpose, 'client_management');
  assert.equal(fields.usage_purpose_at, '2026-07-20T08:00:00.000Z');
  // absent on legacy entries -> null, not undefined (stable admin JSON shape)
  const legacy = keysTable.parseAccountFields({ key: KEY, plan: 'community' });
  assert.equal(legacy.usage_purpose, null);
  assert.equal(legacy.usage_purpose_at, null);
});
