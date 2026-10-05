'use strict';
// Unit tests for the per-account cap decision (stap 2). Pure: imports the
// computeOverLimit helper only, never starts the relay server.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { computeOverLimit } = require('../lib/keys-table');

// cap config used in tests: community 5, pro/enterprise uncapped.
const CAP = (p) => ({ community: 5, pro: Infinity, enterprise: Infinity })[p] ?? 5;

// Build the three Maps computeOverLimit reads from a flat row list.
function build(rows) {
  const apiKeys = new Map(), accounts = new Map(), accountKeys = new Map();
  for (const r of rows) {
    const aid = r.account_id || r.key;
    apiKeys.set(r.key, { account_id: aid, is_primary: !!r.is_primary, plan: r.plan || 'community', created: r.created || null, active: r.active !== false });
    if (!accounts.has(aid)) accounts.set(aid, { account_id: aid, plan: r.plan || 'community', primary_api_key: null });
    if (r.is_primary) accounts.get(aid).primary_api_key = r.key;
    if (!accountKeys.has(aid)) accountKeys.set(aid, new Set());
    accountKeys.get(aid).add(r.key);
  }
  return { apiKeys, accounts, accountKeys };
}
const run = (rows, opts = {}) => {
  const { apiKeys, accounts, accountKeys } = build(rows);
  return computeOverLimit(apiKeys, accounts, accountKeys, { capForPlan: CAP, licenseMaxKeys: Infinity, edition: 'licensed', ...opts });
};

test('account under cap: nothing over', () => {
  const rows = Array.from({ length: 4 }, (_, i) => ({ key: 'k' + i, account_id: 'a', is_primary: i === 0 }));
  assert.equal(run(rows).size, 0);
});

test('account exactly at cap (5): nothing over', () => {
  const rows = Array.from({ length: 5 }, (_, i) => ({ key: 'k' + i, account_id: 'a', is_primary: i === 0 }));
  assert.equal(run(rows).size, 0);
});

test('account over cap (6 keys, cap 5): exactly the 6th is over, primary safe', () => {
  const rows = Array.from({ length: 6 }, (_, i) => ({ key: 'k' + i, account_id: 'a', is_primary: i === 0, created: '2026-05-0' + (i + 1) + 'T00:00:00Z' }));
  const over = run(rows);
  assert.equal(over.size, 1);
  assert.ok(over.has('k5'));        // newest non-primary
  assert.ok(!over.has('k0'));       // primary never over
});

test('grandfather: 8 keys cap 5 -> 3 over (flag, not delete)', () => {
  const rows = Array.from({ length: 8 }, (_, i) => ({ key: 'k' + i, account_id: 'a', is_primary: i === 0, created: '2026-05-0' + (i + 1) + 'T00:00:00Z' }));
  const { apiKeys, accounts, accountKeys } = build(rows);
  const over = computeOverLimit(apiKeys, accounts, accountKeys, { capForPlan: CAP, edition: 'licensed' });
  assert.deepEqual([...over].sort(), ['k5', 'k6', 'k7']);   // newest 3 over
  assert.equal(apiKeys.size, 8);                            // nothing removed — flag only
});

test('sort: primary stays even when it is the newest; oldest non-primary survives', () => {
  // cap 1: only one key may stand. primary must be it, even though it is newest.
  const rows = [
    { key: 'old', account_id: 'a', is_primary: false, created: '2026-01-01T00:00:00Z' },
    { key: 'mid', account_id: 'a', is_primary: false, created: '2026-02-01T00:00:00Z' },
    { key: 'prim', account_id: 'a', is_primary: true, created: '2026-03-01T00:00:00Z' },
  ];
  const over = computeOverLimit(...Object.values(build(rows)), { capForPlan: () => 1, edition: 'licensed' });
  assert.ok(!over.has('prim'));            // primary first -> within cap
  assert.deepEqual([...over].sort(), ['mid', 'old']);
});

test('relay-total OR (self-host community): 3 accounts x 5 keys, licenseMax 5 -> keys 6..15 over', () => {
  const rows = [];
  for (let a = 0; a < 3; a++) for (let i = 0; i < 5; i++) rows.push({ key: `a${a}k${i}`, account_id: 'acc' + a, is_primary: i === 0 });
  const over = run(rows, { licenseMaxKeys: 5, edition: 'community' });
  assert.equal(over.size, 10);             // first 5 (global insertion order) survive, rest over
  assert.ok(!over.has('a0k0') && !over.has('a0k4'));   // first account's 5 are within the relay cap
  assert.ok(over.has('a1k0') && over.has('a2k4'));     // keys 6..15 over
});

test('licensed edition: relay-total cap does not apply, only per-account', () => {
  const rows = [];
  for (let a = 0; a < 3; a++) for (let i = 0; i < 5; i++) rows.push({ key: `a${a}k${i}`, account_id: 'acc' + a, is_primary: i === 0 });
  const over = run(rows, { licenseMaxKeys: 5, edition: 'licensed' });
  assert.equal(over.size, 0);              // each account at cap 5, relay term off
});

test('plan-switch: pro (uncapped) 8 keys -> none; same account on community(5) -> 3 over', () => {
  const mk = (plan) => Array.from({ length: 8 }, (_, i) => ({ key: 'k' + i, account_id: 'a', plan, is_primary: i === 0, created: '2026-05-0' + (i + 1) + 'T00:00:00Z' }));
  assert.equal(run(mk('pro')).size, 0);
  assert.equal(run(mk('community')).size, 3);
});

test('inactive keys are ignored in the count', () => {
  const rows = Array.from({ length: 7 }, (_, i) => ({ key: 'k' + i, account_id: 'a', is_primary: i === 0, active: i < 5, created: '2026-05-0' + (i + 1) + 'T00:00:00Z' }));
  // only 5 active -> at cap -> nothing over
  assert.equal(run(rows).size, 0);
});
