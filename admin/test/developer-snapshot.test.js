'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { buildSnapshot, maskKey, ymKey } = require('../lib/developer-snapshot');
const { DEVELOPER_TOOLS, toolsStatusFromAudit, isToolEvent } = require('../lib/developer-tools');

// The relay's entitlement layer, the one source for every tier number. The
// admin image does not ship it (its Dockerfile copies server.js, lib/ and
// public/ and nothing else), which is precisely why the caps are FETCHED from
// the relay at runtime instead of copied into admin/lib. The test can require
// it because the test runs in the repo, and that is the point: the numbers this
// suite asserts are the relay's own, not a second set written down here.
const relayEntitlements = require('../../relay/lib/entitlements');

function fakeRedis(map) { return () => ({ get: async (k) => (k in map ? String(map[k]) : null) }); }

// Build the deps a route hands to buildSnapshot for an account with these
// stored per-product plans, exactly as GET /v2/admin/entitlements/:id answers.
function depsFor(account, extra) {
  return Object.assign({
    redis: fakeRedis({}),
    getAuditEvents: async () => [],
    entitlements: relayEntitlements.getEntitlements(account),
    now: new Date('2026-05-31T12:00:00Z'),
  }, extra || {});
}

test('catalogue: 10 tools, each with category/install/usage/source', () => {
  assert.equal(DEVELOPER_TOOLS.length, 10);
  for (const t of DEVELOPER_TOOLS) {
    assert.ok(t.name && t.tagline && t.category, 'core fields ' + t.name);
    assert.match(t.install, /git clone .*paramant-solutions/);
    assert.match(t.usage, /\{KEY\}/, 'usage carries a {KEY} placeholder');
    assert.match(t.source, /github\.com\/Apolloccrypt\/paramant-solutions\/tree\/main\/tools\//);
  }
});

test('maskKey / ymKey', () => {
  assert.equal(maskKey('pgp_' + 'a'.repeat(40)), 'pgp_aaaa…aaaa');
  assert.equal(maskKey('short'), 'short');
  assert.equal(ymKey(new Date('2026-05-31T12:00:00Z')), '2026-05');
});

test('toolsStatusFromAudit: never_used when no tool events', () => {
  const st = toolsStatusFromAudit(DEVELOPER_TOOLS, [{ event_type: 'webauthn_login', ts: Date.now() }]);
  for (const t of DEVELOPER_TOOLS) assert.equal(st[t.name].state, 'never_used');
});

test('toolsStatusFromAudit: idle + stats when a tool event exists', () => {
  const now = Date.now();
  const audit = [
    { event_type: 'tool_run', ts: now - 1000, metadata: { tool: 'paramant-s3-migrate', result: 'ok', duration_ms: 1200 } },
    { event_type: 'tool_run', ts: now - 2000, metadata: { tool: 'paramant-s3-migrate', result: 'fail', duration_ms: 800 } },
  ];
  const st = toolsStatusFromAudit(DEVELOPER_TOOLS, audit);
  assert.equal(st['paramant-s3-migrate'].state, 'idle');
  assert.equal(st['paramant-s3-migrate'].runs_week, 2);
  assert.equal(st['paramant-s3-migrate'].success_rate, 50);
  assert.equal(st['paramant-s3-migrate'].avg_ms, 1000);
  assert.equal(st['paramant-db-backup'].state, 'never_used');
});

test('isToolEvent', () => {
  assert.ok(isToolEvent({ event_type: 'tool_run' }));
  assert.ok(isToolEvent({ event_type: 'x', metadata: { tool: 'paramant-x' } }));
  assert.ok(!isToolEvent({ event_type: 'webauthn_login' }));
});

test('buildSnapshot: full shape, caps, masked key, no key leak', async () => {
  const uid = 'pgp_' + 'b'.repeat(60);
  const redis = fakeRedis({
    [`paramant:quota:transfers:${uid}:2026-05`]: '7',
    [`paramant:quota:signs:${uid}:2026-05`]: '1',
  });
  const getAuditEvents = async () => [{ event_type: 'webauthn_login', ts: Date.parse('2026-05-31T10:00:00Z'), metadata: {} }];
  const snap = await buildSnapshot(
    depsFor({ plan: 'community', plan_parasend: 'community', plan_parasign: 'free' }, { redis, getAuditEvents }),
    { user_id: uid, email: 'dev@x.io' });

  assert.equal(snap.email, 'dev@x.io');
  assert.deepEqual(snap.tiers, { parasend: 'community', parasign: 'free' });
  assert.equal(snap.key_masked, 'pgp_bbbb…bbbb');
  assert.ok(!snap.key_masked.includes(uid), 'full key never returned');
  assert.equal(snap.quota.transfers, 7);
  assert.equal(snap.quota.signs, 1);
  assert.equal(snap.quota.caps.transfers, 10);
  assert.equal(snap.quota.caps.signs, 2);
  assert.equal(snap.audit.length, 1);
  assert.equal(Object.keys(snap.tools_status).length, 10);
});

// ── The bug this file was rewritten for ─────────────────────────────────────
//
// A self-serve ParaSign Pro customer keeps the unified `plan` he signed up
// with, because entitlements.applyProductTier writes plan_parasign alone. The
// admin's own tier table read that unified field, and had no `business` row at
// all, so /dashboard and the signed-in homepage told a paying customer he had
// 2 signatures a month while the relay was granting him 100, and told a
// Business customer the same where the relay grants 1000.
//
// Every number below comes out of relay/lib/entitlements.js. Reinstating any
// local table in admin/lib/developer-snapshot.js fails these cases, because a
// table keyed on `plan` answers community for the first account.
test('ParaSign Pro on a community ParaSend account: 100 signs, 10 transfers', async () => {
  const snap = await buildSnapshot(
    depsFor({ plan: 'community', plan_parasign: 'pro', plan_parasend: 'community' }),
    { user_id: 'pgp_pro', email: 'pro@x.io' });
  assert.deepEqual(snap.tiers, { parasend: 'community', parasign: 'pro' });
  assert.equal(snap.quota.caps.signs, 100, 'the relay grants ParaSign Pro 100 signatures a month');
  assert.equal(snap.quota.caps.transfers, 10, 'buying ParaSign does not move the ParaSend tier');
});

test('ParaSign Business: 1000 signs, and the row exists at all', async () => {
  const snap = await buildSnapshot(
    depsFor({ plan: 'community', plan_parasign: 'business', plan_parasend: 'community' }),
    { user_id: 'pgp_biz', email: 'biz@x.io' });
  assert.equal(snap.tiers.parasign, 'business');
  assert.equal(snap.quota.caps.signs, 1000, 'business is a tier the pricing page sells, not a fall-through to community');
  assert.equal(snap.quota.caps.transfers, 10);
});

test('community on both products: 2 signs, 10 transfers, counters default to 0', async () => {
  const snap = await buildSnapshot(
    depsFor({ plan: 'community', plan_parasign: 'free', plan_parasend: 'community' }),
    { user_id: 'pgp_free', email: 'free@x.io' });
  assert.equal(snap.quota.caps.signs, 2);
  assert.equal(snap.quota.caps.transfers, 10);
  assert.equal(snap.quota.transfers, 0);
  assert.equal(snap.quota.signs, 0);
});

test('ParaSend Pro on a free ParaSign account: 500 transfers, still 2 signs', async () => {
  // The mirror image of the Pro case above, so neither product can be shown to
  // decide the other one's ceiling.
  const snap = await buildSnapshot(
    depsFor({ plan: 'community', plan_parasign: 'free', plan_parasend: 'pro' }),
    { user_id: 'pgp_send', email: 'send@x.io' });
  assert.equal(snap.quota.caps.transfers, 500);
  assert.equal(snap.quota.caps.signs, 2);
});

test('every metered cap is a finite number, enterprise included', async () => {
  // relay/lib/entitlements.js holds even enterprise to a real monthly ceiling,
  // so the dashboard may never print an infinity sign. null here would mean
  // "not read", and that must not happen for an account the relay answered for.
  const snap = await buildSnapshot(
    depsFor({ plan: 'enterprise', plan_parasign: 'enterprise', plan_parasend: 'enterprise' }),
    { user_id: 'pgp_ent', email: 'e@x.io' });
  for (const dim of ['transfers', 'signs']) {
    assert.equal(typeof snap.quota.caps[dim], 'number', `${dim} cap must be a number`);
    assert.ok(Number.isFinite(snap.quota.caps[dim]), `${dim} cap must be finite`);
  }
});

test('no entitlements means no snapshot, never a guessed cap', async () => {
  // The relay being unreachable is not a licence to invent a ceiling. The route
  // turns this into a 503 and the page keeps what it last drew.
  await assert.rejects(
    () => buildSnapshot({ redis: fakeRedis({}), getAuditEvents: async () => [] }, { user_id: 'pgp_x', email: 'x@x.io' }),
    /entitlements_required/);
  await assert.rejects(
    () => buildSnapshot({ redis: fakeRedis({}), getAuditEvents: async () => [], entitlements: { parasend: {} } }, { user_id: 'pgp_x', email: 'x@x.io' }),
    /entitlements_required/);
});

// ── Sabotage guard ──────────────────────────────────────────────────────────
//
// The behavioural cases above already fail if a copied table comes back and is
// used. This one fails if a copied table comes back at all, used or not, and it
// names the reason: a second table is a table that drifts, and the last one
// drifted into telling a paying customer a false number about his own account.
test('admin/lib/developer-snapshot.js carries no tier table of its own', () => {
  const SRC = fs.readFileSync(path.join(__dirname, '..', 'lib', 'developer-snapshot.js'), 'utf8');
  const code = SRC.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^[ \t]*\/\/.*$/gm, ' ');
  assert.doesNotMatch(code, /\b(community|pro|business|enterprise|free|licensed|dev)\s*:/,
    'no tier row may be written in this file; the relay owns the numbers');
  assert.doesNotMatch(code, /\b(transfers|signs|transfers_month|signs_month)\s*:\s*\d/,
    'no cap may be hard-coded in this file');
  assert.equal(require('../lib/developer-snapshot').TIER_CAPS, undefined,
    'developer-snapshot must not export a tier table');
});
