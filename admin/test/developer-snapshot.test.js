'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildSnapshot, normalisePlan, maskKey, ymKey, TIER_CAPS } = require('../lib/developer-snapshot');
const { DEVELOPER_TOOLS, toolsStatusFromAudit, isToolEvent } = require('../lib/developer-tools');

function fakeRedis(map) { return () => ({ get: async (k) => (k in map ? String(map[k]) : null) }); }

test('catalogue: 10 tools, each with category/install/usage/source', () => {
  assert.equal(DEVELOPER_TOOLS.length, 10);
  for (const t of DEVELOPER_TOOLS) {
    assert.ok(t.name && t.tagline && t.category, 'core fields ' + t.name);
    assert.match(t.install, /git clone .*paramant-solutions/);
    assert.match(t.usage, /\{KEY\}/, 'usage carries a {KEY} placeholder');
    assert.match(t.source, /github\.com\/Apolloccrypt\/paramant-solutions\/tree\/main\/tools\//);
  }
});

test('maskKey / normalisePlan / ymKey', () => {
  assert.equal(maskKey('pgp_' + 'a'.repeat(40)), 'pgp_aaaa…aaaa');
  assert.equal(maskKey('short'), 'short');
  assert.equal(normalisePlan('free'), 'community');
  assert.equal(normalisePlan('licensed'), 'enterprise');
  assert.equal(normalisePlan('PRO'), 'pro');
  assert.equal(normalisePlan('whatever'), 'community');
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
  const snap = await buildSnapshot({ redis, getAuditEvents, plan: 'community', now: new Date('2026-05-31T12:00:00Z') }, { user_id: uid, email: 'dev@x.io' });

  assert.equal(snap.email, 'dev@x.io');
  assert.equal(snap.plan, 'community');
  assert.equal(snap.key_masked, 'pgp_bbbb…bbbb');
  assert.ok(!snap.key_masked.includes(uid), 'full key never returned');
  assert.equal(snap.quota.transfers, 7);
  assert.equal(snap.quota.signs, 1);
  assert.equal(snap.quota.caps.transfers, 10);
  assert.equal(snap.quota.caps.signs, 2);
  assert.equal(snap.audit.length, 1);
  assert.equal(Object.keys(snap.tools_status).length, 10);
});

test('buildSnapshot: enterprise caps = unlimited (null), missing counters = 0', async () => {
  const snap = await buildSnapshot({ redis: fakeRedis({}), getAuditEvents: async () => [], plan: 'enterprise', now: new Date('2026-05-31T00:00:00Z') }, { user_id: 'pgp_x', email: 'e@x.io' });
  assert.equal(snap.quota.transfers, 0);
  assert.equal(snap.quota.caps.transfers, null);
  assert.equal(snap.quota.caps.signs, null);
});
