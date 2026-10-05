'use strict';
// GET /v2/user/history handler (lib/user-history.js). Proves the tier gate:
// a Free/community key is refused (403); a Pro key gets its own send/link history
// projected from the audit chain, newest-first, with no payload and infra events
// filtered out. Driven the DI way with a fake res -- no socket, no redis.

const { test } = require('node:test');
const assert = require('assert');
const uh = require('../lib/user-history');

const J = JSON.stringify;
function fakeRes() {
  return {
    statusCode: null, headers: null, _body: '',
    writeHead(c, h) { this.statusCode = c; this.headers = h || {}; },
    end(b) { this._body = b == null ? '' : String(b); },
    json() { try { return JSON.parse(this._body); } catch { return null; } },
  };
}

const CHAIN = {
  k1: [
    { ts: '2026-07-19T10:00:00Z', event: 'inbound',        hash: 'aaaa...16', bytes: 100, device: 'dev1', chain_hash: 'c1' },
    { ts: '2026-07-19T11:00:00Z', event: 'outbound_burn',  hash: 'aaaa...16', bytes: 100, device: 'dev1', chain_hash: 'c2' },
    { ts: '2026-07-19T09:00:00Z', event: 'did_registered', hash: '',          chain_hash: 'c0' }, // infra -> filtered
  ],
};
const auditFor = (k) => CHAIN[k] || [];

test('Free/community key -> 403 tier_upgrade_required', () => {
  const res = fakeRes();
  uh.handle({ res, J, keyData: { plan: 'community', active: true }, memberKeys: ['k1'], auditFor, query: {} });
  assert.strictEqual(res.statusCode, 403);
  assert.strictEqual(res.json().error, 'tier_upgrade_required');
  assert.strictEqual(res.json().feature, 'history');
});

test('Pro key -> 200 history, newest-first, infra events filtered, no payload', () => {
  const res = fakeRes();
  uh.handle({ res, J, keyData: { plan: 'pro', active: true }, memberKeys: ['k1'], auditFor, query: {} });
  assert.strictEqual(res.statusCode, 200);
  const b = res.json();
  assert.strictEqual(b.ok, true);
  assert.strictEqual(b.count, 2, 'did_registered filtered out');
  assert.strictEqual(b.entries[0].status, 'downloaded_burned', 'newest first');
  assert.strictEqual(b.entries[1].status, 'sent');
  assert.strictEqual(b.entries[0].payload, undefined, 'never a payload');
  assert.ok('recipient_hash' in b.entries[0] && 'id' in b.entries[0] && 'time' in b.entries[0]);
});

test('inactive key -> 401', () => {
  const res = fakeRes();
  uh.handle({ res, J, keyData: { plan: 'pro', active: false }, memberKeys: ['k1'], auditFor, query: {} });
  assert.strictEqual(res.statusCode, 401);
});

test('ParaSign-pro / parasend-free still sees history (either product Pro+)', () => {
  const res = fakeRes();
  uh.handle({ res, J, keyData: { plan_parasend: 'community', plan_parasign: 'pro', active: true }, memberKeys: ['k1'], auditFor, query: {} });
  assert.strictEqual(res.statusCode, 200);
});
