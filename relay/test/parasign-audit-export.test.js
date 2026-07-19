'use strict';
// GET /v2/parasign/audit-export handler (lib/parasign-audit-export.js). Proves the
// Business+ tier gate: a Pro key is refused (403); a Business/Enterprise key gets
// the account's tamper-evident audit trail + CT signed tree head, as JSON or CSV.
// DI-driven with a fake res -- no socket, no redis.

const { test } = require('node:test');
const assert = require('assert');
const ax = require('../lib/parasign-audit-export');

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
    { ts: '2026-07-19T10:00:00Z', event: 'inbound', hash: 'a'.repeat(16), bytes: 100, device: 'd1', chain_hash: 'h1' },
    { ts: '2026-07-19T11:00:00Z', event: 'did_registered', hash: '', chain_hash: 'h2' },
  ],
};
const deps = (keyData, query = {}) => ({
  res: fakeRes(), J, keyData, memberKeys: ['k1'],
  auditFor: (k) => CHAIN[k] || [],
  ctHead: () => ({ tree_size: 5, tree_hash: 'root', timestamp: '2026-07-19T12:00:00Z' }),
  verifyChain: () => true,
  query,
});

test('Pro key -> 403 (audit export is Business+)', () => {
  const d = deps({ plan: 'pro', active: true });
  ax.handle(d);
  assert.strictEqual(d.res.statusCode, 403);
  assert.strictEqual(d.res.json().error, 'tier_upgrade_required');
  assert.strictEqual(d.res.json().feature, 'audit_export');
});

test('Business key -> 200 JSON export with entries + ct_head anchor', () => {
  const d = deps({ plan: 'business', active: true });
  ax.handle(d);
  assert.strictEqual(d.res.statusCode, 200);
  const b = d.res.json();
  assert.strictEqual(b.type, 'parasign-audit-export');
  assert.strictEqual(b.chain_valid, true);
  assert.strictEqual(b.ct_head.tree_size, 5);
  assert.strictEqual(b.count, 2);
  assert.strictEqual(b.entries[0].event, 'did_registered', 'newest first');
});

test('Enterprise key -> 200', () => {
  const d = deps({ plan: 'enterprise', active: true });
  ax.handle(d);
  assert.strictEqual(d.res.statusCode, 200);
});

test('Business CSV export sets text/csv + attachment', () => {
  const d = deps({ plan: 'business', active: true }, { format: 'csv' });
  ax.handle(d);
  assert.strictEqual(d.res.statusCode, 200);
  assert.strictEqual(d.res.headers['Content-Type'], 'text/csv');
  assert.match(d.res.headers['Content-Disposition'], /parasign_audit\.csv/);
  assert.match(d.res._body, /^time,event,doc_hash,bytes,device,chain_hash/);
});

test('inactive key -> 401', () => {
  const d = deps({ plan: 'business', active: false });
  ax.handle(d);
  assert.strictEqual(d.res.statusCode, 401);
});
