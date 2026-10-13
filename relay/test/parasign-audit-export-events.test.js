'use strict';
// COSIGN-47: the audit export said entries 0 and its CSV was only a header,
// after dozens of signatures: it read the key audit chain (transfers), never
// the envelopes. Every envelope now contributes its own events.
const { test } = require('node:test');
const assert = require('assert');
const exp = require('../lib/parasign-audit-export');

function res() { return { statusCode: 0, headers: {}, _body: '', writeHead(c, h) { this.statusCode = c; this.headers = h || {}; }, end(b) { this._body = String(b || ''); } }; }
const keyData = { active: true, plan: 'enterprise', plan_parasign: 'business' };
const envStore = {
  async listAccountEnvelopeIds() { return ['envA', 'envB']; },
  async auditTimeline(id) {
    if (id === 'envA') return { id, doc_hash: 'a'.repeat(64), status: 'complete', created_at: '2026-10-01T10:00:00Z', completed_at: '2026-10-01T12:00:00Z', voided_at: null, void_reason: null,
      parties: [{ index: 0, label: 'Anna', viewed_at: '2026-10-01T11:00:00Z', signed_at: '2026-10-01T12:00:00Z', declined_at: null }] };
    return { id, doc_hash: 'b'.repeat(64), status: 'void', created_at: '2026-10-02T10:00:00Z', completed_at: null, voided_at: '2026-10-02T11:00:00Z', void_reason: 'declined',
      parties: [{ index: 0, label: 'Bob', viewed_at: null, signed_at: null, declined_at: '2026-10-02T11:00:00Z' }] };
  },
  async getForReceipt() { return null; },
};

test('JSON and CSV carry created, viewed, signed, declined and completed events', async () => {
  const base = { J: JSON.stringify, keyData, memberKeys: [], auditFor: () => [], ctHead: () => null, account: 'acct', envStore, buildPsign: () => null };
  const r1 = res();
  await exp.handle({ ...base, res: r1, query: {} });
  const j = JSON.parse(r1._body);
  const events = j.entries.map((e) => e.event).sort();
  assert.deepStrictEqual(events, ['envelope_completed', 'envelope_created', 'envelope_created', 'envelope_declined', 'envelope_signed', 'envelope_viewed']);
  const r2 = res();
  await exp.handle({ ...base, res: r2, query: { format: 'csv' } });
  const lines = r2._body.trim().split('\n');
  assert.strictEqual(lines.length, 7, 'header plus six rows');
  assert.match(lines[0], /envelope_id,party,party_label$/);
  assert.ok(lines.some((l) => l.includes('envelope_signed') && l.includes('Anna')));
});
