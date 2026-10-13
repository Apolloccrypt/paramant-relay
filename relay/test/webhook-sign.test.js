'use strict';
// Review #555, LAAG: webhook HMAC without a timestamp, so a captured delivery
// verified forever. Every delivery now also carries X-Paramant-Signature with
// the time inside the HMAC, and verifySignature refuses it outside the window.
// Run: node --test relay/test/webhook-sign.test.js
const { test } = require('node:test');
const assert = require('assert');
const ws = require('../lib/webhook-sign');
const api = require('../lib/parasign-open-api');

test('a signature verifies inside the window, not after it, not over another body', () => {
  const now = 1_800_000_000_000;
  const h = ws.signatureHeaders('whsec_demo', '{"a":1}', now);
  assert.strictEqual(h['X-Paramant-Timestamp'], String(now / 1000));
  assert.ok(ws.verifySignature('whsec_demo', '{"a":1}', h['X-Paramant-Signature'], { nowMs: now + 60_000 }));
  assert.ok(!ws.verifySignature('whsec_demo', '{"a":1}', h['X-Paramant-Signature'], { nowMs: now + 301_000 }), 'a replay after the window fails');
  assert.ok(!ws.verifySignature('whsec_demo', '{"a":2}', h['X-Paramant-Signature'], { nowMs: now }), 'another body fails');
  assert.ok(!ws.verifySignature('whsec_other', '{"a":1}', h['X-Paramant-Signature'], { nowMs: now }), 'another secret fails');
});

test('the /v1 envelope webhook sends the timestamped signature', async () => {
  let sent = null;
  const deps = {
    store: { async getMeta() { return { webhook_url: 'https://hooks.example.com/x', webhook_secret: 'whsec_demo', metadata: {} }; } },
    J: (o) => JSON.stringify(o), log: () => {},
    safeHttpsRequest: async (url, opts) => { sent = opts; return { status: 200 }; },
  };
  const r = await api.emitEvent(deps, 'env_demo', 'signer.completed', {});
  assert.strictEqual(r.ok, true);
  assert.ok(sent.headers['X-Paramant-Sig'], 'the old header stays');
  assert.ok(ws.verifySignature('whsec_demo', sent.body, sent.headers['X-Paramant-Signature']), JSON.stringify(sent.headers));
});
