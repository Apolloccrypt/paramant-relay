'use strict';
// Unit test for the passkey step-up flow-store the signing-key bind relies on
// (admin POST /api/user/account/signing-key/step-up/{options,bind} — the
// TOTP-equivalent gate for the "your sign-in passkey IS your signing key" path).
// The bind route's replay safety + session binding rest on webauthn.putAuthFlow
// / takeAuthFlow being one-shot and carrying the {user_id, step_up} the route
// re-checks (flow.step_up === 'signing-key' && flow.user_id === session user).
// Asserted here against an in-memory redis double.
// Run: node admin/test/signing-key-stepup.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const wa = require('../lib/webauthn');

function fakeRedis() {
  const m = new Map();
  return {
    _m: m,
    async set(k, v) { m.set(k, v); },          // EX ignored (no expiry in-test)
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async del(k) { return m.delete(k) ? 1 : 0; },
  };
}

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

async function main() {
  const r = fakeRedis();
  const flowId = wa.newFlowId();
  assert.ok(/^[0-9a-f]{32}$/.test(flowId), 'flowId is 32-hex');

  // The step-up challenge is bound to the account + marked as a signing-key step.
  await wa.putAuthFlow(r, flowId, { challenge: 'chal-abc', user_id: 'pgp_u1', step_up: 'signing-key' });

  // First take returns the record with its binding intact (the route checks
  // flow.step_up === 'signing-key' && flow.user_id === the session user).
  const got = await wa.takeAuthFlow(r, flowId);
  assert.ok(got, 'flow resolves on first take');
  assert.strictEqual(got.step_up, 'signing-key', 'step_up marker round-trips');
  assert.strictEqual(got.user_id, 'pgp_u1', 'account binding round-trips');
  assert.strictEqual(got.challenge, 'chal-abc', 'challenge round-trips');
  ok('step-up flow: binding round-trips on first take');

  // One-shot: a replay (second take of the same flowId) gets nothing — so a
  // captured assertion challenge can never be re-bound.
  assert.strictEqual(await wa.takeAuthFlow(r, flowId), null, 'second take -> null (one-shot consumed)');
  ok('step-up flow: one-shot (replay refused)');

  // Malformed flowId never resolves (input validation before any crypto).
  assert.strictEqual(await wa.takeAuthFlow(r, 'not-a-flow-id'), null, 'malformed flowId -> null');
  assert.strictEqual(await wa.takeAuthFlow(r, ''), null, 'empty flowId -> null');
  ok('step-up flow: malformed flowId rejected');

  console.log(`\n${passed} checks passed.`);
}

main().catch((e) => { console.error('FAIL:', (e && e.stack) || e); process.exit(1); });
