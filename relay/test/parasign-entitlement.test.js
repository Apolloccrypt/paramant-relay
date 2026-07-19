'use strict';
// ParaSign entitlement hooks (lib/parasign-open-api.js). They used to be
// in-memory-only stubs with a TODO(persist). Now they flip the live apiKeys
// record AND call an injected persist callback (relay.js mirrors it to
// users.json + writes an audit entry). This proves the flip + the persist
// hand-off, and that they still work (no throw) without a persist callback.

const assert = require('assert');
const openApi = require('../lib/parasign-open-api');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

function main() {
  const apiKeys = new Map([['k1', { active: true }]]);
  const calls = [];
  const persist = (key, opts) => calls.push({ key, opts });

  // grant flips parasign + plan AND persists
  assert.strictEqual(openApi.grantParaSignScope(apiKeys, 'k1', 'pro', persist), true, 'grant returns true');
  assert.strictEqual(apiKeys.get('k1').parasign, true, 'parasign flag set');
  assert.strictEqual(apiKeys.get('k1').plan, 'pro', 'plan set');
  assert.deepStrictEqual(calls[0], { key: 'k1', opts: { parasign: true, plan: 'pro' } }, 'persist called with grant');
  ok('grantParaSignScope flips the record and persists');

  // unknown key -> false, no persist
  assert.strictEqual(openApi.grantParaSignScope(apiKeys, 'nope', 'pro', persist), false, 'unknown key returns false');
  assert.strictEqual(calls.length, 1, 'no persist for unknown key');
  ok('grantParaSignScope returns false for an unknown key');

  // disable persists the off state
  assert.strictEqual(openApi.setParaSignEnabled(apiKeys, 'k1', false, persist), true, 'disable returns true');
  assert.strictEqual(apiKeys.get('k1').parasign, false, 'parasign flag cleared');
  assert.deepStrictEqual(calls[1], { key: 'k1', opts: { parasign: false } }, 'persist called with disable');
  ok('setParaSignEnabled persists the off state');

  // still works without a persist callback (no throw)
  assert.strictEqual(openApi.setParaSignEnabled(apiKeys, 'k1', true), true, 'works without persist');
  assert.strictEqual(apiKeys.get('k1').parasign, true, 're-enabled in memory');
  ok('entitlement hooks work without a persist callback (no throw)');
}

try { main(); console.log(`\nparasign-entitlement: ${passed} checks passed`); }
catch (e) { console.error('\nFAILED:', e && e.stack || e); process.exit(1); }
