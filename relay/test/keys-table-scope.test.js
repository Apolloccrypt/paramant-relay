'use strict';
// The scope of a v2 API key, and the gate that keeps it honest.
//
// THE CLASS, NOT THE CASE. A field the relay stores and shows back to the user
// is a promise. `scope` was stored on every key record, echoed in every key
// listing and rendered on the dashboard, and enforced by nothing: a key issued
// read-only could write anywhere on the v2 plane, /v2/admin/* included. The
// first test below fails on that shape rather than on that instance, so a
// seventh scope added to VALID_SCOPES without a row in SCOPE_ACTIONS is red
// before anybody ships it.
//
// Found on sec/relay-scope-enforcement (16 July 2026), unlanded for 51 days.
const test = require('node:test');
const assert = require('node:assert/strict');
const kt = require('../lib/keys-table');

const key = (scope) => (scope === undefined ? { active: true } : { active: true, scope });

// Enough of the v2 surface to prove a scope bites, one per action.
const PROBES = [
  ['read',   'GET',    '/v2/user/envelopes'],
  ['common', 'POST',   '/v2/pubkey'],
  ['send',   'POST',   '/v2/inbound'],
  ['sign',   'POST',   '/v2/envelopes'],
  ['admin',  'POST',   '/v2/admin/keys'],
  ['write',  'POST',   '/v2/a-route-that-does-not-exist-yet'],
];

test('every action a probe claims is the action the classifier returns', () => {
  for (const [action, method, path] of PROBES) {
    assert.equal(kt.scopeActionFor(method, path), action, `${method} ${path}`);
  }
});

test('a scope that is stored and shown must deny something', () => {
  // The bug in one assertion. Any scope other than 'full' has to be refused at
  // least one route that 'full' is allowed; otherwise the relay is selling a
  // restriction it does not apply.
  const toothless = [];
  for (const scope of kt.VALID_SCOPES) {
    if (scope === 'full') continue;
    const denied = PROBES.filter(([action]) => !kt.requireScope(key(scope), action));
    if (denied.length === 0) toothless.push(scope);
  }
  assert.deepEqual(toothless, [],
    'these scopes are accepted, stored and displayed but restrict nothing:\n  ' +
    toothless.join(', ') + '\n' +
    'Either give the scope a row in SCOPE_ACTIONS that denies something, or\n' +
    'take it out of VALID_SCOPES so no key can be minted with it.');
});

test('every scope in the enum is known to the matrix', () => {
  const unknown = [...kt.VALID_SCOPES].filter(
    (s) => !Object.values(kt.SCOPE_ACTIONS).some((set) => set.has(s)));
  assert.deepEqual(unknown, [],
    'a scope no action grants is denied everything, including reads: ' + unknown.join(', '));
});

test('a full key is denied nothing, so enforcement changes no existing flow', () => {
  for (const action of Object.keys(kt.SCOPE_ACTIONS)) {
    assert.equal(kt.requireScope(key('full'), action), true, `full denied ${action}`);
  }
  // Legacy records carry no scope field at all, and an unrecognised string can
  // only come from a hand-edited users.json. Both normalise to full, matching
  // what parseAccountFields does at load.
  for (const legacy of [key(undefined), key(''), key('what-is-this')]) {
    for (const action of Object.keys(kt.SCOPE_ACTIONS)) {
      assert.equal(kt.requireScope(legacy, action), true,
        `a legacy key was denied ${action}; enforcement must be invisible to it`);
    }
  }
});

test('read-only cannot write, and that is the escalation that was open', () => {
  const ro = key('read-only');
  assert.equal(kt.requireScope(ro, 'read'), true);
  for (const action of ['common', 'send', 'sign', 'admin', 'write']) {
    assert.equal(kt.requireScope(ro, action), false, `read-only still allowed ${action}`);
  }
  // The concrete escalation: a read-only key minting another key.
  assert.equal(kt.requireScope(ro, kt.scopeActionFor('POST', '/v2/admin/keys')), false);
  assert.equal(kt.requireScope(ro, kt.scopeActionFor('POST', '/v2/user/parasign-keys')), false);
  assert.equal(kt.requireScope(ro, kt.scopeActionFor('POST', '/v2/inbound')), false);
});

test('send-only and sign-only keep their own lane and stay out of the other', () => {
  const send = key('send-only');
  const sign = key('sign-only');
  assert.equal(kt.requireScope(send, kt.scopeActionFor('POST', '/v2/inbound')), true);
  assert.equal(kt.requireScope(send, kt.scopeActionFor('POST', '/v2/envelopes')), false);
  assert.equal(kt.requireScope(sign, kt.scopeActionFor('POST', '/v2/envelopes')), true);
  assert.equal(kt.requireScope(sign, kt.scopeActionFor('POST', '/v2/inbound')), false);
  // Neither may touch account or key management.
  for (const k of [send, sign]) {
    assert.equal(kt.requireScope(k, kt.scopeActionFor('POST', '/v2/admin/keys/revoke')), false);
    assert.equal(kt.requireScope(k, kt.scopeActionFor('POST', '/v2/billing/checkout')), false);
  }
  // Both may still register a public key and acknowledge a delivery.
  for (const k of [send, sign]) {
    assert.equal(kt.requireScope(k, kt.scopeActionFor('POST', '/v2/pubkey')), true);
    assert.equal(kt.requireScope(k, kt.scopeActionFor('POST', '/v2/ack')), true);
  }
});

test('an unclassified v2 write fails closed rather than passing as a read', () => {
  // The 2026-07 branch returned 'read' for anything it did not list, so a route
  // added later silently reopened the hole for every narrow key. The fallback
  // is full-only instead, which cannot break a full key (see the test above).
  assert.equal(kt.scopeActionFor('POST', '/v2/something-new'), 'write');
  assert.equal(kt.scopeActionFor('PATCH', '/v2/something-new'), 'write');
  assert.equal(kt.scopeActionFor('DELETE', '/v2/something-new'), 'write');
  for (const scope of ['read-only', 'send-only', 'sign-only', 'parasign']) {
    assert.equal(kt.requireScope(key(scope), 'write'), false, `${scope} waved through a new write route`);
  }
});

test('safe methods are reads on every path, including the admin plane', () => {
  for (const p of ['/v2/admin/keys', '/v2/user/webauthn/credentials', '/v2/billing/invoices']) {
    for (const m of ['GET', 'HEAD', 'OPTIONS']) {
      assert.equal(kt.scopeActionFor(m, p), 'read', `${m} ${p}`);
    }
  }
});

test('nothing outside /v2 is classified here', () => {
  // /v1 carries its own psk_ Bearer + parasign gate and returns before this one;
  // /health and /metrics are not the data plane. Classifying them would be a
  // second, competing policy.
  for (const p of ['/v1/envelopes', '/health', '/metrics', '/']) {
    assert.equal(kt.scopeActionFor('POST', p), 'read', p);
  }
});

test('an unknown action is denied, including to a full key', () => {
  assert.equal(kt.requireScope(key('full'), 'teleport'), false);
  assert.equal(kt.requireScope(key('full'), undefined), false);
});

test('relay.js actually calls the gate, above the routes it protects', () => {
  // A pure matrix that nothing consults is the same bug in a new place, so the
  // suite checks the wiring too, not just the policy. Source text rather than a
  // boot: relay.js needs @paramant/core and redis at load, and this job has
  // neither on purpose.
  const fs = require('node:fs');
  const path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

  const call = src.indexOf('keysTable.requireScope(');
  assert.notEqual(call, -1,
    'relay.js no longer calls requireScope, so every key is full again regardless of its scope');
  assert.ok(src.includes('keysTable.scopeActionFor('), 'relay.js no longer classifies the route');
  assert.ok(src.includes("error: 'insufficient_scope'"), 'the refusal no longer names itself');

  // Above the data plane. If the gate ever drifts below a route handler, that
  // route answers before it is ever asked about scope.
  for (const route of ["path === '/v2/inbound'", "path === '/v2/envelopes'", "path === '/v2/admin/keys'"]) {
    const at = src.indexOf(route);
    assert.notEqual(at, -1, `route disappeared: ${route}`);
    assert.ok(call < at, `the scope gate sits BELOW ${route} and cannot protect it`);
  }
});
