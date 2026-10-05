'use strict';
// authenticateBearer: the one definition of "known /v1 caller".
//
// This suite is a rescue. It lived inside relay/test/paraid-closed.test.js,
// which existed to prove that POST /v1/paraid/issue-document refused an
// unauthenticated caller. ParaID is gone, and with it that route and that test,
// but the check underneath it is not ParaID's: the ParaSign open-API router
// runs on the same function, and it is what any future /v1 route must reach
// before it does anything.
//
// The shape it guards against is worth stating, because it is what produced
// audit finding 1 of 2026-07-21. authenticateBearer used to live only INSIDE
// the ParaSign router, so a handler that ran in front of that router never met
// it. The route was on /v1 and looked gated; it was not. Splitting the check
// out of the router is what made it reachable, and this suite is what keeps it
// honest afterwards.
//
// No redis, no crypto, no @paramant/core: it calls one pure function.
// Run: node relay/test/v1-bearer-gate.test.js (exits non-zero on failure).

const assert = require('assert');
const openApi = require('../lib/parasign-open-api');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

const KEY = 'psk_live_gatetest00000000000000000';
const REVOKED = 'psk_live_revoked00000000000000000';
const TEST_KEY = 'psk_test_gatetest00000000000000000';
const keys = new Map([
  [KEY, { plan: 'pro', active: true, account_id: 'acct_demo', scope: 'parasign' }],
  [REVOKED, { plan: 'pro', active: false, account_id: 'acct_demo' }],
  [TEST_KEY, { plan: 'pro', active: true, account_id: 'acct_demo', scope: 'parasign' }],
]);

// Every way a caller can fail to be a known one. Each must be 401, and each
// must be 401 for the same reason: the answer never tells an outsider which of
// these it was.
for (const [label, header] of [
  ['no Authorization header', ''],
  ['a non-Bearer header', 'Basic hunter2'],
  ['a Bearer token that is not a psk_ key', 'Bearer abc123'],
  ['an unknown psk_ key', 'Bearer psk_live_neverissued0000000'],
  ['a revoked psk_ key', `Bearer ${REVOKED}`],
  // The boundary between the two Bearer credentials this relay now has. A pst_
  // ParaSend session token is resolved in relay.js, against redis, and it opens
  // five /v2 routes; /v1 is the ParaSign developer API and knows only psk_
  // keys. Neither may be mistaken for the other, and the direction that would
  // hurt is this one: a token minted for a browser must not become a developer
  // credential on an open API. The prefix is what separates them, so the case
  // is written out rather than assumed.
  ['a pst_ ParaSend session token', `Bearer pst_${'a'.repeat(64)}`],
]) {
  const r = openApi.authenticateBearer(header, keys);
  assert.strictEqual(r.ok, false, `${label} was accepted`);
  assert.strictEqual(r.code, 401, `${label} did not answer 401`);
  ok(`rejects ${label} with 401`);
}

const good = openApi.authenticateBearer(`Bearer ${KEY}`, keys);
assert.strictEqual(good.ok, true, 'an active psk_live_ key was refused');
assert.strictEqual(good.token, KEY);
assert.strictEqual(good.mode, 'live');
ok('accepts an active psk_live_ key and reports mode live');

// The sandbox key must authenticate too, and must be distinguishable, because
// mode is what decides whether an envelope is driven by the auto-signer and
// whether its receipt carries the test marker.
const sandbox = openApi.authenticateBearer(`Bearer ${TEST_KEY}`, keys);
assert.strictEqual(sandbox.ok, true, 'an active psk_test_ key was refused');
assert.strictEqual(sandbox.mode, 'test', 'a psk_test_ key must report mode test, not live');
ok('accepts an active psk_test_ key and reports mode test');

// A key the map does not know at all is not the same object as a revoked one,
// but the caller may not learn the difference from the answer.
const unknown = openApi.authenticateBearer('Bearer psk_live_neverissued0000000', keys);
const revoked = openApi.authenticateBearer(`Bearer ${REVOKED}`, keys);
assert.strictEqual(unknown.code, revoked.code, 'unknown and revoked answer with different codes');
assert.strictEqual(unknown.error, revoked.error, 'unknown and revoked answer with different errors');
ok('an unknown key and a revoked key are indistinguishable from outside');

// And the same boundary from the other side, so a reader of either suite finds
// it: relay/lib/session-token.js refuses a psk_ key as a session token, and its
// scope allowlist contains no /v1 path at all. Cheap to assert, and it is the
// pair of facts that keeps the two Bearer namespaces from drifting together.
const sessionTokens = require('../lib/session-token');
assert.strictEqual(sessionTokens.isSessionToken(KEY), false, 'a psk_ key must not be readable as a session token');
assert.strictEqual(sessionTokens.bearerToken(`Bearer ${KEY}`), KEY,
  'the parse is shared and takes any Bearer; it is isSessionToken that refuses this one');
assert.strictEqual(sessionTokens.scopeAllows('POST', '/v1/envelopes'), false,
  'a session token must not reach the ParaSign developer API');
assert.strictEqual(sessionTokens.scopeAllows('GET', '/v1/code-manifest'), false);
ok('a psk_ key is not a session token, and a session token opens no /v1 route');

console.log(`\nv1-bearer-gate: ${passed} checks passed`);
