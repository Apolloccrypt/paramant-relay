'use strict';
// Closure guard for the retired keyless upload tier (POST /v2/anon-inbound).
//
// The route no longer has its own pre-auth handler. It is aliased into the
// authenticated POST /v2/inbound handler, so a keyless caller is refused by the
// API-key gate (401) and a keyed caller runs the identical getEntitlements +
// gateTransfer quota path that /v2/inbound uses (the quota decision itself is
// covered by entitlements.test.js and quota-gate.test.js). There is no HTTP-boot
// harness in this suite -- the relay unit job runs with no native @paramant/core
// build and no Redis -- so this pins the routing invariant structurally against
// relay.js: it fails if a future edit re-opens a keyless accept path, or moves
// anon-inbound back in front of the auth gate.
const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

test('anon-inbound is aliased into the authenticated /v2/inbound handler', () => {
  assert.ok(
    SRC.includes("if ((path === '/v2/inbound' || path === '/v2/anon-inbound') && req.method === 'POST')"),
    'the /v2/inbound POST handler must also match /v2/anon-inbound'
  );
});

test('the old keyless accept path is gone (no keyless 200 for anon uploads)', () => {
  assert.ok(!SRC.includes('anon_blob_stored'), 'keyless success log must be removed');
  assert.ok(
    !SRC.includes("path === '/v2/anon-inbound' && req.method === 'POST'"),
    'anon-inbound must have no standalone pre-gate handler'
  );
});

test('anon-inbound is matched only AFTER the API-key gate, so keyless callers get 401', () => {
  const gate = SRC.indexOf("error: 'Invalid API key'");
  const handler = SRC.indexOf("path === '/v2/anon-inbound'");
  assert.ok(gate !== -1, 'the API-key gate must exist');
  assert.ok(handler !== -1, 'anon-inbound must be referenced by the shared handler');
  assert.ok(handler > gate, 'anon-inbound must be matched after the auth gate (no key => 401)');
});

test('the dead keyless per-IP rate-limit map is removed', () => {
  assert.ok(!SRC.includes('anonInboundIpRequests'), 'keyless per-IP limiter must be gone');
});
