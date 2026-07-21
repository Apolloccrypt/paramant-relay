'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const adminSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const relaySource = fs.readFileSync(path.join(__dirname, '..', '..', 'relay', 'relay.js'), 'utf8');

test('user document route is session-authenticated and supplies the session account', () => {
  const route = adminSource.match(/api\.get\("\/user\/documents"[\s\S]*?\n\}\);/);
  assert.ok(route, 'user documents route exists');
  assert.match(route[0], /authUser/);
  assert.match(route[0], /const \{ user_id \} = req\.userSession/);
  assert.match(route[0], /callRelay\("\/v2\/user\/envelopes", \{ user_id, limit: 100 \}, "POST"\)/);
  assert.doesNotMatch(route[0], /req\.(body|query).*user_id/);
});

test('secret-shaped user id never enters the relay query string', () => {
  assert.doesNotMatch(adminSource, /\/v2\/user\/envelopes\?/);
  assert.match(relaySource, /req\.method === "POST" && path === "\/v2\/user\/envelopes"/);
  assert.match(relaySource, /if \(!_internalOk\(\)\) return _internalReject\(\)/);
});
