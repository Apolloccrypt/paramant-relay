'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

test('admin entitlement read-back uses the same merged record as gates', () => {
  const start = src.indexOf("const entitlementRead = path.match(");
  const end = src.indexOf('// ── POST /v2/admin/keys/set-parasign', start);
  assert.ok(start >= 0 && end > start);
  const route = src.slice(start, end);
  assert.match(route, /_internalOk\(\)/);
  assert.match(route, /entitlementRecordOf\(accountId\)/);
  assert.match(route, /entitlements\.getEntitlements\(record\)/);
  assert.match(route, /account_not_found/);
});
