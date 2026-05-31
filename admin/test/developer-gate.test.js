'use strict';
// Unit test for admin/lib/developer-gate.js: the email allowlist parsing and
// the open/closed rules for the hidden /developer dashboard.
// Run: node admin/test/developer-gate.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const { developerAllowlist, isDeveloper } = require('../lib/developer-gate');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// developerAllowlist parsing
assert.deepStrictEqual(developerAllowlist({ DEVELOPER_ALLOWLIST: '' }), [], 'empty => []');
assert.deepStrictEqual(developerAllowlist({}), [], 'missing => []');
assert.deepStrictEqual(
  developerAllowlist({ DEVELOPER_ALLOWLIST: 'a@x.com, B@Y.COM ,,c@z.com' }),
  ['a@x.com', 'b@y.com', 'c@z.com'],
  'split, trim, lowercase, drop blanks');
ok('developerAllowlist parsing');

// Allowlisted email => allowed (case/space-insensitive)
const prodEnv = { DEVELOPER_ALLOWLIST: 'mickbr@protonmail.com' };
assert.strictEqual(isDeveloper('mickbr@protonmail.com', prodEnv), true, 'exact match allowed');
assert.strictEqual(isDeveloper('  MickBr@Protonmail.com ', prodEnv), true, 'case/space-insensitive');
ok('allowlisted email allowed');

// Non-allowlisted email => denied (this is the "/developer 404" case)
assert.strictEqual(isDeveloper('someone@else.com', prodEnv), false, 'other account denied');
assert.strictEqual(isDeveloper('', prodEnv), false, 'empty email denied');
assert.strictEqual(isDeveloper(null, prodEnv), false, 'null email denied');
assert.strictEqual(isDeveloper(undefined, prodEnv), false, 'undefined email denied');
ok('non-allowlisted email denied');

// Empty allowlist in production (NODE_ENV unset) => closed for everyone
assert.strictEqual(isDeveloper('mickbr@protonmail.com', { DEVELOPER_ALLOWLIST: '' }), false,
  'empty allowlist, no NODE_ENV => closed');
assert.strictEqual(isDeveloper('mickbr@protonmail.com', { DEVELOPER_ALLOWLIST: '', NODE_ENV: 'production' }), false,
  'empty allowlist in production => closed');
ok('empty allowlist closed in production');

// Empty allowlist + NODE_ENV=development => open (local dev/test bypass)
assert.strictEqual(isDeveloper('anyone@dev.local', { NODE_ENV: 'development' }), true,
  'empty allowlist + development => open');
// ...but an explicit allowlist still wins even in development
assert.strictEqual(isDeveloper('anyone@dev.local', { NODE_ENV: 'development', DEVELOPER_ALLOWLIST: 'only@me.com' }), false,
  'explicit allowlist overrides dev bypass');
assert.strictEqual(isDeveloper('only@me.com', { NODE_ENV: 'development', DEVELOPER_ALLOWLIST: 'only@me.com' }), true,
  'allowlisted in development allowed');
ok('development bypass only when allowlist empty');

console.log(`\n${passed} groups passed.`);
