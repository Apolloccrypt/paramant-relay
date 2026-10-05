'use strict';
// Unit test for admin/lib/developer-config.js: validation + merge for the
// per-account saved tool commands. Proves unknown tools, oversize, and literal
// keys are rejected, and that the merged map drops unknown keys + caps size.
// Run: node admin/test/developer-config.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const { validateConfig, mergeConfig, removeConfig, TOOL_NAMES, MAX_CMD } =
  require('../lib/developer-config');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

const TOOL = [...TOOL_NAMES][0]; // a real catalogue tool name
assert.ok(TOOL, 'catalogue is non-empty');

// validateConfig
assert.strictEqual(validateConfig('not-a-tool', 'x').ok, false, 'unknown tool rejected');
assert.strictEqual(validateConfig(TOOL, 123).ok, false, 'non-string command rejected');
assert.strictEqual(validateConfig(TOOL, 'a'.repeat(MAX_CMD + 1)).ok, false, 'oversize command rejected');
assert.strictEqual(validateConfig(TOOL, 'paramant-x s3://b --to bob').ok, true, 'normal command accepted');
ok('validateConfig basics');

// a literal key must NEVER be storable
assert.strictEqual(validateConfig(TOOL, 'PARAMANT_API_KEY=pgp_abc123def paramant-x').ok, false, 'literal pgp_ key refused');
assert.strictEqual(validateConfig(TOOL, 'paramant-x --to bob # uses $PARAMANT_API_KEY').ok, true, 'env-var form accepted');
ok('literal key is refused (defence in depth)');

// mergeConfig: drops unknown keys, keeps known, enforces structure
const m1 = mergeConfig(JSON.stringify({ 'bogus-tool': 'evil', [TOOL]: 'old' }), TOOL, 'new');
assert.strictEqual(m1.ok, true, 'merge ok');
assert.strictEqual(m1.map[TOOL], 'new', 'updates the entry');
assert.strictEqual(m1.map['bogus-tool'], undefined, 'drops unknown tool keys');
ok('mergeConfig drops unknown keys, updates entry');

// mergeConfig: tolerant of garbage existing JSON
assert.strictEqual(mergeConfig('not json', TOOL, 'x').ok, true, 'garbage existing JSON tolerated');
assert.strictEqual(mergeConfig('[1,2,3]', TOOL, 'x').map[TOOL], 'x', 'array existing coerced to {}');
ok('mergeConfig tolerant of bad existing state');

// removeConfig
const rj = removeConfig(JSON.stringify({ [TOOL]: 'x' }), TOOL);
assert.strictEqual(JSON.parse(rj)[TOOL], undefined, 'removeConfig deletes the entry');
ok('removeConfig');

console.log('developer-config:', passed, 'groups passed');
