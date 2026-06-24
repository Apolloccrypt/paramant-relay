'use strict';
// Unit test for cli-commands.validateArgs / buildArgv: proves a string arg can
// never smuggle a leading '-' that a handler script would read as an option
// flag instead of a positional value (option/argument injection). Also pins
// the existing control-char / shell-metachar rejection and the positional
// buildArgv contract (no '--' terminator, which would shift handler args).
// Run: node admin/test/cli-argvalidate.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const { validateArgs, buildArgv, COMMANDS } = require('../lib/cli-commands');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

const REVOKE = COMMANDS['key revoke']; // sole string-typed arg: key_prefix (minLength 8)

// 1. A normal hash-prefix is accepted and passed through unchanged.
const good = validateArgs(REVOKE, { key_prefix: 'a1b2c3d4e5' });
assert.ok(good.ok, 'valid key_prefix accepted: ' + good.error);
assert.strictEqual(good.values.key_prefix, 'a1b2c3d4e5');
ok('valid string arg accepted');

// 2. A leading '-' value is REJECTED (option-injection guard). Each sample is
//    >= minLength (8) so it must fail specifically on the leading-dash rule,
//    not on length. (A short leading-dash value is still rejected, by length.)
for (const bad of ['--helpme1', '-rf------', '--output=/etc']) {
  const r = validateArgs(REVOKE, { key_prefix: bad });
  assert.strictEqual(r.ok, false, 'leading-dash rejected: ' + bad);
  assert.ok(/start with '-'/.test(r.error), 'clear error for ' + bad + ': ' + r.error);
}
ok('leading-dash string values rejected');

// 3. A dash NOT in the leading position is still allowed (it cannot be a flag),
//    so legitimate prefixes are not over-rejected.
const mid = validateArgs(REVOKE, { key_prefix: 'a1b2-c3d4' });
assert.ok(mid.ok, 'non-leading dash allowed: ' + mid.error);
ok('non-leading dash allowed');

// 4. The pre-existing control-char / shell-metachar rejection still holds.
//    Samples use explicit escapes (\t, \x00) so the source stays byte-clean.
for (const bad of ['abc;rm-rf1', 'a$bcdefgh', 'abc\tdefgh', 'abc\x00defg', 'abc`id`xx', 'pipe|cat1']) {
  const r = validateArgs(REVOKE, { key_prefix: bad });
  assert.strictEqual(r.ok, false, 'metachar/control rejected: ' + JSON.stringify(bad));
}
ok('control-char and shell-metachar values still rejected');

// 5. buildArgv keeps the strict positional contract: it emits ONLY the values
//    in declared order, with no leading '--' terminator (which would land as
//    $1 in the handler and shift every real positional).
const argv = buildArgv(REVOKE, good.values);
assert.deepStrictEqual(argv, ['a1b2c3d4e5'], 'argv is bare positional, no -- prefix');
assert.notStrictEqual(argv[0], '--', 'no -- option terminator injected');
ok('buildArgv emits bare positional argv');

console.log('cli-argvalidate:', passed, 'groups passed');
