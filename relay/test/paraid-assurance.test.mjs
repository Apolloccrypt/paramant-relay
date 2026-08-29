// The assurance label on a ParaID credential must never claim more than the
// issuer actually checked.
//
// What this guards: /v1/paraid/issue-document takes two lines of text, recomputes
// the ICAO check digits, and signs the result. Check digits are a typo guard, not
// a signature, so anyone can write an MRZ that passes them. The credential used
// to come back labelled 'substantial', the eIDAS word for a legally defined level
// of identity assurance, on evidence that establishes no identity at all.
// Run: node relay/test/paraid-assurance.test.mjs (exits non-zero on failure).

import assert from 'assert';
import { assuranceOf, assuranceAtLeast, ASSURANCE_RANK } from '../lib/paraid-issuer.mjs';

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`ok   ${name}`); }
  catch (e) { console.error(`FAIL ${name}\n     ${e.message}`); process.exitCode = 1; }
}

test('the ladder runs presence, mrz-unverified, high', () => {
  assert.deepStrictEqual([...ASSURANCE_RANK], ['presence', 'mrz-unverified', 'high']);
});

test('no rung is called substantial', () => {
  assert.ok(!ASSURANCE_RANK.includes('substantial'),
    'substantial is an eIDAS level; nothing here establishes it');
});

test('a pre-rename credential reads as the rung it always was', () => {
  assert.strictEqual(assuranceOf({ tier: 'substantial' }), 'mrz-unverified');
});

test('an MRZ credential never satisfies a chip requirement', () => {
  assert.strictEqual(assuranceAtLeast({ tier: 'mrz-unverified' }, 'high'), false);
  assert.strictEqual(assuranceAtLeast({ tier: 'substantial' }, 'high'), false);
});

test('presence never satisfies an MRZ requirement', () => {
  assert.strictEqual(assuranceAtLeast({ tier: 'presence' }, 'mrz-unverified'), false);
});

test('an MRZ credential does satisfy a presence requirement', () => {
  assert.strictEqual(assuranceAtLeast({ tier: 'mrz-unverified' }, 'presence'), true);
});

test('an unknown label is never treated as higher than presence', () => {
  assert.strictEqual(assuranceAtLeast({ tier: 'gold' }, 'presence'), false);
  assert.strictEqual(assuranceAtLeast({ tier: 'eidas-high' }, 'high'), false);
});

test('a credential with no tier falls back to presence, the lowest rung', () => {
  assert.strictEqual(assuranceOf({}), 'presence');
  assert.strictEqual(assuranceOf(null), 'presence');
  assert.strictEqual(assuranceAtLeast({}, 'mrz-unverified'), false);
});

console.log(`\n${passed} passed`);
