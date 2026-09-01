// The purchase path must survive the detour through sign-in.
//
// Two leaks used to sit between a price button and a payment. First, clicking
// while signed out redirected to /auth/login?next=/pricing and dropped WHICH
// plan was wanted, so the visitor had to want it twice. Second, the registration
// finish button was hardcoded to /dashboard, so even a correct `next` was thrown
// away on the way back.
//
// safeNext is also a security boundary: it decides where a signed-in visitor is
// sent, so anything it accepts is a redirect an attacker can hand out.
// Run: node relay/test/koop-pad-intentie.test.mjs (exits non-zero on failure).

import assert from 'assert';
import { readFileSync } from 'fs';

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`ok   ${name}`); }
  catch (e) { console.error(`FAIL ${name}\n     ${e.message}`); process.exitCode = 1; }
}

const passkey = readFileSync(new URL('../../frontend/js/passkey.js', import.meta.url), 'utf8');
const pricing = readFileSync(new URL('../../frontend/js/pricing-billing.js', import.meta.url), 'utf8');

// Lift safeNext out of the file and run it against a fake location, so the test
// exercises the real shipped source rather than a copy that can drift from it.
function loadSafeNext() {
  const m = passkey.match(/function safeNext\(\)\s*\{[\s\S]*?\n\}/);
  assert.ok(m, 'safeNext not found in passkey.js');
  const fn = new Function('window', 'URLSearchParams', `${m[0]}; return safeNext;`);
  return (search) => fn({ location: { search } }, URLSearchParams)();
}
const safeNext = loadSafeNext();

test('a local path is honoured', () => {
  assert.strictEqual(safeNext('?next=%2Fpricing'), '/pricing');
  assert.strictEqual(safeNext('?next=%2Fpricing%3Fplan%3Dpro'), '/pricing?plan=pro');
});

test('the older return parameter still works', () => {
  assert.strictEqual(safeNext('?return=%2Fpricing'), '/pricing');
});

test('no parameter falls back to the dashboard', () => {
  assert.strictEqual(safeNext(''), '/dashboard');
  assert.strictEqual(safeNext('?next='), '/dashboard');
});

test('a protocol-relative target is refused, not followed', () => {
  // //evil.example is a URL for another host, not a path on ours.
  assert.strictEqual(safeNext('?next=%2F%2Fevil.example'), '/dashboard');
  assert.strictEqual(safeNext('?next=%2F%5Cevil.example'), '/dashboard');
});

test('an absolute URL is refused', () => {
  assert.strictEqual(safeNext('?next=https%3A%2F%2Fevil.example'), '/dashboard');
  assert.strictEqual(safeNext('?next=http%3A%2F%2Fevil.example'), '/dashboard');
});

test('the registration finish button uses safeNext, not a hardcoded dashboard', () => {
  const line = passkey.split('\n').find(l => l.includes('passkey-finish-btn') && l.includes('addEventListener'))
    || passkey.split('\n').find(l => l.includes('finishBtn.addEventListener'));
  assert.ok(line, 'finish button handler not found');
  assert.ok(line.includes('safeNext()'), `finish button still hardcodes its target: ${line.trim()}`);
});

test('safeNext is defined once, so the rule cannot drift apart', () => {
  const defs = (passkey.match(/function safeNext\(/g) || []).length;
  assert.strictEqual(defs, 1);
});

test('the pricing page remembers the plan before sending the visitor to sign in', () => {
  const i = pricing.indexOf('rememberIntent(btn)');
  const j = pricing.indexOf("'/auth/login?next='");
  assert.ok(i > -1, 'the choice is never stored');
  assert.ok(j > -1, 'the sign-in redirect is gone');
  assert.ok(i < j, 'the redirect happens before the choice is stored');
});

test('a remembered choice is read once and then cleared', () => {
  assert.ok(pricing.includes('sessionStorage.removeItem(INTENT)'),
    'the intent is never cleared, so it would replay on every later visit');
});

test('resuming presses the real button, so there is only one way to buy', () => {
  assert.ok(pricing.includes('target.click()'), 'resume does not go through the button');
});

test('storage failures cannot break the page in private mode', () => {
  const remember = pricing.slice(pricing.indexOf('function rememberIntent'), pricing.indexOf('function takeIntent'));
  assert.ok(remember.includes('catch'), 'rememberIntent does not tolerate a blocked sessionStorage');
});

console.log(`\n${passed} passed`);
