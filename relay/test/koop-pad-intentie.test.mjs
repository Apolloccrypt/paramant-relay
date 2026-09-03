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

// ── the other end of the path: coming back from Mollie ──────────────────────
// The purchase path did not end at the payment. Mollie sends the buyer to
// /dashboard?billing=return (relay.js, the checkout redirectUrl) and grants the
// plan through a SEPARATE webhook call, so the redirect regularly wins the race
// and the buyer arrives before the entitlement does. Nothing on the dashboard
// read that parameter: the money had left the account and the site said nothing
// at all about it, on any page. docs.html has described this return URL the
// whole time, so the contract existed; only the arrival did not.

const dashJs = readFileSync(new URL('../../frontend/js/dashboard.js', import.meta.url), 'utf8');
const dashHtml = readFileSync(new URL('../../frontend/dashboard.html', import.meta.url), 'utf8');

// The real predicate, lifted and run, so the parameter the relay actually sends
// is the parameter the page actually looks for.
function loadIsBillingReturn() {
  const m = dashJs.match(/function isBillingReturn\(\)\s*\{[\s\S]*?\n  \}/);
  assert.ok(m, 'isBillingReturn not found in dashboard.js');
  const fn = new Function('window', 'URLSearchParams', `${m[0]}; return isBillingReturn;`);
  return (search) => fn({ location: { search } }, URLSearchParams)();
}
const isBillingReturn = loadIsBillingReturn();

test('the dashboard recognises the return the checkout actually redirects to', () => {
  assert.strictEqual(isBillingReturn('?billing=return'), true);
  assert.strictEqual(isBillingReturn('?foo=1&billing=return'), true, 'other parameters may ride along');
  assert.strictEqual(isBillingReturn(''), false, 'an ordinary visit announces nothing');
  assert.strictEqual(isBillingReturn('?billing=cancelled'), false, 'only the return value counts');
});

test('the return band exists and is hidden until the page shows it', () => {
  assert.ok(dashHtml.includes('id="dh-billing-return"'), 'there is no band to show');
  const band = dashHtml.slice(dashHtml.indexOf('id="dh-billing-return"'), dashHtml.indexOf('id="dh-plan-paid"'));
  assert.ok(/\bhidden\b/.test(band), 'the band must not appear on an ordinary dashboard visit');
  assert.ok(band.includes('role="status"'), 'a state that changes by itself has to be announced');
  // Same rule the paid band is held to: the sale already happened, so this is
  // not a place to sell.
  assert.ok(!band.includes('href="/pricing"'), 'a buyer who has just paid must not be sold to');
});

test('a grant that has not landed yet is waited for, not denied', () => {
  const fn = dashJs.slice(dashJs.indexOf('function showBillingReturn'), dashJs.indexOf('function render(data)'));
  assert.ok(fn.includes('lastAccountIsPaid'), 'the band does not look at whether the plan is actually active');
  assert.ok(/setTimeout\([\s\S]*?refreshAccount\(tries - 1\)/.test(fn),
    'the webhook can arrive after the redirect, so the page must ask again');
  assert.ok(fn.includes('clearBillingParam()'),
    'a settled state must take the parameter out of the address bar or a reload re-announces the payment');
  // The last word must never be "your money is gone".
  assert.ok(/Nothing is lost/.test(fn), 'the timeout case must tell the buyer where he stands');
});

test('the parameter is only cleared once there is something to say', () => {
  const fn = dashJs.slice(dashJs.indexOf('function showBillingReturn'), dashJs.indexOf('function render(data)'));
  const waiting = fn.indexOf('tries > 0');
  const clears = [...fn.matchAll(/clearBillingParam\(\)/g)].map((m) => m.index);
  assert.strictEqual(clears.length, 2, 'exactly the two settled states clear the parameter');
  assert.ok(clears.some((i) => i < waiting), 'the confirmed state clears it');
  assert.ok(clears.some((i) => i > waiting), 'the gave-up state clears it');
});

console.log(`\n${passed} passed`);
