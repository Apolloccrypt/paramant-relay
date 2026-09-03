// The sentence a customer reads when the passkey prompt never opens.
//
// On 2026-09-04 an owner on an iPhone tapped "Sign in with a passkey" with his
// address filled in and got, as the entire message, "could_not_start (400)".
// That names an HTTP status and no next step, and the one thing that did work
// (the "My passkey is on another device" link directly below it) was not
// mentioned. The cause is fixed in admin/lib/webauthn.js and pinned by
// admin/test/passkey-login-options.test.js; this suite pins the words, because
// the next unforeseen 4xx on that call will produce this sentence too.
//
// The function is lifted out of frontend/js/passkey.js and run for real, the
// way admin/test/log-redact.test.js lifts its three log statements: the module
// itself cannot be imported here (it is a browser entry point that imports
// /vendor/... by absolute path), and a copy of the sentence in a test file
// would agree with a broken page. Node builtins only, so this lands in the
// "Root integration suites" CI job and costs a millisecond.
//
// Sabotage that must turn this red (each verified before commit):
//   1. return the bare 'could_not_start (' + status + ')' as the message again
//   2. drop the technical code, leaving support with nothing to grep
//   3. rename the login button without changing the sentence that points at it
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PASSKEY_JS = path.join(ROOT, 'frontend', 'js', 'passkey.js');
const LOGIN_HTML = path.join(ROOT, 'frontend', 'auth', 'login.html');

const source = fs.readFileSync(PASSKEY_JS, 'utf8');
const loginHtml = fs.readFileSync(LOGIN_HTML, 'utf8');

// Lift the shipped builder, constants and all, and hand back a callable.
function loadFailureBuilder() {
  const from = source.indexOf('const PASSKEY_START_FALLBACK');
  assert.notEqual(from, -1, 'frontend/js/passkey.js must define PASSKEY_START_FALLBACK');
  const marker = '\n}\n';
  const to = source.indexOf(marker, source.indexOf('function passkeyStartFailure'));
  assert.notEqual(to, -1, 'frontend/js/passkey.js must define passkeyStartFailure');
  const block = source.slice(from, to + marker.length);
  return new Function(`${block}\nreturn passkeyStartFailure;`)();
}

const passkeyStartFailure = loadFailureBuilder();
const RAW_CODE = /^could_not_start \(\d+/;

test('the message a customer reads is a sentence, never the raw code', () => {
  for (const [status, serverError] of [[400, 'invalid_email'], [400, null], [429, 'rate_limited'],
    [500, 'internal'], [502, 'relay_unreachable'], [503, null]]) {
    const e = passkeyStartFailure(status, serverError);
    assert.doesNotMatch(e.message, RAW_CODE, `${status}/${serverError}: the code may not be the message`);
    assert.ok(e.message.length > 40, `${status}/${serverError}: too short to say anything: ${e.message}`);
    assert.match(e.message, /[.]$/, `${status}/${serverError}: must be a finished sentence`);
  }
});

test('every message names something the customer can do next', () => {
  const NEXT_STEP = /another device|6-digit code|try again|Reload this page|setup link/i;
  for (const [status, serverError] of [[400, 'invalid_email'], [400, 'unforeseen'], [429, 'rate_limited'],
    [500, 'internal'], [502, 'relay_unreachable']]) {
    const e = passkeyStartFailure(status, serverError);
    assert.match(e.message, NEXT_STEP, `${status}/${serverError} leaves the customer nowhere: ${e.message}`);
  }
});

test('the technical code survives, alongside the sentence and not instead of it', () => {
  const e = passkeyStartFailure(400, 'invalid_email');
  assert.equal(e.techCode, 'could_not_start (400 invalid_email)');
  assert.equal(passkeyStartFailure(502).techCode, 'could_not_start (502)');
  assert.notEqual(e.techCode, e.message, 'the code is the second line, not the message');
});

test('an unforeseen failure points at the exit that is known to still work', () => {
  // The report is exactly this case: the primary call failed and the
  // cross-device link worked. A generic answer has to say so.
  const e = passkeyStartFailure(418, 'something_new');
  assert.match(e.message, /My passkey is on another device/,
    'the fallback must name the cross-device route');
  assert.match(e.message, /6-digit code/, 'and the code route');
});

test('creating a passkey is not offered the sign-in exits', () => {
  // The setup and account screens have neither the cross-device link nor the
  // 6-digit field, so pointing at them sends somebody looking for a button
  // that is not on the page.
  const e = passkeyStartFailure(500, 'internal', 'create');
  assert.doesNotMatch(e.message, /another device|6-digit code/);
  assert.match(e.message, /Reload this page|authenticator app/);
});

test('the sentence quotes the label that is actually on the login page', () => {
  const quoted = passkeyStartFailure(418, null).message.match(/“([^”]+)”/);
  assert.ok(quoted, 'the fallback quotes a control by name');
  assert.ok(loginHtml.includes(`>${quoted[1]}<`),
    `/auth/login has no control labelled "${quoted[1]}"`);
});

test('no start failure is rendered as a bare code anywhere in passkey.js', () => {
  const offenders = source.split('\n')
    .map((line, i) => [i + 1, line])
    .filter(([, line]) => /throw new Error\(\s*'could_not_start/.test(line)
      || /setStatus\([^)]*'could_not_start/.test(line));
  assert.deepEqual(offenders, [], `a raw code is still shown to a customer:\n${offenders.join('\n')}`);
});

test('the status line renders the code as a node, never as markup', () => {
  // script-src 'self' with no inline script: the second line is built with
  // createElement/textContent, and innerHTML has no business in setStatus.
  const fn = source.slice(source.indexOf('function setStatus'), source.indexOf('// Why the passkey prompt'));
  assert.match(fn, /createElement\('span'\)/);
  assert.match(fn, /code\.textContent = techCode/);
  assert.doesNotMatch(fn, /innerHTML/, 'setStatus may not build markup from a string');
});
