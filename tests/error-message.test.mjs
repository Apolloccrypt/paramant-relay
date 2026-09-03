// The sentence a customer reads when something we did not plan for breaks.
//
// The signing flow translated three TOTP failures into their own words and
// rethrew everything else untouched. That rethrow is the whole bug: the errors
// that reach it come from _postJSON in js/parasign-signer.js, whose message is
// the relay's error field or 'http_' + status, and from fetch itself, which
// rejects with a TypeError whose message is whatever the browser calls a lost
// connection. So a buyer halfway through signing a contract was shown
// "http_502", or "Load failed", and told nothing about what to do with it.
//
// This runs the translator, not the page: node builtins only, no browser, so it
// lands in the "Root integration suites" CI job and costs a millisecond. The
// case that matters is the one nobody wrote a branch for, so the TypeError is
// the first test here.
//
// Sabotage that must turn this red (all four verified before commit):
//   1. put `throw e` back in enrolEphemeralSigningKeyWithTotp
//   2. return error.message from userFacingMessage instead of the constant
//   3. drop 'privacy@paramant.app' or the "Try again in a minute" step
//   4. let parashare.page.js print e.message again
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
// Required, not imported: frontend/js/error-message.js is the same UMD factory
// shape as js/parasign-pdf-ops.js, so the browser, a classic <script> and this
// suite all read the one file rather than three copies of one sentence.
const errors = require('../frontend/js/error-message.js');
const readSource = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

test('a thrown TypeError comes out as the fixed sentence, not its own message', () => {
  const thrown = (() => { try { null.signature; } catch (e) { return e; } })();
  assert.ok(thrown instanceof TypeError, 'the fixture must be a real TypeError');
  assert.equal(errors.userFacingMessage(thrown), errors.SUPPORT_FAILURE_MESSAGE);
  assert.doesNotMatch(errors.userFacingMessage(thrown), /signature|null|undefined/i,
    'the browser\'s own words about a TypeError may never reach the customer');
});

test('the fixed sentence says it is not the customer\'s fault, what to do now, and who to reach', () => {
  const sentence = errors.SUPPORT_FAILURE_MESSAGE;
  assert.match(sentence, /on our side/, 'it must not read as the customer having done something wrong');
  assert.match(sentence, /Try again in a minute/, 'it must give the next step');
  assert.match(sentence, /privacy@paramant\.app/, 'it must name a route to a human');
  assert.match(sentence, /the time and what you did/, 'it must say what to put in that mail');
});

test('every shape that is not a planned failure lands on the same sentence', () => {
  const relay500 = Object.assign(new Error('http_500'), { status: 500 });
  const relayJson = Object.assign(new Error('internal_error'), { status: 500, data: { error: 'internal_error' } });
  const offline = new TypeError('Failed to fetch');
  const nonsense = { toString() { return 'not an Error at all'; } };
  for (const error of [relay500, relayJson, offline, nonsense, null, undefined, 'a bare string']) {
    assert.equal(errors.userFacingMessage(error), errors.SUPPORT_FAILURE_MESSAGE,
      `${String(error)} must not get a message of its own`);
  }
});

test('the three planned failures keep their own instruction', () => {
  assert.match(errors.userFacingMessage({ code: 'totp_invalid' }), /current 6-digit code/);
  assert.match(errors.userFacingMessage({ code: 'totp_required' }), /Enter the 6-digit code/);
  assert.match(errors.userFacingMessage({ code: 'totp_unavailable' }), /authenticator app on your account/);
  assert.equal(errors.isKnownFailure({ code: 'nonesuch' }), false);
});

test('reportFailure logs the technical detail and hands back a safe error', () => {
  const original = console.error;
  const logged = [];
  console.error = (...args) => logged.push(args);
  let replacement;
  try {
    replacement = errors.reportFailure('signing-key enrolment', Object.assign(new Error('http_502'), { status: 502 }));
  } finally {
    console.error = original;
  }
  assert.equal(replacement.message, errors.SUPPORT_FAILURE_MESSAGE);
  assert.equal(replacement.code, 'service_error');
  assert.equal(replacement.cause.message, 'http_502', 'the original must survive for a debugger');
  assert.equal(logged.length, 1, 'exactly one console line per failure');
  assert.match(String(logged[0][0]), /signing-key enrolment/, 'the log line names the step that broke');
  assert.equal(logged[0][1].message, 'http_502', 'the technical detail goes to the console, not the screen');
});

test('a planned failure keeps its code and its words through reportFailure', () => {
  const original = console.error;
  console.error = () => {};
  let replacement;
  try {
    replacement = errors.reportFailure('signing-key enrolment', Object.assign(new Error('whatever'), { code: 'totp_invalid' }));
  } finally {
    console.error = original;
  }
  assert.equal(replacement.code, 'totp_invalid');
  assert.match(replacement.message, /current 6-digit code/);
});

// ── the callers, so the translator cannot be right and unused ────────────────

test('the signer no longer rethrows the error it caught', () => {
  const signer = readSource('frontend/js/parasign-signer.js');
  assert.match(signer, /paramantErrors\.reportFailure\('signing-key enrolment', e\)/,
    'enrolEphemeralSigningKeyWithTotp must hand its unplanned failures to the translator');
  const enrol = signer.slice(signer.indexOf('export async function enrolEphemeralSigningKeyWithTotp'));
  assert.doesNotMatch(enrol.slice(0, enrol.indexOf('\n}\n')), /^\s*throw e;\s*$/m,
    'a bare `throw e` puts the wire\'s own words back in front of the customer');
});

test('both signing surfaces render the translated sentence instead of a passkey guess', () => {
  for (const file of ['frontend/sign-flow.js', 'frontend/co-sign.js']) {
    assert.match(readSource(file), /e\.code === 'service_error'/,
      `${file} must have a branch for the error the signer now throws, or it falls through to the passkey message`);
  }
});

test('ParaSend prints the same sentence and keeps no raw message on screen', () => {
  const page = readSource('frontend/js/parashare.page.js');
  assert.doesNotMatch(page, /textContent = 'Error: ' \+ e\.message/,
    'parashare.page.js must not put a raw error message on screen');
  // Written without the separator the old line used: it was an em-dash, and
  // scripts/check-commit-style.sh refuses one in an added line, quote or not.
  assert.doesNotMatch(page, /receiver message[^']*' \+ err\.message/,
    'parashare.page.js must not put a raw error message on screen');
  assert.match(page, /failureText\(/, 'parashare.page.js must route its failures through the shared translator');
  assert.match(page, new RegExp(errors.SUPPORT_FAILURE_MESSAGE.split(';')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    'the ParaSend fallback string must be the same sentence, character for character');
  assert.match(readSource('frontend/parashare.html'), /<script src="\/js\/error-message\.js\?v=\d+" defer><\/script>/,
    'parashare.html must load the file the page reads window.paramantErrors from');
});
