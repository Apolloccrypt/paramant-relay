'use strict';
// The two passkey start calls the login page can make, against a real admin.
//
// THE REPORT (2026-09-04, iPhone/Safari, paramant.app/auth/login). With the
// email address filled in, the blue "Sign in with a passkey" button answered
// "could_not_start (400)" in the error box. The link right under it, "My
// passkey is on another device", worked on the first tap: Face ID, signed in.
// Same phone, same account, same page load.
//
// WHAT SEPARATES THE TWO. /login/options is the only passkey route that reads a
// typed field; /login/discoverable/options sends an empty body and cannot fail
// on one. And the ONLY 400 the whole of /login/options can produce is
// invalid_email, so the address that left the phone did not pass its shape
// check. This suite pins that: the shapes a phone keyboard and an autofill
// entry produce (a no-break space or a zero-width space inside the address, a
// newline from a paste, the "Name <addr>" display form) now start the ceremony
// with the account's real credential ids, and the contrast with the
// cross-device route is asserted in the same run.
//
// It also pins what the process log may say when a request IS refused: which
// check failed and the shape of what arrived, never the address.
//
// Sabotage that must turn this red (each verified before commit):
//   1. drop webauthn.normalizeLoginEmail back to .toLowerCase().trim()
//   2. put the address (or its domain) into the refusal log line
//   3. let a bare "not-an-address" through into a ceremony
//   4. give the decoy back its truncated id (webauthn.scopeHash) or drop its
//      transports field, either of which makes the two branches tell apart
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/passkey-login-options.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, summary } = require('./_admin-server');
const wa = require('../lib/webauthn');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const RUN = crypto.randomBytes(5).toString('hex');
const OWNER_KEY = `pgp_passkey_owner_${RUN}`;
const OWNER_EMAIL = `passkey_${RUN}@example.com`;
// A credential id in the shape the relay stores them: base64url, no padding.
// 32 bytes, which is what a platform authenticator produces and what the route's
// decoy is fixed at. The length matters to the shape assertion below: a fixture
// of some other size would be measuring the fixture instead of the decoy.
const CRED_ID = crypto.randomBytes(32).toString('base64url');

// Its own /8 per run: the per-IP window on /login/options is fifteen minutes
// and thirty hits wide, and a rerun inside that window must not inherit them.
const NET = 20 + Math.floor(Math.random() * 200);
let _ipN = 0;
const nextIp = () => { _ipN++; return `${NET}.${(_ipN >> 8) & 255}.${_ipN & 255}.9`; };

let srv = null;
let relay = null;
let redisClient = null;
let checks = 0;
const did = () => { checks++; };

before(async () => {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    // Same doctrine as login-http.test.js: an unmet precondition is declared by
    // name on the runner or it is a hard failure. A silent pass over nothing is
    // worse than red.
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log('  SKIP [redis] - the "redis" module is not installed (declared via ADMIN_TEST_SKIP)');
      return;
    }
    throw new Error(
      'unmet precondition "redis": the redis module is not installed, so this suite\n' +
      '  cannot boot an admin. Run npm ci in admin/, or, if this job is deliberately\n' +
      '  without it, say so on the runner: ADMIN_TEST_SKIP=redis');
  }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log(`  SKIP [redis] - no reachable redis at ${url} (declared via ADMIN_TEST_SKIP)`);
      return;
    }
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  redisClient = rc;

  const state = defaultRelayState([{ key: OWNER_KEY, email: OWNER_EMAIL, active: true }]);
  // One account with one passkey on it, so a started ceremony is telling apart
  // from the decoy the route hands to an address it does not know.
  state.webauthnCredentials = {
    [OWNER_KEY]: [{ credId: CRED_ID, transports: ['internal', 'hybrid'], counter: 0 }],
  };
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay });
});

after(async () => {
  await killAll();
  if (redisClient) { try { await redisClient.disconnect(); } catch (_) { /* already gone */ } }
  summary('passkey-login-options', checks);
});

const ready = () => srv !== null;

function options(body) {
  return srv.post('/api/user/auth/webauthn/login/options', { headers: { 'X-Real-IP': nextIp() }, body });
}

// Did the answer offer THIS account's passkey, or the stable decoy the route
// gives an address it cannot place? That difference is the whole ceremony.
function offersOwnerCredential(res) {
  const list = res.json && res.json.options && res.json.options.allowCredentials;
  return Array.isArray(list) && list.some((c) => c.id === CRED_ID);
}

test('the address a phone sends still starts the ceremony', async (t) => {
  if (!ready()) return t.skip('no redis');
  // Each of these renders on screen as the address the owner typed. Every one
  // of them was a 400 before, and the customer was told "could_not_start (400)".
  const fromAPhone = {
    'plain address': OWNER_EMAIL,
    'trailing space': `${OWNER_EMAIL} `,
    'trailing no-break space': `${OWNER_EMAIL} `,
    'leading and trailing no-break space': ` ${OWNER_EMAIL} `,
    'zero-width space at the end': `${OWNER_EMAIL}​`,
    'zero-width space in the middle': OWNER_EMAIL.replace('@', '​@'),
    'no-break space in the middle': OWNER_EMAIL.replace('@', '@ '),
    'newline from a paste': `${OWNER_EMAIL}\n`,
    'tab from a paste': `\t${OWNER_EMAIL}`,
    'byte order mark': `﻿${OWNER_EMAIL}`,
    'contact-card display form': `Mick <${OWNER_EMAIL}>`,
    'shouted by autocapitalisation': OWNER_EMAIL.toUpperCase(),
  };
  for (const [what, value] of Object.entries(fromAPhone)) {
    const r = await options({ email: value });
    assert.equal(r.status, 200, `${what}: expected a ceremony, got ${r.status} ${r.text}`);
    assert.ok(offersOwnerCredential(r),
      `${what}: the answer must offer the account's own credential, got ${JSON.stringify(r.json.options.allowCredentials)}`);
  }
  did();
});

test('a challenge is still one-shot and account-scoped, not a static answer', async (t) => {
  if (!ready()) return t.skip('no redis');
  const a = await options({ email: OWNER_EMAIL });
  const b = await options({ email: ` ${OWNER_EMAIL}` });
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  assert.notEqual(a.json.flowId, b.json.flowId, 'two starts must not share a flow id');
  assert.notEqual(a.json.options.challenge, b.json.options.challenge, 'two starts must not share a challenge');
  assert.match(a.json.options.rpId || a.json.options.rpID || '', /\S/, 'the options must carry an rpId');
  did();
});

test('input that names no mailbox is still refused, and says so once', async (t) => {
  if (!ready()) return t.skip('no redis');
  // Normalisation is not permission: what is left after it still has to be an
  // address, or there is nothing to look a passkey up by.
  for (const value of ['', 'not-an-address', 'no-at-sign.example.com', 'a@nodot', '@example.com', ' ​', 'a@b@c.com']) {
    const r = await options({ email: value });
    assert.equal(r.status, 400, `${JSON.stringify(value)} must be refused, got ${r.status}`);
    assert.equal(r.json && r.json.error, 'invalid_email');
  }
  const missing = await options({});
  assert.equal(missing.status, 400, 'a body without an email field is refused');
  did();
});

test('the refusal is logged with the shape of the input and nothing about the person', async (t) => {
  if (!ready()) return t.skip('no redis');
  const marker = `zzz_${crypto.randomBytes(4).toString('hex')}`;
  await options({ email: `${marker} not an address` });
  // The admin writes to stdout/stderr; the harness collects both.
  const log = srv.log();
  assert.ok(log.includes('[webauthn/login/options] refused invalid_email'),
    `the refusal must leave a diagnostic line, got:\n${log.slice(-1200)}`);
  assert.ok(!log.includes(marker), 'the log may not carry any part of what was typed');
  assert.ok(!log.includes(OWNER_EMAIL), 'the log may not carry the account address');
  assert.doesNotMatch(log, /[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,
    'no plaintext address may reach the process log');
  did();
});

test('a known and an unknown address are answered in the same shape', async (t) => {
  if (!ready()) return t.skip('no redis');
  // The PROPERTY, not the case. The comment at the top of the route promises a
  // "uniform response shape regardless of whether the email exists / has
  // passkeys ... so it is not an account-existence oracle". Until 2026-09-05 it
  // was not kept: the decoy carried a 16-byte id where a real credential is
  // full length, and no transports field where a real one always has one. Two
  // free answers to the question the route refuses to answer.
  //
  // What is asserted is the shape, never the content: the ids differ and must.
  // The same set of fields, and the same id length, on both branches.
  const unknownEmail = `absent_${crypto.randomBytes(6).toString('hex')}@example.com`;
  const known = await options({ email: OWNER_EMAIL });
  const unknown = await options({ email: unknownEmail });
  assert.equal(known.status, 200, known.text);
  assert.equal(unknown.status, 200, unknown.text);

  const real = known.json.options.allowCredentials;
  const decoy = unknown.json.options.allowCredentials;
  assert.ok(Array.isArray(real) && real.length >= 1, 'a known account is offered its own credentials');
  assert.ok(Array.isArray(decoy) && decoy.length >= 1, 'an unknown address is offered a decoy, not an empty list');
  assert.ok(!decoy.some((c) => c.id === CRED_ID), 'and the decoy is not the account credential itself');

  const fields = (c) => Object.keys(c).sort().join(',');
  assert.equal(fields(decoy[0]), fields(real[0]),
    `same field set on both branches; real=[${fields(real[0])}] decoy=[${fields(decoy[0])}]`);
  const idBytes = (c) => Buffer.from(String(c.id), 'base64url').length;
  assert.equal(idBytes(decoy[0]), idBytes(real[0]),
    `same credential-id length on both branches; real=${idBytes(real[0])}B decoy=${idBytes(decoy[0])}B`);
  assert.ok(Array.isArray(real[0].transports) && Array.isArray(decoy[0].transports),
    'transports is an array on both, present on both');

  // Stable per address: a decoy that changed between two starts would say, on
  // the second call, that it was a decoy.
  const again = await options({ email: unknownEmail });
  assert.equal(again.status, 200, again.text);
  assert.deepEqual(again.json.options.allowCredentials, decoy,
    'the same unknown address must be answered with the same decoy every time');
  did();
});

test('the cross-device route is the contrast: no address, no shape check', async (t) => {
  if (!ready()) return t.skip('no redis');
  const r = await srv.post('/api/user/auth/webauthn/login/discoverable/options', {
    headers: { 'X-Real-IP': nextIp() }, body: {},
  });
  assert.equal(r.status, 200, 'the cross-device start never depended on a typed field');
  assert.deepEqual(r.json.options.allowCredentials, [],
    'discoverable means an empty allowCredentials, so the browser offers its QR');
  // The report in one assertion: the same input that used to sink the primary
  // button has no bearing on this route at all.
  did();
});

// ── The pure part, without a server ─────────────────────────────────────────

test('normalizeLoginEmail strips what is invisible and nothing that names a mailbox', (t) => {
  assert.equal(wa.normalizeLoginEmail('  A@B.com  '), 'a@b.com');
  assert.equal(wa.normalizeLoginEmail('a​@b.com'), 'a@b.com');
  assert.equal(wa.normalizeLoginEmail('Mick <a@b.com>'), 'a@b.com');
  assert.equal(wa.normalizeLoginEmail(null), '');
  assert.equal(wa.normalizeLoginEmail(undefined), '');
  // What it must NOT do: two addresses that reach different mailboxes must
  // stay different. No dot-folding, no plus-tag stripping, no case folding of
  // anything but the ASCII case the RFC already treats as equal.
  assert.notEqual(wa.normalizeLoginEmail('a.b@gmail.com'), wa.normalizeLoginEmail('ab@gmail.com'));
  assert.notEqual(wa.normalizeLoginEmail('a+tag@b.com'), wa.normalizeLoginEmail('a@b.com'));
  assert.ok(wa.isLoginEmail('a@b.com'));
  assert.ok(!wa.isLoginEmail('a@b'));
  assert.ok(!wa.isLoginEmail(''));
  did();
});

test('loginEmailShape records facts about the input and none about the person', (t) => {
  const shape = wa.loginEmailShape('Mick <mick.bruinsma@example.com> ');
  assert.equal(typeof shape.len, 'number');
  assert.equal(shape.angled, true);
  assert.equal(shape.invisible, true);
  assert.equal(shape.normalised_ok, true);
  assert.equal(shape.changed_by_normalise, true);
  const line = JSON.stringify(shape);
  assert.ok(!line.includes('mick'), 'no part of the local part may appear');
  assert.ok(!line.includes('example.com'), 'not even the domain');
  assert.doesNotMatch(line, /[A-Za-z0-9._%+-]{2,}@/, 'nothing address-shaped at all');
  // A shape that would NOT have been refused before must say so, or the flag
  // proves nothing when it appears in a real log.
  assert.equal(wa.loginEmailShape('a@b.com').changed_by_normalise, false);
  assert.equal(wa.loginEmailShape('not-an-address').normalised_ok, false);
  did();
});
