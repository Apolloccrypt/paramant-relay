'use strict';
// THE SESSION CREDENTIAL GATE. A session cookie is a one-hour capability. What
// it can be exchanged for must not be a credential that never expires, and it
// must not work from a machine that never logged in.
//
// WHY THIS EXISTS. Finding 22i of the 2026-09-05 hostile review, and it is
// sharper than the review wrote it. The session record does not merely CARRY the
// account's raw pgp_ API key: the key IS the identity. Every mint site writes
//
//     { user_id: user.key, ..., primary_api_key: user.key }
//
// so `session.user_id === session.primary_api_key === the credential`. Removing
// the field would change nothing, because proxyApiKey falls back to user_id
// (admin/lib/account-keys.js). And `ip` and `ua` were written at login and then
// read only to be printed on the account screen; nothing compared them, so a
// lifted cookie worked from anywhere.
//
// WHAT IS REPAIRED HERE, AND WHAT IS NOT. The binding is: a session is refused
// from a client that is not the one that opened it, and the single route that
// turns a cookie into the raw key leaves an audit entry. What is NOT repaired is
// the identity itself. Minting sessions on an `acct_` id and resolving the key
// from the account record is a schema change across five mint sites, the
// account-keys module, the parasend token mint and every fixture in this
// directory. It is a change of its own and does not belong as a rider on a
// review round. This gate holds the surface flat in the meantime: exactly one
// route may hand the key out, and it is the one that has always done so.
//
// WHAT IT REQUIRES
//   K1  authUser compares the stored client against the request's, and refuses.
//   K2  exactly one route in the whole file returns revealKey(). A second one is
//       a second place a stolen cookie becomes a permanent credential.
//   K3  that route records the reveal.
//   K4  the binding is stamped, not enforced, on a record that predates it, so a
//       deploy does not log everybody out.
//
// Runs anywhere for the source rules; the behavioural half needs a redis and is
// declared through ADMIN_TEST_SKIP like the rest of this directory.

const { test, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');
const SRC = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

function authUserBody() {
  const at = SRC.indexOf('async function authUser(');
  assert.ok(at > 0, 'authUser is gone');
  return SRC.slice(at, SRC.indexOf('\n}\n', at));
}

test('authUser binds the session to the client that opened it', () => {
  const body = authUserBody();
  assert.match(body, /req\.get\('user-agent'\)/, 'authUser does not read the request user agent');
  assert.match(body, /sess\.ua !== ua/, 'authUser reads the stored client and never compares it');
  assert.match(body, /session_expired/, 'a mismatch does not end the session');
  // Stamped, not refused, when the record predates the field.
  assert.match(body, /typeof sess\.ua !== 'string'/, 'a record without a stored client is refused rather than stamped');
});

test('exactly one route hands the raw key to the browser', () => {
  const reveals = [];
  SRC.split('\n').forEach((l, i) => {
    if (/revealKey\s*\(/.test(l) && !/require\(|function revealKey/.test(l)) reveals.push(`admin/server.js:${i + 1} ${l.trim().slice(0, 90)}`);
  });
  assert.strictEqual(reveals.length, 1, `expected exactly one reveal, found ${reveals.length}:\n  ${reveals.join('\n  ')}`);
  assert.match(reveals[0], /res\.json\(revealKey\(req\.userSession\)\)/);
});

test('the reveal is recorded', () => {
  const at = SRC.indexOf('api.get("/user/account/key"');
  assert.ok(at > 0, 'the reveal route is gone');
  const route = SRC.slice(at, SRC.indexOf('\n});', at));
  assert.match(route, /logAuditEvent\([^)]*'account_key_revealed'/, 'the reveal leaves no mark');
  assert.match(route, /authUser/, 'the reveal route lost its authentication');
});

test('the proxy hands the key to a relay, never to a response body', () => {
  // proxyApiKey resolves the key for a server-to-server call. It must never end
  // up in something the browser reads, which is the shape that would quietly
  // add a second reveal route.
  const offenders = [];
  SRC.split('\n').forEach((l, i) => {
    if (!/proxyApiKey\s*\(/.test(l)) return;
    if (/res\.json\(|res\.send\(|return\s+\{/.test(l)) offenders.push(`admin/server.js:${i + 1} ${l.trim().slice(0, 90)}`);
  });
  assert.deepStrictEqual(offenders, [], `the account key is being written into a response:\n  ${offenders.join('\n  ')}`);
});

// ── behaviour, on a booted admin ─────────────────────────────────────────────

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const SUFFIX = crypto.randomBytes(4).toString('hex');
const ACCOUNT_KEY = `pgp_bind_${SUFFIX}`;
let rc = null;
let srv = null;
let relay = null;

before(async () => {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error('unmet precondition "redis": the redis module is not installed. Run npm ci in admin/, or declare it: ADMIN_TEST_SKIP=redis');
  }
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); }
  catch (e) {
    try { await c.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  rc = c;
  relay = await stubRelay(defaultRelayState([]));
  srv = await boot({ redisUrl: url, relay });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* already gone */ } }
});

async function plant(fields = {}) {
  const token = crypto.randomBytes(24).toString('hex');
  await rc.set(`paramant:user:session:${token}`, JSON.stringify({
    user_id: ACCOUNT_KEY, email: `bind-${SUFFIX}@example.test`,
    created_at: Date.now(), last_seen: Date.now(), ip: '203.0.113.9',
    primary_api_key: ACCOUNT_KEY, legacy_revealable: true, ...fields,
  }), { EX: 3600 });
  return token;
}

const ask = (token, ua) => fetch(`${srv.base}/api/user/account/key`, {
  headers: { Cookie: `paramant_user_session=${token}`, ...(ua ? { 'User-Agent': ua } : {}) },
});

test('over HTTP: the cookie works from the client that opened it', async () => {
  if (!srv) return;
  const token = await plant({ ua: 'Mozilla/5.0 (honest)' });
  const r = await ask(token, 'Mozilla/5.0 (honest)');
  assert.strictEqual(r.status, 200, `the owner was refused: ${r.status}`);
  assert.strictEqual((await r.json()).api_key, ACCOUNT_KEY);
});

test('over HTTP: the same cookie replayed from another client gets nothing', async () => {
  if (!srv) return;
  const token = await plant({ ua: 'Mozilla/5.0 (honest)' });
  const r = await ask(token, 'Mozilla/5.0 (thief)');
  assert.strictEqual(r.status, 401, `a lifted cookie still yields the key: ${r.status}`);
  const body = await r.text();
  assert.ok(!body.includes(ACCOUNT_KEY), 'the refusal leaked the key anyway');
  // And the session is gone, so the thief cannot retry with the right agent
  // once he notices.
  assert.strictEqual(await rc.get(`paramant:user:session:${token}`), null, 'a session used from a second client survived');
});

test('over HTTP: a record with no stored client is stamped and keeps working', async () => {
  if (!srv) return;
  const token = await plant();          // no `ua` at all, as an older record has
  const r = await ask(token, 'Mozilla/5.0 (deploy)');
  assert.strictEqual(r.status, 200, `a pre-existing session was logged out: ${r.status}`);
  const stored = JSON.parse(await rc.get(`paramant:user:session:${token}`));
  assert.strictEqual(stored.ua, 'Mozilla/5.0 (deploy)', 'the client was not stamped on the way through');
  // Stamped means bound from now on.
  assert.strictEqual((await ask(token, 'Mozilla/5.0 (thief)')).status, 401, 'the stamp did not start binding the session');
});
