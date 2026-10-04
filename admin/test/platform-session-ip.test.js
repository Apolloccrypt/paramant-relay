'use strict';
// The 2026-10-04 test round, admin half. Three things a signed-in customer ran
// into, each held over HTTP against a booted admin and a stub relay.
//
//   SLIDING    the cookie was set once with Max-Age=3600 and never again, so an
//              active person was logged out an hour after login and lost a
//              half-built signing request. Every authenticated call now re-issues
//              it with the lifetime the Redis record gets: one hour idle, twelve
//              hours at most (lib/session-client.js).
//   CLIENT     the session was bound to the exact user-agent string, so Safari's
//              "Request Desktop Website" or a browser update logged people out.
//              It is bound to the browser engine now. A different kind of client
//              is still refused.
//   CLIENT IP  every relay call the admin made for a customer arrived from the
//              admin container, so all customers shared the relay's per-IP sign
//              and view limits; and a relay 429 on activation came back as 403,
//              which the signing page reads as "a different email address".
//
// Needs a redis (REDIS_URL), like the rest of this directory.

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');
const sessionClient = require('../lib/session-client');

const DEFAULT_REDIS = 'redis://127.0.0.1:6379';
const SUFFIX = crypto.randomBytes(4).toString('hex');
const ACCOUNT_KEY = `pgp_plat_${SUFFIX}`;
const EMAIL = `plat-${SUFFIX}@example.test`;
const ORIGIN = 'http://127.0.0.1';

const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const IPHONE_DESKTOP = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15';
const CHROME_120 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const CHROME_121 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36';
const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0';
const CURL = 'curl/8.5.0';

let rc = null; let srv = null; let relay = null;

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
  const state = defaultRelayState([]);
  state.envelopeReply = null;
  state.route = (method, p) => {
    if (method === 'GET' && /^\/v2\/envelopes\/[A-Za-z0-9_-]+$/.test(p) && state.envelopeReply) return state.envelopeReply;
    return null;
  };
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } }
});

async function plant(fields = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:user:session:${token}`, JSON.stringify({
    user_id: ACCOUNT_KEY, email: EMAIL, created_at: Date.now(), last_seen: Date.now(),
    ip: '203.0.113.9', primary_api_key: ACCOUNT_KEY, legacy_revealable: true, ...fields,
  }), { EX: 3600 });
  return token;
}
const ask = (token, ua, path = '/api/user/account/key') => fetch(`${srv.base}${path}`, {
  headers: { Cookie: `paramant_user_session=${token}`, 'User-Agent': ua },
});
const maxAgeOf = (r) => {
  const m = /paramant_user_session=[0-9a-f]+;[^,]*Max-Age=(\d+)/.exec(r.headers.get('set-cookie') || '');
  return m ? Number(m[1]) : null;
};

// ── SLIDING ──────────────────────────────────────────────────────────────────

test('SLIDING: an authenticated call re-issues the cookie for another hour, record and cookie alike', async () => {
  if (!srv) return;
  const token = await plant({ ua: CHROME_120, created_at: Date.now() - 50 * 60 * 1000 });
  await rc.expire(`paramant:user:session:${token}`, 600);  // ten minutes left, as after 50 idle-free minutes
  const r = await ask(token, CHROME_120);
  assert.strictEqual(r.status, 200, `the owner was refused: ${r.status}`);
  assert.strictEqual(maxAgeOf(r), 3600, `the cookie was not slid: ${r.headers.get('set-cookie')}`);
  const ttl = await rc.ttl(`paramant:user:session:${token}`);
  assert.ok(ttl > 3500 && ttl <= 3600, `the record TTL is ${ttl}, not the cookie's hour`);
});

test('SLIDING: near the twelve-hour cap the cookie gets only what is left, never past it', async () => {
  if (!srv) return;
  const token = await plant({ ua: CHROME_120, created_at: Date.now() - (11.5 * 3600 * 1000) });
  const r = await ask(token, CHROME_120);
  assert.strictEqual(r.status, 200);
  const age = maxAgeOf(r);
  assert.ok(age > 1700 && age <= 1800, `Max-Age ${age}: half an hour was left of the twelve`);
  const ttl = await rc.ttl(`paramant:user:session:${token}`);
  assert.ok(Math.abs(ttl - age) <= 2, `record TTL ${ttl} and cookie ${age} drifted apart`);
});

test('SLIDING: past twelve hours the session ends, however active', async () => {
  if (!srv) return;
  const token = await plant({ ua: CHROME_120, created_at: Date.now() - (12 * 3600 * 1000 + 60000) });
  assert.strictEqual((await ask(token, CHROME_120)).status, 401);
  const v = await ask(await plant({ ua: CHROME_120, created_at: Date.now() - (12 * 3600 * 1000 + 60000) }), CHROME_120, '/api/user/session/verify');
  assert.strictEqual((await v.json()).authenticated, false, 'session/verify still called a capped session signed in');
});

test('SLIDING: session/verify, the call every page makes first, slides the cookie too', async () => {
  if (!srv) return;
  const token = await plant({ ua: CHROME_120, created_at: Date.now() - 30 * 60 * 1000 });
  const r = await ask(token, CHROME_120, '/api/user/session/verify');
  assert.strictEqual((await r.json()).authenticated, true);
  assert.strictEqual(maxAgeOf(r), 3600);
});

test('SLIDING: the lifetime rule itself', () => {
  const now = 1_800_000_000_000;
  assert.strictEqual(sessionClient.sessionLifetimeS(now, now), 3600);
  assert.strictEqual(sessionClient.sessionLifetimeS(now - 11 * 3600e3, now), 3600);
  assert.strictEqual(sessionClient.sessionLifetimeS(now - 11.75 * 3600e3, now), 900);
  assert.strictEqual(sessionClient.sessionLifetimeS(now - 13 * 3600e3, now), 1, 'never 0, which would delete the cookie on an allowed call');
});

// ── CLIENT ───────────────────────────────────────────────────────────────────

test('CLIENT: Safari "Request Desktop Website" keeps the session', async () => {
  if (!srv) return;
  const token = await plant({ ua: IPHONE });
  assert.strictEqual((await ask(token, IPHONE)).status, 200);
  const r = await ask(token, IPHONE_DESKTOP);
  assert.strictEqual(r.status, 200, `the desktop-site toggle logged the iPhone out: ${r.status}`);
  assert.ok(await rc.get(`paramant:user:session:${token}`), 'the session was deleted');
});

test('CLIENT: a browser update between two requests keeps the session', async () => {
  if (!srv) return;
  const token = await plant({ ua: CHROME_120 });
  assert.strictEqual((await ask(token, CHROME_121)).status, 200);
});

test('CLIENT: a cookie replayed from another kind of client is still refused and the session ends', async () => {
  if (!srv) return;
  for (const [from, to] of [[IPHONE, CURL], [CHROME_120, FIREFOX], [FIREFOX, IPHONE]]) {
    const token = await plant({ ua: from });
    assert.strictEqual((await ask(token, to)).status, 401, `${to} used a ${from} cookie`);
    assert.strictEqual(await rc.get(`paramant:user:session:${token}`), null, 'the session survived a client swap');
  }
});

test('CLIENT: the engine rule itself', () => {
  const f = sessionClient.clientFamily;
  assert.strictEqual(f(IPHONE), f(IPHONE_DESKTOP));
  assert.strictEqual(f(CHROME_120), f(CHROME_121));
  assert.notStrictEqual(f(CHROME_120), f(FIREFOX));
  assert.notStrictEqual(f(IPHONE), f(CHROME_120));
  assert.strictEqual(f('curl/8.5.0'), f('curl/8.9.1'), 'a non-browser is compared without its version');
  assert.notStrictEqual(f('curl/8.5.0'), f('python-requests/2.31'));
});

// ── CLIENT IP ────────────────────────────────────────────────────────────────

const activation = (token, extraHeaders = {}) => fetch(`${srv.base}/api/user/sign/activation`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Origin: ORIGIN, Cookie: `paramant_user_session=${token}`, 'User-Agent': CHROME_120, ...extraHeaders },
  body: JSON.stringify({ envelope_id: `env${SUFFIX}abcdefghijklmnopq`, party_index: 0, doc_hash: 'a'.repeat(64), invite_token: 'b'.repeat(43) }),
});

test('CLIENT IP: the admin names the customer to the relay, from X-Real-IP and never from the browser', async () => {
  if (!srv) return;
  relay.state.envelopeReply = { status: 404, body: { error: 'not_found' } };
  relay.state.calls.length = 0;
  const token = await plant({ ua: CHROME_120 });
  await activation(token, { 'X-Real-IP': '198.51.100.23', 'X-Paramant-Client-IP': '192.0.2.66' });
  const call = relay.state.calls.find((c) => c.path.startsWith('/v2/envelopes/'));
  assert.ok(call, 'the activation never asked the relay');
  assert.ok(call.headers['x-internal-auth'], 'the call lost its internal auth');
  assert.strictEqual(call.headers['x-paramant-client-ip'], '198.51.100.23',
    'the relay was not told the customer address, or was told the one the browser chose');
});

test('CLIENT IP: a relay 429 on activation stays a 429 with words, not "a different email address"', async () => {
  if (!srv) return;
  relay.state.envelopeReply = { status: 429, body: { error: 'Too many requests' }, headers: { 'Retry-After': '60' } };
  const token = await plant({ ua: CHROME_120 });
  const r = await activation(token, { 'X-Real-IP': '198.51.100.24' });
  assert.strictEqual(r.status, 429, `a rate limit came back as ${r.status}`);
  const body = await r.json();
  assert.strictEqual(body.error, 'rate_limited');
  assert.match(body.message, /minuut/);
  assert.strictEqual(r.headers.get('retry-after'), '60');
  // A relay that is down is not a verdict on the signer either.
  relay.state.envelopeReply = { status: 503, body: { error: 'down' } };
  const r2 = await activation(token, { 'X-Real-IP': '198.51.100.24' });
  assert.strictEqual(r2.status, 502);
  // An answer about the invitation itself stays what it was.
  relay.state.envelopeReply = { status: 404, body: { error: 'not_found' } };
  const r3 = await activation(token, { 'X-Real-IP': '198.51.100.24' });
  assert.strictEqual(r3.status, 403);
});
