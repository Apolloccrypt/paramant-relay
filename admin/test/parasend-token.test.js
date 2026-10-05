'use strict';
// POST /api/user/parasend/token, on a really booted admin/server.js.
//
// WHY THIS SUITE EXISTS. keys-session.test.js next door is a pure-logic test of
// admin/lib/account-keys.js, and it is the right shape for a decision. This is
// not a decision, it is a boundary: the browser asks for a credential, the
// admin fetches it from the relay with headers no browser has, and hands back
// strictly less than it received. Every one of those properties is a property
// of a REQUEST, so this suite spawns the real server, gives it a real redis for
// its session store, and puts a stub relay behind it that records exactly what
// the admin sent.
//
// What is asserted, and why each line earns its place:
//   * no session is 401, before the relay is touched at all. The relay is
//     reachable in this suite, so a route that leaked would leak here;
//   * a signed-in browser gets a token, and NOTHING else. Not the api-key, not
//     alongside it, not in a field nobody reads. That is the entire feature;
//   * the admin authenticates to the relay with the SESSION's key plus the
//     internal header, and takes no account id from the request. A body naming
//     someone else's account changes nothing;
//   * a relay that refuses, breaks, or cannot be reached is passed through as a
//     status the page can act on, with the relay's own words dropped;
//   * and the fallback that must never exist: no failure path returns the key.
//
// Verified by sabotage: return `api_key` next to the token and two cases go
// red; read the account from req.body and the "a body cannot name an account"
// case goes red; drop the X-Internal-Auth header and the stub records a mint
// without it; relay 503 turned into a 200 with the key fails the outage case.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/parasend-token.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, summary } = require('./_admin-server');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const INTERNAL = 'internal-token-for-the-parasend-token-suite';
const SUFFIX = crypto.randomBytes(6).toString('hex');
const ACCOUNT_KEY = `pgp_account_key_for_the_parasend_suite_${SUFFIX}`;
const OTHER_KEY = `pgp_other_account_key_${SUFFIX}`;
const MINTED = `pst_${'a'.repeat(64)}`;

let redis = null;
let srv;
let relay;
let checks = 0;
const did = () => { checks++; };

// A redis for the admin's session store, and for planting a session directly.
// Logging in through the real flow would need TOTP and a captcha and would
// measure the login, not this route.
async function connectRedis() {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    throw new Error(`unmet precondition "redis": the "redis" module is not installed: ${e.message}\n` +
      '  Run npm ci in admin/, or, if this job is deliberately without it: ADMIN_TEST_SKIP=redis');
  }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); return rc; }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* already gone */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').map(s => s.trim()).includes('redis')) return null;
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}\n` +
      '  Give the job a redis service, or: ADMIN_TEST_SKIP=redis');
  }
}

// A session in the store, the shape admin/server.js writes at login.
async function session(key = ACCOUNT_KEY) {
  const token = crypto.randomBytes(24).toString('hex');
  await redis.set(`paramant:user:session:${token}`, JSON.stringify({
    user_id: key, email: `owner-${SUFFIX}@example.com`,
    primary_api_key: key, legacy_revealable: true,
  }), { EX: 3600 });
  return { Cookie: `paramant_user_session=${token}` };
}

// The stub answers /v2/session-token as the relay does, and `mintReply` lets a
// test hand the admin any of the answers a real relay can give.
function relayState() {
  const state = defaultRelayState([]);
  state.mintReply = () => ({ status: 200, body: { ok: true, token: MINTED, expires_ms: Date.now() + 900_000, expires_in_s: 900 } });
  return state;
}

before(async () => {
  redis = await connectRedis();
  if (!redis) return;
  relay = await stubRelay(relayState());
  // The stub answers the mint through state.mintReply, which relayState() set
  // above, so no other suite in this directory sees the route at all.
  srv = await boot({
    redisUrl: process.env.REDIS_URL || DEFAULT_REDIS,
    relay,
    internalToken: INTERNAL,
    env: { RELAY_HEALTH: relay.base },
  });
});

after(async () => {
  await killAll();
  if (redis) { try { await redis.disconnect(); } catch (_) { /* already gone */ } }
  summary('parasend-token', checks);
});

const mint = (headers = {}) => srv.post('/api/user/parasend/token', { headers });
const mintApp = (headers = {}) => srv.post('/api/user/app/token', { headers });
const mintCalls = () => relay.state.calls.filter(c => c.path === '/v2/session-token');

test('no session is 401, and the relay is never asked', async (t) => {
  if (!redis) return t.skip('no redis');
  const before = mintCalls().length;
  const r = await mint();
  assert.strictEqual(r.status, 401);
  assert.deepStrictEqual(r.json, { error: 'unauthenticated' });
  assert.strictEqual(mintCalls().length, before,
    'an unauthenticated caller must not cause a mint: the relay is reachable in this suite, so a leak would leak here');

  // A cookie that names no live session is the same 401, one word different,
  // and still no mint.
  const dead = await mint({ Cookie: `paramant_user_session=${crypto.randomBytes(24).toString('hex')}` });
  assert.strictEqual(dead.status, 401);
  assert.strictEqual(mintCalls().length, before);
  did();
});

test('THE POINT: a signed-in browser gets a token, and the api-key is nowhere in the answer', async (t) => {
  if (!redis) return t.skip('no redis');
  const r = await mint(await session());
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.token, MINTED);
  assert.strictEqual(r.json.expires_in_s, 900);
  assert.ok(!r.text.includes(ACCOUNT_KEY),
    'the response carries the account key. This route exists so that it cannot.');
  assert.ok(!r.text.includes('pgp_'), 'nothing shaped like an api-key may leave this route');
  // Strictly less than the relay handed over: no relay internals, no expires_ms
  // the page has no use for, no ok flag it does not read.
  assert.deepStrictEqual(Object.keys(r.json).sort(), ['expires_in_s', 'token']);
  assert.match(r.headers['cache-control'] || '', /no-store/,
    'a bearer credential must not be cached by a proxy or a back button');
  did();
});

test('the admin authenticates to the relay with the SESSION key plus the internal header', async (t) => {
  if (!redis) return t.skip('no redis');
  relay.state.calls.length = 0;
  const r = await mint(await session());
  assert.strictEqual(r.status, 200, r.text);
  const call = mintCalls().at(-1);
  assert.ok(call, 'the admin must actually ask the relay');
  assert.strictEqual(call.method, 'POST');
  assert.strictEqual(call.headers['x-api-key'], ACCOUNT_KEY,
    'the relay must be told which account, and told it by the server from the session');
  assert.strictEqual(call.headers['x-internal-auth'], INTERNAL,
    'without the internal header the relay refuses, and a route that forgot it would fail closed but silently');
  did();
});

test('a body cannot name an account: the session decides, always', async (t) => {
  if (!redis) return t.skip('no redis');
  relay.state.calls.length = 0;
  const r = await srv.post('/api/user/parasend/token', {
    headers: await session(),
    body: { user_id: OTHER_KEY, account_id: OTHER_KEY, key: OTHER_KEY },
  });
  assert.strictEqual(r.status, 200, r.text);
  const call = mintCalls().at(-1);
  assert.strictEqual(call.headers['x-api-key'], ACCOUNT_KEY,
    'a browser named another account and the admin passed it on. The account is the session, and only the session.');
  did();
});

// ── The second route: the signed-in app pages ────────────────────────────────
// /pricing and /dashboard stopped fetching the account's pgp_ key and mint a
// token of their own. It is a SECOND route rather than a parameter on the first
// one, because a purpose the browser could name is a purpose the browser could
// change: a script on /parashare would ask for an `app` token and start a
// checkout with it. The word is fixed by the route, and the body is still
// ignored.

test('the app route mints with purpose app, and the browser never chooses that word', async (t) => {
  if (!redis) return t.skip('no redis');
  relay.state.calls.length = 0;
  const r = await mintApp(await session());
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.token, MINTED);
  assert.deepStrictEqual(Object.keys(r.json).sort(), ['expires_in_s', 'token'],
    'the app route answers exactly what the ParaSend one does: a token and its life, nothing else');
  assert.ok(!r.text.includes('pgp_'), 'nothing shaped like an api-key may leave this route either');

  const call = mintCalls().at(-1);
  assert.ok(call, 'the admin must actually ask the relay');
  assert.strictEqual(call.headers['x-api-key'], ACCOUNT_KEY);
  assert.strictEqual(call.headers['x-internal-auth'], INTERNAL);
  assert.deepStrictEqual(call.body, { purpose: 'app' },
    'the purpose the relay is asked for must be the route\'s own word');
  did();
});

test('the ParaSend route still asks for the ParaSend purpose, and a body cannot change either', async (t) => {
  if (!redis) return t.skip('no redis');
  relay.state.calls.length = 0;
  await mint(await session());
  assert.deepStrictEqual(mintCalls().at(-1).body, { purpose: 'parasend' });

  // A browser trying to name the other purpose on either route gets its own
  // route's word, not the one it asked for. This is the whole reason the
  // purpose is not a parameter.
  for (const [path, expected] of [['/api/user/parasend/token', 'parasend'], ['/api/user/app/token', 'app']]) {
    relay.state.calls.length = 0;
    const r = await srv.post(path, { headers: await session(), body: { purpose: 'admin' } });
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(mintCalls().at(-1).body, { purpose: expected },
      `${path} passed on a purpose the caller supplied`);
  }
  did();
});

test('the app route needs a session too: no cookie, no token, no mint', async (t) => {
  if (!redis) return t.skip('no redis');
  const before = mintCalls().length;
  const r = await mintApp();
  assert.strictEqual(r.status, 401);
  assert.deepStrictEqual(r.json, { error: 'unauthenticated' });
  assert.strictEqual(mintCalls().length, before, 'an unauthenticated caller must not cause a mint');
  did();
});

test('a relay that refuses is passed through as a status, without its words', async (t) => {
  if (!redis) return t.skip('no redis');
  for (const status of [401, 403]) {
    relay.state.mintReply = () => ({ status, body: { error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' } });
    const r = await mint(await session());
    assert.strictEqual(r.status, status, `a relay ${status} must reach the page as ${status}`);
    assert.deepStrictEqual(r.json, { error: 'token_unavailable' });
    assert.ok(!/X-Api-Key/.test(r.text),
      'the relay writes for an operator reading a log; that text must not land on a page anyone can open');
  }
  relay.state.mintReply = relayState().mintReply;
  did();
});

test('a store outage reaches the page as 503, so the retry is a retry and not a re-login', async (t) => {
  if (!redis) return t.skip('no redis');
  relay.state.mintReply = () => ({ status: 503, body: { error: 'redis_unavailable' } });
  const r = await mint(await session());
  assert.strictEqual(r.status, 503, r.text);
  assert.deepStrictEqual(r.json, { error: 'token_unavailable' });
  assert.ok(!r.text.includes(ACCOUNT_KEY),
    'NO FALLBACK. Handing the key over when the mint fails would put the credential back in the browser on exactly the days something is already wrong.');
  relay.state.mintReply = relayState().mintReply;
  did();
});

test('a 200 with no token in it is a bad gateway, not a success', async (t) => {
  if (!redis) return t.skip('no redis');
  for (const body of [{}, { ok: true }, { token: '' }, { token: null }]) {
    relay.state.mintReply = () => ({ status: 200, body });
    const r = await mint(await session());
    assert.strictEqual(r.status, 502, `a 200 carrying ${JSON.stringify(body)} answered ${r.status}`);
    assert.deepStrictEqual(r.json, { error: 'token_unavailable' });
  }
  relay.state.mintReply = relayState().mintReply;
  did();
});

test('a relay that cannot be reached at all is 502, and says so once', async (t) => {
  if (!redis) return t.skip('no redis');
  const offline = await boot({
    redisUrl: process.env.REDIS_URL || DEFAULT_REDIS,
    internalToken: INTERNAL,
    // Nothing listens here. RELAY_HEALTH is what this route calls.
    env: { RELAY_HEALTH: 'http://127.0.0.1:1' },
  });
  t.after(() => offline.stop());
  const r = await offline.post('/api/user/parasend/token', { headers: await session() });
  assert.strictEqual(r.status, 502, r.text);
  assert.deepStrictEqual(r.json, { error: 'relay_unreachable' });
  did();
});

test('the reveal route still exists: the manual way out is not collateral damage', async (t) => {
  if (!redis) return t.skip('no redis');
  // /parashare no longer calls it, but a self-hoster and the account page do,
  // and removing it while removing its caller would be a silent breakage.
  const r = await srv.get('/api/user/account/key', { headers: await session() });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.api_key, ACCOUNT_KEY);
  assert.strictEqual(r.json.revealable, true);
  did();
});
