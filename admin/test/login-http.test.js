'use strict';
// The login limiter, attempted for real against a booted admin.
//
// WHY THIS SUITE EXISTS. login-ratelimit.test.js pins the module and the source
// order, and both are worth having, but neither runs the handler. Its
// attemptLogin() is a reimplementation of the decision written inside the test
// file: it can pass while the real route is wrong, because the real route is
// not what it calls. The reviewer's objection was exactly that, and the
// scenario they described is a request-level one:
//
//     ten wrong codes on address X from three IP addresses,
//     then the owner, with a proof-of-work, gets a session.
//
// That property depends on the real express handler, the real limiter, real
// redis keys, a real proof-of-work challenge and the order express runs them
// in. So this suite starts admin/server.js, points it at a stub relay, and
// speaks HTTP to it. See _admin-server.js for what is real and what is not.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/login-http.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, solvePow, summary } = require('./_admin-server');

const HTTP_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const HTTP_SECRET = '123456';
// One account per run. The failure counter that decides whether an address owes
// a proof-of-work lives in redis for fifteen minutes and is shared with every
// other suite pointed at the same server, so a fixed address inherits their
// failures and starts answering 428 in the middle of a run.
const HTTP_RUN = crypto.randomBytes(5).toString('hex');
const HTTP_OWNER_KEY = `pgp_owner_account_for_the_login_http_suite_${HTTP_RUN}`;
const HTTP_OWNER_EMAIL = `owner_${HTTP_RUN}@example.com`;
// login-ratelimit.js: five per IP in fifteen minutes, ten failures before the
// address has to carry a proof-of-work.
const HTTP_IP_LIMIT = 5;
const HTTP_POW_THRESHOLD = 10;

let httpSrv = null;
let httpRelay = null;
let httpRedis = null;
let httpChecks = 0;
const httpDid = () => { httpChecks++; };

// Its own /8 per run, so the fifteen-minute per-IP counters left behind by the
// last run of this suite cannot refuse the first request of this one.
const HTTP_NET = 20 + Math.floor(Math.random() * 200);
let _ipN = 0;
const nextIp = () => { _ipN++; return `${HTTP_NET}.${(_ipN >> 8) & 255}.${_ipN & 255}.7`; };

// A fresh address per test. The failure counter has a fifteen-minute window and
// no test may inherit another's score.
const freshEmail = () => `user_${crypto.randomBytes(6).toString('hex')}@example.com`;

before(async () => {
  const url = process.env.REDIS_URL || HTTP_DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    // Same doctrine as relay/test/_requires.js: a precondition the suite cannot
    // meet is a hard failure, not a silent pass over nothing. The admin unit
    // job runs without npm ci on purpose, so it has to say so by name.
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
  httpRedis = rc;

  httpRelay = await stubRelay(defaultRelayState(
    [{ key: HTTP_OWNER_KEY, email: HTTP_OWNER_EMAIL, active: true }], HTTP_SECRET));
  httpSrv = await boot({ redisUrl: url, relay: httpRelay });
  // The account has its second factor switched on, which is what makes a login
  // reach the relay at all.
  await httpRedis.set(`paramant:user:totp_active:${HTTP_OWNER_KEY}`, 'true');
});

after(async () => {
  await killAll();
  if (httpRedis) { try { await httpRedis.disconnect(); } catch (_) { /* already gone */ } }
  summary('login-http', httpChecks);
});

const ready = () => httpSrv !== null;

// Add an account to the stub relay's table for the duration of one test.
async function withAccount(email, key) {
  httpRelay.state.accounts.push({ key, email, active: true });
  await httpRedis.set(`paramant:user:totp_active:${key}`, 'true');
}

// Solve the proof-of-work the login page solves in the browser. About 2^18
// sha256 hashes, which is the point: it is a cost, and the test pays it once.
async function powFor(ip) {
  const ch = await httpSrv.get('/api/captcha/challenge', { headers: { 'X-Real-IP': ip } });
  assert.equal(ch.status, 200, `a challenge must be issuable: ${ch.status} ${ch.text}`);
  const nonce = solvePow(ch.json.challenge_id, ch.json.salt, ch.json.difficulty);
  return { challenge_id: ch.json.challenge_id, nonce };
}

test('ten wrong codes from three addresses do not lock the owner out', async (t) => {
  if (!ready()) return t.skip('no redis');
  const email = freshEmail();
  const key = `pgp_victim_${crypto.randomBytes(5).toString('hex')}`;
  await withAccount(email, key);

  // The attack, exactly as the review described it. Three IP addresses, because
  // one only has five attempts before the per-IP limiter refuses IT -- which is
  // the limiter doing its job, and is not the property under test here.
  const attackers = [nextIp(), nextIp(), nextIp()];
  const statuses = [];
  for (let i = 0; i < HTTP_POW_THRESHOLD; i++) {
    const ip = attackers[Math.floor(i / 4)] || attackers[2];
    const r = await httpSrv.login({ email, totp: '000000', ip });
    statuses.push(r.status);
  }
  assert.ok(!statuses.includes(429),
    `no attempt on somebody else's address may be refused, got: ${statuses.join(',')}`);
  assert.deepEqual([...new Set(statuses)], [401],
    `ten wrong codes are ten wrong codes, got: ${statuses.join(',')}`);
  httpDid();

  // The owner, from their own address, with the code their app shows. Past the
  // threshold the attempt is priced, so it costs one proof-of-work -- and then
  // it is a session, not a 429. Under the counter this replaced it was fifteen
  // minutes of refusal that no correct code could clear.
  const ownerIp = nextIp();
  const priced = await httpSrv.login({ email, totp: HTTP_SECRET, ip: ownerIp });
  assert.equal(priced.status, 428, `past the threshold the answer is 428, got ${priced.status} ${priced.text}`);
  assert.equal(priced.json.error, 'pow_required');
  httpDid();

  const proof = await powFor(ownerIp);
  const signedIn = await httpSrv.login({ email, totp: HTTP_SECRET, ip: ownerIp, ...proof });
  assert.equal(signedIn.status, 200, `the owner must get in: ${signedIn.status} ${signedIn.text}`);
  assert.equal(signedIn.json.success, true);
  assert.ok(String(signedIn.headers['set-cookie'] || '').length > 0, 'and a session cookie comes with it');
  httpDid();

  // And the score is gone, so the NEXT sign-in costs nothing. Without the clear
  // the owner would keep paying for the attacker for the rest of the window.
  const again = await httpSrv.login({ email, totp: HTTP_SECRET, ip: nextIp() });
  assert.equal(again.status, 200, `the next sign-in is clean, got ${again.status} ${again.text}`);
  httpDid();
});

test('the per-IP refusal still works, and follows the caller and not the address', async (t) => {
  if (!ready()) return t.skip('no redis');
  const email = freshEmail();
  const key = `pgp_ipcap_${crypto.randomBytes(5).toString('hex')}`;
  await withAccount(email, key);

  const ip = nextIp();
  for (let i = 0; i < HTTP_IP_LIMIT; i++) {
    const r = await httpSrv.login({ email, totp: '000000', ip });
    assert.equal(r.status, 401, `attempt ${i + 1} of ${HTTP_IP_LIMIT} is allowed through to a verdict`);
  }
  const over = await httpSrv.login({ email, totp: '000000', ip });
  assert.equal(over.status, 429, 'the sixth attempt from one address is refused');
  httpDid();

  // The victim, from their own address, is unaffected by the exhausted one.
  const owner = await httpSrv.login({ email, totp: HTTP_SECRET, ip: nextIp() });
  assert.ok(owner.status === 200 || owner.status === 428,
    `a different IP has its own budget, got ${owner.status} ${owner.text}`);
  httpDid();
});

test('a priced attempt hands the IP its try back, so a quote costs nothing', async (t) => {
  if (!ready()) return t.skip('no redis');
  const email = freshEmail();
  const key = `pgp_refund_${crypto.randomBytes(5).toString('hex')}`;
  await withAccount(email, key);

  // Put the address over the threshold from other addresses.
  for (let i = 0; i < HTTP_POW_THRESHOLD; i++) {
    await httpSrv.login({ email, totp: '000000', ip: nextIp() });
  }

  // Now one IP asks repeatedly without a proof. Each of those is a 428, and if
  // the 428 spent the IP's budget the sixth would be a 429: an honest user
  // whose page is solving a challenge would be locked out by the very
  // mechanism that is supposed to let them in.
  const ip = nextIp();
  for (let i = 0; i < HTTP_IP_LIMIT + 3; i++) {
    const r = await httpSrv.login({ email, totp: HTTP_SECRET, ip });
    assert.equal(r.status, 428, `quote ${i + 1} must stay a 428, got ${r.status} ${r.text}`);
  }
  httpDid();

  const proof = await powFor(ip);
  const signedIn = await httpSrv.login({ email, totp: HTTP_SECRET, ip, ...proof });
  assert.equal(signedIn.status, 200, `and the answer still gets in: ${signedIn.status} ${signedIn.text}`);
  httpDid();
});

test('a relay that cannot reach its replay store is reported as an outage, not a wrong code', async (t) => {
  if (!ready()) return t.skip('no redis');
  const email = freshEmail();
  const key = `pgp_outage_${crypto.randomBytes(5).toString('hex')}`;
  await withAccount(email, key);

  const previous = httpRelay.state.verify;
  httpRelay.state.verify = () => ({ status: 503, body: { error: 'replay_store_unavailable' } });
  try {
    const r = await httpSrv.login({ email, totp: HTTP_SECRET, ip: nextIp() });
    assert.equal(r.status, 503, `an outage must be passed through: ${r.status} ${r.text}`);
    assert.equal(r.json.error, 'totp_unavailable');
    httpDid();

    // And it must not be charged to the address. Nobody failed; the service is
    // down, and counting it would move an honest user towards a proof-of-work
    // they did nothing to earn.
    const failKey = `paramant:user:loginfail:${crypto.createHash('sha256').update(email).digest('hex')}`;
    assert.equal(await httpRedis.get(failKey), null, 'an outage is not a failed sign-in');
    httpDid();
  } finally {
    httpRelay.state.verify = previous;
  }
});

test('an unknown address and a known one are both a plain 401', async (t) => {
  if (!ready()) return t.skip('no redis');
  // The status code half of the enumeration defence. The timing half is
  // login-timing.test.js.
  const unknown = await httpSrv.login({ email: freshEmail(), totp: '000000', ip: nextIp() });
  const known = await httpSrv.login({ email: HTTP_OWNER_EMAIL, totp: '000000', ip: nextIp() });
  assert.equal(unknown.status, 401);
  assert.equal(known.status, 401);
  assert.deepEqual(unknown.json, known.json, 'and the bodies are identical too');
  httpDid();
});
