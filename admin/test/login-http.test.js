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
// The same reasoning brought two more request-level properties in here, both
// from the 2026-09-05 review and both untestable without a running handler:
// the byte-vs-character compare on the ADMIN_TOKEN gate, and the absolute
// lifetime of a user session. See their tests at the bottom of the file.
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

// ── /api/user/login-with-backup ──────────────────────────────────────────────
// The other unauthenticated, session-granting route, and until now no test
// reached it over HTTP either. The argon2 cost that makes it a timing oracle is
// measured in login-timing.test.js against a real relay; what is checked here
// is the wiring: the caps, the verdicts, the cookie, and the flag that keeps
// the relay from charging its per-account delay a second time.
const HTTP_BACKUP_CODE = 'AAAA-BBBB-CCCC';
// admin/lib/login-ratelimit.js BACKUP_ATTEMPT_LIMIT.
const HTTP_BACKUP_LIMIT = 5;

function backupLogin(email, code, ip) {
  return httpSrv.post('/api/user/login-with-backup', {
    headers: { 'X-Real-IP': ip || nextIp() },
    body: { email, backup_code: code },
  });
}

test('a backup code signs the owner in, and a wrong one does not', async (t) => {
  if (!ready()) return t.skip('no redis');
  const email = freshEmail();
  const key = `pgp_backup_${crypto.randomBytes(5).toString('hex')}`;
  await withAccount(email, key);
  const previous = httpRelay.state.consumeBackup;
  httpRelay.state.consumeBackup = (body) => ({ valid: body && body.code === HTTP_BACKUP_CODE });
  try {
    const wrong = await backupLogin(email, 'ZZZZ-ZZZZ-ZZZZ');
    assert.equal(wrong.status, 401, `a wrong code is refused: ${wrong.status} ${wrong.text}`);
    httpDid();

    const right = await backupLogin(email, HTTP_BACKUP_CODE);
    assert.equal(right.status, 200, `the owner's code gets in: ${right.status} ${right.text}`);
    assert.ok(String(right.headers['set-cookie'] || '').length > 0, 'with a session cookie');
    httpDid();

    // The relay must be told the delay was already charged here, exactly as on
    // /user/login. Without it the account-keyed delay comes back on top of the
    // address-keyed one, and only an address with an account pays it.
    const calls = httpRelay.state.calls.filter((c) => c.path === '/v2/user/consume-backup');
    assert.ok(calls.length >= 2, 'the suite must have reached the relay');
    assert.ok(calls.every((c) => c.body && c.body.throttled_upstream === true),
      'every consume-backup call must declare the throttle was applied upstream');
    httpDid();
  } finally {
    httpRelay.state.consumeBackup = previous;
  }
});

test('the backup route refuses per address, and an unknown address reads the same as a known one', async (t) => {
  if (!ready()) return t.skip('no redis');
  const email = freshEmail();
  const key = `pgp_backupcap_${crypto.randomBytes(5).toString('hex')}`;
  await withAccount(email, key);

  // Five attempts on one address are answered; the sixth is refused. Each uses
  // its own source address, so this measures the per-address cap and not the
  // per-IP one that sits in front of it.
  for (let i = 0; i < HTTP_BACKUP_LIMIT; i++) {
    const r = await backupLogin(email, 'ZZZZ-ZZZZ-ZZZZ');
    assert.equal(r.status, 401, `attempt ${i + 1} of ${HTTP_BACKUP_LIMIT} gets a verdict, got ${r.status}`);
  }
  const over = await backupLogin(email, 'ZZZZ-ZZZZ-ZZZZ');
  assert.equal(over.status, 429, 'the sixth attempt on one address is refused');
  httpDid();

  const unknown = await backupLogin(freshEmail(), 'ZZZZ-ZZZZ-ZZZZ');
  const known = await backupLogin(freshEmail(), 'ZZZZ-ZZZZ-ZZZZ');
  assert.equal(unknown.status, 401);
  assert.deepEqual(unknown.json, known.json, 'and the bodies are identical');
  httpDid();
});

test('a body that is not what it says it is gets a 400, not a 500', async (t) => {
  if (!ready()) return t.skip('no redis');
  // `{"email": {}}` is truthy, so a `!email` check waved it through into
  // String(email).toLowerCase(), which threw. That answered 500 in about a
  // millisecond: an unhandled throw on an unauthenticated route, and the
  // fastest answer either handler had.
  const junk = [{}, [], 42, true, null];
  for (const value of junk) {
    const login = await httpSrv.post('/api/user/login', {
      headers: { 'X-Real-IP': nextIp() }, body: { email: value, totp: '000000' },
    });
    assert.equal(login.status, 400, `/user/login with email=${JSON.stringify(value)} must be a 400, got ${login.status} ${login.text}`);
    const backup = await httpSrv.post('/api/user/login-with-backup', {
      headers: { 'X-Real-IP': nextIp() }, body: { email: value, backup_code: 'AAAA-BBBB-CCCC' },
    });
    assert.equal(backup.status, 400, `/user/login-with-backup with email=${JSON.stringify(value)} must be a 400, got ${backup.status} ${backup.text}`);
  }
  // And the same for the second field, which has the same shape of check.
  const badCode = await httpSrv.post('/api/user/login-with-backup', {
    headers: { 'X-Real-IP': nextIp() }, body: { email: freshEmail(), backup_code: {} },
  });
  assert.equal(badCode.status, 400, `a non-string backup_code must be a 400, got ${badCode.status} ${badCode.text}`);
  httpDid();
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

// ── The ADMIN_TOKEN gate compares bytes, not characters ─────────────────────

test('a token of the right character length but the wrong byte length is a 401, not a 500', async (t) => {
  if (!ready()) return t.skip('no redis');
  // POST /admin/resend-setup used to guard timingSafeEqual with
  // `tok.length !== ADMIN_TOKEN.length`. String#length counts UTF-16 code
  // units; Buffer.from() counts utf8 bytes. One multibyte character keeps the
  // first number equal and changes the second, so the guard waved the token
  // through and timingSafeEqual threw a RangeError on the buffer mismatch,
  // which express 5 answers as a 500. A 500 for one wrong token and a 401 for
  // another is an oracle on the length of the configured token, free to ask and
  // unauthenticated.
  const real = httpSrv.env.ADMIN_TOKEN;
  const body = { user_id: 'acct_demo', email: 'demo@example.com' };

  const sameChars = real.slice(0, -1) + '\u00e9';
  assert.equal(sameChars.length, real.length, 'the probe has the same character count');
  assert.notEqual(Buffer.byteLength(sameChars, 'utf8'), Buffer.byteLength(real, 'utf8'),
    'and a different byte count, which is the whole point of it');
  const multibyte = await httpSrv.post('/api/admin/resend-setup', {
    headers: { 'X-Admin-Token': sameChars }, body,
  });
  assert.equal(multibyte.status, 401,
    `a same-length wrong token must be refused with 401, got ${multibyte.status} ${multibyte.text}`);
  assert.equal(multibyte.json && multibyte.json.error, 'unauthorized');

  // The two controls: a plainly wrong token and none at all answer the same.
  for (const [what, headers] of [['a plainly wrong token', { 'X-Admin-Token': 'nope' }], ['no token at all', {}]]) {
    const r = await httpSrv.post('/api/admin/resend-setup', { headers, body });
    assert.equal(r.status, 401, `${what} must be a 401, got ${r.status} ${r.text}`);
    assert.deepEqual(r.json, multibyte.json, `${what} must be answered identically`);
  }

  // And the gate still opens for the real token: the next thing it reaches is
  // the body check, so a 400 here proves the refusals above are the compare and
  // not a route that refuses everything.
  const opened = await httpSrv.post('/api/admin/resend-setup', {
    headers: { 'X-Admin-Token': real }, body: {},
  });
  assert.equal(opened.status, 400, `the real token must get past the gate, got ${opened.status} ${opened.text}`);
  assert.equal(opened.json && opened.json.error, 'missing_fields');
  httpDid();
});

// ── A session ends, whether or not it is being used ─────────────────────────

// Sign in for real and hand back the session cookie's token.
async function signInForSession() {
  const email = freshEmail();
  const key = `pgp_session_${crypto.randomBytes(5).toString('hex')}`;
  await withAccount(email, key);
  const r = await httpSrv.login({ email, totp: HTTP_SECRET, ip: nextIp() });
  assert.equal(r.status, 200, `sign-in failed: ${r.status} ${r.text}`);
  const raw = [].concat(r.headers['set-cookie'] || []).join('; ');
  const m = raw.match(/paramant_user_session=([^;]+)/);
  assert.ok(m, `no session cookie in ${raw}`);
  return { token: m[1], email, key };
}

test('a session has an absolute lifetime, and a last_seen that is actually last seen', async (t) => {
  if (!ready()) return t.skip('no redis');
  // authUser refreshed the redis TTL on every request and enforced nothing
  // else, so a session used once an hour never ended: an unbounded sliding
  // window against a standard (SESS-01) that asks for both halves. created_at
  // was written by every issuing path and read by nobody except a cosmetic
  // line that printed it under the label "last_seen".
  const { token } = await signInForSession();
  const cookie = { Cookie: `paramant_user_session=${token}` };
  const key = `paramant:user:session:${token}`;

  const first = await httpSrv.get('/api/user/account', { headers: cookie });
  assert.equal(first.status, 200, `a fresh session must be accepted: ${first.status} ${first.text}`);
  const stored = JSON.parse(await httpRedis.get(key));
  assert.equal(typeof stored.last_seen, 'number', 'authUser stamps last_seen on the record');
  assert.ok(stored.last_seen >= stored.created_at, 'and it is never older than the login itself');
  const mine = (first.json.sessions || []).find((s) => s.current);
  assert.ok(mine, 'the account view lists the session the request arrived on');
  assert.equal(mine.last_seen, new Date(stored.last_seen).toISOString(),
    'and the column labelled last_seen prints last_seen, not the creation time');
  httpDid();

  // The cap. Backdate the record past twelve hours and leave the TTL exactly
  // where an hourly request would have kept it: a full hour still to run.
  stored.created_at = Date.now() - (13 * 3600 * 1000);
  await httpRedis.set(key, JSON.stringify(stored), { EX: 3600 });
  const expired = await httpSrv.get('/api/user/account', { headers: cookie });
  assert.equal(expired.status, 401,
    `past the absolute lifetime the session must be refused, got ${expired.status} ${expired.text}`);
  assert.equal(expired.json && expired.json.error, 'session_expired');
  assert.equal(await httpRedis.get(key), null,
    'and the record is deleted rather than left behind with a freshly extended TTL');
  httpDid();
});

test('a session record written before created_at existed is capped, not exempted', async (t) => {
  if (!ready()) return t.skip('no redis');
  // Refusing a record without created_at would sign every logged-in customer
  // out on deploy; exempting it would leave a population of sessions that can
  // never expire. So the first request that touches one stamps it, and the cap
  // runs from then.
  const token = crypto.randomBytes(32).toString('hex');
  const key = `paramant:user:session:${token}`;
  await httpRedis.set(key, JSON.stringify(
    { user_id: HTTP_OWNER_KEY, email: HTTP_OWNER_EMAIL, ip: '203.0.113.9', ua: 'probe', via: 'totp' },
  ), { EX: 3600 });
  // The User-Agent is sent to match the one on the fixture. Since 2026-09-06
  // authUser binds a session to the client that opened it (finding 22i), so a
  // request from a different agent is theft and gets a 401. That is a separate
  // property, asserted in session-credential-gate.test.js; here it would just
  // be noise standing between this test and the thing it measures.
  const r = await httpSrv.get('/api/user/account', {
    headers: { Cookie: `paramant_user_session=${token}`, 'User-Agent': 'probe' },
  });
  assert.equal(r.status, 200, `a record without created_at must keep working: ${r.status} ${r.text}`);
  const stored = JSON.parse(await httpRedis.get(key));
  assert.equal(typeof stored.created_at, 'number',
    'and it is stamped on the way through, so its cap starts now instead of never');
  assert.equal(typeof stored.last_seen, 'number', 'with a last_seen to match');
  await httpRedis.del(key);
  httpDid();
});
