'use strict';
// The login lockout vector, pinned from both ends.
//
// Before this branch /api/user/login incremented a per-e-mail counter BEFORE any
// authentication ran and refused at eleven, and no successful sign-in ever
// cleared it. Eleven posts spread over three IP addresses (the per-IP cap is 5)
// put the owner of that address on 429 for fifteen minutes. The address is
// request input, so the limiter was a denial-of-service primitive aimed at the
// account rather than at the guesser.
//
// Two halves here. The first drives lib/login-ratelimit.js directly: failures
// only, never a refusal, cleared by a success, per-IP untouched. The second
// reads admin/server.js and pins the ORDER the handler uses them in, because a
// module that cannot lock anyone out is no help if the handler goes back to
// counting attempts before it authenticates.
//
// Run: node --test admin/test/login-ratelimit.test.js

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const loginRate = require('../lib/login-ratelimit');

// Minimal stand-in for the node-redis surface this module uses.
function fakeRedis() {
  const store = new Map();
  const ttl = new Map();
  return {
    async incr(k) { const n = (Number(store.get(k)) || 0) + 1; store.set(k, String(n)); return n; },
    async expire(k, s) { ttl.set(k, s); return 1; },
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async del(k) { ttl.delete(k); return store.delete(k) ? 1 : 0; },
    _store: store,
    _ttl: ttl,
  };
}

// The decision the handler makes, in the handler's order, so the scenario tests
// below read as sign-ins rather than as Redis calls. `code` is the code typed;
// `secret` is the one the account actually has.
async function attemptLogin(r, { ip, email, code, secret, proof }) {
  const hit = await loginRate.hitIp(r, ip);
  if (!hit.allowed) return { status: 429, why: 'ip' };
  const failures = await loginRate.emailFailures(r, email);
  if (loginRate.powRequired(failures) && !proof) return { status: 428, why: 'pow_required' };
  if (code !== secret) {
    await loginRate.noteEmailFailure(r, email);
    return { status: 401, why: 'bad_code' };
  }
  await loginRate.clearEmailFailures(r, email);
  return { status: 200, why: 'signed_in' };
}

test('an attacker cannot lock a victim out of their own account', async () => {
  const r = fakeRedis();
  const victim = 'victim@example.com';

  // Ten wrong codes for the victim's address, each from its own IP so the
  // per-IP cap is never the thing that stops them. This is the exact shape of
  // the old attack, and eleven of these used to buy fifteen minutes of 429.
  for (let i = 0; i < 10; i++) {
    const out = await attemptLogin(r, { ip: `10.0.0.${i}`, email: victim, code: '000000', secret: '123456' });
    assert.equal(out.status, 401, `attacker attempt ${i + 1} is a plain wrong code, not a lockout`);
  }
  assert.equal(await loginRate.emailFailures(r, victim), 10, 'ten failures are on the address');

  // The victim now signs in from their own IP with the right code. Under the
  // old counter this was a 429. It has to be a session.
  const owner = await attemptLogin(r, { ip: '203.0.113.9', email: victim, code: '123456', secret: '123456', proof: true });
  assert.equal(owner.status, 200, 'the owner with a correct code signs in despite the attacker score');

  // And the score is gone, so the next sign-in needs no proof-of-work either.
  assert.equal(await loginRate.emailFailures(r, victim), 0, 'a success clears the failures collected in this address name');
  const again = await attemptLogin(r, { ip: '203.0.113.9', email: victim, code: '123456', secret: '123456' });
  assert.equal(again.status, 200, 'the next sign-in is clean, no leftover cost');
});

test('past the threshold the attempt is priced, not refused', async () => {
  const r = fakeRedis();
  const addr = 'target@example.com';
  for (let i = 0; i < 10; i++) await loginRate.noteEmailFailure(r, addr);

  // No proof: 428, which is "bring work", not "go away". Crucially never 429.
  const bare = await attemptLogin(r, { ip: '198.51.100.7', email: addr, code: '123456', secret: '123456' });
  assert.equal(bare.status, 428, 'the eleventh attempt asks for a proof-of-work');
  assert.notEqual(bare.status, 429, 'and never refuses the address outright');

  // With the proof the correct code still wins.
  const paid = await attemptLogin(r, { ip: '198.51.100.8', email: addr, code: '123456', secret: '123456', proof: true });
  assert.equal(paid.status, 200, 'the owner pays the proof-of-work once and gets in');

  // powRequired is a pure step function on the failure count.
  assert.equal(loginRate.powRequired(0), false);
  assert.equal(loginRate.powRequired(loginRate.EMAIL_FAIL_THRESHOLD - 1), false, 'the threshold itself is still free');
  assert.equal(loginRate.powRequired(loginRate.EMAIL_FAIL_THRESHOLD), true);
  assert.equal(loginRate.powRequired(loginRate.EMAIL_FAIL_THRESHOLD + 50), true);
});

test('merely naming an address never moves its counter', async () => {
  const r = fakeRedis();
  const addr = 'quiet@example.com';
  // A read is a read. This is the whole difference between the old counter and
  // this one: the old one incremented here, before it knew whether anything had
  // failed, which is why the address alone was enough to trip it.
  for (let i = 0; i < 50; i++) await loginRate.emailFailures(r, addr);
  assert.equal(await loginRate.emailFailures(r, addr), 0, 'fifty lookups, zero failures recorded');
  assert.equal(r._store.size, 0, 'and no key was even created');
});

test('the per-IP limit still refuses, and still costs the caller and not a victim', async () => {
  const r = fakeRedis();
  for (let i = 0; i < loginRate.IP_LIMIT; i++) {
    const hit = await loginRate.hitIp(r, '192.0.2.5');
    assert.equal(hit.allowed, true, `hit ${i + 1} of ${loginRate.IP_LIMIT} allowed`);
  }
  const over = await loginRate.hitIp(r, '192.0.2.5');
  assert.equal(over.allowed, false, 'the sixth attempt from one IP is refused');
  assert.equal(r._ttl.get(loginRate.ipKey('192.0.2.5')), loginRate.WINDOW_S, 'the window is 15 minutes');

  // A second IP has its own budget: the refusal follows the connection.
  const other = await loginRate.hitIp(r, '192.0.2.6');
  assert.equal(other.allowed, true, 'a different IP is unaffected');

  // And an exhausted IP does not stop the victim signing in from their own.
  const addr = 'shared@example.com';
  const out = await attemptLogin(r, { ip: '203.0.113.1', email: addr, code: '123456', secret: '123456' });
  assert.equal(out.status, 200);
});

test('the failure key carries no address and does not inherit the old counters', () => {
  const addr = 'Someone@Example.COM ';
  const k = loginRate.emailFailKey(addr);
  assert.equal(k, loginRate.emailFailKey('someone@example.com'), 'case and whitespace normalise to one key');
  assert.notEqual(k, loginRate.emailFailKey('other@example.com'), 'distinct addresses stay distinct');
  assert.ok(!k.includes('someone') && !k.includes('example.com'), 'the address itself is never in the key');
  assert.ok(k.startsWith('paramant:user:loginfail:'), 'namespaced');
  // The old namespace held ATTEMPT counters. Reusing it would let a counter
  // written before the deploy keep somebody locked out afterwards.
  assert.ok(!k.startsWith('paramant:user:ratelimit:email:'), 'new namespace, so no stale attempt counter is inherited');
});

test('the login handler counts failures after authenticating, never attempts before it', () => {
  const srv = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const start = srv.indexOf('api.post("/user/login"');
  assert.ok(start > 0, 'the login handler must be findable');
  const handler = srv.slice(start, srv.indexOf('api.post("/user/login-with-backup"'));
  assert.ok(handler.length > 0 && handler.length < 8000, 'sliced the login handler, not the rest of the file');

  // The regression that started this: an e-mail counter incremented before
  // findUserByEmail, and a 429 keyed on it.
  assert.doesNotMatch(handler, /paramant:user:ratelimit:email:/,
    'the per-e-mail ATTEMPT counter must not come back');
  assert.doesNotMatch(handler, /emailCount\s*>/,
    'no refusal may be keyed on how often an address was merely typed');

  const iFind = handler.indexOf('findUserByEmail');
  const iNote = handler.indexOf('noteEmailFailure');
  const iClear = handler.indexOf('clearEmailFailures');
  assert.ok(iFind > 0 && iNote > 0 && iClear > 0, 'all three steps are present');
  assert.ok(iNote > iFind, 'a failure is only recorded after authentication has actually failed');
  assert.ok(iClear > iFind, 'and a success clears the counter');

  // Per-IP: still a hard 429, and it is the ONLY 429 the handler can produce.
  assert.match(handler, /hitIp\(/, 'the per-IP limiter is still there');
  const refusals = handler.match(/status\(429\)/g) || [];
  assert.equal(refusals.length, 1, 'exactly one 429 in the handler, and it is the per-IP one');
  const iIp = handler.indexOf('hitIp(');
  const i429 = handler.indexOf('status(429)');
  assert.ok(i429 > iIp && i429 - iIp < 200, 'the 429 belongs to the IP limiter');

  // Past the threshold: priced, not refused, and the relay 503 is passed on
  // rather than reported as a wrong code.
  assert.match(handler, /status\(428\)/, 'over the threshold the answer is 428 pow_required');
  assert.match(handler, /pow\.verifyChallenge/, 'and the existing proof-of-work is what is asked for');
  assert.match(handler, /status\(503\)/, 'a replay-store outage is passed through as 503');
});
