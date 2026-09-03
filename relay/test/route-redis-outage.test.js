'use strict';
// A relay with its redis taken away, sabotaged two different ways, asked for an
// answer on every kind of route it has.
//
// WHY THIS SUITE EXISTS. #368 bounded ONE redis read, on the TOTP verify path,
// and said so in SECURITY.md: "that queue-forever behaviour is a property of
// the relay's redis client, not of this path. Every other redis-backed route in
// relay.js still inherits it and will still hang in an outage." That was the
// open finding. This suite is what closes it, and it is deliberately not a
// source-text assertion: the property is "the request comes back", and only a
// request can show that.
//
// TWO SABOTAGES, BECAUSE THEY BREAK DIFFERENTLY.
//
//   CUT      the proxy destroys every socket and stops listening. The client
//            sees the socket die. Measured on redis 5.12.1: the first command
//            after the cut rejects, and every one after it neither resolves nor
//            rejects, because node-redis holds them on its offline queue while
//            it reconnects. disableOfflineQueue is what fixes this one.
//
//   HOLE     the proxy keeps both sockets open and stops copying bytes. Nothing
//            fails: isReady stays true, the command goes out, the reply never
//            arrives. disableOfflineQueue cannot see this, because as far as
//            the client is concerned nothing is wrong. Only a deadline catches
//            it, and it is the more realistic outage of the two -- a dropped
//            firewall rule, a wedged proxy, a frozen container.
//
// WHAT IS ASSERTED. Every redis-backed route answers, and answers 503, inside
// the deadline. /health keeps saying 200, because the process is up and the
// route touches no redis. /v2/health/deep goes red on the redis check instead
// of reporting the same green as a healthy relay, which is what it used to do.
//
// The deadline is set to 400 ms for this suite rather than the 1000 ms default,
// which also proves PARAMANT_REDIS_DEADLINE_MS is the knob it claims to be: if
// it were ignored the answers would arrive around a second and the bound below
// would fail.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-redis-outage.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const net = require('net');
const { boot, killAll, freePort } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

const OUTAGE_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const OUTAGE_INTERNAL = 'internal-token-for-the-redis-outage-suite';
const OUTAGE_KEY = `pgp_owner_key_for_the_outage_suite_${crypto.randomBytes(6).toString('hex')}`;
// Short on purpose: the suite is measuring a bound, so it should not have to
// wait a second per route to see one.
const OUTAGE_DEADLINE_MS = 400;
// The deadline plus room for the request itself. Anything under this is a bound
// working; the failure it replaces was not slow, it was infinite.
const OUTAGE_CEILING_MS = 3000;

let outageRedis = null;
let outageChecks = 0;
const outageDid = () => { outageChecks++; };

before(async () => {
  outageRedis = await requireRedis(OUTAGE_DEFAULT_REDIS);
});

after(async () => {
  await killAll();
  if (outageRedis) { try { await outageRedis.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-redis-outage', outageChecks);
});

// A TCP pass-through in front of redis that can be broken in either of the two
// ways an outage actually looks. Same shape as the proxy in
// route-user-mfa-lockout.test.js, with the black hole added.
function outageProxy(port, upstreamUrl) {
  const u = new URL(upstreamUrl);
  const sockets = new Set();
  let holed = false;
  const server = net.createServer((client) => {
    const upstream = net.connect(Number(u.port || 6379), u.hostname || '127.0.0.1');
    sockets.add(client); sockets.add(upstream);
    client.on('error', () => {}); upstream.on('error', () => {});
    // Copied by hand rather than with pipe(), so the copying can be switched
    // off without closing anything. pipe() would also forward the end of the
    // stream, which is exactly what the black hole must not do.
    client.on('data', (d) => { if (!holed) upstream.write(d); });
    upstream.on('data', (d) => { if (!holed) client.write(d); });
    // Copying by hand means closing by hand too. Without this, every reconnect
    // the relay makes leaves its upstream socket to redis open for good, and
    // four of them keep node --test alive long after the last assertion.
    const drop = () => {
      sockets.delete(client); sockets.delete(upstream);
      try { client.destroy(); } catch (_) { /* already gone */ }
      try { upstream.destroy(); } catch (_) { /* already gone */ }
    };
    client.on('close', drop);
    upstream.on('close', drop);
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({
      // The connection stays up and goes quiet. Nothing fails; the reply simply
      // never comes.
      hole() { holed = true; },
      // Bytes flow again, on the same sockets. Nothing is reset here on
      // purpose: this is the case where the network heals and the client does
      // not, because node-redis is still waiting for the reply that was
      // swallowed. Only the connection rebuild in lib/redis-deadline gets past
      // it.
      unhole() { holed = false; },
      // The connection dies and the listener goes away, so reconnects are
      // refused too.
      cut() {
        for (const sock of sockets) { try { sock.destroy(); } catch (_) { /* already gone */ } }
        sockets.clear();
        return new Promise((r) => server.close(r));
      },
      close() { try { server.close(); } catch (_) { /* already closed */ } },
    }));
  });
}

// A relay of its own, behind a proxy this suite is allowed to break.
async function bootBehindProxy(tag) {
  const proxyPort = await freePort();
  const proxy = await outageProxy(proxyPort, process.env.REDIS_URL || OUTAGE_DEFAULT_REDIS);
  const srv = await boot({
    tag,
    users: { api_keys: [{ key: OUTAGE_KEY, plan: 'business', active: true, parasign: true, email: 'owner@example.test', account_id: 'acct_outage' }] },
    env: {
      INTERNAL_AUTH_TOKEN: OUTAGE_INTERNAL,
      REDIS_URL: `redis://127.0.0.1:${proxyPort}`,
      PARAMANT_REDIS_DEADLINE_MS: String(OUTAGE_DEADLINE_MS),
      PARAMANT_TOTP_MASTER_KEY: Buffer.alloc(32, 9).toString('base64'),
    },
  });
  return { srv, proxy };
}

// One request, with the wall clock around it.
async function timed(fn) {
  const t0 = Date.now();
  const res = await fn();
  return { ...res, ms: Date.now() - t0 };
}

// Every redis-backed shape of route this relay has. The user routes are the
// auth surface; the envelope routes are the product surface; both used to hang.
function outageRoutes(srv) {
  const internal = { 'X-Internal-Auth': OUTAGE_INTERNAL };
  const uid = `pgp_outage_${crypto.randomBytes(5).toString('hex')}`;
  return [
    ['auth: POST /v2/user/setup-totp', () => srv.post('/v2/user/setup-totp', { headers: internal, body: { user_id: uid } })],
    ['auth: POST /v2/user/verify-totp', () => srv.post('/v2/user/verify-totp', { headers: internal, body: { user_id: uid, totp: '000000' } })],
    // The one #368 left open by name: consumeBackupCode does sMembers and then
    // sRem, and neither was bounded. A timed-out sRem is not even safe in the
    // way a timed-out replay SET is: it leaves the code spendable.
    ['auth: POST /v2/user/consume-backup', () => srv.post('/v2/user/consume-backup', { headers: internal, body: { user_id: uid, code: 'AAAA-BBBB' } })],
    ['auth: POST /v2/user/get-totp-provisional', () => srv.post('/v2/user/get-totp-provisional', { headers: internal, body: { user_id: uid } })],
    ['envelope: POST /v2/envelopes', () => srv.post('/v2/envelopes', {
      headers: { 'X-Api-Key': OUTAGE_KEY, 'X-Real-IP': '10.9.9.9' },
      body: { doc_hash: crypto.randomBytes(32).toString('hex'), parties: [{ label: 'Demo' }, { label: 'Acme' }] },
    })],
    ['envelope: GET /v2/envelopes/:id', () => srv.get('/v2/envelopes/env_does_not_matter_here', {
      headers: { 'X-Api-Key': OUTAGE_KEY, 'X-Real-IP': '10.9.9.10' },
    })],
  ];
}

// The property, run against one kind of sabotage.
async function assertOutageAnswers(t, breakIt, tag) {
  if (!outageRedis) return t.skip('no redis');
  const { srv, proxy } = await bootBehindProxy(tag);

  // With the store up the same routes are not 503, so the assertions below are
  // about the outage and not about a route that never worked.
  const up = await srv.post('/v2/user/setup-totp', { headers: { 'X-Internal-Auth': OUTAGE_INTERNAL }, body: { user_id: `pgp_up_${crypto.randomBytes(4).toString('hex')}` } });
  assert.equal(up.status, 200, `with redis up, setup-totp must work: ${up.status} ${up.text}`);
  outageDid();

  await breakIt(proxy);

  for (const [name, call] of outageRoutes(srv)) {
    const res = await timed(call);
    assert.equal(res.status, 503,
      `${name} must answer 503 when the store is gone, got ${res.status} ${res.text}`);
    assert.ok(res.ms < OUTAGE_CEILING_MS,
      `${name} must answer inside the deadline, took ${res.ms}ms`);
    // The body has to say what happened. A bare 503 with no reason is what
    // sends an operator to the wrong system.
    assert.match(res.text, /unavailable|redis/i,
      `${name} must name the outage in its body, got ${res.text}`);
    outageDid();
  }

  // /health does not touch redis and must not start failing because redis did.
  // A relay that answers 500 here gets pulled out of a load balancer for a
  // dependency outage it can still report on.
  const health = await timed(() => srv.get('/health'));
  assert.equal(health.status, 200, `/health stays 200 in a store outage, got ${health.status}`);
  assert.ok(health.ms < OUTAGE_CEILING_MS, `/health must not hang either, took ${health.ms}ms`);
  outageDid();

  // The deep check is the one that has to be honest, and it was not: before
  // this change it listed relay, crypto, storage, memory, disk, tls, users and
  // audit, and never mentioned the store that holds every TOTP secret.
  const deep = await timed(() => srv.get('/v2/health/deep'));
  assert.equal(deep.status, 200, '/v2/health/deep answers');
  assert.ok(deep.ms < OUTAGE_CEILING_MS, `/v2/health/deep must not hang, took ${deep.ms}ms`);
  const redisCheck = (deep.json.checks || []).find((c) => c.name === 'redis');
  assert.ok(redisCheck, 'the deep check must report on redis at all');
  assert.equal(redisCheck.status, 'red', `redis is unreachable and must read as red, got ${JSON.stringify(redisCheck)}`);
  assert.notEqual(deep.json.overall, 'green', 'and a relay that cannot reach its store is not green');
  outageDid();

  srv.stop();
  proxy.close();
}

test('a cut connection: every redis-backed route answers 503 inside the deadline', async (t) => {
  await assertOutageAnswers(t, (proxy) => proxy.cut(), 'outage-cut');
});

test('a silent connection: the same, where the client still believes it is ready', async (t) => {
  // This is the case disableOfflineQueue alone does not cover, and the reason
  // the deadline is not redundant with it.
  await assertOutageAnswers(t, (proxy) => { proxy.hole(); return Promise.resolve(); }, 'outage-hole');
});

test('the store coming back is the end of it: no restart needed', async (t) => {
  if (!outageRedis) return t.skip('no redis');
  const { srv, proxy } = await bootBehindProxy('outage-recover');
  const uid = () => `pgp_recover_${crypto.randomBytes(5).toString('hex')}`;

  proxy.hole();
  const during = await timed(() => srv.post('/v2/user/setup-totp', { headers: { 'X-Internal-Auth': OUTAGE_INTERNAL }, body: { user_id: uid() } }));
  assert.equal(during.status, 503, 'refused while the store is silent');

  // Bytes flow again. The old reconnect strategy in the admin gave up after ten
  // tries and stayed down until somebody restarted the process; the relay never
  // had one at all. A bounded call site can afford to keep retrying, so this
  // has to heal by itself.
  proxy.unhole();
  const deadline = Date.now() + 15000;
  let after = null;
  while (Date.now() < deadline) {
    after = await srv.post('/v2/user/setup-totp', { headers: { 'X-Internal-Auth': OUTAGE_INTERNAL }, body: { user_id: uid() } });
    if (after.status === 200) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  assert.equal(after.status, 200, `the relay must recover on its own once redis answers again, last: ${after.status} ${after.text}`);
  outageDid();

  srv.stop();
  proxy.close();
});
