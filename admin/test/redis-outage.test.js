'use strict';
// A booted admin with its redis taken away, sabotaged the two ways an outage
// actually happens, asked for an answer.
//
// WHY THIS SUITE EXISTS. #368 bounded one redis read on the relay's TOTP path
// and left the rest open in SECURITY.md. The admin was not touched at all, and
// it is the worse half of the problem: every authenticated request goes through
// a session read (server.js authUser), and POST /api/user/login does an INCR
// before it has authenticated anything. node-redis holds commands on an offline
// queue while it reconnects, so against a dead store none of those resolve or
// reject. The sign-in page does not fail; it just never answers.
//
// The admin's old reconnect strategy made it worse rather than better: it gave
// up after ten retries, and a client that has given up stays given up. A store
// that came back after a minute left an admin that needed a restart.
//
// WHAT IS ASSERTED. Every redis-backed route answers 503 inside the deadline,
// /health stays 200 and says "degraded" out loud, and the process heals by
// itself when the store comes back.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/redis-outage.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const net = require('net');
const { boot, killAll, freePort, stubRelay, defaultRelayState, summary } = require('./_admin-server');

const AO_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const AO_DEADLINE_MS = 400;
const AO_CEILING_MS = 3000;
// One account per run, not one per repo. The failure counter behind the
// proof-of-work threshold lives in redis for fifteen minutes and is shared with
// every other suite pointed at the same server, so a fixed address collects
// other people's failures and starts answering 428 halfway through a run.
const AO_RUN = crypto.randomBytes(5).toString('hex');
const AO_KEY = `pgp_account_for_the_admin_outage_suite_${AO_RUN}`;
const AO_EMAIL = `owner_${AO_RUN}@example.com`;

let aoUrl = null;
let aoChecks = 0;
const aoDid = () => { aoChecks++; };

const AO_NET = 20 + Math.floor(Math.random() * 200);
let _aoIp = 0;
const aoIp = () => { _aoIp++; return `${AO_NET}.${(_aoIp >> 8) & 255}.${_aoIp & 255}.13`; };

before(async () => {
  const url = process.env.REDIS_URL || AO_DEFAULT_REDIS;
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log('  SKIP [redis] - the "redis" module is not installed (declared via ADMIN_TEST_SKIP)');
      return;
    }
    throw new Error('unmet precondition "redis": the redis module is not installed. ' +
      'Run npm ci in admin/, or declare it: ADMIN_TEST_SKIP=redis');
  }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); await rc.disconnect(); }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log(`  SKIP [redis] - no reachable redis at ${url} (declared via ADMIN_TEST_SKIP)`);
      return;
    }
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  aoUrl = url;
});

after(async () => {
  await killAll();
  summary('admin-redis-outage', aoChecks);
});

// The same two sabotages as relay/test/route-redis-outage.test.js. A cut socket
// is what disableOfflineQueue answers; a socket that stays open and goes silent
// is what only a deadline answers, because the client still believes it is fine.
function aoProxy(port, upstreamUrl) {
  const u = new URL(upstreamUrl);
  const sockets = new Set();
  let holed = false;
  const server = net.createServer((client) => {
    const upstream = net.connect(Number(u.port || 6379), u.hostname || '127.0.0.1');
    sockets.add(client); sockets.add(upstream);
    client.on('error', () => {}); upstream.on('error', () => {});
    client.on('data', (d) => { if (!holed) upstream.write(d); });
    upstream.on('data', (d) => { if (!holed) client.write(d); });
    // Copying by hand means closing by hand: an orphaned upstream socket keeps
    // the test process alive after the last assertion.
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
      hole() { holed = true; },
      unhole() { holed = false; },
      cut() {
        for (const s of sockets) { try { s.destroy(); } catch (_) { /* already gone */ } }
        sockets.clear();
        return new Promise((r) => server.close(r));
      },
      close() {
        for (const s of sockets) { try { s.destroy(); } catch (_) { /* already gone */ } }
        sockets.clear();
        try { server.close(); } catch (_) { /* already closed */ }
      },
    }));
  });
}

// Ten failures on one address costs the eleventh attempt a proof-of-work, and
// this suite spends failures freely. Each boot gets a clean slate.
async function clearFailures() {
  const { createClient } = require('redis');
  const c = createClient({ url: aoUrl });
  c.on('error', () => {});
  await c.connect();
  await c.del(`paramant:user:loginfail:${crypto.createHash('sha256').update(AO_EMAIL).digest('hex')}`);
  await c.destroy();
}

async function bootBehindProxy() {
  await clearFailures();
  const proxyPort = await freePort();
  const proxy = await aoProxy(proxyPort, aoUrl);
  const relay = await stubRelay(defaultRelayState([{ key: AO_KEY, email: AO_EMAIL, active: true }], '123456'));
  const srv = await boot({
    redisUrl: `redis://127.0.0.1:${proxyPort}`,
    relay,
    env: { PARAMANT_REDIS_DEADLINE_MS: String(AO_DEADLINE_MS) },
  });
  return { srv, proxy, relay };
}

async function timed(fn) {
  const t0 = Date.now();
  const res = await fn();
  return { ...res, ms: Date.now() - t0 };
}

async function assertAdminOutage(t, breakIt, name) {
  if (!aoUrl) return t.skip('no redis');
  const { srv, proxy, relay } = await bootBehindProxy();
  // Before the first assertion: a red test still has to release its sockets, or
  // the run hangs on the failure instead of reporting it.
  t.after(async () => { srv.stop(); proxy.close(); await relay.close(); });

  // With the store up the route works, so the 503s below are about the outage.
  const up = await srv.login({ email: AO_EMAIL, totp: '000000', ip: aoIp() });
  assert.equal(up.status, 401, `with redis up, a wrong code is a 401: ${up.status} ${up.text}`);
  aoDid();

  await breakIt(proxy);

  const routes = [
    // The INCR before any authentication. This is the first redis call on the
    // whole sign-in path, so it is the one that used to swallow the request.
    ['POST /api/user/login', () => srv.login({ email: AO_EMAIL, totp: '000000', ip: aoIp() })],
    // The session read every authenticated request makes.
    ['GET /api/user/me', () => srv.get('/api/user/me', { headers: { Cookie: `paramant_user_session=${crypto.randomBytes(16).toString("hex")}` } })],
    ['GET /api/user/session/verify', () => srv.get('/api/user/session/verify', { headers: { Cookie: `paramant_user_session=${crypto.randomBytes(16).toString("hex")}` } })],
    // A proof-of-work challenge is a redis write, and the login page asks for
    // one the moment an address goes over the threshold.
    ['GET /api/captcha/challenge', () => srv.get('/api/captcha/challenge', { headers: { 'X-Real-IP': aoIp() } })],
  ];

  for (const [label, call] of routes) {
    const res = await timed(call);
    assert.equal(res.status, 503,
      `${label} must answer 503 with the store gone (${name}), got ${res.status} ${res.text}`);
    assert.ok(res.ms < AO_CEILING_MS,
      `${label} must answer inside the deadline, took ${res.ms}ms`);
    aoDid();
  }

  // The admin had no health route at all before this change: the container
  // probe was GET /api/auth/check, which answers 401 when nobody is signed in,
  // so "healthy" meant "the process still refuses me" whether the store was
  // there or not.
  const health = await timed(() => srv.get('/health'));
  assert.equal(health.status, 200, `/health stays 200 in a store outage, got ${health.status}`);
  assert.ok(health.ms < AO_CEILING_MS, `/health must not hang either, took ${health.ms}ms`);
  assert.equal(health.json.status, 'degraded', `and it says so: ${health.text}`);
  assert.equal(health.json.redis.ok, false);
  aoDid();

}

test('a cut connection: every redis-backed admin route answers 503 inside the deadline', async (t) => {
  await assertAdminOutage(t, (proxy) => proxy.cut(), 'cut');
});

test('a silent connection: the same, where the client still believes it is ready', async (t) => {
  await assertAdminOutage(t, (proxy) => { proxy.hole(); return Promise.resolve(); }, 'black hole');
});

test('the admin heals by itself when the store comes back', async (t) => {
  if (!aoUrl) return t.skip('no redis');
  const { srv, proxy, relay } = await bootBehindProxy();
  t.after(async () => { srv.stop(); proxy.close(); await relay.close(); });

  proxy.hole();
  const during = await timed(() => srv.login({ email: AO_EMAIL, totp: '000000', ip: aoIp() }));
  assert.equal(during.status, 503, 'refused while the store is silent');
  assert.equal((await srv.get('/health')).json.status, 'degraded');
  aoDid();

  // Bytes flow again on the same sockets, which is the case node-redis does not
  // survive on its own: it is still waiting for the reply that was swallowed
  // and holds every later command behind it. The connection rebuild in
  // lib/redis-deadline is what gets past that. The old ten-retry give-up made
  // this worse: it stopped trying and stayed stopped.
  proxy.unhole();

  // Polled on /health rather than on the login route, because a poll made of
  // failed sign-ins would push the address over the proof-of-work threshold and
  // then measure that instead.
  const deadline = Date.now() + 20000;
  let healthy = null;
  while (Date.now() < deadline) {
    healthy = await srv.get('/health');
    if (healthy.json && healthy.json.status === 'ok') break;
    await new Promise((r) => setTimeout(r, 250));
  }
  assert.equal(healthy.json.status, 'ok',
    `the admin must recover without a restart, /health still says: ${healthy.text}`);

  const after = await srv.login({ email: AO_EMAIL, totp: '000000', ip: aoIp() });
  assert.equal(after.status, 401,
    `and the login route works again, got ${after.status} ${after.text}`);
  aoDid();

});
