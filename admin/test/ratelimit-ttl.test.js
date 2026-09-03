'use strict';
// A rate-limit counter that loses its expiry is a permanent refusal.
//
// THE BUG. Every limiter in both services was INCR followed by a CONDITIONAL
// expiry, `if (count === 1) await expire(k, WINDOW)`. The redis deadline this
// branch added makes the gap between those two commands reachable in a single
// request: if the INCR exceeds the deadline while the SERVER still executes it,
// the caller gets an outage and the EXPIRE is never sent. The key then holds a
// count with TTL -1, and because the next INCR returns 2 rather than 1, no
// later call sets the expiry either. TTL -1 means for ever.
//
// For paramant:user:ratelimit:ip:<ip> that is a 429 for that source address
// until somebody deletes the key by hand. For paramant:user:loginfail:<hash> it
// is a proof-of-work obligation that never lifts, on an address anybody may
// name. Both are denial of service produced by a redis hiccup, in the code that
// exists to prevent denial of service.
//
// WHAT THIS SUITE DOES. It boots a real admin behind a proxy that can drop
// REPLIES while still delivering commands, which is the shape that makes the
// server execute the INCR and the client give up on it. Then it reads the TTL
// with its own connection and asserts the key is not immortal.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/ratelimit-ttl.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const net = require('net');
const { boot, killAll, freePort, stubRelay, defaultRelayState, summary } = require('./_admin-server');

const TTL_DEFAULT_REDIS = 'redis://127.0.0.1:6399';
// Short, so the suite spends a deadline and not a second per sabotaged request.
const TTL_DEADLINE_MS = 300;
const TTL_ACCOUNT = 'pgp_account_for_the_ratelimit_ttl_suite';
const TTL_EMAIL = 'owner@example.com';
// login-ratelimit.js WINDOW_S.
const TTL_WINDOW_S = 900;

let ttlUrl = null;
let ttlRedis = null;
let ttlChecks = 0;
const ttlDid = () => { ttlChecks++; };

const TTL_NET = 20 + Math.floor(Math.random() * 200);
let _ttlIp = 0;
const ttlIp = () => { _ttlIp++; return `${TTL_NET}.${(_ttlIp >> 8) & 255}.${_ttlIp & 255}.17`; };

before(async () => {
  const url = process.env.REDIS_URL || TTL_DEFAULT_REDIS;
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
  try { await rc.connect(); await rc.ping(); }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log(`  SKIP [redis] - no reachable redis at ${url} (declared via ADMIN_TEST_SKIP)`);
      return;
    }
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  ttlUrl = url;
  ttlRedis = rc;
});

after(async () => {
  await killAll();
  if (ttlRedis) { try { await ttlRedis.disconnect(); } catch (_) { /* already gone */ } }
  summary('ratelimit-ttl', ttlChecks);
});

// A proxy that can drop one direction. holeReplies() is the important one: the
// command still reaches redis and is executed, and the answer never comes back.
// A full black hole would not reproduce the bug, because then the INCR never
// happens either and there is no orphaned counter to strand.
function halfProxy(port, upstreamUrl) {
  const u = new URL(upstreamUrl);
  const sockets = new Set();
  let dropReplies = false;
  const server = net.createServer((client) => {
    const upstream = net.connect(Number(u.port || 6379), u.hostname || '127.0.0.1');
    sockets.add(client); sockets.add(upstream);
    client.on('error', () => {}); upstream.on('error', () => {});
    client.on('data', (d) => upstream.write(d));
    upstream.on('data', (d) => { if (!dropReplies) client.write(d); });
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
      holeReplies() { dropReplies = true; },
      heal() { dropReplies = false; },
      close() {
        for (const s of sockets) { try { s.destroy(); } catch (_) { /* already gone */ } }
        sockets.clear();
        try { server.close(); } catch (_) { /* already closed */ }
      },
    }));
  });
}

async function bootBehindHalfProxy() {
  const proxyPort = await freePort();
  const proxy = await halfProxy(proxyPort, ttlUrl);
  const relay = await stubRelay(defaultRelayState([{ key: TTL_ACCOUNT, email: TTL_EMAIL, active: true }], '123456'));
  const srv = await boot({
    redisUrl: `redis://127.0.0.1:${proxyPort}`,
    relay,
    env: { PARAMANT_REDIS_DEADLINE_MS: String(TTL_DEADLINE_MS) },
  });
  return { srv, proxy, relay };
}

// Wait for the admin's client to be usable again. The guard rebuilds the
// connection after two unanswered commands, and the rebuild is not instant.
async function waitHealthy(srv) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const h = await srv.get('/health');
    if (h.json && h.json.status === 'ok') return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

const ipKey = (ip) => `paramant:user:ratelimit:ip:${ip}`;
const failKey = (email) =>
  `paramant:user:loginfail:${crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex')}`;

test('a counter whose INCR outlived the deadline still gets an expiry', async (t) => {
  if (!ttlUrl) return t.skip('no redis');
  const { srv, proxy, relay } = await bootBehindHalfProxy();
  // Registered before the first assertion: a test that goes red must still hand
  // its sockets back, or node --test sits there after the failure it just found.
  t.after(async () => { srv.stop(); proxy.close(); await relay.close(); });
  const ip = ttlIp();
  const key = ipKey(ip);
  await ttlRedis.del(key);

  // Drop the ANSWERS only. The INCR lands on the server and is executed; the
  // caller waits out the deadline and gives up, so the expiry after it is never
  // sent. This is the one request that used to strand the key for good.
  proxy.holeReplies();
  const during = await srv.login({ email: TTL_EMAIL, totp: '000000', ip });
  assert.equal(during.status, 503, `the outage itself must still answer 503, got ${during.status} ${during.text}`);
  ttlDid();

  // The damage really happened: the counter moved.
  const stranded = await ttlRedis.get(key);
  assert.ok(Number(stranded) >= 1, `the INCR must have been executed by the server, got ${stranded}`);
  ttlDid();

  proxy.heal();
  assert.ok(await waitHealthy(srv), 'the admin has to come back before the repair can be measured');

  // The next healthy attempt on the same key repairs the window. Before this
  // fix the expiry was only ever set when the count came back as exactly 1, and
  // it never does again, so the TTL stayed -1 for the life of the key.
  const after = await srv.login({ email: TTL_EMAIL, totp: '000000', ip });
  assert.ok([200, 401, 428].includes(after.status), `a healthy attempt answers normally, got ${after.status} ${after.text}`);
  const ttl = await ttlRedis.ttl(key);
  assert.ok(ttl > 0, `the per-IP counter must carry a window, got TTL ${ttl} (-1 means this address is refused for ever)`);
  assert.ok(ttl <= TTL_WINDOW_S, `and not a longer one than the limiter's own window, got ${ttl}`);
  ttlDid();

  await ttlRedis.del(key);
});

test('the same for the failure counter behind the proof-of-work threshold', async (t) => {
  if (!ttlUrl) return t.skip('no redis');
  const { srv, proxy, relay } = await bootBehindHalfProxy();
  // Registered before the first assertion: a test that goes red must still hand
  // its sockets back, or node --test sits there after the failure it just found.
  t.after(async () => { srv.stop(); proxy.close(); await relay.close(); });
  // A fresh address: this counter is keyed on the address, not on the caller,
  // so a stranded one is a permanent proof-of-work bill for its owner.
  const email = `victim_${crypto.randomBytes(5).toString('hex')}@example.com`;
  const key = failKey(email);
  await ttlRedis.del(key);

  // One healthy failure first, so the counter exists at 1 with a window, then a
  // sabotaged one on top. This is the harder case: the reviewer's report is
  // about a counter that is stranded at any value, not only at its first hit.
  const first = await srv.login({ email, totp: '000000', ip: ttlIp() });
  assert.equal(first.status, 401, `a miss is a 401: ${first.status} ${first.text}`);
  await ttlRedis.persist(key); // strip the TTL the way a lost expiry would have
  assert.equal(await ttlRedis.ttl(key), -1, 'the key is now in the state the bug leaves behind');
  ttlDid();

  proxy.holeReplies();
  await srv.login({ email, totp: '000000', ip: ttlIp() }).catch(() => null);
  proxy.heal();
  assert.ok(await waitHealthy(srv), 'the admin has to come back');

  const after = await srv.login({ email, totp: '000000', ip: ttlIp() });
  assert.ok([401, 428].includes(after.status), `a healthy attempt answers normally, got ${after.status} ${after.text}`);
  const ttl = await ttlRedis.ttl(key);
  assert.ok(ttl > 0,
    `the failure counter must carry a window, got TTL ${ttl} (-1 is a proof-of-work bill that never lifts)`);
  ttlDid();

  await ttlRedis.del(key);
});

test('an expiry that already exists is never extended by a later hit', async (t) => {
  if (!ttlUrl) return t.skip('no redis');
  // The repair uses EXPIRE ... NX, which only ever CREATES a window. If it slid
  // the window instead, a caller who keeps trying would keep their own refusal
  // alive for ever, which is the same denial of service from the other end.
  const { srv, proxy, relay } = await bootBehindHalfProxy();
  // Registered before the first assertion: a test that goes red must still hand
  // its sockets back, or node --test sits there after the failure it just found.
  t.after(async () => { srv.stop(); proxy.close(); await relay.close(); });
  const ip = ttlIp();
  const key = ipKey(ip);
  await ttlRedis.del(key);

  await srv.login({ email: TTL_EMAIL, totp: '000000', ip });
  const firstTtl = await ttlRedis.ttl(key);
  assert.ok(firstTtl > 0, `the first hit sets the window, got ${firstTtl}`);

  // Move the clock on by shortening the TTL, then hit it again.
  await ttlRedis.expire(key, 60);
  await srv.login({ email: TTL_EMAIL, totp: '000000', ip });
  const secondTtl = await ttlRedis.ttl(key);
  assert.ok(secondTtl <= 60,
    `a later hit must not extend the window, it was 60s and is now ${secondTtl}`);
  ttlDid();

  await ttlRedis.del(key);
});
