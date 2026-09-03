'use strict';
// The bound itself, without a redis and without a relay.
//
// route-redis-outage.test.js proves the property where it matters, on booted
// processes with a real store cut out from under them. It needs redis, so the
// unit job does not run it. This suite is the part that can be checked
// everywhere: the classifier, the deadline, the proxy that puts the deadline on
// every command, and the connection rebuild.
//
// Run: node --test relay/test/redis-deadline.test.js

const { test } = require('node:test');
const assert = require('assert');
const {
  RedisUnavailableError, isRedisOutage, redisDeadlineMs, withRedisDeadline,
  guardRedisClient, redisClientBounds, RESET_AFTER_BREACHES,
} = require('../lib/redis-deadline');

let deadlineChecks = 0;
const deadlineDid = () => { deadlineChecks++; };

// The four shapes node-redis actually throws, by constructor name, because it
// leaves err.name as a plain 'Error' on all of them.
function namedError(ctorName, message) {
  const C = { [ctorName]: class extends Error {} }[ctorName];
  Object.defineProperty(C, 'name', { value: ctorName });
  const e = new C(message || ctorName);
  return e;
}

const never = () => new Promise(() => {});

test('a call that never answers becomes an outage, inside the deadline', async () => {
  const t0 = Date.now();
  await assert.rejects(
    withRedisDeadline(never(), { ms: 60, op: 'get' }),
    (err) => {
      assert.ok(err instanceof RedisUnavailableError, 'the type a route can branch on');
      assert.equal(err.code, 'REDIS_UNAVAILABLE');
      assert.match(err.message, /get/, 'and it says which command');
      return true;
    });
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 1000, `it must not wait longer than it said, took ${elapsed}ms`);
  deadlineDid();
});

test('a command that simply fails keeps its own identity', async () => {
  // WRONGTYPE, a bad Lua script, a syntax error: the store answered, so this is
  // a bug and not an outage. Laundering it into a 503 would tell a monitor to
  // page the person who looks after redis for something in this repo.
  const boom = new Error('WRONGTYPE Operation against a key holding the wrong kind of value');
  await assert.rejects(withRedisDeadline(Promise.reject(boom), { ms: 60 }), (err) => {
    assert.equal(err, boom, 'the original error, not a wrapper');
    assert.equal(isRedisOutage(err), false, 'and it does not read as an outage');
    return true;
  });
  deadlineDid();
});

test('a connection failure reads as an outage whatever shape it arrives in', () => {
  for (const ctor of ['ClientClosedError', 'ClientOfflineError', 'SocketClosedUnexpectedlyError',
    'ConnectionTimeoutError', 'ReconnectStrategyError', 'DisconnectsClientError']) {
    assert.equal(isRedisOutage(namedError(ctor)), true, `${ctor} is an outage`);
  }
  for (const code of ['ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'ENOTFOUND']) {
    const e = new Error('socket'); e.code = code;
    assert.equal(isRedisOutage(e), true, `${code} is an outage`);
  }
  assert.equal(isRedisOutage(new Error('WRONGTYPE')), false, 'a command error is not');
  assert.equal(isRedisOutage(null), false);
  assert.equal(isRedisOutage('a string'), false);
  // The marker, so the check survives two copies of this module in one process.
  assert.equal(isRedisOutage({ isRedisOutage: true }), true);
  deadlineDid();
});

test('a socket failure is re-reported as an outage rather than passed through raw', async () => {
  const offline = namedError('ClientOfflineError', 'The client is offline');
  await assert.rejects(withRedisDeadline(Promise.reject(offline), { ms: 60, op: 'incr' }), (err) => {
    assert.ok(err instanceof RedisUnavailableError, 'one type for every way the store can be gone');
    assert.equal(err.cause, offline, 'with the original kept as the cause');
    return true;
  });
  deadlineDid();
});

test('the deadline is configurable, and cannot be switched off', () => {
  assert.equal(redisDeadlineMs({}), 1000, 'unset means one second');
  assert.equal(redisDeadlineMs({ PARAMANT_REDIS_DEADLINE_MS: '2500' }), 2500, 'a slow store can be given more room');
  for (const bad of ['0', '-1', 'off', 'true', '', 'NaN']) {
    assert.equal(redisDeadlineMs({ PARAMANT_REDIS_DEADLINE_MS: bad }), 1000,
      `"${bad}" cannot disable the bound`);
  }
  deadlineDid();
});

test('the client options refuse a queued command instead of holding it', () => {
  const opts = redisClientBounds({});
  // The load-bearing one. Without it a command issued while the socket is down
  // is pushed onto an unbounded offline queue and held until the server comes
  // back, which against a server that never comes back is forever.
  assert.equal(opts.disableOfflineQueue, true);
  assert.equal(typeof opts.socket.connectTimeout, 'number');
  assert.ok(opts.socket.connectTimeout > 0);
  // Reconnecting for ever is right, now that reconnecting no longer parks a
  // request. The admin's old strategy gave up after ten tries and stayed given
  // up, which turned a two-minute outage into one that needed a restart.
  assert.equal(typeof opts.socket.reconnectStrategy, 'function');
  for (const retries of [0, 1, 10, 100, 10000]) {
    const wait = opts.socket.reconnectStrategy(retries);
    assert.equal(typeof wait, 'number', `retry ${retries} must keep trying, not give up`);
    assert.ok(wait > 0 && wait <= 3000, `retry ${retries} backs off inside a sane bound, got ${wait}`);
  }
  deadlineDid();
});

// A client with the surface guardRedisClient touches, and a switch that makes
// every command hang the way a black hole does.
function fakeClient() {
  const calls = [];
  let hanging = false;
  const client = {
    isOpen: true,
    isReady: true,
    destroyed: 0,
    connected: 0,
    listeners: [],
    hang(on) { hanging = on; },
    async get(k) { calls.push(['get', k]); if (hanging) return never(); return 'value'; },
    async set(k, v) { calls.push(['set', k, v]); if (hanging) return never(); return 'OK'; },
    async ping() { if (hanging) return never(); return 'PONG'; },
    on(ev, fn) { client.listeners.push([ev, fn]); return client; },
    connect() { client.connected++; return Promise.resolve(); },
    destroy() { client.destroyed++; return Promise.resolve(); },
    multi() {
      const cmds = [];
      const m = {
        set(k, v) { cmds.push(['set', k, v]); return m; },
        exec() { if (hanging) return never(); return Promise.resolve(cmds.map(() => 'OK')); },
      };
      return m;
    },
    scanIterator() {
      let n = 0;
      return { [Symbol.asyncIterator]() { return {
        next() { if (hanging) return never(); n++; return Promise.resolve(n > 2 ? { done: true } : { done: false, value: [`k${n}`] }); },
      }; } };
    },
    calls,
  };
  // hang() returns a pending promise from an async function, which resolves to
  // a promise rather than staying pending, so the plain-function form is used
  // for the ones that must really never settle.
  client.get = (k) => { calls.push(['get', k]); return hanging ? never() : Promise.resolve('value'); };
  client.set = (k, v) => { calls.push(['set', k, v]); return hanging ? never() : Promise.resolve('OK'); };
  client.ping = () => (hanging ? never() : Promise.resolve('PONG'));
  return client;
}

test('the guard puts the bound on every command, without the call site asking', async () => {
  const raw = fakeClient();
  const c = guardRedisClient(raw, { ms: 60 });

  assert.equal(await c.get('k'), 'value', 'a healthy call is untouched');
  raw.hang(true);
  await assert.rejects(c.get('k'), (e) => isRedisOutage(e), 'and a hanging one is not');
  await assert.rejects(c.set('k', 'v'), (e) => isRedisOutage(e), 'the same for a command nobody wrapped by hand');
  deadlineDid();

  // The point of wrapping the client rather than the call sites: a method that
  // did not exist when this was written is bounded too.
  raw.hang(false);
  raw.brandNew = () => never();
  await assert.rejects(c.brandNew(), (e) => isRedisOutage(e),
    'a method added later inherits the bound instead of opting out of it');
  deadlineDid();
});

test('the guard leaves everything that is not a command alone', () => {
  const raw = fakeClient();
  const c = guardRedisClient(raw, { ms: 60 });
  assert.equal(c.isReady, true, 'flags read straight through');
  assert.equal(c.isOpen, true);
  const fn = () => {};
  c.on('error', fn);
  assert.deepEqual(raw.listeners, [['error', fn]], 'event registration is not a command');
  // Stable identity: code that stores a handler and compares it later must not
  // see a different function on every read.
  assert.equal(c.get, c.get, 'the wrapper is memoised');
  deadlineDid();
});

test('a MULTI cannot escape the bound by being chainable', async () => {
  const raw = fakeClient();
  const c = guardRedisClient(raw, { ms: 60 });
  assert.deepEqual(await c.multi().set('a', '1').set('b', '2').exec(), ['OK', 'OK']);
  raw.hang(true);
  await assert.rejects(c.multi().set('a', '1').exec(), (e) => isRedisOutage(e),
    'the exec at the end of the chain is bounded, not just the multi() that started it');
  deadlineDid();
});

test('an iterator is bounded per step, not per loop', async () => {
  // A big keyspace is slow, not broken, so a whole-loop deadline would be
  // wrong. Each round trip gets its own.
  const raw = fakeClient();
  const c = guardRedisClient(raw, { ms: 60 });
  const seen = [];
  for await (const batch of c.scanIterator({ MATCH: '*' })) seen.push(batch);
  assert.deepEqual(seen, [['k1'], ['k2']]);
  deadlineDid();

  raw.hang(true);
  await assert.rejects(async () => {
    for await (const _ of c.scanIterator({ MATCH: '*' })) { /* never gets here */ }
  }, (e) => isRedisOutage(e), 'a scan against a silent store stops instead of looping forever');
  deadlineDid();
});

test('two unanswered commands in a row rebuild the connection', async () => {
  // A bound makes the CALLER safe, not the client. node-redis goes on waiting
  // for the reply that was lost and holds every later command behind it, so a
  // connection that goes silent and then recovers never comes back on its own.
  // Measured on 5.12.1 and 6.2.1; destroy() plus connect() fixes it in about
  // three milliseconds.
  const raw = fakeClient();
  const c = guardRedisClient(raw, { ms: 40 });
  raw.hang(true);

  await assert.rejects(c.get('k'), (e) => isRedisOutage(e));
  assert.equal(raw.destroyed, 0, 'one slow command is not a wedge: a big SCAN must not cost the socket');
  deadlineDid();

  await assert.rejects(c.get('k'), (e) => isRedisOutage(e));
  // The rebuild is fired and not awaited, so give the microtask queue its turn.
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(raw.destroyed, 1, `${RESET_AFTER_BREACHES} in a row is`);
  assert.equal(raw.connected, 1, 'and it reconnects rather than staying down');
  deadlineDid();
});

test('a command that succeeds clears the score, so a slow patch never wedges the socket', async () => {
  const raw = fakeClient();
  const c = guardRedisClient(raw, { ms: 40 });

  raw.hang(true);
  await assert.rejects(c.get('k'), (e) => isRedisOutage(e));
  raw.hang(false);
  assert.equal(await c.get('k'), 'value');
  raw.hang(true);
  await assert.rejects(c.get('k'), (e) => isRedisOutage(e));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(raw.destroyed, 0,
    'two breaches with a success between them are two slow commands, not a dead connection');
  deadlineDid();
});

test('a client somebody closed on purpose is not rebuilt underneath them', async () => {
  const raw = fakeClient();
  const c = guardRedisClient(raw, { ms: 40 });
  raw.hang(true);
  raw.isOpen = false; // what shutdown looks like
  await assert.rejects(c.get('k'), (e) => isRedisOutage(e));
  await assert.rejects(c.get('k'), (e) => isRedisOutage(e));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(raw.connected, 0, 'a process that is shutting down must not reconnect its store');
  deadlineDid();
});

test('redis-deadline: closing count', () => {
  // The silent-suite gate greps for this line; a run that asserted nothing has
  // to say so rather than reporting a pass over nothing.
  console.log(deadlineChecks > 0
    ? `\nredis-deadline: ${deadlineChecks} checks passed`
    : '\nredis-deadline: SKIPPED - 0 checks ran');
});
