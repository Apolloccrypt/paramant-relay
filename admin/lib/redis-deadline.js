'use strict';
// Every redis call answers, or fails, inside a bound. Nothing waits forever.
//
// WHY THIS FILE EXISTS. node-redis does not time a command out. Two separate
// mechanisms can park a request until the client gives up, and neither of them
// has a default deadline:
//
//   1. THE OFFLINE QUEUE. While the socket is down and the client is
//      reconnecting, every command is pushed onto an in-memory queue and held
//      there. The default reconnect strategy retries forever, so the queue is
//      drained only if the server comes back. Measured against redis 5.12.1 and
//      6.2.1 with the connection cut underneath a live client: the FIRST command
//      after the cut rejects (SocketClosedUnexpectedlyError, ~1ms), and every
//      command after that neither resolves nor rejects. Still pending after four
//      seconds, and after twelve, and after any bound you care to measure.
//
//   2. A BLACK HOLE. If the packets stop arriving but the socket stays open
//      (a firewall that drops rather than rejects, a wedged proxy, a paused
//      container), the client never learns anything is wrong. isReady stays
//      true, the command goes out, and the reply never comes. Measured on both
//      versions: pending forever, with disableOfflineQueue on.
//
// So both fixes are needed, and neither is sufficient alone. disableOfflineQueue
// turns case 1 into an immediate rejection; it cannot see case 2, because from
// the client's point of view nothing has failed. A per-command deadline catches
// case 2, and also case 1 for the window before the socket error lands.
//
// WHY IT IS A PROXY AND NOT A CALL-SITE WRAPPER. #368 bounded exactly one read,
// by hand, on the TOTP path. There are roughly 300 redis call sites across
// relay.js, relay/lib/*, relay/envelope.js, admin/server.js and admin/lib/* --
// a wrapper each is a list that is wrong the first time somebody adds a route.
// guardRedisClient wraps the CLIENT, so a call site cannot opt out of the bound
// by forgetting about it, and a new call site inherits it for free.
//
// WHAT A CALLER SEES. A bound that is exceeded, a socket that is gone, a client
// that is offline: all three arrive as RedisUnavailableError, which
// isRedisOutage() recognises. That is the whole point of one error type -- the
// route does not have to know which of the three happened to know that the
// honest answer is 503 and not a wrong-code 401 or a 500.
//
// WHAT IT DOES BEYOND THE BOUND. It rebuilds the connection after two
// unanswered commands in a row, because a bound alone leaves the client wedged:
// node-redis goes on waiting for a reply that was lost and holds every later
// command behind it, forever, even after the network heals. See
// RESET_AFTER_BREACHES.
//
// WHAT IT DOES NOT DO. It does not retry a command, and it does not hold a
// circuit open. While the store is down every request pays the deadline once
// and then answers 503; it does not learn. That is deliberate: a breaker adds
// state that has to be right, and the property this module owes the auth paths
// is a BOUND, not throughput during an outage.
//
// This file is byte-identical to admin/lib/redis-deadline.js. The two services
// are separate npm projects on different major versions of the redis client
// (relay 5.x, admin 6.x) and their Dockerfiles copy only their own lib/, so the
// module cannot be shared by require(). tests/redis-deadline-parity.test.mjs
// fails if the two copies drift.

const DEFAULT_DEADLINE_MS = 1000;

// Errors the redis client raises when the connection, rather than the command,
// is the problem. Matched on the constructor name because node-redis sets
// err.name to a plain 'Error' on all of them.
const OUTAGE_CONSTRUCTORS = new Set([
  'ClientClosedError',
  'ClientOfflineError',
  'ConnectionTimeoutError',
  'DisconnectsClientError',
  'ReconnectStrategyError',
  'SocketClosedUnexpectedlyError',
  'SocketTimeoutError',
]);

// Socket-level failures that surface as a plain Error with a code.
const OUTAGE_CODES = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'EHOSTUNREACH', 'ENETUNREACH',
  'ENOTFOUND', 'ETIMEDOUT', 'EAI_AGAIN',
]);

// The store answers, and refuses. Redis replies to a command with an error
// whose message starts with one of these words; node-redis raises that as a
// plain Error, so neither the constructor set nor the socket codes above see
// it. Every one of them means the same thing to a caller as an unreachable
// store: the request failed for a reason that is not the caller's fault and
// that a retry may fix. They are NOT command mistakes -- WRONGTYPE, a bad Lua
// script and a wrong arity stay 500, because those are bugs in this code.
//
// Found on 07-09-2026: /api/captcha/challenge answered 500 internal_error in
// production while signup and password reset were dead. The route's own catch
// could not have produced that body, and the 503 branch in the error handler
// did not fire, because the store was not unreachable -- it was refusing
// writes. A safeguard that exists and cannot fire for the failure that is
// actually happening.
const REFUSAL_PREFIXES = [
  'READONLY',   // write sent to a read-only replica
  'MISCONF',    // RDB snapshot failing, so writes are refused (usually a full disk)
  'OOM',        // maxmemory reached
  'NOPERM',     // the ACL user may read but not write
  'NOAUTH',     // the connection never authenticated
  'WRONGPASS',  // it tried and the password is wrong
  'LOADING',    // still reading the dataset from disk
  'BUSY',       // a script is blocking the server
  'CLUSTERDOWN',
  'TRYAGAIN',
  'MASTERDOWN',
];

// The refusal word Redis put at the front of its reply, or null. Kept separate
// from the boolean so a caller can log WHICH refusal it was; without that the
// operator sees "redis_unavailable" and still has to guess between a full disk
// and a wrong ACL.
function redisRefusal(err) {
  const msg = err && typeof err.message === 'string' ? err.message : '';
  if (!msg) return null;
  const first = msg.split(/[\s:]/, 1)[0].toUpperCase();
  return REFUSAL_PREFIXES.includes(first) ? first : null;
}

// One failure type for "the store could not answer", whatever the reason. A
// route that catches this knows the request failed for a reason that is not the
// caller's fault, which is exactly the 503 case.
class RedisUnavailableError extends Error {
  constructor(op, reason, cause) {
    super(`redis_unavailable: ${op} (${reason})`);
    this.name = 'RedisUnavailableError';
    this.code = 'REDIS_UNAVAILABLE';
    // A plain marker as well as instanceof, so the check survives two copies of
    // this module in one process (relay lib + a dependency's, say).
    this.isRedisOutage = true;
    this.op = op;
    this.reason = reason;
    if (cause !== undefined) this.cause = cause;
  }
}

// Is this error the store failing us, rather than the command being wrong? A
// WRONGTYPE or a bad Lua script is a 500 and must not be laundered into a 503,
// so the match stays on connection failures plus the refusals above -- never on
// a command this code got wrong.
function isRedisOutage(err) {
  if (!err || typeof err !== 'object') return false;
  if (err.isRedisOutage === true) return true;
  if (err.code && OUTAGE_CODES.has(err.code)) return true;
  const ctor = err.constructor && err.constructor.name;
  if (ctor && OUTAGE_CONSTRUCTORS.has(ctor)) return true;
  if (OUTAGE_CONSTRUCTORS.has(err.name)) return true;
  return redisRefusal(err) !== null;
}

// The configured bound, in milliseconds. One name for the whole estate:
// PARAMANT_REDIS_DEADLINE_MS, the knob #368 introduced for the single TOTP read,
// now read by every redis call in both services. A deployment with a slow or
// distant redis may need more room; one that would rather refuse than wait may
// want less. Zero or nonsense is not an opt-out, because "wait forever" is the
// failure this exists to prevent.
function redisDeadlineMs(env = process.env) {
  const raw = parseInt((env && env.PARAMANT_REDIS_DEADLINE_MS) || '', 10);
  return Number.isFinite(raw) && raw > 0 ? raw : 1000;
}

// Race one redis call against the clock. A rejection that is already an outage
// is passed through as one; anything else keeps its own identity, because a
// command error is not an availability problem.
//
// opts.onTimeout / opts.onSettled let a caller count breaches. guardRedisClient
// uses them to decide when the connection itself has to be rebuilt; see
// RESET_AFTER_BREACHES.
function withRedisDeadline(promise, opts = {}) {
  const ms = opts.ms || redisDeadlineMs();
  const op = opts.op || 'command';
  let timer = null;
  const deadline = new Promise((_, reject) => {
    // Deliberately NOT unref'd. A deadline timer that does not hold the event
    // loop open does not fire when nothing else is running, and the call it was
    // supposed to bound stays pending for good -- which is the exact failure
    // this module exists to prevent, reintroduced in the mechanism that
    // prevents it. It lives at most `ms` and the finally below always clears it.
    timer = setTimeout(() => {
      if (opts.onTimeout) { try { opts.onTimeout(); } catch (_) { /* never the caller's problem */ } }
      reject(new RedisUnavailableError(op, `no answer within ${ms}ms`));
    }, ms);
  });
  return Promise.race([Promise.resolve(promise), deadline])
    .then((value) => {
      if (opts.onSettled) { try { opts.onSettled(); } catch (_) { /* idem */ } }
      return value;
    }, (err) => {
      if (err instanceof RedisUnavailableError) throw err;
      // A command error (WRONGTYPE, a bad script) proves the connection is
      // alive, so it clears the breach count as much as a success does.
      if (opts.onSettled) { try { opts.onSettled(); } catch (_) { /* idem */ } }
      if (isRedisOutage(err)) throw new RedisUnavailableError(op, err.message, err);
      throw err;
    })
    .finally(() => { if (timer) clearTimeout(timer); });
}

// How many deadline breaches in a row before the connection is rebuilt.
//
// WHY THE CONNECTION HAS TO BE REBUILT AT ALL. A deadline makes the CALLER
// safe, not the client. When a command is lost to a silent connection,
// node-redis keeps waiting for its reply, and every command issued afterwards
// waits behind it. Measured on 5.12.1 and 6.2.1: hole a connection, let one
// command be swallowed, then let the bytes flow again -- the client never
// recovers. isReady stays true, every later command hangs, and only a restart
// of the process fixes it. destroy() followed by connect() rebuilds the
// pipeline in about three milliseconds.
//
// WHY NOT ON THE FIRST BREACH. One slow command is not a wedge. A big SCAN, a
// loaded server, a garbage-collection pause: tearing the socket down for those
// would turn a slow minute into a broken one, and it would do it exactly when
// the server is under most pressure. Two in a row, with nothing succeeding in
// between, is a connection that is not coming back by itself.
const RESET_AFTER_BREACHES = 2;

// Members that must reach the real client untouched: lifecycle, events, and the
// flags callers read to decide whether to try at all. Bounding connect() would
// fight the socket's own connectTimeout, and bounding an event registration is
// meaningless.
const PASSTHROUGH = new Set([
  'connect', 'disconnect', 'quit', 'close', 'destroy', 'unref', 'ref',
  'on', 'off', 'once', 'emit', 'addListener', 'removeListener', 'prependListener',
  'prependOnceListener', 'removeAllListeners', 'setMaxListeners', 'getMaxListeners',
  'listeners', 'rawListeners', 'listenerCount', 'eventNames',
]);

function guardValue(value, target, proxy, ms, op, hooks) {
  // A chainable command on a MULTI returns the multi itself. Hand back the
  // proxy instead, or the rest of the chain (and its exec) escapes the bound.
  if (value === target) return proxy;
  if (value && typeof value.then === 'function') return withRedisDeadline(value, { ms, op, ...hooks });
  if (value && typeof value[Symbol.asyncIterator] === 'function') return guardAsyncIterable(value, ms, op, hooks);
  // MULTI/pipeline builders and duplicated clients are objects whose own
  // methods still have to be bounded, so wrap them the same way.
  if (value && typeof value === 'object' && looksLikeCommandBuilder(value)) {
    return guardRedisClient(value, { ms });
  }
  return value;
}

function looksLikeCommandBuilder(value) {
  return typeof value.exec === 'function'
    || typeof value.execAsPipeline === 'function'
    || typeof value.sendCommand === 'function';
}

// scanIterator and friends yield over many round trips. A bound on the whole
// loop would be wrong (a big keyspace is slow, not broken), so each step gets
// its own: no single next() can park the caller.
function guardAsyncIterable(iterable, ms, op, hooks) {
  return {
    [Symbol.asyncIterator]() {
      const it = iterable[Symbol.asyncIterator]();
      return {
        next(...args) { return withRedisDeadline(it.next(...args), { ms, op: `${op}.next`, ...hooks }); },
        return(...args) { return it.return ? it.return(...args) : Promise.resolve({ done: true, value: undefined }); },
        throw(...args) { return it.throw ? it.throw(...args) : Promise.reject(args[0]); },
      };
    },
  };
}

// Wrap a connected (or connecting) redis client so every command it exposes is
// bounded. Returns a Proxy: property reads, isReady, isOpen and the event
// emitter all behave exactly as before.
function guardRedisClient(client, opts = {}) {
  if (!client) return client;
  const ms = opts.ms || redisDeadlineMs();
  const label = opts.label || 'redis';

  let breaches = 0;
  let rebuilding = false;
  const settled = () => { breaches = 0; };
  const timedOut = () => {
    breaches++;
    if (breaches < RESET_AFTER_BREACHES || rebuilding) return;
    // A client somebody closed on purpose (shutdown) is not a wedge.
    if (client.isOpen === false) return;
    breaches = 0;
    rebuilding = true;
    console.error(`[${label}] rebuilding the connection: ${RESET_AFTER_BREACHES} commands in a row went unanswered`);
    Promise.resolve()
      .then(() => client.destroy())
      .catch(() => { /* already gone is the state we wanted */ })
      .then(() => client.connect())
      .catch(() => { /* the reconnect strategy keeps trying */ })
      .then(() => { rebuilding = false; }, () => { rebuilding = false; });
  };
  const hooks = { onTimeout: timedOut, onSettled: settled };

  // Wrapped methods are memoised so f === f across reads, which code that
  // stores a handler or compares functions relies on.
  const wrapped = new Map();
  const proxy = new Proxy(client, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== 'function') return value;
      if (typeof prop !== 'string' || PASSTHROUGH.has(prop)) return value.bind(target);
      if (wrapped.has(prop)) return wrapped.get(prop);
      const fn = (...args) => guardValue(value.apply(target, args), target, proxy, ms, prop, hooks);
      wrapped.set(prop, fn);
      return fn;
    },
  });
  return proxy;
}

// The client options that stop a command being queued behind a reconnect. Merged
// into whatever the service already passes, so a caller keeps its own url and
// its own reconnectStrategy.
//
// disableOfflineQueue is the load-bearing one: without it a command issued while
// the socket is down is held, not refused. connectTimeout bounds the other end
// of the same problem, a connect that never completes.
function redisClientBounds(env = process.env) {
  return {
    disableOfflineQueue: true,
    socket: {
      connectTimeout: redisDeadlineMs(env),
      // Keep reconnecting (an outage should heal by itself), but never let a
      // command wait for it: disableOfflineQueue refuses the command instead.
      reconnectStrategy: (retries) => Math.min(50 * (retries + 1), 3000),
    },
  };
}

module.exports = {
  DEFAULT_DEADLINE_MS,
  RESET_AFTER_BREACHES,
  RedisUnavailableError,
  REFUSAL_PREFIXES,
  redisRefusal,
  isRedisOutage,
  redisDeadlineMs,
  withRedisDeadline,
  guardRedisClient,
  redisClientBounds,
};
