'use strict';
// A counter that always carries an expiry, even when the call that created it
// did not finish.
//
// THE BUG THIS REPLACES. Every rate limiter in both services was written as
// INCR followed by a CONDITIONAL expiry:
//
//   const count = await redis.incr(k);
//   if (count === 1) await redis.expire(k, WINDOW_S);   // only on the first hit
//
// That is correct only if the two commands always happen together. They do not.
// The redis deadline added alongside this file makes the failure reachable in
// one request: if the INCR exceeds the deadline while the SERVER still executes
// it, the caller gets an outage and the EXPIRE is never sent. The key now holds
// a count with TTL -1, and TTL -1 means for ever. The next request INCRs it to
// 2, so `count === 1` is false and the expiry is never set by any later call
// either. Measured on a booted admin with redis frozen for 1.4 s during one
// login: the per-IP counter stood at 9 with TTL -1, and that address kept
// getting 429 until somebody deleted the key by hand.
//
// It is worse than a slow limiter. paramant:user:ratelimit:ip:<ip> becomes a
// permanent 429 for that source address; paramant:user:loginfail:<hash> becomes
// a permanent proof-of-work obligation on an address anybody may name; and the
// monthly quota counters in relay/lib/quota.js become an account that is over
// its limit for good. All three are denial of service handed out by the code
// that exists to prevent denial of service, and all three are triggered by a
// redis hiccup rather than by an attacker.
//
// THE RULE. Set the expiry UNCONDITIONALLY after every INCR, with NX so it can
// only ever create a window and never slide one. NX is what keeps the semantics
// exactly as they were for the healthy case: the first hit sets the window, and
// every later hit in that window is a no-op that costs one round trip. What
// changes is the broken case: the first hit that lands after a lost expiry
// repairs it, so a missing TTL survives exactly one request instead of for ever.
//
// The alternative fix is a window inside the key, which relay.js:1509 already
// does for envcreate. It also bounds the damage, but only to one window, and it
// leaks a key per window per subject. This is the smaller change and it repairs
// the keys that are already stuck in production.
//
// This file is byte-identical to admin/lib/redis-counter.js, for the reason
// given at the top of lib/redis-deadline.js; tests/redis-deadline-parity.test.mjs
// fails if they drift.

// EXPIRE ... NX needs Redis 7.0. docker-compose.yml pins 7.4.8 by digest, so
// the supported deployment has it. A self-hoster on 6.x would otherwise get an
// error on every rate-limited route, which would be a far worse regression than
// the bug being fixed, so the first refusal switches this process to the
// two-round-trip form for good.
let nxSupported = true;

// An error that means "this server does not know EXPIRE ... NX", as opposed to
// an error that means the store is unreachable. Redis answers an unknown option
// with a syntax error; getting that wrong either way would be bad, so the match
// is narrow and anything else is re-thrown.
function isUnsupportedNx(err) {
  const msg = String((err && err.message) || '').toLowerCase();
  return msg.includes('syntax error')
    || msg.includes('wrong number of arguments')
    || msg.includes('unknown argument');
}

// Give `key` a window if it does not already have one. Never shortens or
// extends an existing TTL.
async function ensureWindow(client, key, windowSec) {
  if (nxSupported) {
    try {
      await client.expire(key, windowSec, 'NX');
      return;
    } catch (err) {
      if (!isUnsupportedNx(err)) throw err;
      nxSupported = false;
    }
  }
  // Redis 6 and older: the same decision, in two round trips. -1 is "no TTL",
  // -2 is "no key" (which EXPIRE would ignore anyway).
  const ttl = await client.ttl(key);
  if (ttl === -1) await client.expire(key, windowSec);
}

// INCR a counter and make sure it expires. Returns the post-increment count,
// exactly like INCR, so a call site changes from two lines to one and nothing
// else about it moves.
//
// A store outage during the expiry still propagates: the count moved, the
// window did not, and the next healthy call repairs it. That is the point.
async function incrInWindow(client, key, windowSec) {
  const count = await client.incr(key);
  await ensureWindow(client, key, windowSec);
  return count;
}

module.exports = { incrInWindow, ensureWindow };
