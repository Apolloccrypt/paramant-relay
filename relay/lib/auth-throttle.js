'use strict';
// Failure-counting throttle for the per-account MFA limiter in relay.js.
//
// WHAT IT REPLACES. userMfaAttemptOk(user_id) counted ATTEMPTS: it incremented
// on the way in and refused with 429 once ten of them landed inside five
// minutes, and only a success cleared it. The user_id comes off the request
// body, so ten posts naming somebody else's account shut that account out of
// /v2/user/verify-totp and /v2/user/consume-backup for the rest of the window.
// That is the same shape as the e-mail counter on the admin login: a limiter
// keyed on an identity the caller gets to name, producing a hard refusal for
// the owner of that identity.
//
// WHAT THIS DOES INSTEAD. Count failures, not attempts. A success clears the
// bucket. Past the threshold the caller is not refused, it is DELAYED, with the
// delay growing per extra failure and capped so a request never hangs. Cost,
// not denial: the account owner with a correct code always gets through, while
// a guesser pays for every wrong one, and the delay throttles the argon2 work
// on the backup-code path just as a refusal did.
//
// Pure and time-injectable (`now`), like lib/rate-limit.js: the caller owns the
// Map and its eviction sweep, this owns the decision.

// Failures inside one window before the delay starts.
const FAIL_THRESHOLD = 10;
// Window in which failures accumulate.
const WINDOW_MS = 300_000;
// Delay added per failure past the threshold, and the ceiling on it. 2s is long
// enough to make bulk guessing pointless and short enough that no honest client
// times out on it.
const STEP_MS = 250;
const MAX_DELAY_MS = 2_000;

// Failures currently counted against this key. Read-only: naming a key must
// never move its counter (that was the whole bug).
function failureCount(map, key, now = Date.now()) {
  const b = map.get(key);
  if (!b || now > b.resetAt) return 0;
  return b.count;
}

// Record one genuine failure. Returns the new count.
function noteFailure(map, key, windowMs = WINDOW_MS, now = Date.now()) {
  const b = map.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + windowMs; }
  b.count++;
  map.set(key, b);
  return b.count;
}

function clearFailures(map, key) {
  map.delete(key);
}

// How long the next attempt on this key has to wait. Zero up to and including
// the threshold, then STEP_MS per extra failure, capped at MAX_DELAY_MS. Never
// returns "refused", because there is no value it could return that an attacker
// could not aim at somebody else's account.
function throttleDelayMs(failures, opts = {}) {
  const { threshold = FAIL_THRESHOLD, stepMs = STEP_MS, maxMs = MAX_DELAY_MS } = opts;
  const over = failures - threshold;
  if (!(over > 0)) return 0;
  return Math.min(over * stepMs, maxMs);
}

function sleep(ms) {
  return ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve();
}

module.exports = {
  FAIL_THRESHOLD, WINDOW_MS, STEP_MS, MAX_DELAY_MS,
  failureCount, noteFailure, clearFailures, throttleDelayMs, sleep,
};
