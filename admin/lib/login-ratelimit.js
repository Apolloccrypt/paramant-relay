'use strict';
// Login throttling for /api/user/login that cannot be turned into a lockout.
//
// THE BUG THIS REPLACES. The counter that guarded the endpoint was keyed on the
// e-mail address, incremented BEFORE any authentication ran, and never cleared
// on a successful sign-in:
//
//   const emailKey = `paramant:user:ratelimit:email:${email.toLowerCase()}`;
//   const emailCount = await redis().incr(emailKey);
//   if (ipCount > 5 || emailCount > 10) return res.status(429)...
//   const user = await findUserByEmail(email);   // authentication starts HERE
//
// The address is attacker-supplied input, so the counter measured "how often
// did anyone type this address", not "how often did anyone fail on it". Eleven
// posts spread over three IP addresses (the per-IP cap is 5) put the real owner
// of that address on 429 for the full fifteen minutes, and a correct code could
// not clear it. That is a denial-of-service primitive handed out for free.
//
// THE SPLIT THIS MODULE ENFORCES.
//   - per IP: a hard refusal, unchanged at 5 per 15 minutes. The IP address is
//     the caller's own resource, so refusing it costs the guesser and not the
//     victim. This is the limiter that actually bounds an attack.
//   - per e-mail: counts FAILURES only, is cleared by a successful sign-in, and
//     NEVER refuses. Past the threshold the address must carry a proof-of-work
//     (the same 2^18 challenge signup and password reset already require) before
//     the code is checked.
//
// The rule behind the split: a counter keyed on an identity the attacker gets
// to name may impose COST on that identity, never DENIAL. Cost slows a
// distributed guesser down; denial is exactly the weapon we just took away.
//
// The e-mail key is hashed, so the rate-limit namespace no longer stores the
// address in plaintext, and it is a new namespace, so no stale counter from the
// old shape survives a deploy and keeps somebody locked out.
const crypto = require('crypto');
const { incrInWindow } = require('./redis-counter');

// Per-IP: hard refusal. Same numbers as before, and the same window.
const IP_LIMIT = 5;
const WINDOW_S = 900;

// Per-e-mail: the point at which an address has to pay for the next attempt.
// Not a refusal, and only reachable through genuine failures.
const EMAIL_FAIL_THRESHOLD = 10;

const IP_PREFIX = 'paramant:user:ratelimit:ip:';
// Deliberately NOT paramant:user:ratelimit:email:. That namespace holds the
// old attempt counters, which must not be inherited by the failure counter.
const EMAIL_FAIL_PREFIX = 'paramant:user:loginfail:';

function normalizeEmail(email) {
  return String(email == null ? '' : email).trim().toLowerCase();
}

function ipKey(ip) {
  return IP_PREFIX + String(ip == null ? 'unknown' : ip);
}

// Hashed so the key never carries the address itself, matching the
// login-with-backup limiter (`bk:email:<sha256>`).
function emailFailKey(email) {
  return EMAIL_FAIL_PREFIX + crypto.createHash('sha256').update(normalizeEmail(email)).digest('hex');
}

// One attempt against this IP. Hard limit: the (IP_LIMIT)th request in a window
// is the last allowed. Returns the count too so callers can log it.
async function hitIp(redisClient, ip) {
  const k = ipKey(ip);
  // incrInWindow, not INCR plus a conditional expire: a counter that loses its
  // expiry is a permanent 429 for this source address. See lib/redis-counter.js.
  const count = await incrInWindow(redisClient, k, WINDOW_S);
  return { allowed: count <= IP_LIMIT, count };
}

// Give an IP its attempt back. A request that was answered with a price quote
// (428 pow_required) was never evaluated: no account was looked up, no code was
// checked. Counting it would halve the budget under proof-of-work, because each
// real attempt then costs two requests, the quote and the answer, and the honest
// user would be refused after two tries instead of five. The IP limit is the one
// that has to keep working, so it is spent on attempts only.
async function refundIp(redisClient, ip) {
  const k = ipKey(ip);
  // DECR on a missing key creates it at -1 with no TTL, which would hand that IP
  // a larger budget than it started with. Only ever refund a counter that is
  // actually there.
  const raw = await redisClient.get(k);
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return;
  await redisClient.decr(k);
}

// How many failed sign-ins this address has collected inside the window. A READ,
// never a write: merely naming an address must not move its counter.
async function emailFailures(redisClient, email) {
  const raw = await redisClient.get(emailFailKey(email));
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

// Called only after a sign-in has actually failed.
async function noteEmailFailure(redisClient, email) {
  const k = emailFailKey(email);
  // Same reason as hitIp, and worse here: a counter stuck above the threshold
  // is a proof-of-work obligation that never lifts, on an address anybody may
  // name. See lib/redis-counter.js.
  const count = await incrInWindow(redisClient, k, WINDOW_S);
  return count;
}

// A successful sign-in proves the address belongs to whoever is at the keyboard,
// so the failures collected in its name stop counting immediately. Without this
// the owner inherits the guesser's score for the rest of the window.
async function clearEmailFailures(redisClient, email) {
  await redisClient.del(emailFailKey(email));
}

// Past the threshold the next attempt on this address costs a proof-of-work.
// Cost, not denial: the owner still signs in, one 2^18 challenge later, which is
// a second or two in a browser and 150 to 250 ms for a native solver. That
// prices a guess; it does not stop one. Stopping one is the per-IP limit's job.
function powRequired(failures) {
  return failures >= EMAIL_FAIL_THRESHOLD;
}

// ── The per-account MFA throttle, moved to where existence is not known ──────
//
// relay/lib/auth-throttle.js delays a wrong code by 250 ms per failure past ten,
// capped at two seconds, and relay.js charges it on /v2/user/verify-totp. Only a
// request naming an EXISTING account ever gets that far, because the login
// handler answers two steps earlier for an address it cannot find. So the
// throttle was an account-existence oracle at the admin's edge: measured through
// a booted admin at twelve prior failures, 306 ms against 252 ms with no
// overlap, and 2006 against 252 at the cap. That is four orders of magnitude
// louder than the 4 ms the fixed floor was built to hide.
//
// The delay itself is worth keeping: it is what makes bulk guessing pointless.
// It just has to be charged by something that does not know whether the account
// exists. That is this file. The counter here is keyed on the HASHED ADDRESS and
// is incremented for a miss exactly as for a hit, so it is the same number for
// both. The login handler adds mirrorThrottleMs() to the floor under every
// credential answer and tells the relay it has already paid
// (`throttled_upstream`), so the cost is identical on both branches and the wall
// clock carries no information about which one ran.
//
// These three numbers are the relay's, duplicated because admin/ and relay/ are
// separate npm projects that cannot require across the boundary;
// tests/redis-deadline-parity.test.mjs fails if they drift from
// relay/lib/auth-throttle.js.
const THROTTLE_THRESHOLD = 10;
const THROTTLE_STEP_MS = 250;
const THROTTLE_MAX_MS = 2000;

function mirrorThrottleMs(failures) {
  const over = Number(failures) - THROTTLE_THRESHOLD;
  if (!(over > 0)) return 0;
  return Math.min(over * THROTTLE_STEP_MS, THROTTLE_MAX_MS);
}

// The same idea for /api/user/login-with-backup, on that route's own counter.
//
// WHY IT NEEDS ITS OWN CURVE. That route refuses at BACKUP_ATTEMPT_LIMIT hits
// per address per window, so a counter behind it can never reach the relay's
// threshold of ten and mirrorThrottleMs() would return zero for every attempt
// the route allows. A mirror that is always zero is not a mirror. The cost has
// to escalate inside the range the route actually permits, so it starts after
// the first attempt and steps by the same 250 ms to the same 2 s ceiling.
//
// `attempts` is the number of attempts BEFORE this one, which is the counted
// hit minus one (webauthn.rateHitCounted returns the post-increment value).
const BACKUP_ATTEMPT_LIMIT = 5;
const BACKUP_THROTTLE_THRESHOLD = 1;

function backupThrottleMs(attempts) {
  const over = Number(attempts) - BACKUP_THROTTLE_THRESHOLD;
  if (!(over > 0)) return 0;
  return Math.min(over * THROTTLE_STEP_MS, THROTTLE_MAX_MS);
}

module.exports = {
  IP_LIMIT, WINDOW_S, EMAIL_FAIL_THRESHOLD,
  THROTTLE_THRESHOLD, THROTTLE_STEP_MS, THROTTLE_MAX_MS, mirrorThrottleMs,
  BACKUP_ATTEMPT_LIMIT, BACKUP_THROTTLE_THRESHOLD, backupThrottleMs,
  IP_PREFIX, EMAIL_FAIL_PREFIX,
  normalizeEmail, ipKey, emailFailKey,
  hitIp, refundIp, emailFailures, noteEmailFailure, clearEmailFailures, powRequired,
};
