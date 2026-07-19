'use strict';
// Pure auth-gate decisions extracted from relay.js: the constant-time compare,
// the X-Internal-Auth gate that fronts every /v2/user/* session endpoint, and
// the PSS session-expiry predicate. All behaviour-identical to the inline code;
// relay.js now delegates safeEqual + _internalOk + the session cleanup here.
const crypto = require('crypto');

// Constant-time string compare. Verbatim from relay.js safeEqual: coerces to
// utf8, still runs a timingSafeEqual on a length mismatch to avoid a length
// oracle (result forced false), and swallows any throw as false.
function safeEqual(a, b) {
  try {
    const ba = Buffer.from(String(a || ''), 'utf8');
    const bb = Buffer.from(String(b || ''), 'utf8');
    if (ba.length !== bb.length) {
      const pad = Buffer.alloc(Math.max(ba.length, bb.length));
      crypto.timingSafeEqual(pad, pad);
      return false;
    }
    return crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

// The gate on every internal (admin-proxied user-session) endpoint. Open ONLY
// when a token is configured AND the header is a string AND it matches in
// constant time. Missing config or missing/non-string header => closed. Mirrors
// relay.js _internalOk(): !!tok && typeof header === 'string' && safeEqual(...).
function internalAuthOk(configuredToken, headerValue) {
  return !!configuredToken && typeof headerValue === 'string'
    && safeEqual(headerValue, configuredToken);
}

// A PSS session is live iff it exists and its wall-clock expiry has not passed.
// Expressed as !(now > expires_ms) so it is the exact complement of relay.js's
// cleanup predicate `now > s.expires_ms` (a session exactly AT its expiry ms is
// still live; a session with a non-numeric expires_ms is treated as live, same
// as the monolith, which only ever deletes on a strict now > expires_ms).
function sessionValid(sess, now = Date.now()) {
  return !!sess && !(now > sess.expires_ms);
}

module.exports = { safeEqual, internalAuthOk, sessionValid };
