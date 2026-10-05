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

// ── DID-auth principal ────────────────────────────────────────────────────────
// The ONE decision that turns a verified DID enrollment into a request
// principal. A DID never mints its own plan: it authenticates strictly as the
// API key it was ENROLLED under, so entitlements (lib/entitlements
// getEntitlements) and the monthly quota gates (transfers_month, signs_month)
// resolve against the OWNER's real plan and account_id, byte-identical to a
// request that sends the owner's X-Api-Key itself.
//
// Refused (returns null, request falls through to the normal 401 gate):
//   - no enrollment / keyless enrollment (e.g. 'inv_' receiver-session DIDs)
//   - enrollment marked revoked (revoked flag or revoked_at timestamp)
//   - owner key unknown (deleted/rotated) or not active (revoked)
//
// `getKeyRecord` is injected (key -> api-key record) so the decision stays pure
// and unit-testable without the relay monolith.
function didPrincipal(didEntry, getKeyRecord) {
  if (!didEntry || !didEntry.key) return null;
  if (didEntry.revoked === true || didEntry.revoked_at) return null;
  const owner = (typeof getKeyRecord === 'function') ? getKeyRecord(didEntry.key) : null;
  if (!owner || !owner.active) return null;
  const keyData = { ...owner, label: didEntry.device_id };
  // Quota counters key on account_id: always the OWNER's key, never the device.
  if (!keyData.account_id) keyData.account_id = didEntry.key;
  return keyData;
}

module.exports = { safeEqual, internalAuthOk, sessionValid, didPrincipal };
