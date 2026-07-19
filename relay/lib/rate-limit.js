'use strict';
// Pure fixed-window rate-limit decision, extracted from the ~dozen byte-identical
// in-memory limiters in relay.js (checkTeamRateLimit, checkMfaRateLimit,
// claimRateOk, checkKeyRateOk, lookupSignerRateOk, statusRateOk, envViewRateOk,
// envSignRateOk, envCreateRateOk, ...). Each limiter keeps its own
// Map<key,{count,resetAt}>; this centralises the decision so it is unit-tested
// once. Behaviour-identical to the inline copies:
//   - first hit in a window seeds resetAt = now + windowMs and count = 1,
//   - the window resets lazily on the first request seen AFTER resetAt,
//   - the (limit)th request in a window is the last allowed; count >= limit is
//     refused (returns false) WITHOUT advancing the counter.
// Callers keep their own map + their own out-of-band eviction sweep; this touches
// only the passed-in bucket, so it is a drop-in for the inline `b`-block.
function fixedWindowAllow(map, key, limit, windowMs, now = Date.now()) {
  const b = map.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + windowMs; }
  if (b.count >= limit) return false;
  b.count++; map.set(key, b); return true;
}

module.exports = { fixedWindowAllow };
