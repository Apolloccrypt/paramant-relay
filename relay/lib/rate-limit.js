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

// Sliding window: at most `limit` hits in ANY span of windowMs, not per clock
// hour or per window that starts at the first hit. A fixed window lets a
// caller spend the whole budget at 10:59 and again at 11:00, so "50 per hour"
// let through 100 in two minutes (matrix API-20-N). Keeps the timestamps of
// the allowed hits per key; a refused hit is not recorded.
// Returns { ok, retryAfterMs }: when refused, the wait until the oldest hit in
// the window falls out of it.
function slidingWindowAllow(map, key, limit, windowMs, now = Date.now()) {
  const hits = (map.get(key) || []).filter((t) => t > now - windowMs);
  if (hits.length >= limit) {
    map.set(key, hits);
    return { ok: false, retryAfterMs: Math.max(1, hits[0] + windowMs - now) };
  }
  hits.push(now); map.set(key, hits);
  return { ok: true, retryAfterMs: 0 };
}

// The same decision on a redis sorted set, atomically, so every relay
// instance shares one window. KEYS[1] the set; ARGV now, windowMs, limit,
// member. Returns { allowed (1/0), retryAfterMs }.
const SLIDING_WINDOW_LUA = `
local now = tonumber(ARGV[1]); local win = tonumber(ARGV[2]); local lim = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - win)
local n = redis.call('ZCARD', KEYS[1])
if n >= lim then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  local wait = 1
  if oldest[2] then wait = math.max(1, tonumber(oldest[2]) + win - now) end
  return {0, wait}
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], win)
return {1, 0}`;
async function slidingWindowAllowRedis(client, key, limit, windowMs, now = Date.now(), member) {
  const m = member || `${now}-${Math.random().toString(36).slice(2, 10)}`;
  const r = await client.eval(SLIDING_WINDOW_LUA, { keys: [key], arguments: [String(now), String(windowMs), String(limit), m] });
  return { ok: Number(r[0]) === 1, retryAfterMs: Number(r[1]) || 0 };
}

module.exports = { fixedWindowAllow, slidingWindowAllow, slidingWindowAllowRedis, SLIDING_WINDOW_LUA };
