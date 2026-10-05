// Quota counters for Phase 3 of the tier-foundation.
//
// COUNTS ONLY. Does not enforce. A Redis outage MUST NOT block an upload --
// every helper returns gracefully and logs.
//
// Keys (all monthly counters are CALENDAR-month keyed via <YYYY-MM>, UTC; a
// new month starts a fresh key, so every counter resets on the 1st):
//   paramant:quota:transfers:<account_id>:<YYYY-MM>       INCR + EXPIRE 35d
//   paramant:quota:signs:<account_id>:<YYYY-MM>           INCR + EXPIRE 35d
//   paramant:quota:seen:<account_id>:<chunk_hash>     SET + EXPIRE 24h
//                                                     (dedup for 111-chunk
//                                                     ParaShare uploads)
//
// The dedup window is 24 h: a re-upload of the same first-chunk-hash within
// 24 h does not double-count. After 24 h the upload counts as a new transfer
// (which is what we want -- a brand-new send the next day).
'use strict';
const { incrInWindow } = require('./redis-counter');

const crypto = require('crypto');

const MONTH_TTL_SECONDS = 35 * 86400;          // 35 days: covers a full month plus a safety tail
const SEEN_TTL_SECONDS  = 86400;               // 24 h dedup window
const SEEN_HASH_LEN     = 32;                  // first 32 hex chars (128 bit prefix) is plenty

function ymKey(date) {
  const d = date || new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

// First day of the NEXT calendar month (UTC), ISO YYYY-MM-DD. This is the
// reset_date the sign API reports: the moment every monthly counter starts a
// fresh <YYYY-MM> key.
function nextResetDate(date) {
  const d = date || new Date();
  const n = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1));
  return n.toISOString().slice(0, 10);
}

function transfersKey(accountId, ym)    { return `paramant:quota:transfers:${accountId}:${ym || ymKey()}`; }
function signsKey(accountId, ym)        { return `paramant:quota:signs:${accountId}:${ym || ymKey()}`; }
function seenKey(accountId, hashHex)  { return `paramant:quota:seen:${accountId}:${hashHex.slice(0, SEEN_HASH_LEN)}`; }

// Compute a stable hash of the first chunk of a blob.
// The caller passes a Buffer; we take SHA3-256 of up to the first 64 KiB.
// Two uploads of the same content produce the same hash, so a 111-chunk
// ParaShare counts as a single transfer.
function firstChunkHash(buf) {
  if (!buf || !buf.length) return null;
  const slice = buf.length > 65536 ? buf.subarray(0, 65536) : buf;
  return crypto.createHash('sha3-256').update(slice).digest('hex');
}

// Count a transfer for account_id, deduplicating by chunk_hash within 24 h.
// Returns { counted: bool, deduped: bool, error: string|null }.
// Never throws.
async function recordTransfer(redisClient, accountId, chunkHash, log) {
  if (!accountId) return { counted: false, deduped: false, error: 'no_account_id' };
  if (!redisClient || !redisClient.isReady) return { counted: false, deduped: false, error: 'redis_not_ready' };
  try {
    if (chunkHash) {
      const sk = seenKey(accountId, chunkHash);
      // SET key value NX EX 86400 -> returns 'OK' if newly set, null if it already existed.
      const setRes = await redisClient.set(sk, '1', { NX: true, EX: SEEN_TTL_SECONDS });
      if (setRes !== 'OK') return { counted: false, deduped: true, error: null };
    }
    const tk = transfersKey(accountId);
    const n  = await incrInWindow(redisClient, tk, MONTH_TTL_SECONDS);
    return { counted: true, deduped: false, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_transfer_record_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { counted: false, deduped: false, error: e.message };
  }
}

// Count a sign for account_id (no dedup -- every signature is its own event).
// Returns the fresh month count as `used` so a caller that has just counted a
// signature can report the number without a second read. Never throws.
async function recordSign(redisClient, accountId, log) {
  if (!accountId) return { counted: false, used: null, error: 'no_account_id' };
  if (!redisClient || !redisClient.isReady) return { counted: false, used: null, error: 'redis_not_ready' };
  try {
    const sk = signsKey(accountId);
    const n  = await incrInWindow(redisClient, sk, MONTH_TTL_SECONDS);
    return { counted: true, used: n, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_sign_record_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { counted: false, used: null, error: e.message };
  }
}

// ── The sign gate: the included quota IS the limit ───────────────────────────
// signGateDecision is the ONE pure decision both sign paths (the R018
// /v2/envelopes/:id/sign pre-gate and the /v1 create gate) share. `used` is the
// account's signs count this calendar month; `ent` is the parasign entitlement
// from entitlements.getEntitlements (quotas.signs_month). EVERY tier blocks at
// its included quota (used >= included -> 402 monthly_sign_quota_reached).
//
// Pro used to be the exception: it sailed past 100 metering each extra sign at
// EUR 0.40 up to a hard cap of 1000. Nothing ever charged for those signatures
// (see the note in entitlements.js), and the two sign paths did not even agree
// about it: the /v1 create gate has always blocked pro at 100 while this one
// let it through to 1000. One rule, applied the same on both paths, is now both
// the truthful one and the consistent one. Limits come exclusively from the
// entitlement object.
function signGateDecision(used, ent) {
  const included = ent && ent.quotas ? ent.quotas.signs_month : Infinity;
  if (!Number.isFinite(used) || !Number.isFinite(included)) {
    return { allowed: true, reason: null, limit: null };
  }
  if (used >= included) return { allowed: false, reason: 'quota', limit: included };
  return { allowed: true, reason: null, limit: included };
}

// ── Phase 4 enforcement ──────────────────────────────────────────────────────
// Decline NEW active use once the monthly tier cap is reached, WITHOUT touching
// access to existing data (download/view paths never call these). Fail-open:
// missing account, unlimited plan, or any Redis trouble => allowed:true, so a
// paying user is never locked out by infra and existing access always works.
//
// gateTransfer also counts (it replaces recordTransfer on the upload path) so a
// declined transfer is never counted and can't be bypassed by retrying — the
// dedup `seen` key is only claimed once we've decided to count.
//
// ── Why these are Lua and not JavaScript ─────────────────────────────────────
// The 2026-09-05 hostile review, finding 8. Both gates used to read the counter,
// decide, and then write, with an `await` between the reading and the writing:
//
//     const cur = parseInt((await redisClient.get(signsKey(accountId))) || '0', 10);
//     if (cur >= limit) return { allowed: false, ... };
//     const n = await incrInWindow(redisClient, signsKey(accountId), MONTH_TTL_SECONDS);
//
// The counter stands at 1, the plan sells 2, ten requests arrive together. All
// ten read 1, all ten find 1 < 2, all ten count. Eleven signatures on a plan
// that sells two. The window is not theoretical: on the live sign route the
// read and the increment sat 38 lines and a whole ML-DSA verification apart.
//
// The house already had the recipe. lib/coupon.js does cap, expiry, revocation,
// double-use and the tally in ONE Lua script, and says why in as many words:
// "A JavaScript version of this reads the count, decides, and writes, and two
// requests that read the same 99 both write a hundredth seat." That is this bug,
// written down a month earlier, in the one place that got it right. So these
// gates take that pattern rather than invent a second one: same `redis.eval`
// call shape, same array-of-strings decoding, same reservation semantics.
//
// The TTL is set with `if TTL < 0 then EXPIRE end` rather than `EXPIRE ... NX`
// on purpose: inside a script the read-then-write is already atomic, so the
// two-step form costs nothing here and it keeps the scripts working on the
// Redis 6 that lib/redis-counter.js still carries a fallback for.

// KEYS[1] the monthly counter.
// ARGV[1] the cap, ARGV[2] the counter TTL in seconds.
// Returns { status, used } with status one of: ok | over
const GATE_SIGN_LUA = `
local limit = tonumber(ARGV[1])
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
if cur >= limit then return {'over', tostring(cur)} end
local n = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return {'ok', tostring(n)}
`;

// KEYS[1] the monthly counter, KEYS[2] the dedup `seen` key. When there is no
// chunk hash the caller passes KEYS[1] again and sets ARGV[4] to '0'; nothing in
// the script touches KEYS[2] in that case, so the duplicate key name is inert
// and every key this script can touch is still declared in KEYS.
// ARGV[1] the cap, ARGV[2] the counter TTL, ARGV[3] the seen TTL,
// ARGV[4] '1' when the seen key is in play.
// Returns { status, used } with status one of: ok | over | deduped
const GATE_TRANSFER_LUA = `
local limit = tonumber(ARGV[1])
local hasSeen = ARGV[4] == '1'
if hasSeen and redis.call('EXISTS', KEYS[2]) == 1 then return {'deduped', '0'} end
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
if cur >= limit then return {'over', tostring(cur)} end
if hasSeen and not redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[3]) then
  return {'deduped', '0'}
end
local n = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return {'ok', tostring(n)}
`;

// Give a counted unit back. Only ever called when the thing the count was taken
// for did not happen, so the tally counts what was actually delivered. Never
// goes below zero: a release without a matching reservation must not hand out a
// free unit to the next caller.
const RELEASE_LUA = `
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
if cur <= 0 then return '0' end
return tostring(redis.call('DECR', KEYS[1]))
`;

// node-redis returns Lua's table as an array of strings, exactly as
// lib/coupon.js documents at _claimResult.
function _gateResult(raw) {
  const arr = Array.isArray(raw) ? raw : [];
  return { status: String(arr[0] || 'over'), used: parseInt(String(arr[1] || '0'), 10) || 0 };
}

async function gateTransfer(redisClient, accountId, chunkHash, limit, log) {
  if (!accountId || !redisClient || !redisClient.isReady || !Number.isFinite(limit)) {
    const r = await recordTransfer(redisClient, accountId, chunkHash, log);
    return { allowed: true, counted: r.counted, deduped: r.deduped, over_limit: false, error: r.error };
  }
  try {
    const tk = transfersKey(accountId);
    const sk = chunkHash ? seenKey(accountId, chunkHash) : tk;
    const r = _gateResult(await redisClient.eval(GATE_TRANSFER_LUA, {
      keys: [tk, sk],
      arguments: [String(limit), String(MONTH_TTL_SECONDS), String(SEEN_TTL_SECONDS), chunkHash ? '1' : '0'],
    }));
    if (r.status === 'deduped') return { allowed: true, counted: false, deduped: true, over_limit: false, error: null };
    if (r.status === 'over')    return { allowed: false, counted: false, deduped: false, over_limit: true, error: null };
    return { allowed: true, counted: true, deduped: false, over_limit: false, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_gate_transfer_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { allowed: true, counted: false, deduped: false, over_limit: false, error: e.message }; // fail open
  }
}

async function gateSign(redisClient, accountId, limit, log) {
  if (!accountId || !redisClient || !redisClient.isReady || !Number.isFinite(limit)) {
    const r = await recordSign(redisClient, accountId, log);
    return { allowed: true, counted: r.counted, used: r.used, over_limit: false, error: r.error };
  }
  try {
    const r = _gateResult(await redisClient.eval(GATE_SIGN_LUA, {
      keys: [signsKey(accountId)],
      arguments: [String(limit), String(MONTH_TTL_SECONDS)],
    }));
    if (r.status === 'over') return { allowed: false, counted: false, used: r.used, over_limit: true, error: null };
    return { allowed: true, counted: true, used: r.used, over_limit: false, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_gate_sign_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { allowed: true, counted: false, used: null, over_limit: false, error: e.message }; // fail open
  }
}

// Hand a reserved signature back. gateSign counts BEFORE the signature is
// stored, because counting after is what let ten concurrent requests share one
// slot. The cost of counting first is that a signature the store then rejects
// would be charged for, so the sign route releases it. This is the same
// reservation shape lib/coupon.js uses for a seat: claim, and release when the
// grant that followed the claim did not happen.
async function releaseSign(redisClient, accountId, log) {
  if (!accountId || !redisClient || !redisClient.isReady) return { released: false, used: null };
  try {
    const used = parseInt(String(await redisClient.eval(RELEASE_LUA, { keys: [signsKey(accountId)], arguments: [] })), 10);
    return { released: true, used: Number.isFinite(used) ? used : null };
  } catch (e) {
    // A release that fails leaves the account one unit poorer for the month.
    // That is the safe direction, so it logs and does not throw.
    if (log) log('warn', 'quota_release_sign_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { released: false, used: null };
  }
}

// Read the current month's counts. Used by the Phase 4 admin/usage endpoint.
async function readUsage(redisClient, accountId, ym) {
  if (!accountId || !redisClient || !redisClient.isReady) {
    return { transfers_this_month: null, signs_this_month: null, ym: ym || ymKey(), available: false };
  }
  const m = ym || ymKey();
  try {
    const [t, s] = await Promise.all([
      redisClient.get(transfersKey(accountId, m)),
      redisClient.get(signsKey(accountId, m)),
    ]);
    return {
      transfers_this_month: t == null ? 0 : parseInt(t, 10),
      signs_this_month:     s == null ? 0 : parseInt(s, 10),
      ym: m,
      available: true,
    };
  } catch (e) {
    return { transfers_this_month: null, signs_this_month: null, ym: m, available: false, error: e.message };
  }
}

module.exports = {
  ymKey,
  nextResetDate,
  firstChunkHash,
  recordTransfer,
  recordSign,
  signGateDecision,
  gateTransfer,
  gateSign,
  releaseSign,
  readUsage,
  // exported for tests / admin tooling
  transfersKey,
  signsKey,
  seenKey,
  MONTH_TTL_SECONDS,
  SEEN_TTL_SECONDS,
};
