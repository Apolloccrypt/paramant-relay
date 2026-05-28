// Quota counters for Phase 3 of the tier-foundation.
//
// COUNTS ONLY. Does not enforce. A Redis outage MUST NOT block an upload --
// every helper returns gracefully and logs.
//
// Keys:
//   paramant:quota:transfers:<account_id>:<YYYY-MM>   INCR + EXPIRE 35d
//   paramant:quota:signs:<account_id>:<YYYY-MM>       INCR + EXPIRE 35d
//   paramant:quota:seen:<account_id>:<chunk_hash>     SET + EXPIRE 24h
//                                                     (dedup for 111-chunk
//                                                     ParaShare uploads)
//
// The dedup window is 24 h: a re-upload of the same first-chunk-hash within
// 24 h does not double-count. After 24 h the upload counts as a new transfer
// (which is what we want -- a brand-new send the next day).
'use strict';

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

function transfersKey(accountId, ym)  { return `paramant:quota:transfers:${accountId}:${ym || ymKey()}`; }
function signsKey(accountId, ym)      { return `paramant:quota:signs:${accountId}:${ym || ymKey()}`; }
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
    const n  = await redisClient.incr(tk);
    if (n === 1) await redisClient.expire(tk, MONTH_TTL_SECONDS);
    return { counted: true, deduped: false, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_transfer_record_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { counted: false, deduped: false, error: e.message };
  }
}

// Count a sign for account_id (no dedup -- every sign is a billable event).
async function recordSign(redisClient, accountId, log) {
  if (!accountId) return { counted: false, error: 'no_account_id' };
  if (!redisClient || !redisClient.isReady) return { counted: false, error: 'redis_not_ready' };
  try {
    const sk = signsKey(accountId);
    const n  = await redisClient.incr(sk);
    if (n === 1) await redisClient.expire(sk, MONTH_TTL_SECONDS);
    return { counted: true, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_sign_record_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { counted: false, error: e.message };
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
  firstChunkHash,
  recordTransfer,
  recordSign,
  readUsage,
  // exported for tests / admin tooling
  transfersKey,
  signsKey,
  seenKey,
  MONTH_TTL_SECONDS,
  SEEN_TTL_SECONDS,
};
