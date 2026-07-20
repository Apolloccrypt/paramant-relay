// Quota counters for Phase 3 of the tier-foundation.
//
// COUNTS ONLY. Does not enforce. A Redis outage MUST NOT block an upload --
// every helper returns gracefully and logs.
//
// Keys (all monthly counters are CALENDAR-month keyed via <YYYY-MM>, UTC; a
// new month starts a fresh key, so every counter resets on the 1st):
//   paramant:quota:transfers:<account_id>:<YYYY-MM>       INCR + EXPIRE 35d
//   paramant:quota:signs:<account_id>:<YYYY-MM>           INCR + EXPIRE 35d
//   paramant:quota:signs_overage:<account_id>:<YYYY-MM>   INCR + EXPIRE 100d
//                                                     (billable overage signs;
//                                                      longer TTL so billing can
//                                                      invoice after month close)
//   paramant:quota:seen:<account_id>:<chunk_hash>     SET + EXPIRE 24h
//                                                     (dedup for 111-chunk
//                                                     ParaShare uploads)
//
// The dedup window is 24 h: a re-upload of the same first-chunk-hash within
// 24 h does not double-count. After 24 h the upload counts as a new transfer
// (which is what we want -- a brand-new send the next day).
'use strict';

const crypto = require('crypto');

const MONTH_TTL_SECONDS   = 35 * 86400;        // 35 days: covers a full month plus a safety tail
const OVERAGE_TTL_SECONDS = 100 * 86400;       // ~3 months: billing reads this AFTER month close
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
function signsOverageKey(accountId, ym) { return `paramant:quota:signs_overage:${accountId}:${ym || ymKey()}`; }
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

// ── Tiered sign metering (included quota + Pro overage, Mick's tier brief) ───
// signGateDecision is the ONE pure decision both sign paths (the R018
// /v2/envelopes/:id/sign pre-gate and the /v1 create gate) share. `used` is the
// account's signs count this calendar month; `ent` is the parasign entitlement
// from entitlements.getEntitlements (quotas.signs_month + overage). Tiers
// WITHOUT overage (free, business, enterprise) block AT the included quota
// (used >= included -> 402 monthly_sign_quota_reached). Tiers WITH overage
// (pro) sail past the included quota, metering each extra sign, until the HARD
// cap (used >= hard_cap -> 402 monthly_sign_hard_cap_reached, never a silent
// run-up). Limits come exclusively from the entitlement object.
function signGateDecision(used, ent) {
  const included = ent && ent.quotas ? ent.quotas.signs_month : Infinity;
  const ov = ent && ent.overage;
  const metered = !!(ov && ov.rate_eur != null && Number.isFinite(ov.hard_cap));
  if (!Number.isFinite(used) || !Number.isFinite(included)) {
    return { allowed: true, reason: null, limit: null };
  }
  if (metered) {
    if (used >= ov.hard_cap) return { allowed: false, reason: 'hard_cap', limit: ov.hard_cap };
    return { allowed: true, reason: null, limit: ov.hard_cap };
  }
  if (used >= included) return { allowed: false, reason: 'quota', limit: included };
  return { allowed: true, reason: null, limit: included };
}

// Count ONE accepted signature and, past the included quota, ONE billable
// overage sign. The caller (the R018 sign route) invokes this ONLY for a
// genuinely NEW accepted party-signature (store.sign() -> 'new'); an idempotent
// retry never reaches here, so neither counter can double-count on retry. Both
// keys are calendar-month scoped; the overage key keeps a longer TTL so billing
// can invoice after the month closes. Never throws; fail-open like recordSign.
// Returns { counted, used, overage_count, error }.
async function recordSignTiered(redisClient, accountId, included, log) {
  if (!accountId) return { counted: false, used: null, overage_count: null, error: 'no_account_id' };
  if (!redisClient || !redisClient.isReady) return { counted: false, used: null, overage_count: null, error: 'redis_not_ready' };
  try {
    const sk = signsKey(accountId);
    const n  = await redisClient.incr(sk);
    if (n === 1) await redisClient.expire(sk, MONTH_TTL_SECONDS);
    let overage = 0;
    if (Number.isFinite(included) && n > included) {
      const ok = signsOverageKey(accountId);
      overage = await redisClient.incr(ok);
      if (overage === 1) await redisClient.expire(ok, OVERAGE_TTL_SECONDS);
    }
    return { counted: true, used: n, overage_count: overage, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_sign_tiered_record_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { counted: false, used: null, overage_count: null, error: e.message };
  }
}

// Read the billable overage count for one account and calendar month. Used by
// billing/tests; returns null when redis is unavailable.
async function readSignsOverage(redisClient, accountId, ym) {
  if (!accountId || !redisClient || !redisClient.isReady) return null;
  try {
    const v = await redisClient.get(signsOverageKey(accountId, ym));
    return v == null ? 0 : parseInt(v, 10);
  } catch { return null; }
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
async function gateTransfer(redisClient, accountId, chunkHash, limit, log) {
  if (!accountId || !redisClient || !redisClient.isReady || !Number.isFinite(limit)) {
    const r = await recordTransfer(redisClient, accountId, chunkHash, log);
    return { allowed: true, counted: r.counted, deduped: r.deduped, over_limit: false, error: r.error };
  }
  try {
    if (chunkHash) {
      const sk = seenKey(accountId, chunkHash);
      // Continuing an already-counted (multi-chunk) upload is always allowed.
      if (await redisClient.exists(sk)) return { allowed: true, counted: false, deduped: true, over_limit: false, error: null };
      const cur = parseInt((await redisClient.get(transfersKey(accountId))) || '0', 10);
      if (cur >= limit) return { allowed: false, counted: false, deduped: false, over_limit: true, error: null };
      // Under cap: claim the seen key, then count.
      const setRes = await redisClient.set(sk, '1', { NX: true, EX: SEEN_TTL_SECONDS });
      if (setRes !== 'OK') return { allowed: true, counted: false, deduped: true, over_limit: false, error: null };
    } else {
      const cur = parseInt((await redisClient.get(transfersKey(accountId))) || '0', 10);
      if (cur >= limit) return { allowed: false, counted: false, deduped: false, over_limit: true, error: null };
    }
    const tk = transfersKey(accountId);
    const n  = await redisClient.incr(tk);
    if (n === 1) await redisClient.expire(tk, MONTH_TTL_SECONDS);
    return { allowed: true, counted: true, deduped: false, over_limit: false, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_gate_transfer_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { allowed: true, counted: false, deduped: false, over_limit: false, error: e.message }; // fail open
  }
}

async function gateSign(redisClient, accountId, limit, log) {
  if (!accountId || !redisClient || !redisClient.isReady || !Number.isFinite(limit)) {
    const r = await recordSign(redisClient, accountId, log);
    return { allowed: true, counted: r.counted, over_limit: false, error: r.error };
  }
  try {
    const cur = parseInt((await redisClient.get(signsKey(accountId))) || '0', 10);
    if (cur >= limit) return { allowed: false, counted: false, over_limit: true, error: null };
    const sk = signsKey(accountId);
    const n  = await redisClient.incr(sk);
    if (n === 1) await redisClient.expire(sk, MONTH_TTL_SECONDS);
    return { allowed: true, counted: true, over_limit: false, error: null };
  } catch (e) {
    if (log) log('warn', 'quota_gate_sign_failed', { account: String(accountId).slice(0, 12), err: e.message });
    return { allowed: true, counted: false, over_limit: false, error: e.message }; // fail open
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
  recordSignTiered,
  readSignsOverage,
  gateTransfer,
  gateSign,
  readUsage,
  // exported for tests / admin tooling
  transfersKey,
  signsKey,
  signsOverageKey,
  seenKey,
  MONTH_TTL_SECONDS,
  OVERAGE_TTL_SECONDS,
  SEEN_TTL_SECONDS,
};
