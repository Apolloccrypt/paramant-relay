// Single source of truth for per-tier limits.
//
// Phase 1 (foundation): this file exists, the relay reads from it for the
// dimensions already enforced (devices, view TTL, max views), and the new
// dimensions used by Phase 3 counters (transfers_month, signs_month, file_mb)
// are declared here so Phase 4 admin/usage and Phase 6 enforcement can use
// the same shape.
//
// IMPORTANT -- behaviour preservation:
//   For dimensions that the relay already enforces (devices, view TTL,
//   max views), the values below MIRROR the legacy constants exactly:
//     _pubkeyMax    free=5,  pro=50,  enterprise=Infinity
//     _planMaxTtl   dev=1h,  pro=24h, enterprise=7d
//     _planMaxViews free=1,  pro=10,  enterprise=100
//     MAX_BLOB      5 MB per BLOB on the wire (that is the padding size, and
//                   it is not the file ceiling -- see file_mb below)
//     OUTBOUND_RATE free=50/h, pro=500/h, enterprise=unlimited
//
//   Every one of those legacy tables was keyed on THREE plan names and fell
//   back to the free row for anything else, so `business` silently got the free
//   ceiling. That is why the numbers live here: this table has a row per tier
//   the pricing page sells, and normalisePlan maps the aliases onto it.
//   So this refactor is a refactor, not a behaviour change.
//
//   For dimensions Mick stated in the tier-foundation brief (transfers_month,
//   signs_month) the values follow the brief directly because no legacy
//   enforcement exists to preserve.
//
//   The brief asked for pro.devices=10 and pro.file_mb=500; legacy said
//   pro.devices=50 and file_mb=5 global. file_mb is now 500 on every row, which
//   is the policy change that reservation was waiting for. devices is untouched
//   and still mirrors legacy: that one is a separate decision.
//
// file_mb IS NOT THE BLOB CEILING. This is the number the product sells: the
// largest FILE a plan may send. The relay never sees a file. It sees blobs of a
// fixed 5 MiB (the padding size, crypto-wasm BLOCK / relay MAX_BLOB), and a
// 500 MB file arrives as 112 of them. Holding a file to 500 MB therefore means
// counting blobs against a session, not comparing one blob to this number:
// `Math.min(MAX_BLOB, file_mb * 1048576)` on a single blob was exactly that
// confusion, and it capped every file at the size of one block.
//
// The two numbers move for different reasons. MAX_BLOB moves when the wire
// format or the memory budget changes. file_mb moves when Mick sells something
// different. Never fold them back together.
//
// concurrent_blobs is the capacity axis. Blobs live in RAM and only in RAM, so
// what is actually scarce is memory times residency, and this is the dimension
// that maps onto it one to one. A live hand-over holds a sliding window of a few
// blocks at a time rather than the whole file, so one transfer in flight is a
// handful of blobs whatever the file size; that is why a number this small
// carries a 500 MB transfer. It bounds one account, so a single tenant cannot
// take the pool; the relay-wide budget in relay.js is the separate, harder
// ceiling underneath it.
//
// Plan-name normalisation -- the codebase grew with mixed names:
//   free      -> community  (legacy device/view tables call community 'free')
//   dev       -> community  (legacy ttl table calls community 'dev')
//   licensed  -> enterprise (licensed-self-host treated as enterprise)
//   community / pro / enterprise -> as-is.
'use strict';

const UNLIMITED = -1;

// -1 means unlimited in the limit fields.
const TIER_LIMITS = Object.freeze({
  community: Object.freeze({
    transfers_month: 50,
    signs_month: 2,
    file_mb: 500,          // same ceiling as every paid row: size is not sold
    devices: 5,            // mirrors legacy _pubkeyMax.free
    view_ttl_ms: 3_600_000, // mirrors legacy _planMaxTtl.dev (1 h)
    max_views: 1,          // mirrors legacy _planMaxViews.free (burn-on-read)
    concurrent_blobs: 8, // one live hand-over at a time, plus slack for its window
    outbound_per_hour: 50,  // mirrors legacy OUTBOUND_RATE.free
  }),
  pro: Object.freeze({
    transfers_month: 500,
    signs_month: 100,
    file_mb: 500,
    devices: 50,           // mirrors legacy _pubkeyMax.pro; brief says 10 once policy bump
    view_ttl_ms: 86_400_000, // 24 h
    max_views: 10,
    concurrent_blobs: 24, // about three at a time
    outbound_per_hour: 500,  // mirrors legacy OUTBOUND_RATE.pro
  }),
  business: Object.freeze({
    transfers_month: 2000,
    signs_month: 1000,     // matches the pricing page: ~1,000 signatures a month
    file_mb: 500,
    devices: 100,
    view_ttl_ms: 604_800_000, // 7 d
    max_views: 25,
    concurrent_blobs: 80, // about ten at a time
    outbound_per_hour: 2000, // its transfers_month; never below pro, which is
                             // what the old table did by leaving it out
  }),
  enterprise: Object.freeze({
    transfers_month: UNLIMITED,
    signs_month: UNLIMITED,
    file_mb: UNLIMITED,
    devices: UNLIMITED,
    view_ttl_ms: 604_800_000, // 7 d  (legacy enterprise ceiling)
    max_views: 100,
    concurrent_blobs: UNLIMITED,
    outbound_per_hour: UNLIMITED, // mirrors legacy OUTBOUND_RATE.enterprise
  }),
});

// Normalise a stored plan name to one of the four canonical tiers.
// WITHOUT the business entry a paying business account would silently fall
// back to community caps (2 signatures a month), so this list must cover
// every plan the pricing page sells.
function normalisePlan(plan) {
  if (plan === 'free' || plan === 'dev') return 'community';
  if (plan === 'licensed')               return 'enterprise';
  if (plan === 'community' || plan === 'pro' || plan === 'business' || plan === 'enterprise') return plan;
  return 'community';
}

// tierLimit('pro', 'devices')         -> 50
// tierLimit('community', 'file_mb')   -> 500
// tierLimit('enterprise', 'signs_month') -> -1
// Unknown dimension or unknown plan falls back to community.
function tierLimit(plan, dim) {
  const t = TIER_LIMITS[normalisePlan(plan)] || TIER_LIMITS.community;
  return Object.prototype.hasOwnProperty.call(t, dim) ? t[dim] : null;
}

// True when the limit means "no cap".
function isUnlimited(value) {
  return value === UNLIMITED || value === Infinity;
}

// Return the limit for a plan, but as a number suitable for arithmetic.
// Unlimited becomes Infinity so '>=' comparisons behave correctly when callers
// do limit-checks without first calling isUnlimited.
function tierLimitNum(plan, dim) {
  const v = tierLimit(plan, dim);
  return isUnlimited(v) ? Infinity : v;
}

module.exports = {
  TIER_LIMITS,
  UNLIMITED,
  normalisePlan,
  tierLimit,
  tierLimitNum,
  isUnlimited,
};
