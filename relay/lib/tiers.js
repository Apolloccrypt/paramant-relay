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
//     MAX_BLOB      5 MB (global, today)
//   So this refactor is a refactor, not a behaviour change.
//
//   For dimensions Mick stated in the tier-foundation brief (transfers_month,
//   signs_month) the values follow the brief directly because no legacy
//   enforcement exists to preserve.
//
//   The brief asks for pro.devices=10 and pro.file_mb=500; current legacy
//   says pro.devices=50 and file_mb=5 global. To honour 'no behaviour change
//   in this phase' the legacy values are kept here; when Mick is ready to
//   change policy a one-line edit updates the value.
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
    transfers_month: 10,
    signs_month: 2,
    file_mb: 5,            // mirrors current MAX_BLOB global 5 MB
    devices: 5,            // mirrors legacy _pubkeyMax.free
    view_ttl_ms: 3_600_000, // mirrors legacy _planMaxTtl.dev (1 h)
    max_views: 1,          // mirrors legacy _planMaxViews.free (burn-on-read)
  }),
  pro: Object.freeze({
    transfers_month: 500,
    signs_month: 100,
    file_mb: 5,            // mirrors current MAX_BLOB; brief says 500 once policy bump
    devices: 50,           // mirrors legacy _pubkeyMax.pro; brief says 10 once policy bump
    view_ttl_ms: 86_400_000, // 24 h
    max_views: 10,
  }),
  business: Object.freeze({
    transfers_month: 2000,
    signs_month: 1000,     // matches the pricing page: ~1,000 signatures per month
    file_mb: 5,            // mirrors current MAX_BLOB global 5 MB
    devices: 100,
    view_ttl_ms: 604_800_000, // 7 d
    max_views: 25,
  }),
  enterprise: Object.freeze({
    transfers_month: UNLIMITED,
    signs_month: UNLIMITED,
    file_mb: UNLIMITED,
    devices: UNLIMITED,
    view_ttl_ms: 604_800_000, // 7 d  (legacy enterprise ceiling)
    max_views: 100,
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
// tierLimit('community', 'file_mb')   -> 5
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
