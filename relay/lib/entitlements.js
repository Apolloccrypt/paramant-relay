// Single source of truth for PRODUCT + TIER entitlements.
//
// Why this file exists: before this, one `plan` field on an account drove BOTH
// products (ParaSend transfers and ParaSign signatures) from the same tier row
// in tiers.js. An account could not be Pro on one product and Community/Free on
// the other. This module puts a product axis on top of tiers.js so the two
// products are entitled independently, ahead of any billing wiring.
//
// Layering:
//   tiers.js       -> the raw per-tier numbers (transfers, signs, devices,
//                     view TTL, max views, file size), plus normalisePlan.
//   entitlements.js -> the PRODUCT-aware layer. Splits those numbers into a
//                     ParaSend view and a ParaSign view, each with its own tier
//                     ladder, and derives the two per-product plans from the
//                     legacy `plan` + `parasign` flag WITHOUT downgrading.
//
// Products and their tier ladders (Mick's brief):
//   parasend: community | pro | enterprise
//   parasign: free | pro | business | enterprise
//
// Hard rule -- no unbounded metered tier. Monthly METERED quotas
// (transfers_month, signs_month) are always finite: enterprise gets a high but
// real ceiling (ENTERPRISE_MONTHLY_CEILING), never Infinity. Structural LIMITS
// (devices, view_ttl_ms, max_views, file_mb) MIRROR tiers.js exactly so no
// existing account loses a structural capability it has today (enterprise device
// count stays uncapped as it is now); the plafond rule is enforced on the
// billing-metered dimensions, which is where it matters.
'use strict';

const tiers = require('./tiers');

const PRODUCTS = Object.freeze(['parasend', 'parasign']);

const PARASEND_TIERS = Object.freeze(['community', 'pro', 'enterprise']);
const PARASIGN_TIERS = Object.freeze(['free', 'pro', 'business', 'enterprise']);

// Finite ceiling for enterprise metered monthly quotas. Legacy enterprise was
// UNLIMITED (Infinity) for transfers_month/signs_month; a real business never
// approaches a million events a month, so this honours the "elk tier heeft een
// plafond" rule without being a practical downgrade. Rate limiting stays on
// separately (OUTBOUND_RATE / envelope-create rate limit in relay.js).
const ENTERPRISE_MONTHLY_CEILING = 1_000_000;

// Map a product tier to the tiers.js row it draws its STRUCTURAL limits from.
// parasign has no 'community'/'free' row in tiers.js; free reads the community
// row (same 2 signs, 5 MB) so the numbers match today's behaviour exactly.
const PARASEND_TIER_TO_TIERS = Object.freeze({
  community: 'community',
  pro: 'pro',
  enterprise: 'enterprise',
});
const PARASIGN_TIER_TO_TIERS = Object.freeze({
  free: 'community',
  pro: 'pro',
  business: 'business',
  enterprise: 'enterprise',
});

// ── ParaSign metered overage (Mick's tier brief) ─────────────────────────────
// Pro is the ONLY tier that meters past its included quota instead of blocking:
// 100 signs included, EUR 0.40 per sign from the 101st, and a HARD stop at
// 1000 signs per calendar month (402, never a silent run-up). Free and Business
// block at their included quota; enterprise runs to its config ceiling. These
// numbers live HERE (the single entitlements source), not in the sign paths.
const PARASIGN_OVERAGE = Object.freeze({
  pro: Object.freeze({ rate_eur: 0.40, hard_cap: 1000 }),
});
const NO_OVERAGE = Object.freeze({ rate_eur: null, hard_cap: null });

// Turn a raw tiers.js metered value into a finite number (Infinity/-1 -> ceiling).
function _meteredFinite(v) {
  return tiers.isUnlimited(v) ? ENTERPRISE_MONTHLY_CEILING : v;
}

// Clamp an arbitrary string to a valid tier for the product, defaulting to the
// product's floor so an unknown/typo value never grants more than the base tier.
function normaliseParasendTier(t) {
  return PARASEND_TIERS.includes(t) ? t : 'community';
}
function normaliseParasignTier(t) {
  return PARASIGN_TIERS.includes(t) ? t : 'free';
}

// ── Migration: legacy single `plan` (+ parasign flag) -> per-product plan ─────
// These are pure and additive. They NEVER downgrade: the derived per-product
// tier grants at least the effective level the account has today.
//
// derivePlanParasend:
//   community/free/dev -> community   (10 transfers, as today)
//   pro                -> pro         (500, as today)
//   business           -> enterprise  (business today = 2000 transfers; parasend
//                                       has no business tier, so we go UP to
//                                       enterprise rather than down to pro. This
//                                       over-grants the transfer ceiling for the
//                                       few business accounts, which is the safe
//                                       side of "no silent downgrade".)
//   enterprise/licensed -> enterprise
function derivePlanParasend(plan) {
  const p = tiers.normalisePlan(plan); // community | pro | business | enterprise
  if (p === 'pro') return 'pro';
  if (p === 'business') return 'enterprise';
  if (p === 'enterprise') return 'enterprise';
  return 'community';
}

// derivePlanParasign:
//   pro        -> pro       (100 signs, as today)
//   business   -> business  (1000, as today)
//   enterprise/licensed -> enterprise
//   everything else (community/free/dev) -> free (2 signs, == community today)
// The `parasign` boolean flag grants ACCESS to the ParaSign API (checked
// elsewhere via accountHasParasignEntitlement); it does not by itself raise the
// paid tier, so the metered level follows the plan and stays exactly what the
// account has today.
function derivePlanParasign(plan /* , parasignFlag */) {
  const p = tiers.normalisePlan(plan);
  if (p === 'pro') return 'pro';
  if (p === 'business') return 'business';
  if (p === 'enterprise') return 'enterprise';
  return 'free';
}

// Build the entitlement object for one (product, tier).
function _parasendEntitlement(tier) {
  const t = normaliseParasendTier(tier);
  const row = PARASEND_TIER_TO_TIERS[t];
  return Object.freeze({
    product: 'parasend',
    tier: t,
    quotas: Object.freeze({
      transfers_month: _meteredFinite(tiers.tierLimit(row, 'transfers_month')),
    }),
    limits: Object.freeze({
      file_mb: tiers.tierLimitNum(row, 'file_mb'),
      devices: tiers.tierLimitNum(row, 'devices'),
      view_ttl_ms: tiers.tierLimitNum(row, 'view_ttl_ms'),
      max_views: tiers.tierLimitNum(row, 'max_views'),
    }),
    features: Object.freeze({
      transfers: true,
    }),
  });
}
function _parasignEntitlement(tier) {
  const t = normaliseParasignTier(tier);
  const row = PARASIGN_TIER_TO_TIERS[t];
  return Object.freeze({
    product: 'parasign',
    tier: t,
    quotas: Object.freeze({
      signs_month: _meteredFinite(tiers.tierLimit(row, 'signs_month')),
    }),
    // overage: how the tier behaves PAST quotas.signs_month. rate_eur/hard_cap
    // are null for tiers that simply block at the quota (free, business,
    // enterprise); pro meters at rate_eur per sign up to hard_cap.
    overage: PARASIGN_OVERAGE[t] || NO_OVERAGE,
    limits: Object.freeze({
      file_mb: tiers.tierLimitNum(row, 'file_mb'),
    }),
    features: Object.freeze({
      // audit_export: the ParaSign signing-audit export is a Business+ capability.
      // Enforced at GET /v2/parasign/audit-export in relay.js (403 below business).
      audit_export: t === 'business' || t === 'enterprise',
    }),
  });
}

// Precompute the full matrix so getEntitlements is a pure lookup.
const PARASEND = Object.freeze(Object.fromEntries(
  PARASEND_TIERS.map((t) => [t, _parasendEntitlement(t)]),
));
const PARASIGN = Object.freeze(Object.fromEntries(
  PARASIGN_TIERS.map((t) => [t, _parasignEntitlement(t)]),
));

// getEntitlements(account) -> { parasend: <entitlement>, parasign: <entitlement> }
//
// `account` is any record carrying plan info. Accepted shapes, in order:
//   { plan_parasend, plan_parasign }  -> used directly (already migrated)
//   { plan, parasign }                -> per-product plans derived on the fly
//                                        (belt-and-braces for un-migrated
//                                         in-memory records)
//   a plan string                     -> treated as legacy `plan`
// Missing per-product plan falls back to derivation from the legacy plan, so an
// account never accidentally lands on the floor tier just because migration has
// not run yet.
function getEntitlements(account) {
  const acct = (account && typeof account === 'object') ? account : { plan: account };
  const legacyPlan = acct.plan;
  const psTier = normaliseParasendTier(acct.plan_parasend || derivePlanParasend(legacyPlan));
  const pgTier = normaliseParasignTier(acct.plan_parasign || derivePlanParasign(legacyPlan, acct.parasign));
  return {
    parasend: PARASEND[psTier],
    parasign: PARASIGN[pgTier],
  };
}

// Convenience: the metered monthly quota a gate should enforce, per product.
function transfersQuota(account) { return getEntitlements(account).parasend.quotas.transfers_month; }
function signsQuota(account)     { return getEntitlements(account).parasign.quotas.signs_month; }
// Convenience: the ParaSign overage policy ({ rate_eur, hard_cap }, nulls when
// the tier blocks at its quota instead of metering).
function signsOverage(account)   { return getEntitlements(account).parasign.overage; }

// ── users.json migration ──────────────────────────────────────────────────────
// migrateUserEntry: return a NEW api_keys entry with plan_parasend/plan_parasign
// filled in. Additive: keeps `plan` and `parasign` untouched for compat and for
// billing to key off later. Idempotent: an entry that already has both
// per-product plans is returned unchanged. Never downgrades.
function migrateUserEntry(entry) {
  if (!entry || typeof entry !== 'object') return entry;
  const out = { ...entry };
  let touched = false;
  if (!out.plan_parasend) { out.plan_parasend = derivePlanParasend(entry.plan); touched = true; }
  if (!out.plan_parasign) { out.plan_parasign = derivePlanParasign(entry.plan, entry.parasign); touched = true; }
  return touched ? out : entry;
}

// migrateUsersData: walk a parsed users.json ({ api_keys: [...] }) and add the
// per-product plans to every key. Returns { data, changed } where `changed` is
// the count of entries that gained a field. Pure w.r.t. inputs it does not own:
// it returns a new object; the caller decides whether to persist.
function migrateUsersData(data) {
  if (!data || !Array.isArray(data.api_keys)) return { data, changed: 0 };
  let changed = 0;
  const api_keys = data.api_keys.map((e) => {
    const m = migrateUserEntry(e);
    if (m !== e) changed++;
    return m;
  });
  return { data: { ...data, api_keys }, changed };
}

module.exports = {
  PRODUCTS,
  PARASEND_TIERS,
  PARASIGN_TIERS,
  ENTERPRISE_MONTHLY_CEILING,
  derivePlanParasend,
  derivePlanParasign,
  normaliseParasendTier,
  normaliseParasignTier,
  getEntitlements,
  transfersQuota,
  signsQuota,
  signsOverage,
  migrateUserEntry,
  migrateUsersData,
  // exposed for tests/tooling
  PARASEND,
  PARASIGN,
};

// ── CLI: node relay/lib/entitlements.js migrate [users.json] ──────────────────
// One-shot, idempotent, no-downgrade migration of an on-disk users.json. Writes
// atomically (tmp + rename). Prints a summary. Safe to run repeatedly.
if (require.main === module) {
  const fs = require('fs');
  const path = require('path');
  const cmd = process.argv[2];
  if (cmd !== 'migrate') {
    process.stderr.write('usage: node entitlements.js migrate [path/to/users.json]\n');
    process.exit(2);
  }
  const file = process.argv[3] || process.env.USERS_FILE || './users.json';
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch (e) { process.stderr.write(`cannot read ${file}: ${e.message}\n`); process.exit(1); }
  let data;
  try { data = JSON.parse(raw); }
  catch (e) { process.stderr.write(`invalid JSON in ${file}: ${e.message}\n`); process.exit(1); }
  const { data: migrated, changed } = migrateUsersData(data);
  if (changed === 0) {
    process.stdout.write(`no change: all ${Array.isArray(data.api_keys) ? data.api_keys.length : 0} entries already have per-product plans\n`);
    process.exit(0);
  }
  const tmp = `${file}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmp, JSON.stringify(migrated, null, 2));
  fs.renameSync(tmp, path.resolve(file));
  process.stdout.write(`migrated ${changed} of ${migrated.api_keys.length} entries in ${file} (added plan_parasend/plan_parasign, plan+parasign preserved)\n`);
}
