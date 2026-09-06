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
//   parasend: community | pro | enterprise, plus a legacy `business` row that is
//             resolved but never sold (PARASEND_LADDER)
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

// The tiers a purchase or an admin may GRANT on each product. /pricing sells
// ParaSend as these three; validateProductPlan is held to them.
const PARASEND_TIERS = Object.freeze(['community', 'pro', 'enterprise']);
const PARASIGN_TIERS = Object.freeze(['free', 'pro', 'business', 'enterprise']);

// The full ParaSend ladder, INCLUDING the legacy `business` row. `business` is
// a ParaSign tier name that a legacy unified `plan` can carry, so an account
// holding it never bought ParaSend and it may not be GRANTED as a ParaSend
// tier. It still has to RESOLVE, and to the numbers it has always had:
//   mapping it up to enterprise is a silent UPGRADE (uncapped devices, uncapped
//     downloads per hour, 100 views per link, a 365 day device-pubkey TTL, the
//     10000-receipt retention) for an account that never bought the product;
//   mapping it down to pro is a silent DOWNGRADE (2000 transfers a month to
//     500, 100 devices to 50, a 7 day link to 24 hours, 25 views to 10).
// So it keeps its own row, reading the same tiers.js line it always did, ranked
// between pro and enterprise. Nothing changes for a business account, which is
// the point: this ladder RESOLVES a stored value, it does not sell one.
const PARASEND_LADDER = Object.freeze(['community', 'pro', 'business', 'enterprise']);

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
  business: 'business', // legacy row, not a tier the pricing page sells
  enterprise: 'enterprise',
});
const PARASIGN_TIER_TO_TIERS = Object.freeze({
  free: 'community',
  pro: 'pro',
  business: 'business',
  enterprise: 'enterprise',
});

// ── No metered overage on any ParaSign tier ──────────────────────────────────
// Pro used to meter past its 100 included signs at EUR 0.40 each up to a hard
// cap of 1000, and six places on the site promised the buyer that those extra
// signatures would appear on his next invoice. They never could. Nothing reads
// the billable counter: billing-catalog.js sells fixed monthly and yearly
// amounts only, there is no usage line anywhere in billing.js, invoice.js or
// billing-recurring.js, and no code path turns a metered signature into money.
// So the meter charged nobody and the promise was untrue to the one group that
// had paid.
//
// The honest shape is the one every other tier already had: the included quota
// IS the limit. Every ParaSign tier now blocks at quotas.signs_month, and a
// buyer who needs more moves up a tier. Reintroducing a meter means adding the
// billing line first; until that line exists, this file must not describe one.
// Turn a raw tiers.js metered value into a finite number (Infinity/-1 -> ceiling).
function _meteredFinite(v) {
  return tiers.isUnlimited(v) ? ENTERPRISE_MONTHLY_CEILING : v;
}

// Clamp an arbitrary string to a valid tier for the product, defaulting to the
// product's floor so an unknown/typo value never grants more than the base tier.
function normaliseParasendTier(t) {
  return PARASEND_LADDER.includes(t) ? t : 'community';
}
function normaliseParasignTier(t) {
  return PARASIGN_TIERS.includes(t) ? t : 'free';
}

// Which users.json / apiKeys record field carries a product's tier.
const PRODUCT_PLAN_FIELD = Object.freeze({
  parasend: 'plan_parasend',
  parasign: 'plan_parasign',
});

// The date a paid tier stops being paid for, per product. A tier without one is
// a grant that never ends: before this field, a single 15 euro payment set
// plan_parasend to 'pro' and nothing ever took it back, because Mollie is asked
// for a one-off payment and there is no second collection. Both halves are
// needed. The subscription makes the money come in again; this field makes the
// entitlement stop when it does not. Without it, cancelling an subscription
// leaves the buyer on the paid tier forever.
//
// Absent means "no paid period on record", which is the correct reading for a
// free account and for every account that predates billing. It is NEVER read as
// expired, so a missing field can not silently downgrade anyone.
const PRODUCT_PAID_UNTIL_FIELD = Object.freeze({
  parasend: 'paid_until_parasend',
  parasign: 'paid_until_parasign',
});

// Which BUNDLE bought the period on record, when one did. A bundle (today only
// `firm`, see lib/billing-catalog.js) sells one price that grants two products,
// so plan_parasign and plan_parasend both land on 'pro' and neither field
// remembers that the customer bought one thing and not two. This field does,
// and only the expiry mail reads it: without it a Firm customer got two mails
// about plans he never bought under those names. It carries no entitlement of
// its own, is cleared whenever the tier drops to its floor, and an account from
// before Firm existed simply has no such field.
const PRODUCT_BUNDLE_FIELD = Object.freeze({
  parasend: 'bundle_parasend',
  parasign: 'bundle_parasign',
});

// The tier a product falls back to when a paid period runs out. Mirrors
// billing-catalog.floorTier; kept here too so the entitlement layer can answer
// without importing the billing layer (the dependency runs the other way).
function floorTierOf(product) {
  return product === 'parasign' ? 'free' : 'community';
}

// Parse a stored paid-until value. Anything unparseable is treated as absent
// rather than as expired, on the same no-silent-downgrade rule as the migration
// helpers below: a corrupt date must not cost a paying customer their tier.
function parsePaidUntil(value) {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

// The tier an account ACTUALLY has right now, which is the stored tier unless
// its paid period has passed. Read paths should use this instead of reading
// PRODUCT_PLAN_FIELD directly, so an expired subscription stops granting even
// if no webhook, cron or admin ever came along to write the downgrade.
// Returns { tier, expired, paidUntil }.
function effectiveProductTier(rec, product, now) {
  const field = PRODUCT_PLAN_FIELD[product];
  if (!rec || !field) return { tier: floorTierOf(product), expired: false, paidUntil: null };
  const stored = product === 'parasign'
    ? normaliseParasignTier(rec[field])
    : normaliseParasendTier(rec[field]);
  const floor = floorTierOf(product);
  const paidUntil = parsePaidUntil(rec[PRODUCT_PAID_UNTIL_FIELD[product]]);
  // A floor tier can not expire, and no recorded period means no expiry to
  // enforce (free accounts, and every account from before billing existed).
  if (stored === floor || paidUntil === null) return { tier: stored, expired: false, paidUntil };
  const at = typeof now === 'number' ? now : Date.now();
  if (at >= paidUntil) return { tier: floor, expired: true, paidUntil };
  return { tier: stored, expired: false, paidUntil };
}

// ── Admin per-product grant primitives ───────────────────────────────────────
// These back the fine-grained admin path (POST /v2/admin/keys/set-product-plan)
// so exactly ONE product's tier moves, with the unified `plan` and the other
// product left alone. Kept HERE (the single product/tier source) so the relay
// endpoint and billing's setProductPlan share one rule.

// Strict gate for an admin request. Unlike normalise*Tier (which FLOORS an
// unknown tier to the product's base, silently under-granting), this REJECTS an
// unknown product or a tier that is not a real member of that product's ladder,
// so a typo returns 400 instead of quietly landing on the floor tier. Returns
// { ok:true, product, tier } or { ok:false, error }.
function validateProductPlan(product, tier) {
  if (product !== 'parasend' && product !== 'parasign') return { ok: false, error: 'invalid_product' };
  const ladder = product === 'parasign' ? PARASIGN_TIERS : PARASEND_TIERS;
  if (typeof tier !== 'string' || !ladder.includes(tier)) return { ok: false, error: 'invalid_tier' };
  return { ok: true, product, tier };
}

// Apply ONE product's tier to a single account/key record IN PLACE and report
// what moved. This is the field-level mutation shared by billing's
// setProductPlan (relay.js): it writes only PRODUCT_PLAN_FIELD[product], flips
// the `parasign` ACCESS flag on when parasign lands on a paid (non-free) tier,
// and NEVER touches the other product's field or the unified `plan`. `tier` is
// normalised (idempotent), so passing an already-normalised value is safe.
// Returns { field, tier, changed, parasignGranted }; `changed` reflects the
// plan-field move only (an already-set access flag is not a plan change).
function applyProductTier(rec, product, tier, paidUntil, bundle) {
  const field = PRODUCT_PLAN_FIELD[product];
  const norm = product === 'parasign' ? normaliseParasignTier(tier) : normaliseParasendTier(tier);
  let changed = false;
  if (rec[field] !== norm) { rec[field] = norm; changed = true; }
  let parasignGranted = false;
  if (product === 'parasign' && norm !== 'free' && rec.parasign !== true) { rec.parasign = true; parasignGranted = true; }
  // ...and the flag goes with the tier when the tier goes. The flag is what
  // keys-table.accountHasParasignEntitlement reads to decide whether an account
  // may mint /v1 API keys, and it used to be set on a grant and never cleared,
  // so a chargeback or a lapsed term left the ParaSign API entitlement standing
  // for good: the money went back and the key kept working. Only cleared when
  // the tier ACTUALLY MOVED DOWN to free, so re-applying free to an account
  // that already sits there leaves an operator's explicit grant alone.
  let parasignRevoked = false;
  if (product === 'parasign' && norm === 'free' && changed && rec.parasign === true) {
    delete rec.parasign; parasignRevoked = true;
  }
  // The paid period travels with the tier it paid for. Landing on the floor
  // clears it, so a revoked or lapsed account carries no stale date; passing
  // undefined leaves whatever is there alone, which keeps every existing caller
  // (admin grants, migrations) behaving exactly as before.
  const untilField = PRODUCT_PAID_UNTIL_FIELD[product];
  const bundleField = PRODUCT_BUNDLE_FIELD[product];
  if (norm === floorTierOf(product)) {
    if (rec[untilField] !== undefined) { delete rec[untilField]; changed = true; }
    if (rec[bundleField] !== undefined) delete rec[bundleField];
  } else if (paidUntil !== undefined) {
    const iso = paidUntil === null ? null : new Date(paidUntil).toISOString();
    if (iso === null) { if (rec[untilField] !== undefined) { delete rec[untilField]; changed = true; } }
    else if (rec[untilField] !== iso) { rec[untilField] = iso; changed = true; }
  }
  // The bundle travels with the period, on the same undefined-means-leave-alone
  // rule: an admin grant that names no bundle does not erase one.
  if (norm !== floorTierOf(product) && bundle !== undefined) {
    if (!bundle) { if (rec[bundleField] !== undefined) delete rec[bundleField]; }
    else if (rec[bundleField] !== bundle) rec[bundleField] = bundle;
  }
  return { field, tier: norm, changed, parasignGranted, parasignRevoked, paidUntil: rec[untilField] || null, bundle: rec[bundleField] || null };
}

// ── Migration: legacy single `plan` (+ parasign flag) -> per-product plan ─────
// These are pure and additive. They NEVER downgrade: the derived per-product
// tier grants at least the effective level the account has today.
//
// derivePlanParasend:
//   community/free/dev -> community   (10 transfers, as today)
//   pro                -> pro         (500, as today)
//   business           -> business    (its own row, see PARASEND_LADDER. It used
//                                       to map UP to enterprise, which handed an
//                                       account that never bought ParaSend the
//                                       enterprise resource ceilings. It now
//                                       keeps exactly the numbers it has always
//                                       had: 2000 transfers, 100 devices, a 7
//                                       day link, 25 views, 2000 downloads an
//                                       hour. Neither an upgrade nor a cut.)
//   enterprise/licensed -> enterprise
function derivePlanParasend(plan) {
  const p = tiers.normalisePlan(plan); // community | pro | business | enterprise
  if (p === 'pro') return 'pro';
  if (p === 'business') return 'business';
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
      // The per-hour download ceiling was the one ParaSend dimension missing
      // here, so relay.js had to read the legacy `plan` for it while every
      // other ceiling came off this object. Mirrors tiers.js like the rest.
      outbound_per_hour: tiers.tierLimitNum(row, 'outbound_per_hour'),
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
  PARASEND_LADDER.map((t) => [t, _parasendEntitlement(t)]),
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
function getEntitlements(account, now) {
  const acct = (account && typeof account === 'object') ? account : { plan: account };
  const legacyPlan = acct.plan;
  const psStored = normaliseParasendTier(acct.plan_parasend || derivePlanParasend(legacyPlan));
  const pgStored = normaliseParasignTier(acct.plan_parasign || derivePlanParasign(legacyPlan, acct.parasign));
  // The paid period decides here, at the one place every gate reads. Writing the
  // date on the record is not enough on its own: without this the tier field
  // still grants after the period is over, and an expired subscription keeps
  // working until somebody happens to write a downgrade.
  //
  // A record with no period is never expired, so the legacy paths above and
  // every account from before billing keep exactly the tier they had. Only a
  // tier that was paid for, with a date that has passed, falls to its floor.
  const psTier = effectiveProductTier({ plan_parasend: psStored, [PRODUCT_PAID_UNTIL_FIELD.parasend]: acct[PRODUCT_PAID_UNTIL_FIELD.parasend] }, 'parasend', now).tier;
  const pgTier = effectiveProductTier({ plan_parasign: pgStored, [PRODUCT_PAID_UNTIL_FIELD.parasign]: acct[PRODUCT_PAID_UNTIL_FIELD.parasign] }, 'parasign', now).tier;
  return {
    parasend: PARASEND[psTier],
    parasign: PARASIGN[pgTier],
  };
}

// ── Per-product grant merging ────────────────────────────────────────────────
// A grant is a PAIR: the tier that was paid for and the period it was paid for.
// Merging only the tier is what let an expired subscription keep granting: the
// merged record arrived at getEntitlements with a paid tier and no period, and
// "no recorded period" correctly means "never expires". So the two fields must
// always travel together, here and in keys-table.rebuildKeyIndexes.
//
// _grantOf ranks one record's grant for a product:
//   rank       the tier it is entitled to RIGHT NOW (a lapsed period ranks as
//              the floor tier, so it can never outrank a live lower tier)
//   storedRank the tier on file, which breaks a tie between two floored records
//              so the paid history is not thrown away
//   paidUntil  null means unbounded
function _grantOf(rec, product, at) {
  // The RESOLVING ladder, so a stored legacy `business` ranks where it belongs
  // instead of falling off the list and tying with community.
  const ladder = product === 'parasign' ? PARASIGN_TIERS : PARASEND_LADDER;
  const norm = product === 'parasign' ? normaliseParasignTier : normaliseParasendTier;
  return {
    rank: ladder.indexOf(effectiveProductTier(rec, product, at).tier),
    storedRank: ladder.indexOf(norm(rec[PRODUCT_PLAN_FIELD[product]])),
    paidUntil: parsePaidUntil(rec[PRODUCT_PAID_UNTIL_FIELD[product]]),
  };
}

// Does grant `a` beat grant `b`? Effective tier first, then the tier on file,
// then the more generous period: no recorded period beats a date, and a later
// date beats an earlier one.
function _outranksGrant(a, b) {
  if (a.rank !== b.rank) return a.rank > b.rank;
  if (a.storedRank !== b.storedRank) return a.storedRank > b.storedRank;
  if ((a.paidUntil === null) !== (b.paidUntil === null)) return a.paidUntil === null;
  if (a.paidUntil === null) return false;
  return a.paidUntil > b.paidUntil;
}

// Copy `source`'s grant for one product onto `target` IN PLACE when it is the
// better of the two, tier AND period together. A source with no tier on file
// carries no grant and is skipped. Clearing is deliberate: when the winning
// record has no period, any period already on the target goes, or the target
// would keep a date that belongs to a tier it no longer carries.
function mergeProductGrantInto(target, source, product, now) {
  const planField = PRODUCT_PLAN_FIELD[product];
  const paidField = PRODUCT_PAID_UNTIL_FIELD[product];
  if (!target || !source || !planField || source[planField] == null) return target;
  const at = typeof now === 'number' ? now : Date.now();
  if (target[planField] != null && !_outranksGrant(_grantOf(source, product, at), _grantOf(target, product, at))) return target;
  target[planField] = source[planField];
  if (source[paidField] == null) delete target[paidField];
  else target[paidField] = source[paidField];
  // The bundle marker belongs to the period it was written with, so it travels
  // with it or it goes; a leftover marker would name a plan the winning record
  // never bought.
  const bundleField = PRODUCT_BUNDLE_FIELD[product];
  if (source[bundleField] == null) delete target[bundleField];
  else target[bundleField] = source[bundleField];
  return target;
}

// mergeAccountRecord(acctRec, keyRecs) -> one record safe to hand to
// getEntitlements, or null when the account is unknown.
//
// Why this exists: an account is stored in TWO places. The accounts summary
// ({account_id, plan, email, primary_api_key, label}) never carries the
// per-product plans; those are written onto the api-key records (plan_parasign,
// plan_parasend, parasign) when a payment lands. A gate that reads only the
// summary therefore cannot see a paid upgrade at all and silently derives the
// tier from the legacy `plan` -- which is how a paying Pro account kept hitting
// the 2-signature free wall on the ParaSign web sign path (2026-07-21).
//
// The HIGHEST tier any key of the account holds wins, so a stale free key can
// never hold a paid account down. Never mutates its inputs.
function mergeAccountRecord(acctRec, keyRecs, now) {
  const keys = Array.isArray(keyRecs) ? keyRecs.filter(Boolean) : [];
  if (!acctRec && keys.length === 0) return null;
  const merged = Object.assign({}, acctRec || {});
  for (const rec of keys) {
    if (!merged.plan) merged.plan = rec.plan;
    if (rec.parasign) merged.parasign = true;
    for (const product of PRODUCTS) mergeProductGrantInto(merged, rec, product, now);
  }
  return merged;
}

// Convenience: the metered monthly quota a gate should enforce, per product.
function transfersQuota(account) { return getEntitlements(account).parasend.quotas.transfers_month; }
function signsQuota(account)     { return getEntitlements(account).parasign.quotas.signs_month; }

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
  PARASEND_LADDER,
  PARASIGN_TIERS,
  ENTERPRISE_MONTHLY_CEILING,
  derivePlanParasend,
  derivePlanParasign,
  normaliseParasendTier,
  normaliseParasignTier,
  PRODUCT_PLAN_FIELD,
  PRODUCT_PAID_UNTIL_FIELD,
  PRODUCT_BUNDLE_FIELD,
  floorTierOf,
  validateProductPlan,
  applyProductTier,
  effectiveProductTier,
  getEntitlements,
  mergeAccountRecord,
  mergeProductGrantInto,
  transfersQuota,
  signsQuota,
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
