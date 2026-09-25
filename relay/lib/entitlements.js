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

// Every paid term a product holds, ONE PER TIER, when it holds more than one.
// { "pro": { "until": ISO, "bundle": "firm" }, "business": { "until": ISO } },
// with until null for a term without an end.
//
// Why a product needs more than one. A customer who pays for a Firm year and
// for one Business month (two tabs, a payment link, an older subscription) has
// paid for both, and one tier with one date cannot hold that: the Business
// month either took the end date of the year (thirteen months of Business,
// betaaltest R2), or replaced the year (eleven paid months of Pro gone, review
// of #515). With a term per tier, the tier a gate sees is simply the highest one
// whose term still runs; when the Business month ends the account is on Pro
// until the end of the year, and nobody has to repair anything.
//
// The field is written only while a product holds two or more terms. With one
// term the pair above (plan_<p>, paid_until_<p>, bundle_<p>) says everything,
// exactly as it did before this field existed, so every users.json on disk
// today reads as it always has and a record with one term is written byte for
// byte the same. With two or more, that pair still holds the term a reader
// should see: the one running, and it is rewritten on every write.
const PRODUCT_TERMS_FIELD = Object.freeze({
  parasend: 'terms_parasend',
  parasign: 'terms_parasign',
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

function _normTier(product, tier) {
  return product === 'parasign' ? normaliseParasignTier(tier) : normaliseParasendTier(tier);
}

// A stored terms value: the object users.json holds, or the JSON string the
// shared redis row carries. Anything else is no terms at all.
function _termsObject(raw) {
  let v = raw;
  if (!v) return null;
  if (typeof v === 'string') { try { v = JSON.parse(v); } catch { return null; } }
  return (v && typeof v === 'object' && !Array.isArray(v)) ? v : null;
}

// Every paid term one product holds, as [{ tier, until, bundle }], `until` in
// epoch ms or null for a term without an end. The stored pair always counts as
// one of them, so a record from before terms existed (one tier, one
// paid_until) is one term, and a writer that set only the pair is honoured.
//
// A FLOOR TIER ON FILE MEANS NO PAID TERM, whatever else the record carries.
// Every path that takes a plan away writes the floor, including the ones that
// predate this field (update-plan), and the floor has always won.
function termsOf(rec, product) {
  const planField = PRODUCT_PLAN_FIELD[product];
  if (!rec || !planField) return [];
  const floor = floorTierOf(product);
  const head = _normTier(product, rec[planField]);
  if (head === floor) return [];
  const byTier = new Map();
  const add = (tier, until, bundle) => {
    if (_normTier(product, tier) !== tier || tier === floor) return;
    // Unparseable reads as no end, on the no-silent-downgrade rule above.
    const u = parsePaidUntil(until);
    const b = bundle ? String(bundle) : null;
    const prev = byTier.get(tier);
    // Two answers for one tier: the later end wins, and the bundle that bought
    // it travels with it.
    if (!prev || (prev.until !== null && (u === null || u > prev.until))) byTier.set(tier, { tier, until: u, bundle: b });
  };
  const stored = _termsObject(rec[PRODUCT_TERMS_FIELD[product]]);
  if (stored) for (const [tier, v] of Object.entries(stored)) add(tier, v && v.until, v && v.bundle);
  add(head, rec[PRODUCT_PAID_UNTIL_FIELD[product]], rec[PRODUCT_BUNDLE_FIELD[product]]);
  return [...byTier.values()];
}

const _running = (t, at) => t.until === null || at < t.until;

// The term a gate grants: the highest tier whose term still runs.
function _pickRunning(product, terms, at) {
  let best = null;
  for (const t of terms) {
    if (!_running(t, at)) continue;
    if (!best || tierRank(product, t.tier) > tierRank(product, best.tier)) best = t;
  }
  return best;
}

// The term to show when none runs: the highest tier on file, which is what the
// stored pair has always said about a lapsed account.
function _pickOnFile(product, terms) {
  let best = null;
  for (const t of terms) if (!best || tierRank(product, t.tier) > tierRank(product, best.tier)) best = t;
  return best;
}

const _iso = (ms) => (ms === null ? null : new Date(ms).toISOString());

// The tier an account ACTUALLY has right now: the highest paid tier whose term
// still runs, or the floor once none does. Read paths should use this instead
// of reading PRODUCT_PLAN_FIELD directly, so an expired subscription stops
// granting even if no webhook, cron or admin ever came along to write the
// downgrade, and a Business month that ends drops the account to the Pro year
// underneath it rather than to the floor.
// Returns { tier, expired, paidUntil } (paidUntil in epoch ms: the end of the
// term that grants, or of the last one once they have all run out).
function effectiveProductTier(rec, product, now) {
  const field = PRODUCT_PLAN_FIELD[product];
  if (!rec || !field) return { tier: floorTierOf(product), expired: false, paidUntil: null };
  const floor = floorTierOf(product);
  const terms = termsOf(rec, product);
  // A floor tier can not expire, and no recorded period means no expiry to
  // enforce (free accounts, and every account from before billing existed).
  if (terms.length === 0) return { tier: floor, expired: false, paidUntil: parsePaidUntil(rec[PRODUCT_PAID_UNTIL_FIELD[product]]) };
  const at = typeof now === 'number' ? now : Date.now();
  const run = _pickRunning(product, terms, at);
  if (run) return { tier: run.tier, expired: false, paidUntil: run.until };
  let last = null;
  for (const t of terms) if (last === null || t.until > last) last = t.until;
  return { tier: floor, expired: true, paidUntil: last };
}

// What a reader is shown for one product now: the running term, or when none
// runs the one on file. { tier, paidUntil (ISO or null), bundle }. The stored
// pair says the same thing at the moment it was written; this says it at the
// moment it is read, so a screen shows the Pro year the day after a Business
// month ends, and not a Business plan that has ended.
function currentTermOf(rec, product, now) {
  const terms = termsOf(rec, product);
  if (terms.length === 0) {
    return { tier: floorTierOf(product), paidUntil: (rec && rec[PRODUCT_PAID_UNTIL_FIELD[product]]) || null, bundle: null };
  }
  const at = typeof now === 'number' ? now : Date.now();
  const t = _pickRunning(product, terms, at) || _pickOnFile(product, terms);
  return { tier: t.tier, paidUntil: _iso(t.until), bundle: t.bundle };
}

// The term that ends last: the day this product falls to its floor, and what
// was bought for it. null when a term has no end, or nothing is paid. The
// expiry mail is about this day and no other: the end of a Business month with
// a Pro year under it is not the end of anything the customer has to act on.
function finalTermOf(rec, product) {
  const terms = termsOf(rec, product);
  if (terms.length === 0 || terms.some((t) => t.until === null)) return null;
  let last = terms[0];
  for (const t of terms) {
    if (t.until > last.until || (t.until === last.until && tierRank(product, t.tier) > tierRank(product, last.tier))) last = t;
  }
  return { tier: last.tier, paidUntil: _iso(last.until), bundle: last.bundle };
}

// The end of ONE tier's term on this product (ISO), or null when that tier
// holds no term or one without an end. What a renewal of that tier extends.
function termEndOf(rec, product, tier) {
  const t = termsOf(rec, product).find((x) => x.tier === _normTier(product, tier));
  return t ? _iso(t.until) : null;
}

// Does this tier hold a term that is still running on this product.
function hasRunningTerm(rec, product, tier, now) {
  const at = typeof now === 'number' ? now : Date.now();
  return termsOf(rec, product).some((t) => t.tier === _normTier(product, tier) && _running(t, at));
}

// Write a product's terms back onto a record. The stored pair holds the term a
// reader should see (the running one, else the one on file); the full list is
// written only when there is more than one, and lapsed terms are dropped once
// a running one is left, because they carry no time. Returns whether a field
// changed.
function _storeTerms(rec, product, terms, at) {
  const planField = PRODUCT_PLAN_FIELD[product];
  const untilField = PRODUCT_PAID_UNTIL_FIELD[product];
  const bundleField = PRODUCT_BUNDLE_FIELD[product];
  const termsField = PRODUCT_TERMS_FIELD[product];
  const snap = () => JSON.stringify([rec[planField], rec[untilField], rec[bundleField], rec[termsField]]);
  const before = snap();
  let keep = terms;
  if (keep.some((t) => _running(t, at))) keep = keep.filter((t) => _running(t, at));
  if (keep.length === 0) {
    rec[planField] = floorTierOf(product);
    delete rec[untilField];
    delete rec[bundleField];
    delete rec[termsField];
    return snap() !== before;
  }
  const head = _pickRunning(product, keep, at) || _pickOnFile(product, keep);
  rec[planField] = head.tier;
  if (head.until === null) delete rec[untilField]; else rec[untilField] = _iso(head.until);
  if (head.bundle) rec[bundleField] = head.bundle; else delete rec[bundleField];
  if (keep.length > 1) {
    const out = {};
    for (const t of [...keep].sort((a, b) => tierRank(product, a.tier) - tierRank(product, b.tier))) {
      out[t.tier] = t.bundle ? { until: _iso(t.until), bundle: t.bundle } : { until: _iso(t.until) };
    }
    rec[termsField] = out;
  } else {
    delete rec[termsField];
  }
  return snap() !== before;
}

// ── One rule for every writer of a paid term ────────────────────────────────
// A payment, a gift code and an admin grant all end in setProductPlan, and
// until 2026-09-25 none of them looked at what was already running. A Firm
// payment, or a code for Pro, put a customer who had paid for ParaSign
// Business back on Pro, and only on the relay that took the request: the
// others refuse a lower grant from redis (mergeProductGrantInto below), so the
// fleet then disagreed about what he had. And a Firm-year customer who paid
// for one Business month got thirteen, because the month was added to the end
// of his year (betaaltest 25-09, R2 and R3).
//
// The data answers most of it now: a product holds a term per tier
// (PRODUCT_TERMS_FIELD), a dated grant writes the term of ITS tier and no
// other, and the tier a gate sees is the highest one still running. So a
// payment can not lower anything, and a renewal extends its own tier from its
// own end. What is left for a writer to decide is a policy, and this is the
// question it asks: how does the tier it is about to write relate to the tier
// RUNNING on that product now (a lapsed term runs at the floor):
//   'none'            nothing paid is running
//   'same'            the same tier is running
//   'higher_running'  a HIGHER tier is running
//   'lower_running'   a lower paid tier is running
// relay.js: the checkout sells no second plan next to a running one (renewing
// a tier that holds a term is fine), a gift code adds nothing under a higher
// tier, and an admin grant lowers a running tier only when asked to explicitly,
// and then keeps its end date.
function tierRank(product, tier) {
  if (product === 'parasign') return PARASIGN_TIERS.indexOf(normaliseParasignTier(tier));
  return PARASEND_LADDER.indexOf(normaliseParasendTier(tier));
}

function termRelation(product, tier, runningTier) {
  const running = product === 'parasign' ? normaliseParasignTier(runningTier) : normaliseParasendTier(runningTier);
  if (running === floorTierOf(product)) return 'none';
  const next = tierRank(product, tier);
  const now = tierRank(product, running);
  if (next === now) return 'same';
  return next < now ? 'higher_running' : 'lower_running';
}

// The same question asked of a record, through effectiveProductTier, so a
// lapsed period counts as the floor exactly as every gate counts it.
function termRelationOf(rec, product, tier, now) {
  return termRelation(product, tier, effectiveProductTier(rec, product, now).tier);
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

// The `parasign` ACCESS flag follows the tier on file. The flag is what
// keys-table.accountHasParasignEntitlement reads to decide whether an account
// may mint /v1 API keys, and it used to be set on a grant and never cleared,
// so a chargeback or a lapsed term left the ParaSign API entitlement standing
// for good: the money went back and the key kept working. Only cleared when
// the tier ACTUALLY MOVED DOWN to free, so re-applying free to an account that
// already sits there leaves an operator's explicit grant alone.
function _followAccessFlag(rec, product, beforeTier) {
  const out = { parasignGranted: false, parasignRevoked: false };
  if (product !== 'parasign') return out;
  const after = normaliseParasignTier(rec[PRODUCT_PLAN_FIELD.parasign]);
  if (after !== 'free' && rec.parasign !== true) { rec.parasign = true; out.parasignGranted = true; }
  if (after === 'free' && normaliseParasignTier(beforeTier) !== 'free' && rec.parasign === true) {
    delete rec.parasign; out.parasignRevoked = true;
  }
  return out;
}

// Apply ONE product's tier to a single account/key record IN PLACE and report
// what moved. This is the field-level mutation behind setProductPlan
// (relay.js): it writes only this product's fields, keeps the `parasign`
// access flag with the tier, and NEVER touches the other product or the unified
// `plan`. Three ways in, told apart by `paidUntil`:
//
//   the floor tier     every term on this product goes: a revoke, a refund, an
//                      admin taking a plan back
//   a date, or null    the term of THIS tier ends then (null: no end). The terms
//                      of other tiers are not touched, so this can not lower
//                      what a gate sees. It never shortens this tier's own term
//                      either: only the floor takes paid time away.
//   undefined          an admin grant, which names no date. The running term
//                      moves to this tier WITH ITS END DATE: up, or down (the
//                      relay only asks for down explicitly). A tier that
//                      already holds a term is left as it is, and with nothing
//                      running this is the grant an admin has always made,
//                      without an end.
//
// `bundle` travels with a dated term (undefined leaves it alone, null clears
// it). opts.now moves the clock, for tests.
// Returns { field, tier, changed, parasignGranted, parasignRevoked, paidUntil,
// bundle }, the last two being what the stored pair says afterwards.
function applyProductTier(rec, product, tier, paidUntil, bundle, opts) {
  const field = PRODUCT_PLAN_FIELD[product];
  const norm = _normTier(product, tier);
  const at = (opts && typeof opts.now === 'number') ? opts.now : Date.now();
  const beforeTier = rec[field];
  let terms = [];
  if (norm !== floorTierOf(product)) {
    terms = termsOf(rec, product);
    const own = terms.find((t) => t.tier === norm);
    if (paidUntil !== undefined) {
      const u = paidUntil === null ? null : parsePaidUntil(new Date(paidUntil).toISOString());
      if (!own) terms.push({ tier: norm, until: u, bundle: bundle ? String(bundle) : null });
      else {
        if (own.until !== null && (u === null || u > own.until)) own.until = u;
        if (bundle !== undefined) own.bundle = bundle ? String(bundle) : null;
      }
    } else {
      const run = _pickRunning(product, terms, at);
      const rank = tierRank(product, norm);
      if (!run) {
        if (!own) terms = [{ tier: norm, until: null, bundle: null }];
      } else if (tierRank(product, run.tier) > rank) {
        // Down: every term above this tier folds into it, and the latest end
        // among them (and its own) is the end it keeps. Nothing paid for is
        // lost, and nothing becomes a term without an end that had one.
        const above = terms.filter((t) => tierRank(product, t.tier) > rank);
        let u = own ? own.until : undefined;
        for (const t of above) {
          if (!_running(t, at)) continue;
          if (u === undefined || (u !== null && (t.until === null || t.until > u))) u = t.until;
        }
        terms = terms.filter((t) => tierRank(product, t.tier) < rank);
        terms.push({ tier: norm, until: u === undefined ? null : u, bundle: own && own.until === u ? own.bundle : null });
      } else if (tierRank(product, run.tier) < rank) {
        // Up: the running term becomes this tier, with the same end (a term
        // this tier still has on file has lapsed, or it would be the one
        // running). Its bundle does not come along: a term moved to another
        // tier is no longer what the bundle sold.
        terms = terms.filter((t) => t !== run && t.tier !== norm);
        terms.push({ tier: norm, until: run.until, bundle: null });
      }
    }
  }
  const changed = _storeTerms(rec, product, terms, at);
  return { field, tier: norm, changed, ..._followAccessFlag(rec, product, beforeTier),
    paidUntil: rec[PRODUCT_PAID_UNTIL_FIELD[product]] || null, bundle: rec[PRODUCT_BUNDLE_FIELD[product]] || null };
}

// Put one product's grant from `source` on `target` exactly as it is: the
// stored pair, the bundle and every term. The write half of hydration, where
// the decision was already taken on a copy by mergeProductGrantInto (or by a
// revocation), and five member keys must end up holding the same thing.
function copyProductGrant(target, source, product) {
  const beforeTier = target[PRODUCT_PLAN_FIELD[product]];
  for (const f of [PRODUCT_PLAN_FIELD[product], PRODUCT_PAID_UNTIL_FIELD[product], PRODUCT_BUNDLE_FIELD[product], PRODUCT_TERMS_FIELD[product]]) {
    const v = source[f];
    if (v === undefined || v === null || v === '') { delete target[f]; continue; }
    target[f] = f === PRODUCT_TERMS_FIELD[product] ? _termsObject(v) : v;
    if (target[f] === null) delete target[f];
  }
  return _followAccessFlag(target, product, beforeTier);
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
      // The capacity ceiling, and the one that was silently absent.
      //
      // relay.js reads `_psend.limits.concurrent_blobs` and refuses an upload
      // when an account is holding more than its plan allows. That field was
      // never put here, so the value was undefined, Number.isFinite(undefined)
      // is false, and the whole guard was skipped on every request since it was
      // written. Blobs live in RAM and only in RAM, so the one thing that
      // bounds memory per tenant did nothing at all.
      //
      // NEVER BELOW WHAT THE PLAN SELLS. Waking the guard up with the numbers
      // as written would have refused uploads the customer had paid for: the
      // table says 8 blocks on community and 24 on pro, while file_mb says 500
      // MB on every row. A 500 MB file is a hundred blocks, and in a send to
      // named recipients nobody collects them for hours, so they all sit there
      // at once. Measured: it broke a pro account at its 25th block and a
      // community account at its 9th transfer.
      //
      // Two dimensions of one plan contradicting each other is a pricing
      // question, not something to settle quietly inside a guard. So the floor
      // here is whatever file_mb already promises, and the guard keeps doing
      // the job it was written for: stopping the unbounded case.
      concurrent_blobs: _blobCeiling(row),
    }),
    features: Object.freeze({
      transfers: true,
    }),
  });
}
// The blocks one account may hold at once: its own ceiling, but never fewer
// than the largest file its plan allows. MAX_BLOB on the wire is 5 MiB, and a
// little slack covers padding and the block that is still in flight.
function _blobCeiling(row) {
  const eigen = tiers.tierLimitNum(row, 'concurrent_blobs');
  const mb = tiers.tierLimitNum(row, 'file_mb');
  if (!Number.isFinite(eigen)) return eigen;          // unlimited stays unlimited
  if (!Number.isFinite(mb)) return Infinity;          // an uncapped file needs uncapped room
  const nodig = Math.ceil((mb * 1048576) / (5 * 1048576)) + 8;
  return Math.max(eigen, nodig);
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
  // With every term the record holds, so a Business month that ended hands
  // over to the Pro year under it here too.
  const psTier = effectiveProductTier({ plan_parasend: psStored, [PRODUCT_PAID_UNTIL_FIELD.parasend]: acct[PRODUCT_PAID_UNTIL_FIELD.parasend], [PRODUCT_TERMS_FIELD.parasend]: acct[PRODUCT_TERMS_FIELD.parasend] }, 'parasend', now).tier;
  const pgTier = effectiveProductTier({ plan_parasign: pgStored, [PRODUCT_PAID_UNTIL_FIELD.parasign]: acct[PRODUCT_PAID_UNTIL_FIELD.parasign], [PRODUCT_TERMS_FIELD.parasign]: acct[PRODUCT_TERMS_FIELD.parasign] }, 'parasign', now).tier;
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
// And since a product holds a term per tier, what travels is every term. Two
// records of one account (two member keys, the accounts summary, this relay and
// the shared redis row) are merged per TIER: a tier either record holds is
// held, with the later of the two ends. That is what makes the Pro year under a
// Business month survive the trip from relay-main to relay-health; picking the
// "better" of two whole grants, as this did before, kept the Business month and
// dropped the year. It never lowers anything either: a term only ever gets
// longer here, and taking a term away is a revocation (shared-grants
// applyRevocation), which has its own path.
//
// A source with no tier on file carries no grant and is skipped. A target with
// no tier on file takes the source as it is.
function mergeProductGrantInto(target, source, product, now) {
  const planField = PRODUCT_PLAN_FIELD[product];
  if (!target || !source || !planField || source[planField] == null) return target;
  if (target[planField] == null) {
    copyProductGrant(target, source, product);
    return target;
  }
  const mine = termsOf(target, product);
  const theirs = termsOf(source, product);
  if (theirs.length === 0) return target;
  const byTier = new Map(mine.map((t) => [t.tier, { ...t }]));
  let gained = false;
  for (const t of theirs) {
    const prev = byTier.get(t.tier);
    if (!prev || (prev.until !== null && (t.until === null || t.until > prev.until))) { byTier.set(t.tier, { ...t }); gained = true; }
  }
  // Nothing the source holds beats what is on file: the target stays exactly
  // as it is, down to how it spells a missing date.
  if (!gained) return target;
  _storeTerms(target, product, [...byTier.values()], typeof now === 'number' ? now : Date.now());
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
  PRODUCT_TERMS_FIELD,
  floorTierOf,
  validateProductPlan,
  applyProductTier,
  copyProductGrant,
  effectiveProductTier,
  termsOf,
  termEndOf,
  hasRunningTerm,
  currentTermOf,
  finalTermOf,
  termRelation,
  termRelationOf,
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
