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
    max_recipients: 1,     // named recipients per send; one is the free story
    // Signers on one document. Twenty is what every account could already do,
    // so it stays the floor: a paid ceiling must never be a quiet takeaway from
    // people who have been using twenty since before it was a plan field.
    max_parties: 20,
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
    max_recipients: 10,
    max_parties: 20,
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
    max_recipients: 30,
    max_parties: 30,
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
    // Deliberately not UNLIMITED. Above thirty named people a send stops being
    // a send and becomes a distribution list, which needs list ownership and a
    // different conversation. Thirty is the product ceiling, not a price step.
    max_recipients: 30,
    max_parties: 30,
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

// Check a list of named recipients against the plan's ceiling.
//
// This is the ONLY place that decides who may address more than one person.
// The browser may show the field to anyone; the answer is made here, server
// side, from the plan on the key. A front end that forgets to hide the field
// therefore cannot hand a community account a paid capability.
//
// Rejects rather than silently truncating. Quietly dropping addresses from a
// send of a confidential document is the worst possible failure: the sender
// believes twenty people were reached and nineteen never hear about it.
//
// Returns { ok, plan, limit, recipients, count, reason, rejected }.
//   recipients  validated, NFC-normalised, lowercased and de-duplicated
//   reason      'empty' | 'over_limit' | 'invalid_address' when ok is false
//   rejected    the first address that failed validation, for the error message

// One address, or null when it is not one.
//
// WHY THIS IS STRICT. The old version did String(raw).trim().toLowerCase() and
// called it a day, which let three things through that an adversarial pass
// demonstrated on 22-09:
//
//   ['a@x.org','b@x.org'] as ONE entry became the single string
//   "a@x.org,b@x.org". One recipient by the count, two mailboxes on the wire,
//   sharing one pickup token. A community account with a ceiling of one reached
//   two people.
//
//   "a@x.org\nBcc: someone@else" survived trim() whole, because trim only takes
//   the ends. That line feeds the invitation mail: a blind copy of a pickup link
//   to a third party.
//
//   Combining characters meant one mailbox could appear as two recipients with
//   two live tokens, so revoking one revoked nothing.
//
// Hence: normalise first, then reject anything that is not a single ordinary
// address. Better a sender who has to fix a typo than a leak nobody sees.
const CONTROL_OR_SEPARATOR = /[ -,;<>"\\\s]/;

function normaliseAddress(raw) {
  if (typeof raw !== 'string') return null;         // arrays, numbers, objects: no
  let email;
  try {
    // Fold twice: some capitals do not come back to their plain form in one
    // pass (the Turkish dotted capital I becomes i plus a combining dot).
    email = raw.normalize('NFC').trim().toLowerCase().normalize('NFC');
  } catch (_) {
    return null;
  }
  if (!email) return null;
  if (email.length > 254) return null;               // RFC 5321 ceiling
  if (CONTROL_OR_SEPARATOR.test(email)) return null; // CR, LF, comma, angle brackets
  // ASCII only. Internationalised addresses (EAI) are rare in this market and
  // they carry a whole class of trouble: the Turkish dotted capital I folds to
  // an i with a separate combining dot, so one mailbox can enter the list twice
  // as two recipients with two live tokens, and revoking one revokes nothing.
  // Refusing them is a product choice, and a sender gets a clear error rather
  // than a silent duplicate.
  if (!/^[\x20-\x7e]+$/.test(email)) return null;
  const at = email.indexOf('@');
  if (at < 1 || at !== email.lastIndexOf('@')) return null;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (!local || local.length > 64) return null;
  if (!domain || domain.length > 253) return null;
  if (!domain.includes('.')) return null;
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return null;
  if (domain.startsWith('-') || domain.endsWith('-')) return null;
  return email;
}

function checkRecipients(plan, list) {
  const named = normalisePlan(plan);
  const limit = tierLimitNum(named, 'max_recipients');
  const seen = new Set();
  const recipients = [];
  const items = Array.isArray(list) ? list : [];
  for (const raw of items) {
    // Stop at the ceiling instead of building the whole list first. A refused
    // send used to normalise a hundred thousand addresses before saying no,
    // which is free work for whoever asked.
    if (recipients.length > limit) break;
    if (raw == null || (typeof raw === 'string' && raw.trim() === '')) continue;
    const email = normaliseAddress(raw);
    if (!email) {
      return { ok: false, plan: named, limit, recipients: [], count: 0,
               reason: 'invalid_address',
               rejected: typeof raw === 'string' ? raw.slice(0, 80) : typeof raw };
    }
    if (seen.has(email)) continue;
    seen.add(email);
    recipients.push(email);
  }
  if (recipients.length === 0) {
    return { ok: false, plan: named, limit, recipients, count: 0, reason: 'empty',
             rejected: null };
  }
  if (recipients.length > limit) {
    // Report the ceiling and how far over it went, without handing back the
    // whole list: the caller only needs to tell the sender to trim it.
    return { ok: false, plan: named, limit, recipients: [], count: recipients.length,
             reason: 'over_limit', rejected: null };
  }
  return { ok: true, plan: named, limit, recipients, count: recipients.length,
           reason: null, rejected: null };
}

module.exports = {
  TIER_LIMITS,
  UNLIMITED,
  normalisePlan,
  tierLimit,
  tierLimitNum,
  isUnlimited,
  checkRecipients,
  normaliseAddress,
};
