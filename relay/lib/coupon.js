'use strict';
// A code that gives somebody a term, without any money moving.
//
// WHY THIS EXISTS. Every paid term on this platform arrives the same way: a
// one-off Mollie payment, checked against the catalog, granted by the webhook,
// written down as an invoice (lib/billing.js, lib/mollie.js, lib/invoice.js).
// That path is the only way an account has ever reached a paid tier, and it
// cannot be used to say thank you: there is no amount to charge, no payment id
// to be idempotent against, and no document to issue, because nothing was sold.
//
// A coupon is therefore NOT a payment with a 100% discount. It never touches
// Mollie, never draws an invoice number, and never appears in the books as
// revenue. What it shares with a payment is the only half that matters to the
// customer: it writes plan_<product> and paid_until_<product> through the same
// setProductPlan the webhook uses, so the entitlement layer, the expiry index
// and the reminder mails all see an ordinary paid term and need no special case.
//
// THE THREE RULES.
//
// 1. THE HUNDRED AND FIRST MUST REALLY GET A NO. A code handed to a public
//    audience is redeemed concurrently by design. Read-then-write in JavaScript
//    would let two requests both read 99 and both grant, and the whole point of
//    a cap is that it is a cap. The claim below is ONE Lua script: redis runs it
//    to completion before anything else touches the key, so the check and the
//    write cannot be separated.
//
// 2. ONE REDEMPTION PER ACCOUNT PER CODE. The redemption hash is keyed by
//    account id, and the same script that counts also refuses a field that is
//    already there. So "give it to a hundred people" cannot become "one person
//    takes a hundred terms".
//
// 3. A TERM IS ADDED, NEVER SUBSTITUTED. Somebody who already paid for a year
//    and then redeems a 90-day code gets those 90 days AFTER his year, not
//    instead of it (grantEnd, on lib/billing.js's extendFrom rule). Handing a
//    paying customer a shorter period than the one he bought is the one way a
//    gift can cost him something.
//
// The claim is reservation-shaped: it writes the redemption first and the
// caller releases it if the grant itself fails. A reservation that is left
// standing costs one seat out of the hundred; a grant with no reservation would
// cost the cap itself.

const entitlements = require('./entitlements');
const planExpiry = require('./plan-expiry');
const billing = require('./billing');

// ── Redis layout ─────────────────────────────────────────────────────────────
// No TTL anywhere. A coupon that vanishes is a coupon nobody can explain
// afterwards, and the redemption list is the only record that a term was given
// rather than sold.
const K = {
  doc:      (code) => `paramant:coupon:doc:${code}`,
  redeemed: (code) => `paramant:coupon:redeemed:${code}`,
  all:                 'paramant:coupon:all',
};

// Codes are shouted across a Buy Me a Coffee post and typed back in by hand, so
// they are case-insensitive and hold nothing that a phone keyboard fights over.
// Normalising to upper case at the door means COFFEE, coffee and Coffee are one
// code and not three.
const CODE_RE = /^[A-Z0-9-]{3,32}$/;

// The campaign this shipped for: three months of both products, for the first
// hundred people who ask. Exported so the admin route and the docs state one
// number and not two.
const DEFAULT_DAYS = 90;
const DEFAULT_MAX_REDEMPTIONS = 100;
const DEFAULT_GRANTS = Object.freeze([
  Object.freeze({ product: 'parasign', tier: 'pro', days: DEFAULT_DAYS }),
  Object.freeze({ product: 'parasend', tier: 'pro', days: DEFAULT_DAYS }),
]);

// A cap has to be a real number, the same rule tiers.js follows: an unbounded
// coupon is a coupon that cannot be closed once it is out in the world.
const MAX_REDEMPTIONS_CEILING = 100000;
const MAX_DAYS = 3650;

const DEFAULT_SITE_URL = planExpiry.DEFAULT_SITE_URL;

// ── Naming ───────────────────────────────────────────────────────────────────
function normaliseCode(raw) {
  const code = String(raw == null ? '' : raw).trim().toUpperCase();
  if (!CODE_RE.test(code)) return { ok: false, error: 'bad_code' };
  return { ok: true, code };
}

// "3 months", "1 year", "45 days". Whole months and whole years get their own
// word because that is how the gift was described to the person receiving it;
// anything else stays in days rather than being rounded into a lie.
function humanDuration(days) {
  const d = Math.round(Number(days) || 0);
  if (d <= 0) return '0 days';
  if (d % 365 === 0) { const y = d / 365; return `${y} ${y === 1 ? 'year' : 'years'}`; }
  if (d % 30 === 0) { const m = d / 30; return `${m} ${m === 1 ? 'month' : 'months'}`; }
  return `${d} ${d === 1 ? 'day' : 'days'}`;
}

// "3 months of ParaSign Pro and ParaSend Pro". One sentence fragment that reads
// the same in the mail, in the billing history and in the answer to the browser.
function describeGrants(grants) {
  const list = Array.isArray(grants) ? grants : [];
  if (list.length === 0) return 'nothing';
  const plans = list.map((g) => planExpiry.planLabel(g.product, g.tier));
  const names = plans.length === 1
    ? plans[0]
    : `${plans.slice(0, -1).join(', ')} and ${plans[plans.length - 1]}`;
  // Every grant on this coupon runs for the same number of days in every case
  // the admin route allows, so the duration is stated once.
  return `${humanDuration(list[0].days)} of ${names}`;
}

// The line that goes in the billing history. It names the code on purpose: a
// customer reading his own history a year later should be able to see which
// campaign gave him the term, and so should we.
function historyLabel(code, grants) {
  return `Gift: ${describeGrants(grants)}, code ${code}`;
}

// ── Validation ───────────────────────────────────────────────────────────────
// Strict, on entitlements.validateProductPlan, so a typo in an admin request is
// a 400 and never a coupon that silently grants the floor tier.
function validateGrants(input) {
  const list = Array.isArray(input) ? input : [];
  if (list.length === 0) return { ok: false, error: 'no_grants' };
  if (list.length > entitlements.PRODUCTS.length) return { ok: false, error: 'too_many_grants' };
  const out = [];
  const seen = new Set();
  for (const g of list) {
    if (!g || typeof g !== 'object') return { ok: false, error: 'bad_grant' };
    const v = entitlements.validateProductPlan(g.product, g.tier);
    if (!v.ok) return { ok: false, error: v.error };
    // A floor tier is not a gift, it is what the account already has.
    const floor = v.product === 'parasign' ? 'free' : 'community';
    if (v.tier === floor) return { ok: false, error: 'floor_tier' };
    if (seen.has(v.product)) return { ok: false, error: 'duplicate_product' };
    seen.add(v.product);
    const days = Math.trunc(Number(g.days == null ? DEFAULT_DAYS : g.days));
    if (!Number.isFinite(days) || days < 1 || days > MAX_DAYS) return { ok: false, error: 'bad_days' };
    out.push({ product: v.product, tier: v.tier, days });
  }
  // describeGrants states one duration for the whole coupon, so two different
  // durations on one code would make that sentence untrue.
  if (out.some((g) => g.days !== out[0].days)) return { ok: false, error: 'mixed_days' };
  return { ok: true, grants: out };
}

function validateMax(value) {
  const n = Math.trunc(Number(value == null ? DEFAULT_MAX_REDEMPTIONS : value));
  if (!Number.isFinite(n) || n < 1 || n > MAX_REDEMPTIONS_CEILING) return { ok: false, error: 'bad_max_redemptions' };
  return { ok: true, max: n };
}

// A coupon without an end date is one nobody remembers to switch off. Absent is
// allowed and means "no end date"; a value that is not a date is refused rather
// than read as one.
function validateValidUntil(value) {
  if (value === undefined || value === null || value === '') return { ok: true, ms: 0, iso: null };
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return { ok: false, error: 'bad_valid_until' };
  return { ok: true, ms, iso: new Date(ms).toISOString() };
}

// ── The atomic claim ─────────────────────────────────────────────────────────
// One script, one round trip, run to completion by redis with nothing else in
// between. Everything the decision depends on is read INSIDE it: the cap, the
// end date, the revocation, the seats already taken and this account's own
// earlier redemption. A JavaScript version of this reads the count, decides, and
// writes, and two requests that read the same 99 both write a hundredth seat.
//
// KEYS: 1 the coupon hash, 2 the redemption hash
// ARGV: 1 accountId, 2 now in epoch ms, 3 now as ISO
// Returns { status, used } where status is one of:
//   ok | unknown | revoked | expired | already_used | exhausted
const CLAIM_LUA = `
local max = tonumber(redis.call('HGET', KEYS[1], 'max_redemptions'))
if max == nil then return {'unknown', '0'} end
if redis.call('HGET', KEYS[1], 'revoked_at') then return {'revoked', '0'} end
local until_ms = tonumber(redis.call('HGET', KEYS[1], 'valid_until_ms')) or 0
if until_ms > 0 and tonumber(ARGV[2]) > until_ms then return {'expired', '0'} end
if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 1 then return {'already_used', '0'} end
local used = redis.call('HLEN', KEYS[2])
if used >= max then return {'exhausted', tostring(used)} end
redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
return {'ok', tostring(used + 1)}
`;

// node-redis returns Lua's table as an array of strings.
function _claimResult(raw) {
  const arr = Array.isArray(raw) ? raw : [];
  return { status: String(arr[0] || 'unknown'), used: parseInt(String(arr[1] || '0'), 10) || 0 };
}

// ── Store ────────────────────────────────────────────────────────────────────
async function createCoupon(redis, input) {
  if (!redis) return { ok: false, error: 'no_redis' };
  const c = normaliseCode(input && input.code);
  if (!c.ok) return c;
  const g = validateGrants((input && input.grants) || DEFAULT_GRANTS);
  if (!g.ok) return g;
  const m = validateMax(input && input.max_redemptions);
  if (!m.ok) return m;
  const v = validateValidUntil(input && input.valid_until);
  if (!v.ok) return v;

  const createdAt = new Date((input && input.now) || Date.now()).toISOString();
  const fields = {
    code: c.code,
    grants: JSON.stringify(g.grants),
    max_redemptions: String(m.max),
    valid_until_ms: String(v.ms),
    valid_until: v.iso || '',
    created_by: String((input && input.created_by) || 'admin').slice(0, 120),
    created_at: createdAt,
    note: String((input && input.note) || '').slice(0, 200),
  };
  // A code is created once. Re-creating an existing one would silently reset a
  // cap that people are already redeeming against, so it is refused and the
  // admin decides whether to revoke the old one.
  const claimed = await redis.hSetNX(K.doc(c.code), 'code', c.code);
  if (!(claimed === 1 || claimed === true)) return { ok: false, error: 'code_exists' };
  await redis.hSet(K.doc(c.code), fields);
  await redis.sAdd(K.all, c.code);
  return { ok: true, coupon: await getCoupon(redis, c.code) };
}

function _decodeGrants(raw) {
  try { const g = JSON.parse(raw || '[]'); return Array.isArray(g) ? g : []; } catch { return []; }
}

// The admin view of one coupon: what it gives, the cap, and how many seats are
// gone. `used` is HLEN of the redemption hash, so it is the count itself and
// never a second number that can drift from it.
async function getCoupon(redis, codeIn) {
  if (!redis) return null;
  const c = normaliseCode(codeIn);
  if (!c.ok) return null;
  const h = await redis.hGetAll(K.doc(c.code));
  if (!h || !h.code) return null;
  const used = await redis.hLen(K.redeemed(c.code));
  return {
    code: h.code,
    grants: _decodeGrants(h.grants),
    max_redemptions: parseInt(h.max_redemptions, 10) || 0,
    used,
    remaining: Math.max(0, (parseInt(h.max_redemptions, 10) || 0) - used),
    valid_until: h.valid_until || null,
    created_by: h.created_by || '',
    created_at: h.created_at || '',
    note: h.note || '',
    revoked_at: h.revoked_at || null,
    describes: describeGrants(_decodeGrants(h.grants)),
  };
}

async function listCoupons(redis) {
  if (!redis) return [];
  let codes = [];
  try { codes = (await redis.sMembers(K.all)) || []; } catch { return []; }
  const out = [];
  for (const code of codes.sort()) {
    const c = await getCoupon(redis, code);
    if (c) out.push(c);
  }
  return out;
}

// Revoking is a stamp, not a delete: the redemptions that already happened are
// the record of terms that were given away, and they stay readable.
async function revokeCoupon(redis, codeIn, at) {
  if (!redis) return { ok: false, error: 'no_redis' };
  const c = normaliseCode(codeIn);
  if (!c.ok) return c;
  const exists = await redis.hGet(K.doc(c.code), 'code');
  if (!exists) return { ok: false, error: 'unknown_code' };
  await redis.hSet(K.doc(c.code), 'revoked_at', new Date(at || Date.now()).toISOString());
  return { ok: true, coupon: await getCoupon(redis, c.code) };
}

// Who took a seat, and when.
async function redemptionsOf(redis, codeIn) {
  if (!redis) return [];
  const c = normaliseCode(codeIn);
  if (!c.ok) return [];
  const h = await redis.hGetAll(K.redeemed(c.code));
  return Object.entries(h || {})
    .map(([account, at]) => ({ account, at }))
    .sort((a, b) => String(a.at).localeCompare(String(b.at)));
}

// Take one seat, atomically. Returns { ok:true, code, grants, used, coupon } or
// { ok:false, error } with error one of bad_code | unknown | revoked | expired |
// already_used | exhausted.
async function claim(redis, { code: codeIn, accountId, now } = {}) {
  if (!redis) return { ok: false, error: 'no_redis' };
  if (!accountId) return { ok: false, error: 'bad_account' };
  const c = normaliseCode(codeIn);
  if (!c.ok) return { ok: false, error: 'unknown' };
  const at = now instanceof Date ? now : new Date(now || Date.now());
  const raw = await redis.eval(CLAIM_LUA, {
    keys: [K.doc(c.code), K.redeemed(c.code)],
    arguments: [String(accountId), String(at.getTime()), at.toISOString()],
  });
  const r = _claimResult(raw);
  if (r.status !== 'ok') return { ok: false, error: r.status, code: c.code, used: r.used };
  const coupon = await getCoupon(redis, c.code);
  return { ok: true, code: c.code, grants: (coupon && coupon.grants) || [], used: r.used, coupon };
}

// Give a claimed seat back. Only ever called when the grant that followed the
// claim did not happen, so the cap counts terms that were actually given.
async function release(redis, codeIn, accountId) {
  if (!redis || !accountId) return { ok: false };
  const c = normaliseCode(codeIn);
  if (!c.ok) return { ok: false };
  try { await redis.hDel(K.redeemed(c.code), String(accountId)); } catch { return { ok: false }; }
  return { ok: true };
}

// ── The term ─────────────────────────────────────────────────────────────────
// Rule 3. extendFrom is lib/billing.js's renewal rule, unchanged: a live paid
// term is the base, a lapsed one is not, so a gift never shortens a term
// somebody paid for and never retroactively covers a gap.
function grantEnd(currentPaidUntil, now, days) {
  const at = now instanceof Date ? now : new Date(now || Date.now());
  const base = billing.extendFrom(currentPaidUntil, at);
  const end = new Date(base.getTime());
  end.setUTCDate(end.getUTCDate() + Math.trunc(Number(days) || 0));
  return end;
}

// ── The one mail ─────────────────────────────────────────────────────────────
// Same plain register as the expiry mails in lib/plan-expiry.js, and the same
// two facts a reader needs: what he now has, and until when. It says nothing
// was charged because on this path that is literally true, and because the
// reminder that arrives seven days before the end says the same thing.
function redeemMail({ code, grants, ends, siteUrl } = {}) {
  const list = Array.isArray(grants) ? grants : [];
  if (list.length === 0) return null;
  const site = String(siteUrl || DEFAULT_SITE_URL).replace(/\/+$/, '');
  const lines = list
    .map((g) => `${planExpiry.planLabel(g.product, g.tier)} until ${planExpiry.formatDate(g.ends || ends)}`)
    .join('\n');
  const subject = `Your code ${code} is redeemed`;
  const text = [
    `Thank you. Your code ${code} gives you ${describeGrants(list)}.`,
    '',
    lines,
    '',
    'Nothing was charged and nothing will be. This is a gift term, not a subscription, so it simply stops on the date above and your account goes back to Community.',
    '',
    `Your account is here: ${site}/account`,
    '',
    'Paramant',
  ].join('\n');
  return { subject, text, html: _html(subject, text, `${site}/account`) };
}

const escHtml = (s) => String(s === null || s === undefined ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function _html(subject, text, link) {
  const paragraphs = text.split('\n\n')
    .filter((p) => p && p !== 'Paramant')
    .map((p) => `<p style="margin:0 0 16px;line-height:1.6">${escHtml(p).replace(/\n/g, '<br>')}</p>`)
    .join('\n');
  return [
    '<div style="font-family:system-ui,-apple-system,\'Segoe UI\',sans-serif;color:#0B3A6A;max-width:520px">',
    `<h1 style="font-size:18px;margin:0 0 16px">${escHtml(subject)}</h1>`,
    paragraphs,
    `<p style="margin:0"><a href="${escHtml(link)}" style="color:#0B3A6A">${escHtml(link)}</a></p>`,
    '</div>',
  ].join('\n');
}

// ── What the browser is told ─────────────────────────────────────────────────
// Plain sentences, no codes to look up. Every one of these is shown to somebody
// who typed a code into a box and got nothing, so each says what happened and
// what to do next.
const MESSAGES = Object.freeze({
  unknown: 'We do not know that code. Check the spelling and try again.',
  bad_code: 'We do not know that code. Check the spelling and try again.',
  revoked: 'That code is no longer valid.',
  expired: 'That code has expired.',
  already_used: 'You have already used this code on this account.',
  exhausted: 'That code has been fully claimed. It has run out.',
  no_redis: 'We cannot check codes right now. Please try again in a minute.',
  grant_failed: 'We could not add the term to your account. Nothing was changed, please try again.',
});

function messageFor(error) {
  return MESSAGES[error] || MESSAGES.unknown;
}

// The sentence the browser prints on success: what was given, and until when.
function successMessage(grants) {
  const list = Array.isArray(grants) ? grants : [];
  if (list.length === 0) return 'Your code is redeemed.';
  const parts = list.map((g) => `${planExpiry.planLabel(g.product, g.tier)} until ${planExpiry.formatDate(g.ends)}`);
  const joined = parts.length === 1
    ? parts[0]
    : `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
  return `Your code is redeemed. You now have ${joined}. Nothing was charged.`;
}

module.exports = {
  K, CODE_RE, CLAIM_LUA,
  DEFAULT_DAYS, DEFAULT_MAX_REDEMPTIONS, DEFAULT_GRANTS,
  MAX_REDEMPTIONS_CEILING, MAX_DAYS, MESSAGES,
  normaliseCode, humanDuration, describeGrants, historyLabel,
  validateGrants, validateMax, validateValidUntil,
  createCoupon, getCoupon, listCoupons, revokeCoupon, redemptionsOf,
  claim, release, grantEnd, redeemMail, messageFor, successMessage,
};
