'use strict';
// One paid term, visible on every relay that serves the customer.
//
// WHY THIS FILE EXISTS. A paid term is written by relay.js setProductPlan onto
// the api-key records and into users.json. Both of those are PER CONTAINER:
// docker-compose.yml gives relay-main, relay-health, relay-finance, relay-legal
// and relay-iot a volume each, and lib/plan-expiry.js already says so in as many
// words ("accounts do not live in redis; they live in users.json, per
// container"). So a grant is only ever true on the one container that ran it.
//
// That was survivable while the only way to a paid tier was the admin screen,
// because admin/server.js mutatePlanFleet posts a plan change to all five
// sectors and retries the ones that failed. It stopped being survivable the
// moment a CUSTOMER could grant himself a term. Both customer paths -- the
// Mollie webhook and POST /v2/billing/redeem -- are public /v2/ routes, and
// deploy/nginx-paramant-public.conf sends public /v2/ to relay-main. Meanwhile
// every screen the customer then looks at is served by the admin plane, which
// reads relay-HEALTH: /api/user/billing/status reads its /v2/admin/keys,
// /api/user/dashboard/overview reads its /v2/admin/entitlements, and the
// ParaSign signing routes go to SECTORS.health as well.
//
// So the term landed on relay-main and every screen and every gate asked
// relay-health, which had never heard of it. The customer got a confirmation
// that said "you now have ParaSign Pro until 4 December" and a homepage that
// went on saying "2 of 2 signatures left this month" and "Community, free for
// good" -- and, worse than the words, the signature gate really did still stop
// him at two.
//
// WHAT THIS FIXES AND HOW. Redis is the one thing all five containers share.
// A grant is written here as well as locally, and every container hydrates the
// grant back onto its OWN key records. After hydration nothing else has to
// change: /v2/admin/keys, /v2/admin/entitlements, the signs_month gate and the
// account page all read the local record they already read, and it is now the
// right one.
//
// WHAT IT DELIBERATELY DOES NOT DO. It never downgrades. Hydration goes through
// entitlements.mergeProductGrantInto, which copies a grant only when it beats
// the one on file, tier and period together. A revocation therefore does NOT
// travel this way; that stays the admin plane's job, where mutatePlanFleet
// writes it to every sector and reports the sectors that refused. One-way is
// the safe direction for a mechanism that heals in the background: the worst a
// lost message can do is leave a customer on the tier he already had, never
// take away one he paid for.

const entitlements = require('./entitlements');

// ── Redis layout ─────────────────────────────────────────────────────────────
// No TTL. The grant is the record of a term that was sold or given, and it has
// to outlive every container that happens to be running when it is written.
// The period inside it is what expires (entitlements.effectiveProductTier), not
// the row.
const GRANT_PREFIX = 'paramant:entitlements:grant:';
const ACCOUNT_SET = 'paramant:entitlements:accounts';
// One message, one account id. Deliberately not the grant itself: a subscriber
// that trusted the payload would apply a message it cannot verify, and reading
// the hash back costs one round trip on an event that happens a few times a day.
const CHANNEL = 'paramant:entitlements:changed';

const grantKey = (accountId) => `${GRANT_PREFIX}${accountId}`;

// The six fields a grant is made of: for each product the tier, the period it
// was paid for, and the bundle that sold it. Exactly the fields
// entitlements.applyProductTier writes, so what travels is what was written.
function grantFields() {
  const out = [];
  for (const product of entitlements.PRODUCTS) {
    out.push(entitlements.PRODUCT_PLAN_FIELD[product]);
    out.push(entitlements.PRODUCT_PAID_UNTIL_FIELD[product]);
    out.push(entitlements.PRODUCT_BUNDLE_FIELD[product]);
  }
  return out;
}
const FIELDS = Object.freeze(grantFields());

// Take the grant out of a full account record. Everything else on that record
// (email, label, keys, usage) is the container's own business and has no place
// in a shared row.
function grantOf(rec) {
  if (!rec || typeof rec !== 'object') return null;
  const out = {};
  let any = false;
  for (const f of FIELDS) {
    if (rec[f] === undefined || rec[f] === null || rec[f] === '') continue;
    out[f] = String(rec[f]);
    any = true;
  }
  return any ? out : null;
}

// ── Write ────────────────────────────────────────────────────────────────────
// Replace the row wholesale and then say so on the channel. An account whose
// grant is empty -- everything back at the floor tier -- loses its row and
// leaves the set, so the seed below never carries a grant that no longer exists.
//
// ONE HSET, EVERY FIELD, ALWAYS. Absent fields are written as empty strings and
// read back as absent, rather than deleted in a second command. Redeeming a
// two-product code calls setProductPlan twice, so two publishes for the same
// account are in flight within a millisecond of each other, and a write made of
// an HSET plus an HDEL lets the FIRST one's delete land after the SECOND one's
// set. That took the ParaSend half of a gift back off the row seconds after it
// was written, and the customer got a plan line naming one product where the
// mail he had just been sent named two. A single command cannot interleave with
// itself, so the later write simply wins, whole.
//
// Returns { ok } and never throws: a grant that was written locally must not be
// undone by a redis that is having a bad minute. The caller logs the failure and
// the periodic reseed on the writing container picks it up again.
async function publish(redis, accountId, rec) {
  if (!redis || !accountId) return { ok: false, error: 'no_redis' };
  const grant = grantOf(rec);
  const key = grantKey(accountId);
  try {
    if (!grant) {
      await redis.del(key);
      await redis.sRem(ACCOUNT_SET, String(accountId));
    } else {
      const row = { updated_at: new Date().toISOString() };
      for (const f of FIELDS) row[f] = grant[f] === undefined ? '' : grant[f];
      await redis.hSet(key, row);
      await redis.sAdd(ACCOUNT_SET, String(accountId));
    }
    await redis.publish(CHANNEL, String(accountId));
    return { ok: true, grant };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ── Read ─────────────────────────────────────────────────────────────────────
// One account. Returns a record shaped like an api-key record, so it can be fed
// straight to entitlements.mergeProductGrantInto, or null when there is nothing
// on file.
async function read(redis, accountId) {
  if (!redis || !accountId) return null;
  try {
    const h = await redis.hGetAll(grantKey(accountId));
    return grantOf(h);
  } catch {
    return null;
  }
}

// Every account with a grant on file. Used at boot and by the periodic reseed,
// which is the net under the channel: a container that was down, or whose
// subscriber dropped a message, catches up here instead of staying wrong until
// somebody notices. The set is the index, so this is one SMEMBERS and one
// HGETALL per account that has ever been granted a term, not a scan of redis.
async function readAll(redis) {
  if (!redis) return [];
  let ids = [];
  try { ids = (await redis.sMembers(ACCOUNT_SET)) || []; } catch { return []; }
  const out = [];
  for (const accountId of ids) {
    const grant = await read(redis, accountId);
    if (grant) out.push({ accountId, grant });
  }
  return out;
}

// ── Apply ────────────────────────────────────────────────────────────────────
// Merge a shared grant into a local record IN PLACE, per product, and report
// which products actually moved. mergeProductGrantInto is the existing rule and
// the only one that may decide this: effective tier first, then the tier on
// file, then the more generous period, and the period and the bundle travel with
// the tier or not at all. A grant that does not beat what is on file changes
// nothing, which is what makes this safe to run on a timer.
function applyTo(target, grant, now) {
  if (!target || !grant) return [];
  const moved = [];
  for (const product of entitlements.PRODUCTS) {
    const planField = entitlements.PRODUCT_PLAN_FIELD[product];
    const paidField = entitlements.PRODUCT_PAID_UNTIL_FIELD[product];
    const before = `${target[planField]}|${target[paidField]}`;
    entitlements.mergeProductGrantInto(target, grant, product, now);
    if (`${target[planField]}|${target[paidField]}` !== before) moved.push(product);
  }
  return moved;
}

module.exports = {
  GRANT_PREFIX, ACCOUNT_SET, CHANNEL, FIELDS,
  grantKey, grantOf, publish, read, readAll, applyTo,
};
