'use strict';
// A redeemed code, seen from the relay the CUSTOMER's screens actually read.
//
// WHY THIS SUITE EXISTS AND ROUTE-COUPON.TEST.JS DOES NOT COVER IT. That suite
// boots ONE relay, redeems on it and reads the entitlements back off the same
// process. Production has five. deploy/nginx-paramant-public.conf sends public
// /v2/ to relay-main, so POST /v2/billing/redeem is granted there; every screen
// the customer then looks at is served by admin/server.js, which reads
// relay-HEALTH (/api/user/billing/status reads its /v2/admin/keys,
// /api/user/dashboard/overview its /v2/admin/entitlements, and the ParaSign
// signing routes go to SECTORS.health). Accounts live in users.json, per
// container. So a suite with one relay cannot see the only thing that was
// wrong: the term landed on relay-main and every screen asked relay-health.
//
// What the customer got was a confirmation saying "ParaSign Pro until 4
// December" over a homepage that went on saying "2 of 2 signatures left this
// month" and "Community, free for good", and a signature gate that really did
// still stop him at two.
//
// So this suite boots TWO relays against ONE redis, with a users.json each, and
// asks the SECOND one every question a screen asks:
//   the plan line   -> GET /v2/admin/keys?reveal=1 (admin's productPlanFields)
//   the big figure  -> GET /v2/admin/entitlements/<account> (quota.caps.signs)
//   the gate        -> quota.signGateDecision on that same entitlement, which
//                      is the function POST /v2/envelopes/:id/sign calls
// and then restarts it, because a grant that only lives in memory is a grant
// the next deploy throws away.
//
// Needs: a reachable redis. Nothing else, no network, no Mollie.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-coupon-fleet.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const couponLib = require('../lib/coupon');
const sharedGrants = require('../lib/shared-grants');
const entitlements = require('../lib/entitlements');
const quota = require('../lib/quota');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const ADMIN = 'admin-token-for-the-fleet-suite';
const INTERNAL = 'internal-token-for-the-fleet-suite';
const ADMIN_H = { 'X-Admin-Token': ADMIN };
const BOTH = { 'X-Admin-Token': ADMIN, 'X-Internal-Auth': INTERNAL };

const RUN = crypto.randomBytes(3).toString('hex').toUpperCase();
const CODE = `FLEET-${RUN}`;
const ACCOUNT = `acct_fleet_${RUN.toLowerCase()}`;
const KEY = `pgp_fleet_${RUN.toLowerCase()}`;

// The community ParaSign quota, and the number in the sentence the customer was
// reading: "2 of 2 signatures left this month".
const COMMUNITY_SIGNS = 2;
const PRO_SIGNS = 100;

let rc = null;
let main = null;    // where nginx sends public /v2/: the relay that GRANTS
let health = null;  // what the admin plane reads: the relay every SCREEN sees
let checks = 0;
const did = () => { checks++; };

// A second account, for the day this ships. It already holds a term on the
// relay that granted it and holds nothing on the others, which is the state
// every customer who redeemed a code BEFORE this change is in.
const OLD_ACCOUNT = `acct_prior_${RUN.toLowerCase()}`;
const OLD_KEY = `pgp_prior_${RUN.toLowerCase()}`;
const OLD_TERM = new Date(Date.now() + 60 * 86_400_000).toISOString();

const users = ({ priorTerm = false } = {}) => ({
  api_keys: [
    {
      key: KEY, plan: 'community', active: true,
      account_id: ACCOUNT, email: 'demo@example.com',
    },
    Object.assign({
      key: OLD_KEY, plan: 'community', active: true,
      account_id: OLD_ACCOUNT, email: 'prior@example.com',
    }, priorTerm ? { plan_parasign: 'pro', paid_until_parasign: OLD_TERM } : {}),
  ],
});

async function clearState() {
  if (!rc) return;
  for (const k of [
    couponLib.K.doc(CODE), couponLib.K.redeemed(CODE),
    sharedGrants.grantKey(ACCOUNT), sharedGrants.grantKey(OLD_ACCOUNT),
    `paramant:quota:signs:${ACCOUNT}:${quota.ymKey()}`,
  ]) { try { await rc.del(k); } catch (_) { /* best effort */ } }
  try { await rc.sRem(couponLib.K.all, CODE); } catch (_) { /* best effort */ }
  try { await rc.sRem(sharedGrants.ACCOUNT_SET, [ACCOUNT, OLD_ACCOUNT]); } catch (_) { /* best effort */ }
  for (const account of [ACCOUNT, OLD_ACCOUNT]) {
    for (const product of entitlements.PRODUCTS) {
      try { await rc.zRem('paramant:billing:expiry', `${account}|${product}`); } catch (_) { /* best effort */ }
      try { await rc.hDel('paramant:billing:expiry_meta', `${account}|${product}`); } catch (_) { /* best effort */ }
    }
  }
}

const relayEnv = {
  ADMIN_TOKEN: ADMIN,
  INTERNAL_AUTH_TOKEN: INTERNAL,
  REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS,
};

before(async () => {
  rc = await requireRedis(DEFAULT_REDIS);
  await clearState();
  main = await boot({ tag: 'fleet-main', usersFile: true, users: users({ priorTerm: true }), env: relayEnv });
  health = await boot({ tag: 'fleet-health', usersFile: true, users: users(), env: relayEnv });
});

after(async () => {
  await clearState();
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-coupon-fleet', checks);
});

// The grant travels over a redis channel, so it is there in milliseconds rather
// than instantly. Waiting for the answer beats sleeping a fixed amount and
// hoping, and a suite that polls for two seconds still fails in two seconds
// when the mechanism is broken.
async function waitFor(fn, what, ms = 5000) {
  const deadline = Date.now() + ms;
  let last = null;
  for (;;) {
    last = await fn();
    if (last) return last;
    if (Date.now() > deadline) {
      assert.fail(`${what} did not happen within ${ms}ms`);
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}

// Exactly the projection admin/server.js productPlanFields() takes off
// GET /v2/admin/keys and sends to the homepage and the account page as
// /api/user/billing/status. Both screens read plan_parasign and
// paid_until_parasign off this and off nothing else.
async function billingStatusFieldsFrom(srv) {
  const r = await srv.get('/v2/admin/keys?reveal=1', { headers: BOTH });
  if (r.status !== 200) return null;
  const row = (r.json.keys || []).find((k) => k.key === KEY);
  if (!row) return null;
  return {
    current_plan: row.plan || 'community',
    plan_parasign: row.plan_parasign ?? null,
    plan_parasend: row.plan_parasend ?? null,
    paid_until_parasign: row.paid_until_parasign ?? null,
    paid_until_parasend: row.paid_until_parasend ?? null,
  };
}

// What admin/server.js readAccountEntitlements() reads, and the only place a
// limit shown to a customer is allowed to come from. quota.caps.signs on
// /api/user/dashboard/overview is this number.
async function entitlementsFrom(srv, account = ACCOUNT) {
  const r = await srv.get(`/v2/admin/entitlements/${account}`, { headers: BOTH });
  return r.status === 200 && r.json && r.json.ok ? r.json.entitlements : null;
}

// ── 1. before the code is redeemed, both relays say Community ────────────────

test('both relays start the account on Community, which is the sentence the customer was stuck on', async (t) => {
  if (!rc) return t.skip('no redis');
  for (const [name, srv] of [['main', main], ['health', health]]) {
    const ent = await entitlementsFrom(srv);
    assert.strictEqual(ent.parasign.tier, 'free', `${name} should start on the ParaSign floor tier`);
    assert.strictEqual(ent.parasign.quotas.signs_month, COMMUNITY_SIGNS,
      `${name} should start on the 2-signature community quota`);
    assert.strictEqual(ent.parasend.tier, 'community');
  }
  did();
});

// ── 2. the grant crosses the container boundary ──────────────────────────────

test('a code redeemed on the relay nginx serves is a term on the relay every screen reads', async (t) => {
  if (!rc) return t.skip('no redis');

  // The admin screen mints the code. Same shape as the campaign code: both
  // products, one term.
  const made = await main.post('/v2/admin/coupons', {
    headers: ADMIN_H,
    body: { code: CODE, max_redemptions: 5, note: 'fleet suite' },
  });
  assert.strictEqual(made.status, 201, made.text);
  assert.strictEqual(made.json.coupon.describes, '3 months of ParaSign Pro and ParaSend Pro');

  // The customer types it into the box on /account or /pricing. That form posts
  // to /v2/billing/redeem, which nginx sends to relay-main and nowhere else.
  const red = await main.post('/v2/billing/redeem', {
    headers: { 'X-Api-Key': KEY },
    body: { code: CODE },
  });
  assert.strictEqual(red.status, 200, red.text);
  assert.strictEqual(red.json.granted.length, 2, 'the code grants both products');
  assert.match(red.json.message, /Nothing was charged/,
    'the confirmation the customer read, and the reason he expected the screens to move');

  // THE PLAN LINE. "Community, free for good" came from these fields being
  // empty on relay-health. planLine() in frontend/js/home-auth.js reads
  // paid_until_parasign first and only falls back to current_plan when there is
  // no term, so an absent date is not a cosmetic difference: it is the whole
  // sentence.
  // Both halves, because the redeem route calls setProductPlan once per product
  // and each call publishes its own row: a page that arrives between the two
  // sees half a gift, and only for as long as the second message is in flight.
  const fields = await waitFor(
    async () => {
      const f = await billingStatusFieldsFrom(health);
      return f && f.plan_parasign === 'pro' && f.plan_parasend === 'pro'
        && f.paid_until_parasign && f.paid_until_parasend ? f : null;
    },
    'the term reached the relay /api/user/billing/status reads');
  assert.strictEqual(fields.plan_parasign, 'pro');
  assert.strictEqual(fields.plan_parasend, 'pro');
  assert.ok(fields.paid_until_parasign, 'the homepage plan line needs the date, not just the tier');
  assert.ok(Date.parse(fields.paid_until_parasign) > Date.now(),
    'the term must still be running, or the page reads "ended" instead of "ends"');
  assert.strictEqual(fields.paid_until_parasign, fields.paid_until_parasend,
    'one redemption is one instant, so both halves carry the same date');
  did();

  // THE BIG FIGURE. "2 of 2 signatures left this month" is quota.caps.signs on
  // /api/user/dashboard/overview, which is this number and no other.
  const ent = await entitlementsFrom(health);
  assert.strictEqual(ent.parasign.tier, 'pro', 'the screen that sizes the figure must see the paid tier');
  assert.strictEqual(ent.parasign.quotas.signs_month, PRO_SIGNS,
    'the figure must read out of 100, not out of 2');
  assert.strictEqual(ent.parasend.tier, 'pro');
  did();

  // THE GATE. The difference between an ugly screen and a customer who really
  // cannot work. quota.signGateDecision is the function POST /v2/envelopes/:id/
  // sign calls, fed here with the entitlement THIS relay resolved and with the
  // two signatures the customer has already spent this month.
  const spent = COMMUNITY_SIGNS;
  const decision = quota.signGateDecision(spent, ent.parasign);
  assert.strictEqual(decision.allowed, true,
    'with the term on file the third signature of the month must be allowed');
  assert.strictEqual(decision.limit, PRO_SIGNS);
  // And the same call on the tier the relay held before, so the assertion above
  // is proving the grant and not proving that the gate says yes to everything.
  const floorDecision = quota.signGateDecision(spent, entitlements.PARASIGN.free);
  assert.strictEqual(floorDecision.allowed, false, 'the community account is still stopped at two');
  did();
});

// ── 3. the term is on disk, not only in memory ───────────────────────────────

test('the hydrated term survives the restart the next deploy performs', async (t) => {
  if (!rc) return t.skip('no redis');

  // On disk first: users.json is the record, and a period that lives only in
  // memory hands the account an unbounded grant (or none at all) on the next
  // boot. setProductPlan queues that write, so wait for the field.
  const onDisk = await waitFor(
    async () => {
      const entry = (health.readUsersFile().api_keys || []).find((k) => k.key === KEY);
      return entry && entry.plan_parasign === 'pro' ? entry : null;
    },
    'the hydrated term reached the health relay users.json');
  assert.ok(onDisk.paid_until_parasign, 'the tier and its period travel together or not at all');
  did();

  // Then really restart it, on the same scratch dir, and ask again.
  health = await health.restart();
  const ent = await entitlementsFrom(health);
  assert.strictEqual(ent.parasign.tier, 'pro', 'a restart must not throw the term away');
  assert.strictEqual(ent.parasign.quotas.signs_month, PRO_SIGNS);
  did();
});

// ── 4. a container that was down catches up ──────────────────────────────────

test('a relay that was not running when the code was redeemed hydrates the term at boot', async (t) => {
  if (!rc) return t.skip('no redis');
  // A third sector, booted now, on the tier the account had before the code was
  // spent. It never saw the channel message: everything it knows comes from the
  // seed pass, which is the net under the message and the reason a deploy
  // during a campaign does not cost anybody his term.
  const legal = await boot({ tag: 'fleet-legal', usersFile: true, users: users(), env: relayEnv });
  const r = await waitFor(
    async () => {
      const e = await entitlementsFrom(legal);
      return e && e.parasign.tier === 'pro' ? e : null;
    },
    'a freshly booted relay hydrated the term from the shared record', 10000);
  assert.strictEqual(r.parasign.quotas.signs_month, PRO_SIGNS);
  await legal.stop();
  did();
});

// ── 5. the mechanism may never take a tier away ──────────────────────────────

test('hydration never downgrades: a better local term outranks the shared row', async (t) => {
  if (!rc) return t.skip('no redis');
  // The shared row says pro. Write a BUSINESS term straight onto a relay's own
  // table through the admin route (mutatePlanFleet's endpoint) and check the
  // seed pass, which runs every minute, does not pull it back down to pro. A
  // background mechanism that can downgrade is one that will, on the day redis
  // is a version behind.
  const up = await main.post('/v2/admin/keys/set-product-plan', {
    headers: BOTH,
    body: { key: KEY, product: 'parasign', tier: 'business' },
  });
  assert.strictEqual(up.status, 200, up.text);
  const before = await entitlementsFrom(main);
  assert.strictEqual(before.parasign.tier, 'business');

  const grant = await sharedGrants.read(rc, ACCOUNT);
  assert.ok(grant, 'the shared row exists');
  const target = {
    plan_parasign: 'business', paid_until_parasign: null,
    plan_parasend: 'pro', paid_until_parasend: grant.paid_until_parasend,
  };
  const moved = sharedGrants.applyTo(target, grant);
  assert.ok(!moved.includes('parasign'), `a pro row may not move a business account, moved ${moved}`);
  assert.strictEqual(target.plan_parasign, 'business');
  assert.strictEqual(target.paid_until_parasign, null,
    'an unbounded term is the more generous one and keeps its absent date');
  did();
});

// ── 6. the names the screens print ───────────────────────────────────────────

test('every screen that prints a plan name knows the tier a gift code grants', async (t) => {
  // The other half of the same failure, and the one that would look identical
  // to the customer: a tier the relay grants correctly and a script that has no
  // word for it falls back to Community. The three copies of that map are in
  // three files (the comment in home-auth.js says so), so they can drift.
  const tier = couponLib.DEFAULT_GRANTS[0].tier;
  assert.strictEqual(tier, 'pro', 'the campaign code grants the pro tier');
  const root = path.join(__dirname, '..', '..', 'frontend', 'js');
  for (const file of ['home-auth.js', 'account.inline1.js', 'dashboard.js']) {
    const src = fs.readFileSync(path.join(root, file), 'utf8');
    assert.match(src, new RegExp(`\\b${tier}\\s*:\\s*'[A-Z]`),
      `${file} must map the '${tier}' tier to the name it is sold under, or the screen prints Community`);
  }
  did();
});

// ── 7. the terms that were already granted when this shipped ─────────────────

test('a term granted before any of this existed reaches the other relays without a second redemption', async (t) => {
  if (!rc) return t.skip('no redis');
  // The state every account that redeemed a code before this shipped is in: a
  // code spent on relay-main, the term written there and nowhere else, and no
  // shared row at all because there was no such thing yet. Nothing may be asked
  // of that customer. He has already spent one of the hundred seats, and
  // spending a second one to make the first one visible is not a fix.
  const ent = await waitFor(
    async () => {
      const e = await entitlementsFrom(health, OLD_ACCOUNT);
      return e && e.parasign.tier === 'pro' ? e : null;
    },
    'the term already on relay-main reached relay-health by itself', 10000);
  assert.strictEqual(ent.parasign.quotas.signs_month, PRO_SIGNS);
  const row = (await health.get('/v2/admin/keys?reveal=1', { headers: BOTH })).json.keys
    .find((k) => k.key === OLD_KEY);
  assert.strictEqual(row.paid_until_parasign, OLD_TERM,
    'the period travels with the tier, so the plan line names the right day');
  did();
});
