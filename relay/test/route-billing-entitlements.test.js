'use strict';
// What a paying account is entitled to, read out of a really booted relay, and
// what survives a restart of it.
//
// WHY THIS SUITE EXISTS. Two bugs live in this corner and both were about a
// restart, not about arithmetic:
//   #315, the paid period was set in memory but never reached users.json, so
//          the relay came back up and handed every paying account an UNBOUNDED
//          grant. The fix (relay.js:1706-1722) passes paidUntil into the disk
//          write; nothing tested that the value is still there afterwards.
//   entitlements.js:137, a record with no paid_until must NEVER read as
//          expired, or one missing field silently downgrades a paying customer.
// lib/entitlements.js has its own unit tests for the date arithmetic. What had
// no test at all is the layer above it: relay.js reading users.json at boot,
// writing it back on an admin change, and reading the same answer out again
// after a restart. That round trip is what #315 actually broke.
//
// So every test here does the same thing: put a record on disk, ask the relay
// what the account is entitled to, restart the relay, and ask again. If the two
// answers differ, the persistence is broken no matter what the unit tests say.
//
// No redis, no Mollie, no network. Note the gap this suite cannot close: the
// only code path that WRITES paid_until is the Mollie webhook, and lib/mollie.js
// hard-codes api.mollie.com (mollie.js:12) with no override, so the write half
// cannot be driven offline. This suite therefore pins the read-back and the
// admin write; the webhook's own call is covered by lib/billing's unit tests.
// Run: node --test relay/test/route-billing-entitlements.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const ADMIN = 'admin-token-for-the-billing-suite';
const INTERNAL = 'internal-token-for-the-billing-suite';
const ADMIN_ENV = { ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: INTERNAL };
const BOTH = { 'X-Admin-Token': ADMIN, 'X-Internal-Auth': INTERNAL };

const FUTURE = new Date(Date.now() + 20 * 86_400_000).toISOString();
const PAST = new Date(Date.now() - 20 * 86_400_000).toISOString();

let checks = 0;
const did = () => { checks++; };
after(async () => { await killAll(); summary('route-billing-entitlements', checks); });

// One relay per test, on its own users.json, so a restart in one test cannot
// leak state into another.
function withUsers(tag, keys) {
  return boot({ tag, usersFile: true, users: { api_keys: keys }, env: ADMIN_ENV });
}
const entitlementsOf = (srv, account) =>
  srv.get(`/v2/admin/entitlements/${account}`, { headers: BOTH });

// ── 1. the #315 shape: a paid period must survive the process ────────────────

test('#315: a paid period on disk is still bounded after a restart', async () => {
  let srv = await withUsers('paid-until-survives', [{
    key: 'pgp_paid', plan: 'community', active: true, parasign: true,
    account_id: 'acct_paid', email: 'paid@example.test',
    plan_parasign: 'business', paid_until_parasign: FUTURE,
  }]);

  const before = await entitlementsOf(srv, 'acct_paid');
  assert.strictEqual(before.status, 200, before.text);
  assert.strictEqual(before.json.entitlements.parasign.tier, 'business',
    'a period that has not passed still grants the tier it was paid for');

  srv = await srv.restart();
  const after = await entitlementsOf(srv, 'acct_paid');
  assert.strictEqual(after.status, 200, after.text);
  assert.deepStrictEqual(after.json.entitlements, before.json.entitlements,
    'a restart must not change what an account is entitled to');
  // And the bound itself is still on disk, not only the tier. This is the exact
  // field #315 dropped: a bare tier with no date is an unbounded grant.
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === 'pgp_paid');
  assert.strictEqual(onDisk.paid_until_parasign, FUTURE, 'the paid period must still be on disk after a restart');
  srv.stop();
  did();
});

// WAS KNOWN FAILING (PR #341, finding 1), now the rule this whole field exists
// for. The bug had two halves, both of them a DROP of paid_until_* while the
// tier travelled on:
//   keys-table.parseAccountFields() rehydrated plan_parasign off users.json but
//     not paid_until_parasign, so the in-memory key record already had a paid
//     tier and no period before any merge ran;
//   entitlements.mergeAccountRecord() copied the per-product plans off the key
//     records onto the merged account record and left the periods behind, and
//     the same drop sat in keys-table.rebuildKeyIndexes() for the accounts
//     summary.
// Either half is enough: the record reaches getEntitlements with a paid tier and
// no period, and entitlements.js:137 correctly reads "no recorded period" as
// "never expired". So an expired subscription kept granting on every
// account-level gate:
//   relay.js:5316  GET /v2/admin/entitlements/:account_id
//   relay.js:5990  the signs-quota gate on POST /v2/envelopes/:id/sign
//   relay.js:1804  the plan a newly minted psk_ key inherits
// Fixed by making tier and period travel together in all three places
// (entitlements.mergeProductGrantInto).
test('#315: a period that HAS passed stops granting, and stops granting again after a restart', async () => {
  let srv = await withUsers('paid-until-expired', [{
    key: 'pgp_lapsed', plan: 'community', active: true, parasign: true,
    account_id: 'acct_lapsed', email: 'lapsed@example.test',
    plan_parasign: 'business', paid_until_parasign: PAST,
  }]);

  const before = await entitlementsOf(srv, 'acct_lapsed');
  assert.strictEqual(before.json.entitlements.parasign.tier, 'free',
    'a lapsed period falls back to the floor tier, which is the whole point of the date');

  srv = await srv.restart();
  const after = await entitlementsOf(srv, 'acct_lapsed');
  assert.strictEqual(after.json.entitlements.parasign.tier, 'free',
    'and a restart does not resurrect the grant');
  // The stored tier is NOT erased: the grant is bounded by the date, so a
  // renewal only has to move the date.
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === 'pgp_lapsed');
  assert.strictEqual(onDisk.plan_parasign, 'business', 'expiry bounds the grant, it does not delete the record');
  srv.stop();
  did();
});

// The inverse of the finding that used to stand here: the two read paths must
// give the SAME answer about the same record. The direct read was always right;
// it was the merged one that over-granted. Stated as a property, so it holds for
// a lapsed period, a live one, and no period at all -- that last row is the edge
// entitlements.js:137 protects and it must keep granting.
test('the merged read path answers exactly like a direct read of the same record', () => {
  const ent = require('../lib/entitlements');
  const cases = [
    ['expired', { plan: 'community', parasign: true, plan_parasign: 'business', paid_until_parasign: PAST }, 'free'],
    ['live',    { plan: 'community', parasign: true, plan_parasign: 'business', paid_until_parasign: FUTURE }, 'business'],
    ['bare',    { plan: 'community', parasign: true, plan_parasign: 'business' }, 'business'],
  ];
  for (const [tag, keyRec, expect] of cases) {
    assert.strictEqual(ent.getEntitlements(keyRec).parasign.tier, expect,
      `${tag}: precondition, the direct read is the answer we trust`);
    const merged = ent.mergeAccountRecord({ account_id: 'acct', plan: 'community' }, [keyRec]);
    assert.strictEqual(merged.paid_until_parasign, keyRec.paid_until_parasign,
      `${tag}: the merge carries the period with the tier (or carries neither)`);
    assert.strictEqual(ent.getEntitlements(merged).parasign.tier, expect,
      `${tag}: and the account-level path lands on the same tier`);
  }
  // A lapsed grant must not outrank a live lower one, or fixing the drop would
  // introduce a downgrade: the account really does still hold ParaSign Pro.
  const lapsedPlusLive = ent.mergeAccountRecord({ account_id: 'acct', plan: 'community' }, [
    { plan_parasign: 'business', paid_until_parasign: PAST },
    { plan_parasign: 'pro', parasign: true },
  ]);
  assert.strictEqual(ent.getEntitlements(lapsedPlusLive).parasign.tier, 'pro',
    'an expired business grant falls away, the live pro grant on the sibling key stays');
  did();
});

// The same divergence one layer lower: users.json -> in-memory record. Before
// the fix parseAccountFields returned the tier without the date, so the expiry
// could not be enforced no matter what the merge did.
test('a key loaded from users.json keeps the paid period it was stored with', () => {
  const kt = require('../lib/keys-table');
  const lapsed = kt.parseAccountFields({ key: 'k', plan: 'community', parasign: true, plan_parasign: 'business', paid_until_parasign: PAST });
  assert.strictEqual(lapsed.paid_until_parasign, PAST, 'the period is rehydrated with the tier it bounds');
  const bare = kt.parseAccountFields({ key: 'k', plan: 'community', parasign: true, plan_parasign: 'business' });
  assert.ok(!('paid_until_parasign' in bare),
    'and a key with no period on file stays absent, not an explicit null that could read as expired');
  did();
});

test('a key minted while the subscription is LIVE does not outlive it', async () => {
  // The third place the period could be dropped, and the only one a customer can
  // trigger on demand: POST /v2/user/parasign-keys (relay.js:3259, self-serve
  // through the admin server) and the admin mint (relay.js:5451) both run
  // keys-table.buildParasignKeyRecord, which wrote plan_parasign onto the new
  // key and its users.json entry but never paid_until_parasign. A key minted
  // one day before the subscription ended therefore carried a paid tier with no
  // end date, and "no recorded period" means "never expires". Mint on the last
  // day, keep ParaSign Business forever, restart included.
  //
  // The period here is deliberately a few seconds out, so the test watches a
  // real subscription end instead of asserting on a stored string.
  const SOON = new Date(Date.now() + 3500).toISOString();
  let srv = await withUsers('mint-carries-period', [{
    key: 'pgp_minting', plan: 'community', active: true, parasign: true,
    account_id: 'acct_minting', email: 'mint@example.test',
    plan_parasign: 'business', paid_until_parasign: SOON,
  }]);
  const live = await entitlementsOf(srv, 'acct_minting');
  assert.strictEqual(live.json.entitlements.parasign.tier, 'business',
    'precondition: at mint time the account really is a paying Business account');

  const minted = await srv.post('/v2/user/parasign-keys', { headers: BOTH, body: { user_id: 'acct_minting' } });
  assert.strictEqual(minted.status, 201, minted.text);
  assert.match(minted.json.key, /^psk_(live|test)_[0-9a-f]{64}$/);

  // The users.json write is queued, not awaited by the handler.
  await new Promise((r) => setTimeout(r, 300));
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === minted.json.key);
  assert.ok(onDisk, 'the minted key reached users.json');
  assert.strictEqual(onDisk.plan_parasign, 'business', 'the new key inherits the paid tier');
  assert.strictEqual(onDisk.paid_until_parasign, SOON,
    'and the period that bounds it, or the tier is a permanent copy of a temporary grant');

  // Let the subscription actually end, then come back on a cold process so the
  // answer is read from disk and not from anything still in memory.
  while (Date.now() < Date.parse(SOON) + 250) await new Promise((r) => setTimeout(r, 100));
  srv = await srv.restart();
  const after = await entitlementsOf(srv, 'acct_minting');
  assert.strictEqual(after.json.entitlements.parasign.tier, 'free',
    'the minted key must not outlive the subscription that paid for it');
  srv.stop();
  did();
});

test('a key minted for an ALREADY lapsed account is a plain floor key, with no stale date', async () => {
  let srv = await withUsers('mint-after-lapse', [{
    key: 'pgp_lapsed_mint', plan: 'community', active: true, parasign: true,
    account_id: 'acct_lapsed_mint', email: 'lapsed-mint@example.test',
    plan_parasign: 'business', paid_until_parasign: PAST,
  }]);
  const minted = await srv.post('/v2/user/parasign-keys', { headers: BOTH, body: { user_id: 'acct_lapsed_mint' } });
  assert.strictEqual(minted.status, 201, minted.text);
  await new Promise((r) => setTimeout(r, 300));
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === minted.json.key);
  assert.strictEqual(onDisk.plan_parasign, 'free', 'a lapsed account mints what it is entitled to now, not what it paid for once');
  assert.ok(!('paid_until_parasign' in onDisk),
    'and carries no date, because a floor tier has no period to be bounded by');
  srv.stop();
  did();
});

test('entitlements.js:137: a record with NO paid_until is never read as expired', async () => {
  // The dangerous reading of "no date on file" is "the period ended". That would
  // downgrade every account that predates the paid_until field, and every one
  // whose webhook never wrote it. The rule is the opposite: absent means
  // unbounded, and a floor tier can never expire at all.
  let srv = await withUsers('paid-until-missing', [
    { key: 'pgp_bare', plan: 'community', active: true, parasign: true, account_id: 'acct_bare',
      email: 'bare@example.test', plan_parasign: 'pro' },                       // tier, no date
    { key: 'pgp_junk', plan: 'community', active: true, parasign: true, account_id: 'acct_junk',
      email: 'junk@example.test', plan_parasign: 'pro', paid_until_parasign: 'not-a-date' },
    { key: 'pgp_floor', plan: 'community', active: true, account_id: 'acct_floor',
      email: 'floor@example.test', plan_parasign: 'free', paid_until_parasign: PAST },
  ]);

  for (const [account, tier, why] of [
    ['acct_bare', 'pro', 'a missing date must not downgrade anyone'],
    ['acct_junk', 'pro', 'an unparseable date is treated as absent, not as expired'],
    ['acct_floor', 'free', 'a floor tier has nothing to lose and cannot expire'],
  ]) {
    const r = await entitlementsOf(srv, account);
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.entitlements.parasign.tier, tier, `${account}: ${why}`);
  }

  srv = await srv.restart();
  const again = await entitlementsOf(srv, 'acct_bare');
  assert.strictEqual(again.json.entitlements.parasign.tier, 'pro', 'and the same holds after a restart');
  srv.stop();
  did();
});

// ── 2. an admin change must reach the disk ───────────────────────────────────

test('an admin product-plan change is on disk before the relay is restarted, and holds afterwards', async () => {
  // The mechanism #315 broke: an entitlement that lives only in the process
  // memory. setProductPlan fans out over the account and queues a users.json
  // write (relay.js:1710); this asserts the write really lands.
  let srv = await withUsers('admin-write-through', [{
    key: 'pgp_upgrade', plan: 'community', active: true, account_id: 'acct_upgrade', email: 'up@example.test',
  }]);

  const start = await entitlementsOf(srv, 'acct_upgrade');
  assert.strictEqual(start.json.entitlements.parasend.tier, 'community');

  const set = await srv.post('/v2/admin/keys/set-product-plan', {
    headers: BOTH, body: { key: 'pgp_upgrade', product: 'parasend', tier: 'pro' },
  });
  assert.strictEqual(set.status, 200, set.text);
  assert.deepStrictEqual(set.json, { ok: true, key: 'pgp_upgrade', product: 'parasend', tier: 'pro' });

  // The write is queued, not awaited by the handler, so give the queue a tick.
  await new Promise((r) => setTimeout(r, 300));
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === 'pgp_upgrade');
  assert.strictEqual(onDisk.plan_parasend, 'pro', 'the change never reached users.json');
  assert.strictEqual(onDisk.plan, 'community', 'a per-product change must not touch the unified plan');

  srv = await srv.restart();
  const after = await entitlementsOf(srv, 'acct_upgrade');
  assert.strictEqual(after.json.entitlements.parasend.tier, 'pro', 'the upgrade did not survive the restart');
  assert.strictEqual(after.json.entitlements.parasign.tier, 'free', 'and it did not leak into the other product');
  srv.stop();
  did();
});

test('an admin change on one product leaves the other product\'s paid period alone', async () => {
  // applyProductTier is tri-state on paidUntil: undefined means "leave what is
  // on record" (entitlements.js:193-195), and the admin route passes no date.
  // So an admin touching ParaSend must not silently unbound a paid ParaSign.
  let srv = await withUsers('cross-product', [{
    key: 'pgp_mixed', plan: 'community', active: true, parasign: true, account_id: 'acct_mixed',
    email: 'mixed@example.test', plan_parasign: 'business', paid_until_parasign: FUTURE,
  }]);

  const set = await srv.post('/v2/admin/keys/set-product-plan', {
    headers: BOTH, body: { key: 'pgp_mixed', product: 'parasend', tier: 'pro' },
  });
  assert.strictEqual(set.status, 200, set.text);
  await new Promise((r) => setTimeout(r, 300));

  srv = await srv.restart();
  const after = await entitlementsOf(srv, 'acct_mixed');
  assert.strictEqual(after.json.entitlements.parasend.tier, 'pro');
  assert.strictEqual(after.json.entitlements.parasign.tier, 'business');
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === 'pgp_mixed');
  assert.strictEqual(onDisk.paid_until_parasign, FUTURE,
    'the other product\'s paid period must be exactly as it was');
  srv.stop();
  did();
});

test('an admin change is refused for an unknown product or a tier off that product\'s ladder', async () => {
  // Never silently floor a bad tier to the base one: that is how a typo becomes
  // a downgrade nobody notices.
  const srv = await withUsers('bad-product-plan', [{
    key: 'pgp_v', plan: 'pro', active: true, account_id: 'acct_v', email: 'v@example.test',
  }]);
  const cases = [
    [{ key: 'pgp_v', product: 'parasound', tier: 'pro' }, 400],
    [{ key: 'pgp_v', product: 'parasend', tier: 'business' }, 400],  // business is not on the parasend ladder
    [{ key: 'pgp_v', product: 'parasign', tier: 'gold' }, 400],
    [{ key: 'pgp_missing', product: 'parasign', tier: 'pro' }, 404],
  ];
  for (const [body, status] of cases) {
    const r = await srv.post('/v2/admin/keys/set-product-plan', { headers: BOTH, body });
    assert.strictEqual(r.status, status, `${JSON.stringify(body)} -> ${r.status} ${r.text}`);
  }
  // Nothing changed on disk after four refusals.
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === 'pgp_v');
  assert.ok(!onDisk.plan_parasend || onDisk.plan_parasend === 'pro');
  srv.stop();
  did();
});

// ── 3. plan id -> tier -> quota, as the relay itself reports it ──────────────

test('the four plan ids map to the tiers and quotas the pricing rests on', async () => {
  // One table, asserted through the relay rather than against lib/tiers.js, so a
  // change to the mapping in relay.js or entitlements.js shows up here too.
  // parasend has no business tier: a business plan maps UP to enterprise, on
  // purpose (entitlements.js:205, no silent downgrade).
  const srv = await withUsers('tier-map', [
    { key: 'pgp_t_community', plan: 'community', active: true, account_id: 'acct_community', email: 'c@example.test' },
    { key: 'pgp_t_pro', plan: 'pro', active: true, account_id: 'acct_pro', email: 'p@example.test' },
    { key: 'pgp_t_business', plan: 'business', active: true, account_id: 'acct_business', email: 'b@example.test' },
    { key: 'pgp_t_enterprise', plan: 'enterprise', active: true, account_id: 'acct_enterprise', email: 'e@example.test' },
  ]);

  const expected = {
    acct_community: { parasend: 'community', parasign: 'free', transfers: 10, signs: 2 },
    acct_pro: { parasend: 'pro', parasign: 'pro', transfers: 500, signs: 100 },
    // business keeps its own ParaSend row: it is a ParaSign tier name, so the
    // account never bought ParaSend, and it is neither raised to enterprise nor
    // cut to pro (entitlements.PARASEND_LADDER).
    acct_business: { parasend: 'business', parasign: 'business', transfers: 2000, signs: 1000 },
    acct_enterprise: { parasend: 'enterprise', parasign: 'enterprise', transfers: 1_000_000, signs: 1_000_000 },
  };
  for (const [account, want] of Object.entries(expected)) {
    const r = await entitlementsOf(srv, account);
    assert.strictEqual(r.status, 200, r.text);
    const e = r.json.entitlements;
    assert.strictEqual(e.parasend.tier, want.parasend, `${account} parasend tier`);
    assert.strictEqual(e.parasign.tier, want.parasign, `${account} parasign tier`);
    assert.strictEqual(e.parasend.quotas.transfers_month, want.transfers, `${account} transfers/month`);
    assert.strictEqual(e.parasign.quotas.signs_month, want.signs, `${account} signs/month`);
    // A metered quota is never Infinity: an unlimited tier still has a ceiling
    // that a counter can be compared against (entitlements.js:41).
    assert.ok(Number.isFinite(e.parasend.quotas.transfers_month), `${account} transfers quota must be finite`);
    assert.ok(Number.isFinite(e.parasign.quotas.signs_month), `${account} signs quota must be finite`);
  }
  srv.stop();
  did();
});

test('no tier meters past its quota, and only Business+ may export the audit trail', async () => {
  const srv = await withUsers('perks', [
    { key: 'pgp_o_pro', plan: 'pro', active: true, parasign: true, account_id: 'acct_o_pro', email: 'op@example.test' },
    { key: 'pgp_o_bus', plan: 'business', active: true, parasign: true, account_id: 'acct_o_bus', email: 'ob@example.test' },
    { key: 'pgp_o_com', plan: 'community', active: true, account_id: 'acct_o_com', email: 'oc@example.test' },
  ]);
  // Pro was the metering tier: EUR 0.40 a signature past 100, up to 1000. It is
  // served to the frontend from here, so the entitlement a client reads may not
  // carry a rate that nothing in billing collects.
  const pro = (await entitlementsOf(srv, 'acct_o_pro')).json.entitlements.parasign;
  assert.strictEqual(pro.overage, undefined, 'ParaSign Pro no longer meters');
  assert.strictEqual(pro.quotas.signs_month, 100, 'and 100 is what it includes and where it stops');

  const bus = (await entitlementsOf(srv, 'acct_o_bus')).json.entitlements.parasign;
  assert.strictEqual(bus.overage, undefined, 'Business buys its volume up front');
  assert.strictEqual(bus.features.audit_export, true);
  assert.strictEqual(pro.features.audit_export, false, 'audit export is a Business+ feature');

  const com = (await entitlementsOf(srv, 'acct_o_com')).json.entitlements.parasign;
  assert.strictEqual(com.overage, undefined);
  assert.strictEqual(com.features.audit_export, false);
  srv.stop();
  did();
});

test('the admin usage view reports the same per-tier limits it enforces', async () => {
  // /v2/admin/usage is what an operator looks at when a customer says "it says
  // I am over my limit". It must not have a second opinion about the tier.
  const srv = await withUsers('usage-view', [
    { key: 'pgp_u_pro', plan: 'pro', active: true, account_id: 'acct_u_pro', email: 'u@example.test' },
  ]);
  const r = await srv.get('/v2/admin/usage/acct_u_pro', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.plan, 'pro');
  assert.strictEqual(r.json.limits.transfers_month, 500);
  assert.strictEqual(r.json.limits.signs_month, 100);
  assert.strictEqual(r.json.limits.devices, 50);
  assert.strictEqual(r.json.redis_available, false, 'this relay runs without redis, and the view says so');
  srv.stop();
  did();
});

test('the usage view reports the tier that is ENFORCED, not the plan billing left behind', async () => {
  // The Mollie webhook upgrades through setProductPlan -> applyProductTier,
  // which writes plan_parasend and deliberately never the unified `plan`. This
  // view read `plan`, so it would tell an operator "community, 10 transfers,
  // 5 devices" about an account the relay is holding to the Pro 500 and 50 -
  // and, before the read paths moved onto the product axis, the relay really
  // was holding that paying account to the community numbers.
  const srv = await withUsers('usage-axis', [
    // The shape the webhook writes: paid on ParaSend, unified plan untouched.
    { key: 'pgp_v_hook', plan: 'community', plan_parasend: 'pro', active: true, account_id: 'acct_v_hook', email: 'vh@example.test' },
    // The shape POST /v2/admin/keys/update-plan writes: unified plan set, both
    // product plans derived from it.
    { key: 'pgp_v_admin', plan: 'pro', plan_parasend: 'pro', plan_parasign: 'pro', active: true, account_id: 'acct_v_admin', email: 'va@example.test' },
    // No plan at all, the shape every key minted before the field has.
    { key: 'pgp_v_none', active: true, account_id: 'acct_v_none', email: 'vn@example.test' },
  ]);

  const hook = await srv.get('/v2/admin/usage/acct_v_hook', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(hook.status, 200, hook.text);
  assert.strictEqual(hook.json.plan, 'community', 'the unified plan is what billing left behind');
  assert.strictEqual(hook.json.parasend_tier, 'pro', 'and the ParaSend tier is the one that was paid for');
  assert.strictEqual(hook.json.limits.transfers_month, 500, 'the operator reads the limit the gate enforces');
  assert.strictEqual(hook.json.limits.devices, 50);

  // Both shapes mean ParaSend Pro, so no ParaSend dimension may disagree. They
  // differ on ParaSign on purpose: update-plan derives plan_parasign from the
  // unified plan, a ParaSend purchase does not.
  const admin = await srv.get('/v2/admin/usage/acct_v_admin', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(admin.json.parasend_tier, hook.json.parasend_tier);
  for (const dim of ['transfers_month', 'file_mb', 'devices']) {
    assert.strictEqual(admin.json.limits[dim], hook.json.limits[dim],
      `the admin shape and the webhook shape must buy the same ${dim}`);
  }

  const none = await srv.get('/v2/admin/usage/acct_v_none', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(none.json.parasend_tier, 'community', 'a missing plan is not evidence of a paid one');
  assert.strictEqual(none.json.limits.transfers_month, 10);
  assert.strictEqual(none.json.limits.devices, 5);
  srv.stop();
  did();
});

test('the usage view reports the file ceiling the upload gate really applies', async () => {
  // POST /v2/inbound takes the LOWER of the operator's MAX_BLOB and the tier's
  // file_mb, so an uncapped tier row is still held to MAX_BLOB. Reporting the
  // bare tier value put -1 on an enterprise account while the gate was
  // enforcing 5 MB, and file_mb is the one number an operator would act on.
  const srv = await withUsers('usage-file-mb', [
    { key: 'pgp_f_ent', plan: 'enterprise', active: true, account_id: 'acct_f_ent', email: 'fe@example.test' },
    { key: 'pgp_f_com', plan: 'community', active: true, account_id: 'acct_f_com', email: 'fc@example.test' },
  ]);
  const ent = await srv.get('/v2/admin/usage/acct_f_ent', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(ent.status, 200, ent.text);
  assert.strictEqual(ent.json.parasend_tier, 'enterprise');
  assert.strictEqual(ent.json.limits.file_mb, 5,
    'the enterprise row says uncapped, the relay enforces MAX_BLOB, and the view must say what is enforced');
  assert.notStrictEqual(ent.json.limits.file_mb, -1, 'never report uncapped for a ceiling that is capped');
  // devices really is uncapped on enterprise, and that still reports as -1, so
  // the fix is about the file ceiling and not about flattening every -1.
  assert.strictEqual(ent.json.limits.devices, -1);

  const com = await srv.get('/v2/admin/usage/acct_f_com', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(com.json.limits.file_mb, 5, 'a capped tier reads its own value, unchanged');

  // The list view is the same view over every account and must not disagree.
  const list = await srv.get('/v2/admin/usage', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(list.status, 200, list.text);
  for (const row of list.json.accounts) {
    assert.strictEqual(row.limits.file_mb, 5, `${row.account_id} in the list view`);
  }
  srv.stop();
  did();
});

// ── 4. the file itself ───────────────────────────────────────────────────────

test('the users.json write is atomic: no temp file is left behind and the file always parses', async () => {
  // _atomicWriteUsers writes a tmp file and renames it (relay.js:1629-1632),
  // because an O_TRUNC window once let a concurrent reader see an empty file and
  // wipe the key table. Two changes in a row, then check the directory.
  const srv = await withUsers('atomic-write', [
    { key: 'pgp_a1', plan: 'community', active: true, account_id: 'acct_a1', email: 'a1@example.test' },
  ]);
  for (const tier of ['pro', 'community', 'pro']) {
    const r = await srv.post('/v2/admin/keys/set-product-plan', {
      headers: BOTH, body: { key: 'pgp_a1', product: 'parasend', tier },
    });
    assert.strictEqual(r.status, 200, r.text);
  }
  await new Promise((r) => setTimeout(r, 400));
  const leftovers = fs.readdirSync(srv.dir).filter((f) => f.includes('users.json.tmp'));
  assert.deepStrictEqual(leftovers, [], `temp files were left behind: ${leftovers.join(', ')}`);
  const parsed = srv.readUsersFile();
  assert.ok(Array.isArray(parsed.api_keys) && parsed.api_keys.length === 1);
  assert.strictEqual(parsed.api_keys[0].plan_parasend, 'pro', 'the last write wins and the queue kept the order');
  srv.stop();
  did();
});

// ── the period has to LEAVE the relay, not just live on the record ───────────
// Every account surface in admin/ is built on one relay read: findUserByEmail,
// findUserById and /api/user/billing/status all call GET /v2/admin/keys and
// project the row through productPlanFields(), which reads paid_until_*. That
// projection emitted plan_parasign and plan_parasend and dropped the two dates,
// so admin/ always saw null. Both readers treat a missing period as "no period
// recorded", which is the same rule the server uses and means "never expires"
// (entitlements.effectiveProductTier, mirrored client-side in
// frontend/js/dashboard.js paidProductTier). The result was a straight
// contradiction: the relay's own gates floored a lapsed account to free and
// answered 402 at two signatures, while the dashboard and the account page kept
// rendering "Pro plan, active" off the same relay. The tier without its period
// is not a smaller answer, it is a wrong one.
test('the admin key projection carries the paid period, not just the tier', async () => {
  const srv = await withUsers('paid-until-projected', [{
    key: 'pgp_live', plan: 'community', active: true, parasign: true,
    account_id: 'acct_live', email: 'live@example.test',
    plan_parasign: 'pro', paid_until_parasign: FUTURE,
  }, {
    key: 'pgp_lapsed2', plan: 'community', active: true, parasign: true,
    account_id: 'acct_lapsed2', email: 'lapsed2@example.test',
    plan_parasign: 'pro', paid_until_parasign: PAST,
  }]);

  for (const url of ['/v2/admin/keys', '/v2/admin/keys?reveal=1']) {
    const r = await srv.get(url, { headers: BOTH });
    assert.strictEqual(r.status, 200, r.text);
    const live = r.json.keys.find((k) => k.account_id === 'acct_live');
    const lapsed = r.json.keys.find((k) => k.account_id === 'acct_lapsed2');
    assert.strictEqual(live.plan_parasign, 'pro', url);
    assert.strictEqual(live.paid_until_parasign, FUTURE,
      `${url} must carry the period the tier was paid for`);
    assert.strictEqual(lapsed.paid_until_parasign, PAST,
      `${url} must carry a lapsed period too, or the reader calls it unbounded`);
    // An account that never bought anything reports no period, which is the
    // honest answer and the one every reader is built for. It must be present
    // as an explicit null rather than simply absent.
    assert.strictEqual(live.paid_until_parasend, null,
      'no ParaSend purchase means no ParaSend period, stated explicitly');
    assert.ok('paid_until_parasend' in live, `${url} must always state the field`);
  }

  // The point of the projection: what admin/ reads must agree with what the
  // relay's own gates decided, for the lapsed account as well as the live one.
  const gate = await entitlementsOf(srv, 'acct_lapsed2');
  assert.strictEqual(gate.json.entitlements.parasign.tier, 'free',
    'the gate floors the lapsed account, so the projection must let a reader reach the same answer');

  const single = await srv.get('/v2/admin/keys/reveal/acct_live', { headers: BOTH });
  assert.strictEqual(single.status, 200, single.text);
  assert.strictEqual(single.json.paid_until_parasign, FUTURE,
    'the single-key reveal is the same row and must say the same thing');

  srv.stop();
  did();
});
