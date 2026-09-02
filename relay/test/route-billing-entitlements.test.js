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

// KNOWN FAILING, ON PURPOSE. This is the rule the paid_until field exists for,
// and the account-level read path does not honour it today. Marked todo so the
// run stays green while the finding stays visible; when the bug is fixed this
// turns into "ok ... # TODO" and the flag can go.
//
// THE BUG: lib/entitlements.js:328-344 mergeAccountRecord() copies plan_parasign
// and plan_parasend off the api-key records onto the merged account record, but
// NOT their paid_until_* fields. Its own doc comment says why those fields can
// only live on the key records ("the accounts summary never carries the
// per-product plans"), so the merged record always arrives at getEntitlements
// with a paid tier and no period, and entitlements.js:137 correctly reads "no
// recorded period" as "never expired". The result is that an expired
// subscription keeps granting on every account-level gate:
//   relay.js:5316  GET /v2/admin/entitlements/:account_id
//   relay.js:5990  the signs-quota gate on POST /v2/envelopes/:id/sign
//   relay.js:1804  the plan a newly minted psk_ key inherits
// Reading the SAME record directly (without the merge) does expire correctly,
// which is how you can tell it is the merge and not the date logic:
//   getEntitlements(keyRec).parasign.tier                      -> 'free'
//   getEntitlements(mergeAccountRecord(acct,[keyRec])).parasign.tier -> 'business'
test('#315: a period that HAS passed stops granting, and stops granting again after a restart',
  { todo: 'mergeAccountRecord drops paid_until_* (lib/entitlements.js:328-344)' }, async () => {
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

// The same fact, stated as something that is true TODAY, so the finding above is
// not just a comment: the two read paths disagree about the same record. This
// test is the evidence for the bug report, and it is expected to be deleted in
// the same commit that fixes mergeAccountRecord.
test('FINDING: the account-level read path loses the paid period the key record carries', () => {
  const ent = require('../lib/entitlements');
  const keyRec = { plan: 'community', parasign: true, plan_parasign: 'business', paid_until_parasign: PAST };
  assert.strictEqual(ent.getEntitlements(keyRec).parasign.tier, 'free',
    'read straight off the key record, an expired period does fall to the floor');
  const merged = ent.mergeAccountRecord({ account_id: 'acct', plan: 'community' }, [keyRec]);
  assert.ok(!('paid_until_parasign' in merged),
    'the merge drops the period field entirely - this is the bug, in one line');
  assert.strictEqual(ent.getEntitlements(merged).parasign.tier, 'business',
    'so the account-level path still grants a tier that was paid for until ' + PAST);
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
    acct_business: { parasend: 'enterprise', parasign: 'business', transfers: 1_000_000, signs: 1000 },
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

test('only ParaSign Pro meters overage, and only Business+ may export the audit trail', async () => {
  const srv = await withUsers('perks', [
    { key: 'pgp_o_pro', plan: 'pro', active: true, parasign: true, account_id: 'acct_o_pro', email: 'op@example.test' },
    { key: 'pgp_o_bus', plan: 'business', active: true, parasign: true, account_id: 'acct_o_bus', email: 'ob@example.test' },
    { key: 'pgp_o_com', plan: 'community', active: true, account_id: 'acct_o_com', email: 'oc@example.test' },
  ]);
  const pro = (await entitlementsOf(srv, 'acct_o_pro')).json.entitlements.parasign;
  assert.strictEqual(pro.overage.rate_eur, 0.4, 'ParaSign Pro is the metering tier');
  assert.strictEqual(pro.overage.hard_cap, 1000);

  const bus = (await entitlementsOf(srv, 'acct_o_bus')).json.entitlements.parasign;
  assert.strictEqual(bus.overage.rate_eur, null, 'Business buys its volume up front, it does not meter');
  assert.strictEqual(bus.features.audit_export, true);
  assert.strictEqual(pro.features.audit_export, false, 'audit export is a Business+ feature');

  const com = (await entitlementsOf(srv, 'acct_o_com')).json.entitlements.parasign;
  assert.strictEqual(com.overage.rate_eur, null);
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
