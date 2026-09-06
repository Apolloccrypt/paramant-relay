'use strict';
// Product/tier entitlement separation + no-downgrade migration.
//
// Proves: (1) ParaSend and ParaSign are entitled independently; (2) a quota
// overrun on one product returns 402-shaped decline without touching the other;
// (3) the legacy->per-product migration never downgrades any existing account.

const { test, before, after } = require('node:test');
const assert = require('assert');
const ent = require('../lib/entitlements');
const tiers = require('../lib/tiers');
const quota = require('../lib/quota');
const crypto = require('crypto');
const { requireRedis, summary } = require('./_requires');

// The gates run Lua scripts since the 2026-09-05 review, finding 8: reading a
// counter, deciding and writing were three round trips with awaits between them,
// and concurrent requests all read the same number and all went through. An
// in-memory stub cannot run EVAL, and because quota fails open by design a stub
// that cannot run the script does not turn a cap test red, it turns it into a
// pass over nothing. So the tests that drive a gate use a real server, and this
// suite moved to the CI job that has one. See quota-gate.test.js for the longer
// version of this note.

// ── A real redis, and a fresh namespace per run ──────────────────────────────
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const RUN = crypto.randomBytes(6).toString('hex');
let rc = null;
let quotaChecks = 0;
const written = [];
const track = (...keys) => { written.push(...keys); };
// The monthly counters are shared and month-keyed, so a fixed account id would
// make these cases depend on each other and on yesterday's run.
const scoped = (name) => `${name}_${RUN}`;

before(async () => { rc = await requireRedis(DEFAULT_REDIS); });
after(async () => {
  if (rc) {
    for (const k of written) { try { await rc.del(k); } catch (_) {} }
    try { await rc.disconnect(); } catch (_) {}
  }
  summary('entitlements', quotaChecks);
});

// ── 1. Independent per-product entitlement ────────────────────────────────────
test('account pro on parasign + community on parasend gets SEPARATE limits', () => {
  const acct = { plan_parasign: 'pro', plan_parasend: 'community' };
  const e = ent.getEntitlements(acct);
  assert.strictEqual(e.parasign.tier, 'pro');
  assert.strictEqual(e.parasend.tier, 'community');
  assert.strictEqual(e.parasign.quotas.signs_month, 100);     // pro signs
  assert.strictEqual(e.parasend.quotas.transfers_month, 50);  // community transfers
});

test('the mirror case: parasend pro + parasign free is independent too', () => {
  const e = ent.getEntitlements({ plan_parasend: 'pro', plan_parasign: 'free' });
  assert.strictEqual(e.parasend.quotas.transfers_month, 500);
  assert.strictEqual(e.parasign.quotas.signs_month, 2);
});

test('no tier is unbounded: every metered monthly quota is finite', () => {
  for (const t of ent.PARASEND_TIERS) {
    const q = ent.getEntitlements({ plan_parasend: t }).parasend.quotas.transfers_month;
    assert.ok(Number.isFinite(q) && q > 0, `parasend ${t} transfers_month finite`);
  }
  for (const t of ent.PARASIGN_TIERS) {
    const q = ent.getEntitlements({ plan_parasign: t }).parasign.quotas.signs_month;
    assert.ok(Number.isFinite(q) && q > 0, `parasign ${t} signs_month finite`);
  }
});

// ── 2. Cross-product isolation of the quota gate ──────────────────────────────
test('overrun on parasend transfers does NOT block parasign signs (402 isolation)', async () => {
  if (!rc) return;
  const r = rc;
  const ACCT = scoped('acctZ');
  track(quota.transfersKey(ACCT), quota.signsKey(ACCT), quota.seenKey(ACCT, 'freshChunk'));
  const acct = { account_id: ACCT, plan_parasend: 'community', plan_parasign: 'pro' };
  const tLimit = ent.transfersQuota(acct); // 10
  const sLimit = ent.signsQuota(acct);     // 100

  // Drive parasend transfers to the cap.
  await r.set(quota.transfersKey(ACCT), String(tLimit));
  const tGate = await quota.gateTransfer(r, ACCT, 'freshChunk', tLimit, null);
  assert.strictEqual(tGate.allowed, false, 'transfer over cap declined'); quotaChecks++;
  assert.strictEqual(tGate.over_limit, true); quotaChecks++;

  // ParaSign signs are counted on a different Redis key and a different limit,
  // so the account can still sign.
  const sGate = await quota.gateSign(r, ACCT, sLimit, null);
  assert.strictEqual(sGate.allowed, true, 'sign unaffected by transfer overrun'); quotaChecks++;
  assert.strictEqual(sGate.counted, true); quotaChecks++;
});

test('overrun on parasign signs does NOT block parasend transfers', async () => {
  if (!rc) return;
  const r = rc;
  const ACCT = scoped('acctY');
  track(quota.transfersKey(ACCT), quota.signsKey(ACCT), quota.seenKey(ACCT, 'chunkY'));
  const acct = { account_id: ACCT, plan_parasend: 'pro', plan_parasign: 'free' };
  const sLimit = ent.signsQuota(acct); // 2 (free)
  await r.set(quota.signsKey(ACCT), String(sLimit));
  const sGate = await quota.gateSign(r, ACCT, sLimit, null);
  assert.strictEqual(sGate.allowed, false, 'sign over free cap declined'); quotaChecks++;

  track(quota.seenKey(ACCT, 'chunkA'));
  const tGate = await quota.gateTransfer(r, ACCT, 'chunkA', ent.transfersQuota(acct), null);
  assert.strictEqual(tGate.allowed, true, 'transfer unaffected by sign overrun'); quotaChecks++;
});

// ── 3. Migration never downgrades ─────────────────────────────────────────────
// Legacy effective level for a product, using the OLD single-plan tiers.js path.
function legacyTransfers(plan) { return tiers.tierLimitNum(plan, 'transfers_month'); }
function legacySigns(plan)     { return tiers.tierLimitNum(plan, 'signs_month'); }

// A migrated quota is "not a downgrade" when it is >= the legacy value, OR the
// legacy value was unbounded (Infinity) and the migrated value is the agreed
// high finite ceiling (documented, practically unreachable, honours "no
// unbounded tier").
function notDowngraded(migrated, legacy) {
  if (legacy === Infinity) return migrated === ent.ENTERPRISE_MONTHLY_CEILING;
  return migrated >= legacy;
}

test('migration preserves effective level for every legacy plan (no downgrade)', () => {
  const legacyPlans = ['community', 'free', 'dev', 'pro', 'business', 'enterprise', 'licensed'];
  for (const plan of legacyPlans) {
    for (const parasign of [false, true]) {
      const migrated = ent.migrateUserEntry({ key: 'k', plan, parasign, active: true });
      const e = ent.getEntitlements(migrated);
      assert.ok(
        notDowngraded(e.parasend.quotas.transfers_month, legacyTransfers(plan)),
        `parasend not downgraded for plan=${plan} (got ${e.parasend.quotas.transfers_month}, legacy ${legacyTransfers(plan)})`,
      );
      assert.ok(
        notDowngraded(e.parasign.quotas.signs_month, legacySigns(plan)),
        `parasign not downgraded for plan=${plan} (got ${e.parasign.quotas.signs_month}, legacy ${legacySigns(plan)})`,
      );
    }
  }
});

test('specific migration cases match the brief', () => {
  // pro + parasign flag: keeps pro on both products.
  const pro = ent.getEntitlements(ent.migrateUserEntry({ plan: 'pro', parasign: true }));
  assert.strictEqual(pro.parasend.tier, 'pro');
  assert.strictEqual(pro.parasign.tier, 'pro');
  assert.strictEqual(pro.parasend.quotas.transfers_month, 500);
  assert.strictEqual(pro.parasign.quotas.signs_month, 100);

  // community stays community / free -> exact same effective as today (10 / 2).
  const comm = ent.getEntitlements(ent.migrateUserEntry({ plan: 'community' }));
  assert.strictEqual(comm.parasend.tier, 'community');
  assert.strictEqual(comm.parasign.tier, 'free');
  assert.strictEqual(comm.parasend.quotas.transfers_month, 50);
  assert.strictEqual(comm.parasign.quotas.signs_month, 2);

  // business: parasign stays business (1000); parasend keeps its OWN row.
  //
  // `business` is a ParaSign tier name, so an account whose unified plan says
  // business never bought ParaSend. It used to map UP to enterprise on a
  // no-downgrade reading, which handed that account the whole enterprise row:
  // uncapped devices, uncapped downloads per hour, 100 views per link, a 365
  // day device-pubkey TTL and the 10000-receipt retention. Mapping it DOWN to
  // pro would have been the opposite error, cutting 2000 transfers to 500 and
  // a 7 day link to 24 hours. It resolves to its own tiers.js row instead, so
  // it is neither raised nor cut, and it stays ungrantable by an admin.
  const biz = ent.getEntitlements(ent.migrateUserEntry({ plan: 'business' }));
  assert.strictEqual(biz.parasign.tier, 'business');
  assert.strictEqual(biz.parasign.quotas.signs_month, 1000);
  assert.strictEqual(biz.parasend.tier, 'business');
  assert.notStrictEqual(biz.parasend.tier, 'enterprise',
    'a ParaSign Business plan must never grant the ParaSend enterprise row');
  // Exactly the legacy numbers, dimension for dimension, and nothing on the row
  // is uncapped: that is what separates it from enterprise.
  assert.strictEqual(biz.parasend.quotas.transfers_month, 2000);
  assert.deepStrictEqual(biz.parasend.limits, {
    file_mb: 500, devices: 100, view_ttl_ms: 604_800_000, max_views: 25, outbound_per_hour: 2000,
  });
  // And it is not a tier anyone can be sold or granted.
  assert.strictEqual(ent.PARASEND_TIERS.includes('business'), false);
  assert.deepStrictEqual(ent.validateProductPlan('parasend', 'business'), { ok: false, error: 'invalid_tier' });
});

test('migration is idempotent and additive (keeps plan + parasign)', () => {
  const once = ent.migrateUserEntry({ key: 'k', plan: 'pro', parasign: true, active: true });
  assert.strictEqual(once.plan, 'pro');            // legacy field preserved
  assert.strictEqual(once.parasign, true);         // grant flag preserved
  assert.strictEqual(once.plan_parasend, 'pro');
  assert.strictEqual(once.plan_parasign, 'pro');
  const twice = ent.migrateUserEntry(once);
  assert.strictEqual(twice, once, 'second run returns the same object unchanged');
});

test('migrateUsersData reports the changed count and preserves untouched entries', () => {
  const data = { api_keys: [
    { key: 'a', plan: 'community', active: true },
    { key: 'b', plan: 'pro', plan_parasend: 'pro', plan_parasign: 'pro', active: true }, // already done
  ] };
  const { data: out, changed } = ent.migrateUsersData(data);
  assert.strictEqual(changed, 1);
  assert.strictEqual(out.api_keys[0].plan_parasend, 'community');
  assert.strictEqual(out.api_keys[0].plan_parasign, 'free');
  assert.strictEqual(out.api_keys[1].plan_parasign, 'pro');
});

// ── 4. Fallback shapes ────────────────────────────────────────────────────────
test('getEntitlements tolerates a bare plan string and un-migrated records', () => {
  assert.strictEqual(ent.getEntitlements('pro').parasend.quotas.transfers_month, 500);
  assert.strictEqual(ent.getEntitlements({ plan: 'business' }).parasign.quotas.signs_month, 1000);
  // unknown tier clamps to the floor, never over-grants.
  assert.strictEqual(ent.getEntitlements({ plan_parasend: 'bogus' }).parasend.tier, 'community');
  assert.strictEqual(ent.getEntitlements({ plan_parasign: 'bogus' }).parasign.tier, 'free');
});
