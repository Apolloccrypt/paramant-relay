'use strict';
// Product/tier entitlement separation + no-downgrade migration.
//
// Proves: (1) ParaSend and ParaSign are entitled independently; (2) a quota
// overrun on one product returns 402-shaped decline without touching the other;
// (3) the legacy->per-product migration never downgrades any existing account.

const { test } = require('node:test');
const assert = require('assert');
const ent = require('../lib/entitlements');
const tiers = require('../lib/tiers');
const quota = require('../lib/quota');

// Minimal in-memory Redis stub (mirrors quota-gate.test.js).
function fakeRedis() {
  const store = new Map();
  return {
    isReady: true,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async exists(k) { return store.has(k) ? 1 : 0; },
    async incr(k) { const n = (parseInt(store.get(k) || '0', 10)) + 1; store.set(k, String(n)); return n; },
    async expire() { return 1; },
    async set(k, v, opts) { if (opts && opts.NX && store.has(k)) return null; store.set(k, v); return 'OK'; },
    _store: store,
  };
}

// ── 1. Independent per-product entitlement ────────────────────────────────────
test('account pro on parasign + community on parasend gets SEPARATE limits', () => {
  const acct = { plan_parasign: 'pro', plan_parasend: 'community' };
  const e = ent.getEntitlements(acct);
  assert.strictEqual(e.parasign.tier, 'pro');
  assert.strictEqual(e.parasend.tier, 'community');
  assert.strictEqual(e.parasign.quotas.signs_month, 100);     // pro signs
  assert.strictEqual(e.parasend.quotas.transfers_month, 10);  // community transfers
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
  const r = fakeRedis();
  const acct = { account_id: 'acctZ', plan_parasend: 'community', plan_parasign: 'pro' };
  const tLimit = ent.transfersQuota(acct); // 10
  const sLimit = ent.signsQuota(acct);     // 100

  // Drive parasend transfers to the cap.
  r._store.set(quota.transfersKey('acctZ'), String(tLimit));
  const tGate = await quota.gateTransfer(r, 'acctZ', 'freshChunk', tLimit, null);
  assert.strictEqual(tGate.allowed, false, 'transfer over cap declined');
  assert.strictEqual(tGate.over_limit, true);

  // ParaSign signs are counted on a different Redis key and a different limit,
  // so the account can still sign.
  const sGate = await quota.gateSign(r, 'acctZ', sLimit, null);
  assert.strictEqual(sGate.allowed, true, 'sign unaffected by transfer overrun');
  assert.strictEqual(sGate.counted, true);
});

test('overrun on parasign signs does NOT block parasend transfers', async () => {
  const r = fakeRedis();
  const acct = { account_id: 'acctY', plan_parasend: 'pro', plan_parasign: 'free' };
  const sLimit = ent.signsQuota(acct); // 2 (free)
  r._store.set(quota.signsKey('acctY'), String(sLimit));
  const sGate = await quota.gateSign(r, 'acctY', sLimit, null);
  assert.strictEqual(sGate.allowed, false, 'sign over free cap declined');

  const tGate = await quota.gateTransfer(r, 'acctY', 'chunkA', ent.transfersQuota(acct), null);
  assert.strictEqual(tGate.allowed, true, 'transfer unaffected by sign overrun');
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
  assert.strictEqual(comm.parasend.quotas.transfers_month, 10);
  assert.strictEqual(comm.parasign.quotas.signs_month, 2);

  // business: parasign stays business (1000); parasend goes UP to enterprise
  // (never below its current 2000 transfers).
  const biz = ent.getEntitlements(ent.migrateUserEntry({ plan: 'business' }));
  assert.strictEqual(biz.parasign.tier, 'business');
  assert.strictEqual(biz.parasign.quotas.signs_month, 1000);
  assert.strictEqual(biz.parasend.tier, 'enterprise');
  assert.ok(biz.parasend.quotas.transfers_month >= 2000);
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
