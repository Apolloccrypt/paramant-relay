'use strict';
// Tiers + overage enforcement (Mick's tier brief):
//   free      2 signs/month included, blocks at 2 (3rd sign -> 402)
//   pro       100 included, NO block past 100; overage EUR 0.40/sign from the
//             101st; HARD stop at 1000 (402 monthly_sign_hard_cap_reached)
//   business  1000 included, blocks at 1000
//   enterprise config ceiling (unchanged), no overage
//
// Counters are CALENDAR-month keyed (YYYY-MM in the redis key, UTC) and the
// billable overage is persisted per account per month for invoicing. Limits
// come EXCLUSIVELY from entitlements.getEntitlements; the sign paths contain
// zero tiers.tierLimitNum (asserted against the relay.js source below).
//
// routeSign() mirrors the EXACT flow of the fixed POST /v2/envelopes/:id/sign
// route: read-only pre-gate (quota.readUsage + quota.signGateDecision), then
// quota.recordSignTiered ONLY for a genuinely NEW accepted signature, then the
// 200 `quota` field. The /v1 create gate shares signGateDecision, so proving
// the decision here proves both paths.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const quota = require('../lib/quota');
const entitlements = require('../lib/entitlements');

// Minimal in-memory Redis stub (same shape as quota-gate.test.js).
function fakeRedis() {
  const store = new Map();
  return {
    isReady: true,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async exists(k) { return store.has(k) ? 1 : 0; },
    async incr(k) { const n = (parseInt(store.get(k) || '0', 10)) + 1; store.set(k, String(n)); return n; },
    async expire() { return 1; },
    async set(k, v, opts) {
      if (opts && opts.NX && store.has(k)) return null;
      store.set(k, v); return 'OK';
    },
    _store: store,
  };
}

// Mirror of the R018 sign-path metering. storeCode is what EnvelopeStore.sign()
// returned: 'new' (genuinely new signature) or 'idem' (idempotent retry of the
// same sign; the store deduplicates, so metering is never reached twice).
async function routeSign(rc, accountId, planParasign, storeCode = 'new') {
  const ent = entitlements.getEntitlements({ plan_parasign: planParasign }).parasign;
  const included = ent.quotas.signs_month;
  const metered = ent.overage.rate_eur != null && Number.isFinite(ent.overage.hard_cap);
  let used = null;
  const u = await quota.readUsage(rc, accountId);
  if (u.available && Number.isFinite(u.signs_this_month)) {
    used = u.signs_this_month;
    const dec = quota.signGateDecision(used, ent);
    if (!dec.allowed) {
      if (dec.reason === 'hard_cap') {
        return { http: 402, body: { error: 'monthly_sign_hard_cap_reached', plan: ent.tier,
          limit: dec.limit, overage_count: Math.max(0, used - included), reset_date: quota.nextResetDate() } };
      }
      return { http: 402, body: { error: 'monthly_sign_quota_reached', plan: ent.tier,
        limit: dec.limit, used, reset_date: quota.nextResetDate() } };
    }
  }
  if (storeCode === 'new') {
    const r = await quota.recordSignTiered(rc, accountId, included, null);
    if (r.counted) used = r.used;
  }
  return { http: 200, body: { ok: true, quota: {
    used, included,
    overage_count: metered ? Math.max(0, used - included) : null,
    overage_rate_eur: metered ? ent.overage.rate_eur : null,
    hard_cap: metered ? ent.overage.hard_cap : null,
    reset_date: quota.nextResetDate(),
  } } };
}

// ── Limits come from entitlements (the single source) ────────────────────────

test('entitlements carry the tier brief: free 2, pro 100+overage, business 1000, enterprise ceiling', () => {
  const free = entitlements.getEntitlements({ plan_parasign: 'free' }).parasign;
  const pro = entitlements.getEntitlements({ plan_parasign: 'pro' }).parasign;
  const biz = entitlements.getEntitlements({ plan_parasign: 'business' }).parasign;
  const ent = entitlements.getEntitlements({ plan_parasign: 'enterprise' }).parasign;
  assert.strictEqual(free.quotas.signs_month, 2);
  assert.deepStrictEqual({ ...free.overage }, { rate_eur: null, hard_cap: null }, 'free has no overage');
  assert.strictEqual(pro.quotas.signs_month, 100);
  assert.deepStrictEqual({ ...pro.overage }, { rate_eur: 0.40, hard_cap: 1000 }, 'pro meters at 0.40 up to 1000');
  assert.strictEqual(biz.quotas.signs_month, 1000);
  assert.deepStrictEqual({ ...biz.overage }, { rate_eur: null, hard_cap: null }, 'business has no overage');
  assert.strictEqual(ent.quotas.signs_month, entitlements.ENTERPRISE_MONTHLY_CEILING, 'enterprise keeps its config ceiling');
  assert.deepStrictEqual({ ...ent.overage }, { rate_eur: null, hard_cap: null }, 'enterprise has no overage');
});

test('sign paths in relay.js use zero tiers.tierLimitNum (R3)', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
  // R018 sign path: from the route match to the next route (searched FROM the
  // route start; the literal '/v2/verify-receipt' also appears in earlier
  // endpoint lists).
  const r018Start = src.indexOf("path.startsWith('/v2/envelopes/') && path.endsWith('/sign')");
  assert.ok(r018Start > -1, 'found the R018 sign route');
  const r018 = src.slice(r018Start, src.indexOf('/v2/verify-receipt', r018Start));
  assert.ok(r018.length > 1000, 'found the R018 sign-path segment');
  assert.ok(!/tiers\.tierLimitNum/.test(r018), 'R018 sign path has no tiers.tierLimitNum');
  assert.ok(r018.includes('signGateDecision'), 'R018 sign path decides via quota.signGateDecision');
  assert.ok(r018.includes('recordSignTiered'), 'R018 sign path meters via quota.recordSignTiered');
  assert.ok(r018.includes('monthly_sign_hard_cap_reached'), 'R018 sign path emits the hard-cap 402');
  // /v1 create gate: the injected signQuotaGate closure.
  const v1 = src.slice(src.indexOf('signQuotaGate: async'), src.indexOf('readBody, J, log'));
  assert.ok(v1.length > 100, 'found the /v1 signQuotaGate segment');
  assert.ok(!/tiers\.tierLimitNum/.test(v1), '/v1 gate has no tiers.tierLimitNum');
  assert.ok(v1.includes('getEntitlements'), '/v1 gate reads entitlements');
  assert.ok(v1.includes('signGateDecision'), '/v1 gate shares quota.signGateDecision');
});

// ── Free: blocks at 2, not at 1 or 3 ─────────────────────────────────────────

test('free: sign 1 and 2 succeed, sign 3 is a 402 quota block', async () => {
  const rc = fakeRedis();
  const r1 = await routeSign(rc, 'acctF', 'free');
  assert.strictEqual(r1.http, 200, 'sign 1 accepted');
  assert.strictEqual(r1.body.quota.used, 1);
  const r2 = await routeSign(rc, 'acctF', 'free');
  assert.strictEqual(r2.http, 200, 'sign 2 accepted');
  assert.strictEqual(r2.body.quota.used, 2);
  assert.strictEqual(r2.body.quota.included, 2);
  assert.strictEqual(r2.body.quota.overage_count, null, 'free: overage fields null');
  assert.strictEqual(r2.body.quota.overage_rate_eur, null);
  assert.strictEqual(r2.body.quota.hard_cap, null);
  const r3 = await routeSign(rc, 'acctF', 'free');
  assert.strictEqual(r3.http, 402, 'sign 3 blocked');
  assert.deepStrictEqual(r3.body, { error: 'monthly_sign_quota_reached', plan: 'free',
    limit: 2, used: 2, reset_date: quota.nextResetDate() });
  // the refused sign was never counted
  assert.strictEqual(await rc.get(quota.signsKey('acctF')), '2');
});

// ── Pro: no block at 100, overage from the 101st ─────────────────────────────

test('pro: sign 100 and 101 both succeed (no block at 100); overage counts at 101 and 150', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctP'), '99');
  const r100 = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r100.http, 200, 'sign 100 accepted');
  assert.strictEqual(r100.body.quota.used, 100);
  assert.strictEqual(r100.body.quota.overage_count, 0, 'still inside the included 100');
  const r101 = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r101.http, 200, 'sign 101 is NOT blocked');
  assert.deepStrictEqual(r101.body.quota, { used: 101, included: 100, overage_count: 1,
    overage_rate_eur: 0.40, hard_cap: 1000, reset_date: quota.nextResetDate() });
  assert.strictEqual(await rc.get(quota.signsOverageKey('acctP')), '1', 'billable overage persisted');
  for (let i = 102; i <= 150; i++) await routeSign(rc, 'acctP', 'pro');
  const u = await quota.readUsage(rc, 'acctP');
  assert.strictEqual(u.signs_this_month, 150, 'counter correct at 150');
  assert.strictEqual(await quota.readSignsOverage(rc, 'acctP'), 50, 'billable overage 50 at 150 signs');
});

test('pro: hard stop at 1000 is a 402 hard_cap with overage_count, nothing counted past it', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctP'), '999');
  const r1000 = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r1000.http, 200, 'sign 1000 (the last metered one) accepted');
  const r1001 = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r1001.http, 402, 'sign 1001 hits the hard stop');
  assert.deepStrictEqual(r1001.body, { error: 'monthly_sign_hard_cap_reached', plan: 'pro',
    limit: 1000, overage_count: 900, reset_date: quota.nextResetDate() });
  assert.strictEqual(await rc.get(quota.signsKey('acctP')), '1000', 'refused sign not counted');
});

// ── Idempotency and calendar-month reset ─────────────────────────────────────

test('a retry of the same sign (idem) counts neither the sign nor the overage', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctP'), '100');
  const r = await routeSign(rc, 'acctP', 'pro', 'new');       // the 101st: 1 overage
  assert.strictEqual(r.body.quota.overage_count, 1);
  const retry = await routeSign(rc, 'acctP', 'pro', 'idem');  // same sign retried
  assert.strictEqual(retry.http, 200);
  assert.strictEqual(retry.body.quota.used, 101, 'sign counter unchanged on retry');
  assert.strictEqual(retry.body.quota.overage_count, 1, 'overage unchanged on retry');
  assert.strictEqual(await rc.get(quota.signsKey('acctP')), '101');
  assert.strictEqual(await rc.get(quota.signsOverageKey('acctP')), '1');
});

test('counters and overage are calendar-month keyed (YYYY-MM) and reset on the 1st', async () => {
  const jun = new Date(Date.UTC(2026, 5, 15));
  const jul = new Date(Date.UTC(2026, 6, 15));
  assert.strictEqual(quota.ymKey(jun), '2026-06');
  assert.strictEqual(quota.signsKey('a', quota.ymKey(jun)), 'paramant:quota:signs:a:2026-06');
  assert.strictEqual(quota.signsOverageKey('a', quota.ymKey(jun)), 'paramant:quota:signs_overage:a:2026-06');
  assert.notStrictEqual(quota.signsKey('a', quota.ymKey(jun)), quota.signsKey('a', quota.ymKey(jul)),
    'a new month is a new key, so the counter starts at 0');
  // last month's heavy usage does not touch this month's gate
  const rc = fakeRedis();
  const lastMonth = new Date(); lastMonth.setUTCMonth(lastMonth.getUTCMonth() - 1);
  rc._store.set(quota.signsKey('acctP', quota.ymKey(lastMonth)), '1000');
  rc._store.set(quota.signsOverageKey('acctP', quota.ymKey(lastMonth)), '900');
  const r = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r.http, 200, 'new month: pro signs again despite last month at the hard cap');
  assert.strictEqual(r.body.quota.used, 1, 'fresh counter');
  assert.strictEqual(r.body.quota.overage_count, 0, 'fresh overage');
  assert.strictEqual(await quota.readSignsOverage(rc, 'acctP', quota.ymKey(lastMonth)), 900,
    'last month\'s billable overage stays readable for invoicing');
});

test('nextResetDate is the first of the next month (ISO), incl. year rollover', () => {
  assert.strictEqual(quota.nextResetDate(new Date(Date.UTC(2026, 6, 20))), '2026-08-01');
  assert.strictEqual(quota.nextResetDate(new Date(Date.UTC(2026, 11, 31))), '2027-01-01');
  assert.strictEqual(quota.nextResetDate(new Date(Date.UTC(2026, 0, 1))), '2026-02-01');
});

// ── Business and enterprise ──────────────────────────────────────────────────

test('business: sign 1000 succeeds, sign 1001 is a 402 quota block (no overage)', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctB'), '999');
  const r1000 = await routeSign(rc, 'acctB', 'business');
  assert.strictEqual(r1000.http, 200, 'sign 1000 accepted');
  assert.strictEqual(r1000.body.quota.used, 1000);
  assert.strictEqual(r1000.body.quota.overage_count, null, 'business: overage fields null');
  const r1001 = await routeSign(rc, 'acctB', 'business');
  assert.strictEqual(r1001.http, 402, 'sign 1001 blocked');
  assert.deepStrictEqual(r1001.body, { error: 'monthly_sign_quota_reached', plan: 'business',
    limit: 1000, used: 1000, reset_date: quota.nextResetDate() });
});

test('enterprise: unchanged, high config ceiling, no overage metering', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctE'), '5000');
  const r = await routeSign(rc, 'acctE', 'enterprise');
  assert.strictEqual(r.http, 200, 'enterprise signs far past 1000');
  assert.strictEqual(r.body.quota.overage_count, null);
  assert.strictEqual(await rc.exists(quota.signsOverageKey('acctE')), 0, 'no overage recorded');
});

// ── Fail-open and transfers untouched ────────────────────────────────────────

test('redis down: sign is never blocked (fail-open), quota field simply absent', async () => {
  const r = await routeSign({ isReady: false }, 'acctF', 'free');
  assert.strictEqual(r.http, 200);
  assert.strictEqual(r.body.quota.used, null, 'no usable count without redis');
});

test('the shared decision blocks a /v1 create the same way (pro at hard cap, free at quota)', async () => {
  const pro = entitlements.getEntitlements({ plan_parasign: 'pro' }).parasign;
  const free = entitlements.getEntitlements({ plan_parasign: 'free' }).parasign;
  assert.deepStrictEqual(quota.signGateDecision(100, pro), { allowed: true, reason: null, limit: 1000 },
    '/v1 create for pro at 100 used is NOT blocked');
  assert.deepStrictEqual(quota.signGateDecision(1000, pro), { allowed: false, reason: 'hard_cap', limit: 1000 });
  assert.deepStrictEqual(quota.signGateDecision(2, free), { allowed: false, reason: 'quota', limit: 2 });
  assert.deepStrictEqual(quota.signGateDecision(1, free), { allowed: true, reason: null, limit: 2 });
});

test('transfer gating is untouched by the sign tiers', async () => {
  const rc = fakeRedis();
  const g = await quota.gateTransfer(rc, 'acct1', 'hashA', 10, null);
  assert.strictEqual(g.allowed, true);
  assert.strictEqual(g.counted, true);
  assert.strictEqual(await rc.exists(quota.signsOverageKey('acct1')), 0);
});
