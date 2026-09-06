'use strict';
// Tiers + sign-quota enforcement. One rule on every tier: the quota the plan
// includes is the limit for the month.
//   free      2 signs/month included, blocks at 2 (3rd sign -> 402)
//   pro       100 included, blocks at 100 (101st sign -> 402)
//   business  1000 included, blocks at 1000
//   enterprise config ceiling (unchanged)
//
// Pro was the exception until this suite was rewritten: it sailed past 100,
// metering each further signature at EUR 0.40 up to a hard stop at 1000, and
// six places on the site told the buyer those signatures would show up on his
// next invoice. Nothing read the billable counter. billing-catalog.js sells
// fixed monthly and yearly amounts, no usage line exists in billing.js,
// invoice.js or billing-recurring.js, and the counter's only readers were the
// assertions in this file. The meter charged nobody, so the meter is gone and
// the copy with it. What is left is checked here: one stop, at the included
// quota, on both sign paths.
//
// Counters are CALENDAR-month keyed (YYYY-MM in the redis key, UTC). Limits
// come EXCLUSIVELY from entitlements.getEntitlements; the sign paths contain
// zero tiers.tierLimitNum (asserted against the relay.js source below).
//
// routeSign() mirrors the EXACT flow of the POST /v2/envelopes/:id/sign route:
// read-only pre-gate (quota.readUsage + quota.signGateDecision), then
// quota.recordSign ONLY for a genuinely NEW accepted signature, then the 200
// `quota` field. The /v1 create gate shares signGateDecision, so proving the
// decision here proves both paths.

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

// Mirror of the R018 sign-path counting. storeCode is what EnvelopeStore.sign()
// returned: 'new' (genuinely new signature) or 'idem' (idempotent retry of the
// same sign; the store deduplicates, so counting is never reached twice).
async function routeSign(rc, accountId, planParasign, storeCode = 'new') {
  const ent = entitlements.getEntitlements({ plan_parasign: planParasign }).parasign;
  const included = ent.quotas.signs_month;
  let used = null;
  const u = await quota.readUsage(rc, accountId);
  if (u.available && Number.isFinite(u.signs_this_month)) {
    used = u.signs_this_month;
    const dec = quota.signGateDecision(used, ent);
    if (!dec.allowed) {
      return { http: 402, body: { error: 'monthly_sign_quota_reached', plan: ent.tier,
        limit: dec.limit, used, reset_date: quota.nextResetDate() } };
    }
  }
  if (storeCode === 'new') {
    const r = await quota.recordSign(rc, accountId, null);
    if (r.counted) used = r.used;
  }
  return { http: 200, body: { ok: true, quota: {
    used, included, reset_date: quota.nextResetDate(),
  } } };
}

// ── Limits come from entitlements (the single source) ────────────────────────

test('entitlements carry the tier brief: free 2, pro 100, business 1000, enterprise ceiling', () => {
  const free = entitlements.getEntitlements({ plan_parasign: 'free' }).parasign;
  const pro = entitlements.getEntitlements({ plan_parasign: 'pro' }).parasign;
  const biz = entitlements.getEntitlements({ plan_parasign: 'business' }).parasign;
  const ent = entitlements.getEntitlements({ plan_parasign: 'enterprise' }).parasign;
  assert.strictEqual(free.quotas.signs_month, 2);
  assert.strictEqual(pro.quotas.signs_month, 100);
  assert.strictEqual(biz.quotas.signs_month, 1000);
  assert.strictEqual(ent.quotas.signs_month, entitlements.ENTERPRISE_MONTHLY_CEILING, 'enterprise keeps its config ceiling');
  // No tier carries a metered rate. The site may not promise one either, and
  // the source is what it is promised from: an entitlement that grew an overage
  // field again would put EUR 0.40 back on /pricing within a release.
  for (const e of [free, pro, biz, ent]) {
    assert.strictEqual(e.overage, undefined, e.tier + ' must not carry a metered rate');
  }
});

test('nothing in the relay prices a signature: no rate lives outside the catalog', () => {
  // The billing modules sell plans. If a per-unit rate ever needs to exist, it
  // has to exist HERE first, in the same catalog the webhook re-checks a paid
  // amount against, or the site is charging for something the kassa cannot
  // collect. That was exactly the EUR 0.40 situation.
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'entitlements.js'), 'utf8')
    .replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.ok(!/rate_eur|per_sign|overage/i.test(src),
    'entitlements.js must not define a per-unit price; prices live in billing-catalog.js');
  const q = fs.readFileSync(path.join(__dirname, '..', 'lib', 'quota.js'), 'utf8')
    .replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.ok(!/overage/i.test(q), 'quota.js must not keep a billable counter nothing bills');
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
  // Decides AND counts through lib/quota, in one call. It used to read with
  // quota.readUsage, decide with quota.signGateDecision and count later with
  // quota.recordSign; that gap is what let ten concurrent requests share one
  // slot (2026-09-05 review, finding 8). The property this line has always been
  // guarding is unchanged: the limit comes out of the quota module and never
  // out of tiers.js. quota-gate.test.js holds gateSign and signGateDecision to
  // the same answer at the boundary, so the /v1 create gate, which still reads
  // the pure function, cannot drift from this path.
  assert.ok(r018.includes('quota.gateSign('), 'R018 sign path decides and counts via quota.gateSign');
  assert.ok(r018.includes('quota.releaseSign('), 'R018 sign path gives a reserved slot back when the signature does not land');
  assert.ok(r018.includes('monthly_sign_quota_reached'), 'R018 sign path emits the quota 402');
  assert.ok(!/hard_cap/.test(r018), 'R018 sign path has no second, higher stop');
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
  assert.deepStrictEqual(r2.body.quota, { used: 2, included: 2, reset_date: quota.nextResetDate() });
  const r3 = await routeSign(rc, 'acctF', 'free');
  assert.strictEqual(r3.http, 402, 'sign 3 blocked');
  assert.deepStrictEqual(r3.body, { error: 'monthly_sign_quota_reached', plan: 'free',
    limit: 2, used: 2, reset_date: quota.nextResetDate() });
  // the refused sign was never counted
  assert.strictEqual(await rc.get(quota.signsKey('acctF')), '2');
});

// ── Pro: the 100 it includes, and no 101st ───────────────────────────────────

test('pro: sign 100 succeeds, sign 101 is a 402 quota block', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctP'), '99');
  const r100 = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r100.http, 200, 'the 100th signature is included');
  assert.deepStrictEqual(r100.body.quota, { used: 100, included: 100, reset_date: quota.nextResetDate() });
  const r101 = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r101.http, 402, 'the 101st is refused, not metered');
  assert.deepStrictEqual(r101.body, { error: 'monthly_sign_quota_reached', plan: 'pro',
    limit: 100, used: 100, reset_date: quota.nextResetDate() });
  assert.strictEqual(await rc.get(quota.signsKey('acctP')), '100', 'refused sign not counted');
});

test('pro: no key, counter or field records a billable extra signature', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctP'), '99');
  await routeSign(rc, 'acctP', 'pro');
  await routeSign(rc, 'acctP', 'pro');
  // The whole redis surface after a Firm account has run its month out: the
  // month counter, and nothing that looks like something to invoice.
  const keys = [...rc._store.keys()];
  assert.deepStrictEqual(keys, [quota.signsKey('acctP')]);
  assert.ok(!keys.some((k) => /overage/.test(k)), 'no billable counter is kept');
});

// ── Idempotency and calendar-month reset ─────────────────────────────────────

test('a retry of the same sign (idem) counts nothing twice', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctP'), '10');
  const r = await routeSign(rc, 'acctP', 'pro', 'new');
  assert.strictEqual(r.body.quota.used, 11);
  const retry = await routeSign(rc, 'acctP', 'pro', 'idem');  // same sign retried
  assert.strictEqual(retry.http, 200);
  assert.strictEqual(retry.body.quota.used, 11, 'sign counter unchanged on retry');
  assert.strictEqual(await rc.get(quota.signsKey('acctP')), '11');
});

test('counters are calendar-month keyed (YYYY-MM) and reset on the 1st', async () => {
  const jun = new Date(Date.UTC(2026, 5, 15));
  const jul = new Date(Date.UTC(2026, 6, 15));
  assert.strictEqual(quota.ymKey(jun), '2026-06');
  assert.strictEqual(quota.signsKey('a', quota.ymKey(jun)), 'paramant:quota:signs:a:2026-06');
  assert.notStrictEqual(quota.signsKey('a', quota.ymKey(jun)), quota.signsKey('a', quota.ymKey(jul)),
    'a new month is a new key, so the counter starts at 0');
  // last month's heavy usage does not touch this month's gate
  const rc = fakeRedis();
  const lastMonth = new Date(); lastMonth.setUTCMonth(lastMonth.getUTCMonth() - 1);
  rc._store.set(quota.signsKey('acctP', quota.ymKey(lastMonth)), '100');
  const r = await routeSign(rc, 'acctP', 'pro');
  assert.strictEqual(r.http, 200, 'new month: pro signs again despite last month at its limit');
  assert.strictEqual(r.body.quota.used, 1, 'fresh counter');
});

test('nextResetDate is the first of the next month (ISO), incl. year rollover', () => {
  assert.strictEqual(quota.nextResetDate(new Date(Date.UTC(2026, 6, 20))), '2026-08-01');
  assert.strictEqual(quota.nextResetDate(new Date(Date.UTC(2026, 11, 31))), '2027-01-01');
  assert.strictEqual(quota.nextResetDate(new Date(Date.UTC(2026, 0, 1))), '2026-02-01');
});

// ── Business and enterprise ──────────────────────────────────────────────────

test('business: sign 1000 succeeds, sign 1001 is a 402 quota block', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctB'), '999');
  const r1000 = await routeSign(rc, 'acctB', 'business');
  assert.strictEqual(r1000.http, 200, 'sign 1000 accepted');
  assert.strictEqual(r1000.body.quota.used, 1000);
  const r1001 = await routeSign(rc, 'acctB', 'business');
  assert.strictEqual(r1001.http, 402, 'sign 1001 blocked');
  assert.deepStrictEqual(r1001.body, { error: 'monthly_sign_quota_reached', plan: 'business',
    limit: 1000, used: 1000, reset_date: quota.nextResetDate() });
});

test('enterprise: unchanged, high config ceiling', async () => {
  const rc = fakeRedis();
  rc._store.set(quota.signsKey('acctE'), '5000');
  const r = await routeSign(rc, 'acctE', 'enterprise');
  assert.strictEqual(r.http, 200, 'enterprise signs far past 1000');
  assert.strictEqual(r.body.quota.included, entitlements.ENTERPRISE_MONTHLY_CEILING);
});

// ── Fail-open and transfers untouched ────────────────────────────────────────

test('redis down: sign is never blocked (fail-open), quota field simply absent', async () => {
  const r = await routeSign({ isReady: false }, 'acctF', 'free');
  assert.strictEqual(r.http, 200);
  assert.strictEqual(r.body.quota.used, null, 'no usable count without redis');
});

test('the shared decision blocks a /v1 create the same way, on every tier', async () => {
  const pro = entitlements.getEntitlements({ plan_parasign: 'pro' }).parasign;
  const free = entitlements.getEntitlements({ plan_parasign: 'free' }).parasign;
  // The two sign paths used to disagree about exactly this: the /v1 create gate
  // blocked a Firm account at 100 while the R018 sign path let it run to 1000.
  // One decision, one number, both paths.
  assert.deepStrictEqual(quota.signGateDecision(99, pro), { allowed: true, reason: null, limit: 100 });
  assert.deepStrictEqual(quota.signGateDecision(100, pro), { allowed: false, reason: 'quota', limit: 100 });
  assert.deepStrictEqual(quota.signGateDecision(1000, pro), { allowed: false, reason: 'quota', limit: 100 });
  assert.deepStrictEqual(quota.signGateDecision(2, free), { allowed: false, reason: 'quota', limit: 2 });
  assert.deepStrictEqual(quota.signGateDecision(1, free), { allowed: true, reason: null, limit: 2 });
});

// 'transfer gating is untouched by the sign tiers' moved to quota-gate.test.js
// on 2026-09-05. gateTransfer runs a Lua script now (review finding 8) and the
// local fakeRedis has no EVAL, so here it was not testing the separation of the
// two counters, it was testing quota's fail-open catch. It lives where the real
// server is.
