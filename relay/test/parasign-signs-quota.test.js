'use strict';
// ParaSign signs-quota metering. Regression for the bug where the ONLY signing
// path (/v2/envelopes/:id/sign) never counted a signature: gateSign/recordSign
// lived in a dead `&& false` block, so the dashboard signs-counter never moved
// and the monthly signs_month cap was unenforceable.
//
// CHANGED 2026-09-05. The mirror below used to open with `if (accountId && ...)`
// around the pre-gate and `if (storeCode === 'new' && accountId)` around the
// increment, copied verbatim from the route, and it never once called routeSign
// with an empty account. So it reproduced the route's second hole instead of
// finding it: a caller who left account_id out of the body skipped the gate AND
// the counter, and the signature was accepted anyway. That is unlimited signing
// on a plan that sells two a month, and this suite was green throughout.
//
// The lesson is in the shape, not the line: a mirror that copies the
// implementation cannot disagree with it. So the mirror now states the RULE the
// route must satisfy (no account is a refusal, and the account is resolved
// server-side) and the empty case is tested first, not never. The route itself
// is checked end to end over HTTP in route-omission-gate.test.js, which is what
// catches a mirror drifting away from the thing it mirrors.
//
// This replays the decision the fixed route makes (resolve the account, refuse
// when there is none, read-only pre-gate via quota.readUsage vs
// tiers.tierLimitNum, then recordSign only on a NEW accepted signature) against
// a real throwaway redis, and asserts:
//   * a request that names no account is REFUSED, not waved through,
//   * a NEW signature increments the counter by exactly 1,
//   * an idempotent ('idem') retry does NOT double-count,
//   * once the counter reaches the plan cap the next sign is refused with 402.
// Needs a redis (REDIS_URL, default 127.0.0.1:6399). Without one this suite
// FAILS unless the runner declared redis absent; see test/_requires.js.
//   docker run -d --rm -p 6399:6379 --name parasign-test-redis redis:alpine

const assert = require('assert');
const crypto = require('crypto');
const quota = require('../lib/quota');
const tiers = require('../lib/tiers');
const { requireRedis, summary } = require('./_requires');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

// Mirror of the fixed /v2/envelopes/:id/sign metering. storeCode is what
// EnvelopeStore.sign() would return ('new' | 'idem' | 'bad_signature').
//
// `accountId` here stands for the account the ROUTE resolved, not a body field:
// an internal-auth caller may name the signer, otherwise it is the account
// stored on the envelope at create time. Either way it is server-side, and the
// one thing a request can no longer do is make it disappear.
async function routeSign(rc, accountId, plan, storeCode) {
  // No account, no signature. This is the line the old mirror did not have and
  // the old route did not have either: absence is a refusal, never a bypass.
  if (!accountId) return { http: 403, error: 'account_required' };
  const limit = tiers.tierLimitNum(plan, 'signs_month');
  // read-only pre-gate
  if (Number.isFinite(limit)) {
    const u = await quota.readUsage(rc, accountId);
    if (u.available && Number.isFinite(u.signs_this_month) && u.signs_this_month >= limit) {
      return { http: 402, error: 'monthly_sign_quota_reached', limit };
    }
  }
  if (storeCode === 'bad_signature') return { http: 400, error: 'bad_signature' };
  // count ONLY a genuinely new accepted signature
  if (storeCode === 'new') await quota.recordSign(rc, accountId, null);
  return { http: 200, code: storeCode };
}

async function usage(rc, acct) { return (await quota.readUsage(rc, acct)).signs_this_month; }

async function main() {
  const rc = await requireRedis('redis://127.0.0.1:6399');
  if (!rc) return;
  try {
    const acct = 'acct_' + crypto.randomBytes(6).toString('hex');
    await rc.del(quota.signsKey ? quota.signsKey(acct) : `paramant:quota:signs:${acct}:${quota.ymKey()}`);

    // community signs_month cap is 2 (this is the "Signings 0/2" the user saw).
    const cap = tiers.tierLimitNum('community', 'signs_month');
    assert.strictEqual(cap, 2, 'community signs_month cap is 2');
    assert.strictEqual(await usage(rc, acct), 0, 'starts at 0 (0/2)');

    // 0) The case the old suite never ran: no account at all. It must be a
    //    refusal. If this ever returns 200 the whole cap below is theatre,
    //    because a caller can simply not mention an account.
    let none = await routeSign(rc, '', 'community', 'new');
    assert.strictEqual(none.http, 403, 'a sign request with no account is refused');
    assert.strictEqual(none.error, 'account_required');
    assert.strictEqual(await usage(rc, acct), 0, 'and nothing was counted anywhere');
    none = await routeSign(rc, undefined, 'community', 'new');
    assert.strictEqual(none.http, 403, 'undefined is not a lighter kind of absent');
    ok('a signature that names no account is refused, not silently unmetered');

    // 1) A NEW signature increments by exactly 1 (0/2 -> 1/2).
    let r = await routeSign(rc, acct, 'community', 'new');
    assert.strictEqual(r.http, 200, 'first sign accepted');
    assert.strictEqual(await usage(rc, acct), 1, 'counter moved to 1/2 (bug was: never moved)');
    ok('a NEW signature increments the signs counter by exactly 1');

    // 2) An idempotent retry of that same signature does NOT double-count.
    r = await routeSign(rc, acct, 'community', 'idem');
    assert.strictEqual(r.http, 200, 'idem retry still returns 200');
    assert.strictEqual(await usage(rc, acct), 1, 'idem retry did NOT double-count (still 1/2)');
    ok('an idempotent retry does not double-count');

    // 3) Second distinct NEW signature reaches the cap (1/2 -> 2/2).
    r = await routeSign(rc, acct, 'community', 'new');
    assert.strictEqual(r.http, 200, 'second distinct sign accepted (fills the cap)');
    assert.strictEqual(await usage(rc, acct), 2, 'counter at 2/2');
    ok('second signature fills the cap (2/2)');

    // 4) Over the cap -> 402, and nothing else is counted.
    r = await routeSign(rc, acct, 'community', 'new');
    assert.strictEqual(r.http, 402, 'over-cap sign refused with 402');
    assert.strictEqual(r.error, 'monthly_sign_quota_reached', 'correct error code');
    assert.strictEqual(await usage(rc, acct), 2, 'refused sign was not counted');
    ok('over the plan cap the next signature is refused with 402');

    // 5) An unlimited (enterprise) plan is never gated.
    const ent = 'acct_' + crypto.randomBytes(6).toString('hex');
    for (let i = 0; i < 5; i++) assert.strictEqual((await routeSign(rc, ent, 'enterprise', 'new')).http, 200, 'enterprise never blocked');
    ok('unlimited plan (enterprise) is never gated');

    // cleanup
    await rc.del(`paramant:quota:signs:${acct}:${quota.ymKey()}`);
    await rc.del(`paramant:quota:signs:${ent}:${quota.ymKey()}`);
  } finally { try { await rc.disconnect(); } catch {} }
}

main()
  .then(() => summary('parasign-signs-quota', passed))
  .catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
