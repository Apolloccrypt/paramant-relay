'use strict';
// ParaSign signs-quota metering. Regression for the bug where the ONLY signing
// path (/v2/envelopes/:id/sign) never counted a signature: gateSign/recordSign
// lived in a dead `&& false` block, so the dashboard signs-counter never moved
// and the monthly signs_month cap was unenforceable.
//
// This replays the EXACT decision the fixed route makes (read-only pre-gate via
// quota.readUsage vs tiers.tierLimitNum, then recordSign only on a NEW accepted
// signature) against a real throwaway redis, and asserts:
//   * a NEW signature increments the counter by exactly 1,
//   * an idempotent ('idem') retry does NOT double-count,
//   * once the counter reaches the plan cap the next sign is refused with 402.
// Skips when no redis is reachable (REDIS_URL, default 127.0.0.1:6399).
//   docker run -d --rm -p 6399:6379 --name parasign-test-redis redis:alpine

const assert = require('assert');
const crypto = require('crypto');
const quota = require('../lib/quota');
const tiers = require('../lib/tiers');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

async function tryRedis() {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6399';
  let createClient;
  try { ({ createClient } = require('redis')); } catch { return null; }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); return rc; } catch { try { await rc.disconnect(); } catch {} return null; }
}

// Mirror of the fixed /v2/envelopes/:id/sign metering. storeCode is what
// EnvelopeStore.sign() would return ('new' | 'idem' | 'bad_signature').
async function routeSign(rc, accountId, plan, storeCode) {
  const limit = tiers.tierLimitNum(plan, 'signs_month');
  // read-only pre-gate
  if (accountId && Number.isFinite(limit)) {
    const u = await quota.readUsage(rc, accountId);
    if (u.available && Number.isFinite(u.signs_this_month) && u.signs_this_month >= limit) {
      return { http: 402, error: 'monthly_sign_quota_reached', limit };
    }
  }
  if (storeCode === 'bad_signature') return { http: 400, error: 'bad_signature' };
  // count ONLY a genuinely new accepted signature
  if (storeCode === 'new' && accountId) await quota.recordSign(rc, accountId, null);
  return { http: 200, code: storeCode };
}

async function usage(rc, acct) { return (await quota.readUsage(rc, acct)).signs_this_month; }

async function main() {
  const rc = await tryRedis();
  if (!rc) { console.log('  skip - no reachable redis'); return; }
  try {
    const acct = 'acct_' + crypto.randomBytes(6).toString('hex');
    await rc.del(quota.signsKey ? quota.signsKey(acct) : `paramant:quota:signs:${acct}:${quota.ymKey()}`);

    // community signs_month cap is 2 (this is the "Signings 0/2" the user saw).
    const cap = tiers.tierLimitNum('community', 'signs_month');
    assert.strictEqual(cap, 2, 'community signs_month cap is 2');
    assert.strictEqual(await usage(rc, acct), 0, 'starts at 0 (0/2)');

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
  .then(() => console.log(`\nparasign-signs-quota: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
