'use strict';
// Unit test for admin/lib/webauthn.js (ADR R018, PR-A): the exact
// cloned-authenticator counter rule, the rate-limit helper, and the one-shot
// challenge flow store. Run: node admin/test/webauthn.test.js
// (no deps, non-zero exit on failure).

const assert = require('assert');
const wa = require('../lib/webauthn');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

function fakeRedis() {
  const m = new Map();
  return {
    _m: m,
    async incr(k) { const n = (m.get(k) | 0) + 1; m.set(k, n); return n; },
    async expire() { return 1; },
    async set(k, v) { m.set(k, v); },
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async del(k) { return m.delete(k) ? 1 : 0; },
  };
}

async function main() {
  // counterIsAcceptable — the exact rule:
  //   stored OR next == 0  -> allowed, not compared (iCloud Keychain reports 0)
  //   both non-zero        -> next must be STRICTLY higher, else refuse (clone)
  assert.strictEqual(wa.counterIsAcceptable(0, 0), true,  '0/0 allowed');
  assert.strictEqual(wa.counterIsAcceptable(0, 5), true,  'stored 0 -> not compared');
  assert.strictEqual(wa.counterIsAcceptable(5, 0), true,  'next 0 (always-0 authenticator) -> not compared');
  assert.strictEqual(wa.counterIsAcceptable(5, 6), true,  'strictly higher -> ok');
  assert.strictEqual(wa.counterIsAcceptable(5, 5), false, 'equal non-zero -> clone -> refuse');
  assert.strictEqual(wa.counterIsAcceptable(5, 4), false, 'regression -> clone -> refuse');
  assert.strictEqual(wa.counterIsAcceptable(100, 101), true, 'normal advance ok');
  ok('counterIsAcceptable exact rule');

  // limits are concrete (enforced on options AND verify)
  assert.strictEqual(wa.LIMITS.loginVerify.ip, 10, 'verify per-IP limit');
  assert.strictEqual(wa.LIMITS.loginVerify.account, 5, 'verify per-account limit');
  assert.strictEqual(wa.LIMITS.loginOptions.ip, 30, 'options per-IP limit');
  assert.strictEqual(wa.LIMITS.loginOptions.account, 15, 'options per-account limit');
  ok('rate limits are concrete values');

  // rateHit: first `limit` hits pass, the next is refused
  {
    const r = fakeRedis();
    const lim = wa.LIMITS.loginVerify.ip;
    let lastOk = true;
    for (let i = 0; i < lim; i++) lastOk = await wa.rateHit(r, 'lv:ip:test', lim, 900);
    assert.strictEqual(lastOk, true, `hit #${lim} still within limit`);
    assert.strictEqual(await wa.rateHit(r, 'lv:ip:test', lim, 900), false, `hit #${lim + 1} refused`);
    ok('rateHit fixed-window enforcement');
  }

  // scopeHash never stores PII and is stable
  assert.match(wa.scopeHash('a@b.com'), /^[0-9a-f]{32}$/, 'scopeHash is hex');
  assert.notStrictEqual(wa.scopeHash('a@b.com'), 'a@b.com', 'scopeHash is not the email');
  assert.strictEqual(wa.scopeHash('a@b.com'), wa.scopeHash('a@b.com'), 'scopeHash stable');
  ok('scopeHash');

  // one-shot challenge flow: stored, taken once, then gone (no replay)
  {
    const r = fakeRedis();
    const flowId = wa.newFlowId();
    assert.match(flowId, /^[0-9a-f]{32}$/, 'flowId is 32-hex');
    await wa.putAuthFlow(r, flowId, { challenge: 'abc', email: 'a@b.com', user_id: 'pgp_x' });
    const first = await wa.takeAuthFlow(r, flowId);
    assert.ok(first && first.challenge === 'abc', 'flow retrieved once');
    assert.strictEqual(await wa.takeAuthFlow(r, flowId), null, 'flow consumed -> second take is null (no replay)');
    assert.strictEqual(await wa.takeAuthFlow(r, 'not-a-valid-id'), null, 'malformed flowId -> null');
    ok('one-shot challenge flow (consume before verify)');
  }

  // rpId / origin are config-driven, not request-driven
  assert.strictEqual(typeof wa.RP_ID, 'string', 'RP_ID set');
  assert.strictEqual(typeof wa.EXPECTED_ORIGIN, 'string', 'EXPECTED_ORIGIN set');
  ok('rpId/origin are configured constants');
}

main()
  .then(() => console.log(`\nwebauthn: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.message ? e.message : e); process.exit(1); });
