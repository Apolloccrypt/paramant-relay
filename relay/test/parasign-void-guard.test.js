'use strict';
// Regression tests for the void<->sign terminal-state guard in relay/envelope.js.
// Bug (audit 2026-07-19): a voided envelope stayed signable -- sign() only
// rejected status 'complete', never 'void', and voidEnvelope did a non-atomic
// hGetAll->hSet. Fix: SIGN_LUA/VOID_LUA reject terminal states atomically, and
// sign() has a fast-path 'void' pre-check + maps the new 'voided'/'closed'
// script outcomes. Following the repo convention, redis is a fake double whose
// evalSha returns the outcome the Lua would (the Lua text runs unchanged in
// prod redis); these tests pin the JS wrapper contract around it.
// Run: node relay/test/parasign-void-guard.test.js (exits non-zero on failure).

const assert = require('assert');
const { EnvelopeStore } = require('../envelope');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

function fakeRedis(hash, evalResult) {
  return {
    isReady: true,
    _hash: hash,
    async hGetAll() { return { ...hash }; },
    async hGet(_k, f) { return hash[f]; },
    async hSet() { return 1; },
    async scriptLoad() { return 'sha-stub'; },
    async evalSha() { return evalResult; },
  };
}

const ID = 'envVoidGuard000000001';
const DOC = 'a'.repeat(64);
const PUB = Buffer.from('dummy-signer-pubkey').toString('base64');
const SIG = Buffer.from('dummy-signature').toString('base64');

// open-mode envelope in a given status (open mode skips the email-binding gate).
const openEnv = (status) => ({
  id: ID, doc_hash: DOC, status, binding_mode: 'open', recipe_version: '1',
  party_count: '1', signed_count: '0', p0_status: 'pending',
});

async function main() {
  // 1. sign() fast-path rejects a voided envelope BEFORE touching the script.
  {
    let evalCalled = false;
    const redis = fakeRedis(openEnv('void'), ['new', '1', '1', 'void']);
    redis.evalSha = async () => { evalCalled = true; return ['new', '1', '1', 'void']; };
    const store = new EnvelopeStore(redis, { sigVerify: () => true });
    const out = await store.sign(ID, 0, PUB, SIG);
    assert.strictEqual(out.ok, false, 'voided envelope is not signable');
    assert.strictEqual(out.code, 'voided', 'fast-path returns code voided');
    assert.strictEqual(evalCalled, false, 'fast-path short-circuits before evalSha');
    ok('sign() fast-path rejects voided envelope (code voided, no script run)');
  }

  // 2. sign() still rejects a completed envelope (fast path, code closed).
  {
    const store = new EnvelopeStore(fakeRedis(openEnv('complete'), ['idem','1','1','complete']),
                                    { sigVerify: () => true });
    const out = await store.sign(ID, 0, PUB, SIG);
    assert.strictEqual(out.ok, false);
    assert.strictEqual(out.code, 'closed', 'completed envelope -> closed');
    ok('sign() rejects completed envelope (code closed)');
  }

  // 3. RACE: read saw 'sent', but the atomic script reports the envelope voided
  //    between the pre-read and the script -> wrapper maps 'voided'.
  {
    const store = new EnvelopeStore(fakeRedis(openEnv('sent'), ['voided', '0', '1', 'void']),
                                    { sigVerify: () => true });
    const out = await store.sign(ID, 0, PUB, SIG);
    assert.strictEqual(out.ok, false, 'race: sign loses to concurrent void');
    assert.strictEqual(out.code, 'voided', 'atomic-script voided outcome mapped');
    ok('sign() maps atomic-script "voided" outcome (void wins the race)');
  }

  // 4. RACE the other way: script reports 'closed' (completed under us).
  {
    const store = new EnvelopeStore(fakeRedis(openEnv('sent'), ['closed', '1', '1', 'complete']),
                                    { sigVerify: () => true });
    const out = await store.sign(ID, 0, PUB, SIG);
    assert.strictEqual(out.code, 'closed', 'atomic-script closed outcome mapped');
    ok('sign() maps atomic-script "closed" outcome');
  }

  // 5. Normal sign still works (open, recipe upgrades to v4, sig verifies).
  {
    const store = new EnvelopeStore(fakeRedis(openEnv('sent'), ['new', '1', '1', 'complete']),
                                    { sigVerify: () => true });
    const out = await store.sign(ID, 0, PUB, SIG);
    assert.strictEqual(out.ok, true, 'valid sign accepted');
    assert.strictEqual(out.code, 'new');
    assert.strictEqual(out.status, 'complete');
    ok('sign() still accepts a valid signature (no regression)');
  }

  // 6. voidEnvelope maps the atomic VOID_LUA outcomes.
  {
    const store = new EnvelopeStore(fakeRedis(openEnv('sent'), ['void', '2026-07-19T02:00:00Z']));
    const out = await store.voidEnvelope(ID, 'wrong document');
    assert.deepStrictEqual({ ok: out.ok, code: out.code, status: out.status, at: out.voided_at },
      { ok: true, code: 'void', status: 'void', at: '2026-07-19T02:00:00Z' });
    ok('voidEnvelope maps "void" outcome');
  }
  {
    const store = new EnvelopeStore(fakeRedis(openEnv('complete'), ['already_complete', '']));
    const out = await store.voidEnvelope(ID, '');
    assert.strictEqual(out.ok, false);
    assert.strictEqual(out.code, 'already_complete', 'completed cannot be voided');
    ok('voidEnvelope refuses a completed envelope (already_complete)');
  }
  {
    const store = new EnvelopeStore(fakeRedis(openEnv('void'), ['idem', '2026-07-19T02:00:00Z']));
    const out = await store.voidEnvelope(ID, '');
    assert.strictEqual(out.ok, true);
    assert.strictEqual(out.code, 'idem', 'voiding a void is idempotent');
    ok('voidEnvelope is idempotent on an already-void envelope');
  }
  {
    const store = new EnvelopeStore(fakeRedis({}, ['not_found', '']));
    const out = await store.voidEnvelope('envDoesNotExist00000', '');
    assert.strictEqual(out.ok, false);
    assert.strictEqual(out.code, 'not_found');
    ok('voidEnvelope returns not_found for an unknown envelope');
  }

  console.log(`\nPASS parasign-void-guard: ${passed} checks`);
}

main().catch((e) => { console.error('FAIL', e && e.stack || e); process.exit(1); });
