'use strict';
// The rate limiters that guard the envelope routes, measured on a really booted
// relay instead of on the Map underneath them.
//
// WHY THIS SUITE EXISTS. lib/rate-limit.js is well covered as a function, and
// test/rate-limit.test.js even keeps a table of the live budgets. But nothing
// checked that relay.js WIRES those budgets to the routes: a limiter with the
// right numbers, applied to the wrong path or after the handler, is no limiter
// at all. And the envelope-create limiter is not in lib/rate-limit.js at all -
// it is the one redis-backed limiter in the codebase, defined inline at
// relay.js:1426-1439, with a per-process fallback. That fallback is the part
// that matters in an outage and it had no test.
//
// The two properties asserted:
//   * per process, per KEY, creation is capped at 50/hour for one API key and
//     the cap does not spill over to another key;
//   * FLEET-WIDE with redis, two relay processes sharing one redis share one
//     budget. That is the whole reason the redis variant exists: five relays
//     behind nginx must not each grant 50.
//
// The per-IP limiters (view 30/min, sign 10/min) are checked on the routes they
// actually guard, including that they answer BEFORE the handler does, a
// limiter that runs after the work is done saves nothing.
// Run: node --test relay/test/route-rate-limits.test.js
//      (the fleet-wide test additionally needs REDIS_URL)

const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const ENV_CREATE_LIMIT = 50;   // relay.js:1404 and 1427
const ENV_VIEW_LIMIT = 30;     // relay.js:1407, per minute per IP
const ENV_SIGN_LIMIT = 10;     // relay.js:1410, per minute per IP

let checks = 0;
const did = () => { checks++; };
after(async () => { await killAll(); summary('route-rate-limits', checks); });

const docHash = () => crypto.createHash('sha3-256').update(crypto.randomBytes(32)).digest('hex');
const runId = () => crypto.randomBytes(6).toString('hex');

function createEnvelope(srv, key, ip) {
  return srv.post('/v2/envelopes', {
    headers: { 'X-Api-Key': key, 'X-Real-IP': ip || '10.9.0.1' },
    body: { doc_hash: docHash(), parties: [{ label: 'A' }], ttl_days: 1 },
  });
}

// The redis bucket is a wall-clock hour (relay.js:1432), so a test that spans a
// boundary would count into two buckets. Wait it out rather than flake.
async function awaitStableHour(seconds = 20) {
  const msLeft = 3_600_000 - (Date.now() % 3_600_000);
  if (msLeft < seconds * 1000) await new Promise((r) => setTimeout(r, msLeft + 250));
}

// ── 1. the per-process limiter (no redis) ────────────────────────────────────

test('without redis, envelope creation is capped at 50 per hour for one key', async () => {
  // No redis means no envelope store either, so every accepted create answers
  // 503 (relay.js:5669). That is exactly what makes this a clean measurement of
  // the LIMITER: the 503s are the requests it let through, and the switch to
  // 429 is the moment it stopped.
  const key = `pgp_rl_${runId()}`;
  const spare = `pgp_rl_other_${runId()}`;
  const srv = await boot({
    tag: 'rl-process',
    users: { api_keys: [
      { key, plan: 'pro', active: true, account_id: 'acct_rl', email: 'rl@example.test' },
      { key: spare, plan: 'pro', active: true, account_id: 'acct_rl_other', email: 'rl2@example.test' },
    ] },
  });

  for (let i = 1; i <= ENV_CREATE_LIMIT; i++) {
    const r = await createEnvelope(srv, key);
    assert.strictEqual(r.status, 503, `create ${i} of ${ENV_CREATE_LIMIT} should have been let through, got ${r.status}`);
  }
  const over = await createEnvelope(srv, key);
  assert.strictEqual(over.status, 429, 'the 51st create in an hour must be refused');
  assert.strictEqual(over.headers['retry-after'], '3600', 'and must say when to come back');
  assert.match(String(over.json.error), /50\/hour/);

  // The budget is per KEY, not per process: a second tenant is untouched.
  const other = await createEnvelope(srv, spare);
  assert.strictEqual(other.status, 503, 'one key exhausting its budget must not lock out another');

  // A refusal does not reset or extend the window either: still refused.
  assert.strictEqual((await createEnvelope(srv, key)).status, 429);
  srv.stop();
  did();
});

// ── 2. the fleet-wide limiter (with redis) ───────────────────────────────────

test('with redis the budget is FLEET-WIDE: two relays share one 50/hour cap', async () => {
  // The reason the redis variant exists. Production runs five relay containers
  // behind nginx; a per-process cap would grant 250 creations per hour per key
  // while the docs and the 429 both say 50.
  const rc = await requireRedis(DEFAULT_REDIS);
  if (!rc) return;
  await awaitStableHour();

  const key = `pgp_rl_shared_${runId()}`;
  const users = { api_keys: [{ key, plan: 'pro', active: true, account_id: 'acct_shared', email: 's@example.test' }] };
  const env = { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS };
  const a = await boot({ tag: 'rl-shared-a', users, env });
  const b = await boot({ tag: 'rl-shared-b', users, env });

  try {
    // Relay A spends the whole budget. With redis the store works, so these are
    // real envelopes and every one of them is a 200.
    for (let i = 1; i <= ENV_CREATE_LIMIT; i++) {
      const r = await createEnvelope(a, key);
      assert.strictEqual(r.status, 200, `relay A create ${i}: ${r.status} ${r.text}`);
    }
    // Relay B has created nothing at all, and is refused on its first attempt.
    const onB = await createEnvelope(b, key);
    assert.strictEqual(onB.status, 429,
      'relay B must see relay A\'s spend; a per-process counter would have let this through');
    assert.strictEqual(onB.headers['retry-after'], '3600');
    // And A agrees.
    assert.strictEqual((await createEnvelope(a, key)).status, 429);

    // The counter is exactly where the code says it is, so an operator can read
    // it, and it carries an expiry (no key left behind for an hour that passed).
    const bucket = Math.floor(Date.now() / 3_600_000);
    const rk = `paramant:rl:envcreate:${bucket}:${key}`;
    assert.strictEqual(Number(await rc.get(rk)), ENV_CREATE_LIMIT + 2, 'refused attempts are counted too');
    const ttl = await rc.ttl(rk);
    assert.ok(ttl > 0 && ttl <= 3600, `the bucket must expire with its hour, got ttl ${ttl}`);
    await rc.del(rk);
  } finally {
    a.stop(); b.stop();
    try { await rc.disconnect(); } catch (_) {}
  }
  did();
});

// ── 3. the per-IP limiters on the recipient routes ───────────────────────────

test('the public status route is capped at 30 requests a minute per client IP', async () => {
  const srv = await boot({ tag: 'rl-view', users: { api_keys: [] } });
  const ip = '10.9.1.1';
  for (let i = 1; i <= ENV_VIEW_LIMIT; i++) {
    const r = await srv.get('/v2/envelopes/Zm9vYmFyZm9vYmFyZm9vYmFyZm9v', { headers: { 'X-Real-IP': ip } });
    assert.notStrictEqual(r.status, 429, `request ${i} of ${ENV_VIEW_LIMIT} should have been allowed`);
  }
  const over = await srv.get('/v2/envelopes/Zm9vYmFyZm9vYmFyZm9vYmFyZm9v', { headers: { 'X-Real-IP': ip } });
  assert.strictEqual(over.status, 429);
  assert.strictEqual(over.headers['retry-after'], '60');

  // Another client is unaffected: the budget is per IP, not global.
  const other = await srv.get('/v2/envelopes/Zm9vYmFyZm9vYmFyZm9vYmFyZm9v', { headers: { 'X-Real-IP': '10.9.1.2' } });
  assert.notStrictEqual(other.status, 429);
  srv.stop();
  did();
});

test('the public sign route is capped at 10 a minute, and refuses BEFORE it does any work', async () => {
  // Order matters: the limiter sits ahead of the store lookup and the signature
  // verification (relay.js:5932-5934). If it ran after, a flood would still cost
  // a redis read and an ML-DSA verification per request, which is the expensive
  // half. The proof is that an over-limit request answers 429 while an
  // under-limit one answers 503 from the store check behind it.
  const srv = await boot({ tag: 'rl-sign', users: { api_keys: [] } });
  const ip = '10.9.2.1';
  const body = { party_index: 0, signer_public_key: 'AA==', signature: 'AA==' };
  for (let i = 1; i <= ENV_SIGN_LIMIT; i++) {
    const r = await srv.post('/v2/envelopes/Zm9vYmFyZm9vYmFyZm9vYmFyZm9v/sign', { headers: { 'X-Real-IP': ip }, body });
    assert.strictEqual(r.status, 503, `sign attempt ${i} reached the store check, as it should`);
  }
  const over = await srv.post('/v2/envelopes/Zm9vYmFyZm9vYmFyZm9vYmFyZm9v/sign', { headers: { 'X-Real-IP': ip }, body });
  assert.strictEqual(over.status, 429, 'the 11th signature attempt in a minute is refused');
  assert.deepStrictEqual(over.json, { error: 'Too many requests' });

  // The view budget is a different bucket: exhausting sign must not close view.
  const view = await srv.get('/v2/envelopes/Zm9vYmFyZm9vYmFyZm9vYmFyZm9v', { headers: { 'X-Real-IP': ip } });
  assert.notStrictEqual(view.status, 429, 'the two limiters must not share a bucket');
  srv.stop();
  did();
});
