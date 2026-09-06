'use strict';
// DID-auth principal tests (fase 1, item 1.4) — proves the paywall holds for
// keyless DID-auth requests. A DID never mints its own plan: it authenticates
// as the API key it was ENROLLED under, so entitlements and the monthly quota
// gates resolve against the OWNER's real plan and account, identical to a
// request carrying the owner's X-Api-Key. Revoked enrollments and revoked or
// deleted owner keys grant no principal at all.
//
// T1.4  DID-request zonder key krijgt de entitlements van het echte plan
// T1.5  DID-request boven quota geeft 402 (zelfde gate als een API-key)
// T1.6  DID-request van een ingetrokken enrollment wordt geweigerd

const { test, before, after } = require('node:test');
const assert = require('assert');
const { didPrincipal } = require('../lib/auth-gate');
const entitlements = require('../lib/entitlements');
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
// The owner key doubles as the quota account id, and the counters live in a
// shared redis, so it carries the run tag too.
const OWNER_KEY = scoped('pgp_owner_key');

before(async () => { rc = await requireRedis(DEFAULT_REDIS); });
after(async () => {
  if (rc) {
    for (const k of written) { try { await rc.del(k); } catch (_) {} }
    try { await rc.disconnect(); } catch (_) {}
  }
  summary('did-principal', quotaChecks);
});

// A community owner + the DID enrolled under that owner's key, exactly the
// shapes relay.js keeps in apiKeys / didRegistry.
function communityFixture() {
  const owner = { plan: 'community', active: true, label: 'Mick', email: 'm@example.org' };
  const apiKeys = new Map([[OWNER_KEY, owner]]);
  const didEntry = { device_id: 'phone-001', key: OWNER_KEY, doc: { id: 'did:paramant:abc' }, ts: '2026-07-01T00:00:00Z' };
  return { owner, apiKeys, didEntry };
}

// ── T1.4 — entitlements van het echte plan van de eigenaar ───────────────────

test('T1.4 DID-only principal carries the OWNER plan: community stays community, never pro', () => {
  const { owner, apiKeys, didEntry } = communityFixture();
  const p = didPrincipal(didEntry, (k) => apiKeys.get(k));
  assert.ok(p, 'valid enrollment under an active key yields a principal');
  assert.strictEqual(p.plan, 'community');
  assert.strictEqual(p.account_id, OWNER_KEY, 'quota counters key on the owner key, not the device');
  assert.strictEqual(p.label, 'phone-001', 'label is the device, for attribution only');

  // Entitlements resolved for the DID principal are byte-identical to the
  // entitlements of the owner record itself — the API-key path.
  const viaDid = entitlements.getEntitlements(p);
  const viaKey = entitlements.getEntitlements(owner);
  assert.deepStrictEqual(viaDid, viaKey, 'DID path and API-key path resolve the same entitlements');
  assert.strictEqual(viaDid.parasend.tier, 'community');
  assert.strictEqual(viaDid.parasign.tier, 'free');

  // And explicitly NOT the pro limits the old fallback forged.
  const pro = entitlements.getEntitlements({ plan: 'pro' });
  assert.notStrictEqual(viaDid.parasend.quotas.transfers_month, pro.parasend.quotas.transfers_month,
    'community DID principal must not receive the pro transfer quota');
  assert.notStrictEqual(viaDid.parasign.quotas.signs_month, pro.parasign.quotas.signs_month,
    'community DID principal must not receive the pro sign quota');
});

test('T1.4b an owner record without a plan field lands on the community floor, not pro', () => {
  const apiKeys = new Map([['pgp_k', { active: true }]]);
  const p = didPrincipal({ device_id: 'd1', key: 'pgp_k' }, (k) => apiKeys.get(k));
  assert.ok(p);
  assert.strictEqual(entitlements.getEntitlements(p).parasend.tier, 'community');
});

// ── T1.5 — boven quota: zelfde 402-beslissing als een API-key ────────────────

test('T1.5 DID-only request over the monthly transfer quota is declined like an API-key request', async () => {
  const { owner, apiKeys, didEntry } = communityFixture();
  const p = didPrincipal(didEntry, (k) => apiKeys.get(k));
  const limit = entitlements.getEntitlements(p).parasend.quotas.transfers_month;
  assert.strictEqual(limit, entitlements.transfersQuota(owner), 'limit equals the owner limit');

  if (!rc) return;
  const r = rc;
  const ACCT = p.account_id;
  track(quota.transfersKey(ACCT), quota.seenKey(ACCT, 'freshHashDid'), quota.seenKey(ACCT, 'freshHashKey'));
  await r.set(quota.transfersKey(ACCT), String(limit)); // owner account at cap

  // The exact call relay.js makes in POST /v2/inbound before returning 402
  // monthly_transfer_quota_reached — same gate, same account, same limit.
  const viaDid = await quota.gateTransfer(r, ACCT, 'freshHashDid', limit, null);
  assert.strictEqual(viaDid.allowed, false, 'DID request over quota is declined (402 path)'); quotaChecks++;
  assert.strictEqual(viaDid.over_limit, true); quotaChecks++;

  // The owner's API key resolves to the same account, so the same counter is
  // already at the cap and the answer has to match.
  const viaKey = await quota.gateTransfer(r, ACCT, 'freshHashKey', limit, null);
  assert.strictEqual(viaKey.allowed, false, 'the API-key path declines identically'); quotaChecks++;
});

test('T1.5b DID and API-key requests count on the SAME owner counter', async () => {
  const { apiKeys, didEntry } = communityFixture();
  const p = didPrincipal(didEntry, (k) => apiKeys.get(k));
  if (!rc) return;
  const r = rc;
  const ACCT = p.account_id;
  track(quota.transfersKey(ACCT), quota.seenKey(ACCT, 'hash1'), quota.seenKey(ACCT, 'hash2'));
  await r.del(quota.transfersKey(ACCT));
  await quota.gateTransfer(r, ACCT, 'hash1', 10, null);              // via DID
  await quota.gateTransfer(r, OWNER_KEY, 'hash2', 10, null);   // via API key
  assert.strictEqual(await r.get(quota.transfersKey(OWNER_KEY)), '2',
    'both paths increment one shared owner counter'); quotaChecks++;
});

test('T1.5c DID-only request over the monthly sign quota is declined like an API-key request', async () => {
  const { apiKeys, didEntry } = communityFixture();
  const p = didPrincipal(didEntry, (k) => apiKeys.get(k));
  const limit = entitlements.getEntitlements(p).parasign.quotas.signs_month;
  if (!rc) return;
  const r = rc;
  track(quota.signsKey(p.account_id));
  await r.set(quota.signsKey(p.account_id), String(limit));
  const g = await quota.gateSign(r, p.account_id, limit, null);
  assert.strictEqual(g.allowed, false, 'DID request over the signs cap is declined (402 path)');
});

// ── T1.6 — ingetrokken enrollment wordt geweigerd ────────────────────────────

test('T1.6 a revoked enrollment grants no principal', () => {
  const { apiKeys, didEntry } = communityFixture();
  assert.strictEqual(didPrincipal({ ...didEntry, revoked_at: '2026-07-19T12:00:00Z' }, (k) => apiKeys.get(k)), null,
    'revoked_at on the enrollment => refused');
  assert.strictEqual(didPrincipal({ ...didEntry, revoked: true }, (k) => apiKeys.get(k)), null,
    'revoked flag on the enrollment => refused');
});

test('T1.6b an enrollment whose owner key is revoked or deleted grants no principal', () => {
  const { owner, apiKeys, didEntry } = communityFixture();
  owner.active = false; // key intrekking: admin revoke zet active=false
  assert.strictEqual(didPrincipal(didEntry, (k) => apiKeys.get(k)), null, 'owner key revoked => refused');
  apiKeys.delete(OWNER_KEY); // key rotated/deleted (loadKeys drops inactive keys)
  assert.strictEqual(didPrincipal(didEntry, (k) => apiKeys.get(k)), null, 'owner key gone => refused');
});

test('T1.6c a keyless enrollment (inv_ receiver session) never becomes a principal', () => {
  const { apiKeys } = communityFixture();
  assert.strictEqual(didPrincipal({ device_id: 'inv_sess1', key: '' }, (k) => apiKeys.get(k)), null);
  assert.strictEqual(didPrincipal(null, (k) => apiKeys.get(k)), null);
  assert.strictEqual(didPrincipal(undefined, (k) => apiKeys.get(k)), null);
});
