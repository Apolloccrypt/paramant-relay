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

const { test } = require('node:test');
const assert = require('assert');
const { didPrincipal } = require('../lib/auth-gate');
const entitlements = require('../lib/entitlements');
const quota = require('../lib/quota');

// Minimal in-memory Redis stub, same shape as quota-gate.test.js.
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

// A community owner + the DID enrolled under that owner's key, exactly the
// shapes relay.js keeps in apiKeys / didRegistry.
function communityFixture() {
  const owner = { plan: 'community', active: true, label: 'Mick', email: 'm@example.org' };
  const apiKeys = new Map([['pgp_owner_key', owner]]);
  const didEntry = { device_id: 'phone-001', key: 'pgp_owner_key', doc: { id: 'did:paramant:abc' }, ts: '2026-07-01T00:00:00Z' };
  return { owner, apiKeys, didEntry };
}

// ── T1.4 — entitlements van het echte plan van de eigenaar ───────────────────

test('T1.4 DID-only principal carries the OWNER plan: community stays community, never pro', () => {
  const { owner, apiKeys, didEntry } = communityFixture();
  const p = didPrincipal(didEntry, (k) => apiKeys.get(k));
  assert.ok(p, 'valid enrollment under an active key yields a principal');
  assert.strictEqual(p.plan, 'community');
  assert.strictEqual(p.account_id, 'pgp_owner_key', 'quota counters key on the owner key, not the device');
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

  const r = fakeRedis();
  r._store.set(quota.transfersKey(p.account_id), String(limit)); // owner account at cap

  // The exact call relay.js makes in POST /v2/inbound before returning 402
  // monthly_transfer_quota_reached — same gate, same account, same limit.
  const viaDid = await quota.gateTransfer(r, p.account_id, 'freshHashDid', limit, null);
  assert.strictEqual(viaDid.allowed, false, 'DID request over quota is declined (402 path)');
  assert.strictEqual(viaDid.over_limit, true);

  const viaKey = await quota.gateTransfer(r, 'pgp_owner_key', 'freshHashKey', limit, null);
  assert.strictEqual(viaKey.allowed, false, 'the API-key path declines identically');
});

test('T1.5b DID and API-key requests count on the SAME owner counter', async () => {
  const { apiKeys, didEntry } = communityFixture();
  const p = didPrincipal(didEntry, (k) => apiKeys.get(k));
  const r = fakeRedis();
  await quota.gateTransfer(r, p.account_id, 'hash1', 10, null);      // via DID
  await quota.gateTransfer(r, 'pgp_owner_key', 'hash2', 10, null);   // via API key
  assert.strictEqual(await r.get(quota.transfersKey('pgp_owner_key')), '2',
    'both paths increment one shared owner counter');
});

test('T1.5c DID-only request over the monthly sign quota is declined like an API-key request', async () => {
  const { apiKeys, didEntry } = communityFixture();
  const p = didPrincipal(didEntry, (k) => apiKeys.get(k));
  const limit = entitlements.getEntitlements(p).parasign.quotas.signs_month;
  const r = fakeRedis();
  r._store.set(quota.signsKey(p.account_id), String(limit));
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
  apiKeys.delete('pgp_owner_key'); // key rotated/deleted (loadKeys drops inactive keys)
  assert.strictEqual(didPrincipal(didEntry, (k) => apiKeys.get(k)), null, 'owner key gone => refused');
});

test('T1.6c a keyless enrollment (inv_ receiver session) never becomes a principal', () => {
  const { apiKeys } = communityFixture();
  assert.strictEqual(didPrincipal({ device_id: 'inv_sess1', key: '' }, (k) => apiKeys.get(k)), null);
  assert.strictEqual(didPrincipal(null, (k) => apiKeys.get(k)), null);
  assert.strictEqual(didPrincipal(undefined, (k) => apiKeys.get(k)), null);
});
