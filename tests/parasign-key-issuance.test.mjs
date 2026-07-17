// ParaSign /v1 key issuance (psk_) - issuance generator + entitlement gate +
// quota metering + revoke, all dependency-injected (no redis, no relay boot;
// argon2 is not installable here, so the relay HTTP layer is exercised through
// its pure units exactly like the sibling parasign-open-api tests).
//
// Covers the mandated cases:
//   * generator: ONE builder → psk_live_/psk_test_, scope=parasign, bound to acct
//   * minted key authenticates against /v1 (200 on a /v1 route)
//   * full key is NEVER re-retrievable (only masked prefix+last4)
//   * revoke → the same key is rejected on /v1 (401)
//   * self-serve entitlement decision: no entitlement → deny, paid/grant → allow
//   * key → correct plan → correct ParaSign sign quota → 402 monthly_sign_quota_reached
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import keysTable from '../relay/lib/keys-table.js';
import v1 from '../relay/lib/parasign-open-api.js';
import quota from '../relay/lib/quota.js';
import tiers from '../relay/lib/tiers.js';
import entitlements from '../relay/lib/entitlements.js';

// ---- mocks (mirror tests/parasign-open-api.test.mjs) ------------------------
function mockRes() {
  return {
    statusCode: null, headers: null, body: null, ended: false,
    writeHead(code, headers) { this.statusCode = code; this.headers = headers || {}; },
    end(data) { this.body = data; this.ended = true; },
    json() { try { return JSON.parse(this.body); } catch { return null; } },
  };
}
const J = JSON.stringify;
const noop = () => {};
const relayIdentity = { sk: Buffer.alloc(32, 7), pk: Buffer.alloc(32, 9), pk_hash: 'deadbeef' };
const sigEngine = { sign: () => Buffer.from('sig-bytes') };
const canonicalJSON = (o) => JSON.stringify(o);
const PDF_B64 = Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n').toString('base64');
const ENV_ID = 'AAAAAAAAAAAAAAAAAAAAAA'; // 22 chars

function fakeStore() {
  return {
    async create(args) {
      return {
        id: ENV_ID, created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
        binding_mode: args.bindingMode, recipe_version: 2, party_count: args.parties.length,
        party_links: args.parties.map((_, i) => ({ party_index: i, sign_path: `/co-sign?env=${ENV_ID}&p=${i}&t=tok${i}`, invite_token: `tok${i}` })),
      };
    },
    async getRedacted(id) {
      if (id !== ENV_ID) return null;
      return {
        id, status: 'sent', doc_hash: 'a'.repeat(64), binding_mode: 'email', recipe_version: 2,
        original_filename: 'q.pdf', created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
        completed_at: null, voided_at: null, party_count: 1, signed_count: 0,
        parties: [{ index: 0, label: 'Jan', status: 'pending', signed_at: null, signer_pk_hash: null }],
      };
    },
    // The redaction rework (v1-authz-wall) routes GET status through getForReceipt,
    // a superset of getRedacted carrying the creator fingerprint for the owner check.
    // Empty creator_api_hash here means the caller sees the public redacted view.
    async getForReceipt(id) {
      if (id !== ENV_ID) return null;
      return {
        id, status: 'sent', doc_hash: 'a'.repeat(64), binding_mode: 'email',
        recipe_version: 2, effective_recipe: 2, original_filename: 'q.pdf',
        created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
        completed_at: null, voided_at: null, party_count: 1, signed_count: 0,
        creator_pk_hash: '', creator_api_hash: '',
        parties: [{ index: 0, label: 'Jan', email_hash: '', status: 'pending', signed_at: null, signer_pk_hash: null }],
      };
    },
  };
}

function baseDeps(over = {}) {
  return {
    req: {}, res: mockRes(), method: 'GET', path: `/v1/envelopes/${ENV_ID}`,
    query: {}, clientIp: '203.0.113.5', authHeader: '', publicOrigin: 'https://sign.example',
    apiKeys: new Map(), envStore: fakeStore(), envCreateRateOk: () => true,
    safeHttpsRequest: async () => ({ status: 200, body: Buffer.from('%PDF-1.7 x') }),
    canonicalJSON, sigEngine, relayIdentity,
    readBody: async () => Buffer.from('{}'),
    J, log: noop, ...over,
  };
}

// A minimal in-memory redis good enough for quota.gateSign (get/incr/expire).
function fakeRedis() {
  const m = new Map();
  return {
    isReady: true,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, String(v)); return 'OK'; },
    async incr(k) { const n = (parseInt(m.get(k) || '0', 10)) + 1; m.set(k, String(n)); return n; },
    async expire() { return 1; },
    async exists(k) { return m.has(k) ? 1 : 0; },
  };
}
// Exactly the wiring relay.js injects into the /v1 deps: the gate receives the
// key RECORD and meters against its ParaSign entitlement (plan_parasign, with a
// legacy-plan fallback).
function makeSignQuotaGate(redis) {
  return async (accountId, rec) => quota.gateSign(redis, accountId, entitlements.signsQuota(rec), noop);
}

const RAND = () => crypto.randomBytes(32).toString('hex');

// ---- 1) generator ----------------------------------------------------------
test('generator: buildParasignKeyRecord mints a live psk_ bound to the account with the parasign grant', () => {
  const b = keysTable.buildParasignKeyRecord({ accountId: 'acct_demo', plan: 'pro', email: 'demo@example.com', randomHex: RAND() });
  assert.match(b.key, /^psk_live_[0-9a-f]{64}$/);
  assert.equal(b.record.scope, 'parasign');
  assert.equal(b.record.parasign, true);
  assert.equal(b.record.product, 'parasign');
  assert.equal(b.record.account_id, 'acct_demo');
  assert.equal(b.record.is_primary, false);
  assert.equal(b.record.plan, 'pro');
  assert.equal(b.record.active, true);
  // Persisted users.json entry mirrors the in-memory record shape (no drift).
  assert.equal(b.usersEntry.key, b.key);
  assert.equal(b.usersEntry.scope, 'parasign');
  assert.equal(b.usersEntry.parasign, true);
});

test('generator: test flag yields a psk_test_ key (same single code path)', () => {
  const b = keysTable.buildParasignKeyRecord({ accountId: 'a', plan: 'pro', test: true, randomHex: RAND() });
  assert.match(b.key, /^psk_test_[0-9a-f]{64}$/);
  assert.equal(b.record.scope, 'parasign');
});

test('generator: missing accountId / randomHex is rejected', () => {
  assert.throws(() => keysTable.buildParasignKeyRecord({ plan: 'pro', randomHex: RAND() }));
  assert.throws(() => keysTable.buildParasignKeyRecord({ accountId: 'a', plan: 'pro' }));
});

// ---- 2) minted key authenticates against /v1 -------------------------------
test('minted key authenticates on /v1 (200 GET status)', async () => {
  const b = keysTable.buildParasignKeyRecord({ accountId: 'acct1', plan: 'pro', randomHex: RAND() });
  const apiKeys = new Map([[b.key, b.record]]);
  const d = baseDeps({ authHeader: `Bearer ${b.key}`, apiKeys });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.json().signer_count, 1);
});

// ---- 3) full key never re-retrievable, only masked -------------------------
test('masking: the full psk_ key is never exposed in a list projection', () => {
  const b = keysTable.buildParasignKeyRecord({ accountId: 'acct1', plan: 'pro', randomHex: RAND() });
  const masked = keysTable.maskApiKey(b.key);
  assert.notEqual(masked, b.key);
  assert.ok(!masked.includes(b.key.slice(9)), 'masked form must not contain the secret body');
  assert.match(masked, /^psk_live…[0-9a-f]{4}$/);
  // The mechanism that guarantees non-retrievability: only prefix+last4 survive.
  assert.ok(masked.length < b.key.length);
});

// ---- 4) revoke → rejected on /v1 -------------------------------------------
test('revoke: an inactive minted key is rejected on /v1 (401)', async () => {
  const b = keysTable.buildParasignKeyRecord({ accountId: 'acct1', plan: 'pro', randomHex: RAND() });
  const rec = { ...b.record, active: false }; // revoke sets active=false
  const apiKeys = new Map([[b.key, rec]]);
  const d = baseDeps({ authHeader: `Bearer ${b.key}`, apiKeys });
  await v1.route(d);
  assert.equal(d.res.statusCode, 401);
  assert.equal(d.res.json().error, 'unauthorized');
});

// ---- 5) self-serve entitlement decision ------------------------------------
test('entitlement: community account with no grant is NOT entitled (self-serve → 403 path)', () => {
  const members = [{ plan: 'community', parasign: false }];
  assert.equal(keysTable.accountHasParasignEntitlement(members, 'community'), false);
});
test('entitlement: an explicit grant on any member key entitles the account', () => {
  const members = [{ plan: 'community', parasign: false }, { plan: 'community', parasign: true }];
  assert.equal(keysTable.accountHasParasignEntitlement(members, 'community'), true);
});
test('entitlement: a paid plan (pro/enterprise/licensed) entitles the account', () => {
  assert.equal(keysTable.accountHasParasignEntitlement([{ plan: 'pro' }], 'pro'), true);
  assert.equal(keysTable.accountHasParasignEntitlement([{ plan: 'enterprise' }], 'enterprise'), true);
  assert.equal(keysTable.accountHasParasignEntitlement([{ plan: 'licensed' }], 'licensed'), true);
});

// ---- 6) key → plan → quota → 402 -------------------------------------------
test('quota: /v1 creates count against the plan ParaSign sign quota; overage → 402 monthly_sign_quota_reached', async () => {
  // A minted key on the community plan. community.signs_month = 2 (tiers.js).
  const b = keysTable.buildParasignKeyRecord({ accountId: 'acct_q', plan: 'community', randomHex: RAND() });
  const apiKeys = new Map([[b.key, b.record]]);
  const signQuotaGate = makeSignQuotaGate(fakeRedis());
  const body = J({ document: { content_base64: PDF_B64 }, signers: [{ name: 'A', email: 'a@b.nl' }] });
  const mkPost = () => baseDeps({ method: 'POST', path: '/v1/envelopes', authHeader: `Bearer ${b.key}`,
    apiKeys, envStore: fakeStore(), signQuotaGate, readBody: async () => Buffer.from(body) });

  const r1 = mkPost(); await v1.route(r1); assert.equal(r1.res.statusCode, 201, 'sign 1 of 2 allowed');
  const r2 = mkPost(); await v1.route(r2); assert.equal(r2.res.statusCode, 201, 'sign 2 of 2 allowed');
  const r3 = mkPost(); await v1.route(r3);
  assert.equal(r3.res.statusCode, 402, 'sign 3 over the community cap');
  assert.equal(r3.res.json().error, 'monthly_sign_quota_reached');
});

test('quota: an enterprise plan (unlimited signs) never hits the 402', async () => {
  const b = keysTable.buildParasignKeyRecord({ accountId: 'acct_ent', plan: 'enterprise', randomHex: RAND() });
  const apiKeys = new Map([[b.key, b.record]]);
  const signQuotaGate = makeSignQuotaGate(fakeRedis());
  const body = J({ document: { content_base64: PDF_B64 }, signers: [{ name: 'A', email: 'a@b.nl' }] });
  for (let i = 0; i < 5; i++) {
    const r = baseDeps({ method: 'POST', path: '/v1/envelopes', authHeader: `Bearer ${b.key}`,
      apiKeys, envStore: fakeStore(), signQuotaGate, readBody: async () => Buffer.from(body) });
    await v1.route(r);
    assert.equal(r.res.statusCode, 201, `enterprise sign ${i + 1} allowed`);
  }
});
