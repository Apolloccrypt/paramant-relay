'use strict';
// Unit tests for the ParaSign Open Developer-API (/v1) auth + authorization gate
// in relay/lib/parasign-open-api.js. This module is security-critical (it is the
// public front door to the envelope machinery) and was previously untested. These
// tests drive route() directly with injected fakes -- no redis, no network.
// Run: node relay/test/parasign-open-api.test.js (exits non-zero on failure).

const assert = require('assert');
const crypto = require('crypto');
const api = require('../lib/parasign-open-api');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

const J = (o) => JSON.stringify(o);
const SHA3 = (buf) => crypto.createHash('sha3-256').update(buf).digest('hex');

// ── fakes ─────────────────────────────────────────────────────────────────────
function fakeRes() {
  return {
    statusCode: null, headers: null, _body: '',
    writeHead(c, h) { this.statusCode = c; this.headers = h || {}; },
    end(b) { this._body = b == null ? '' : (Buffer.isBuffer(b) ? b : String(b)); },
    json() { try { return JSON.parse(this._body); } catch { return null; } },
  };
}

// A scoped, active psk_ key record.
const OWNER_KEY = 'psk_live_ownerkey000000000000';
const OTHER_KEY = 'psk_live_strangerkey0000000000';
const NOSCOPE_KEY = 'psk_live_noscopekey00000000000';
const apiKeys = new Map([
  [OWNER_KEY,   { active: true, parasign: true, account_id: 'acct_owner', plan: 'pro' }],
  [OTHER_KEY,   { active: true, parasign: true, account_id: 'acct_other', plan: 'pro' }],
  [NOSCOPE_KEY, { active: true, account_id: 'acct_ns', plan: 'pro' }],
  ['psk_live_revoked00000000000000', { active: false, parasign: true }],
]);

// An existing, completed envelope owned by OWNER_KEY (durable fingerprint).
function completedEnv() {
  return {
    id: 'envCompleted0000000001',
    status: 'complete',
    doc_hash: 'a'.repeat(64),
    binding_mode: 'email',
    recipe_version: '2',
    effective_recipe: 2,
    created_at: '2026-07-19T00:00:00Z',
    completed_at: '2026-07-19T01:00:00Z',
    expires_at: '2026-08-18T00:00:00Z',
    party_count: 1, signed_count: 1,
    creator_api_hash: SHA3(Buffer.from(OWNER_KEY)),
    parties: [{ index: 0, label: 'A. Jansen', status: 'signed', signed_at: '2026-07-19T01:00:00Z',
                email_hash: 'b'.repeat(64), pk_b64: 'PK', sig_b64: 'SIG', signer_pk_hash: 'c'.repeat(64) }],
  };
}

function makeDeps(over = {}) {
  const env = over.env !== undefined ? over.env : completedEnv();
  return Object.assign({
    req: { headers: over.headers || {} },
    res: fakeRes(),
    method: over.method || 'GET',
    path: over.path || '/v1/envelopes/envCompleted0000000001',
    query: over.query || {},
    clientIp: '203.0.113.9',
    authHeader: over.authHeader,
    publicOrigin: 'https://paramant.app',
    apiKeys,
    envStore: Object.assign({
      async getForReceipt() { return env; },
      async isParticipantToken() { return -1; },
      async voidEnvelope() { return { ok: true, code: 'void', voided_at: '2026-07-19T02:00:00Z' }; },
    }, over.envStore || {}),
    canonicalJSON: (o) => JSON.stringify(o),
    sigEngine: { sign: () => Buffer.from('notarysig') },
    relayIdentity: { pk_hash: 'relaypkhash', sk: Buffer.from('sk') },
    readBody: async () => Buffer.from(over.body || '{}'),
    J, log: () => {},
  }, over.deps || {});
}

const bearer = (k) => `Bearer ${k}`;

async function main() {
  // ── AUTH ──────────────────────────────────────────────────────────────────
  {
    const d = makeDeps({ authHeader: '' });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 401, 'no auth -> 401');
    assert.strictEqual(d.res.json().error, 'unauthorized');
    ok('missing Authorization -> 401 unauthorized');
  }
  {
    const d = makeDeps({ authHeader: 'Bearer not_a_psk_key' });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 401, 'non-psk -> 401');
    ok('non-psk bearer -> 401');
  }
  {
    const d = makeDeps({ authHeader: bearer('psk_live_unknownkey0000000000') });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 401, 'unknown key -> 401');
    ok('unknown psk_ key -> 401');
  }
  {
    const d = makeDeps({ authHeader: bearer('psk_live_revoked00000000000000') });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 401, 'revoked key -> 401');
    ok('revoked (active:false) key -> 401');
  }
  {
    const d = makeDeps({ authHeader: bearer(NOSCOPE_KEY) });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 403, 'no scope -> 403');
    assert.strictEqual(d.res.json().error, 'forbidden_scope');
    ok('valid key without parasign scope -> 403 forbidden_scope');
  }

  // ── AUTHORIZATION: receipt (owner OR participant), no-existence-leak ─────────
  {
    // stranger scoped key, not owner, not participant -> generic 404 (NOT 403),
    // so it cannot tell "not yours" from "does not exist".
    const d = makeDeps({ method: 'GET', path: '/v1/envelopes/envCompleted0000000001/receipt',
                         authHeader: bearer(OTHER_KEY) });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 404, 'stranger receipt -> 404');
    assert.strictEqual(d.res.json().error, 'not_found');
    ok('receipt by unrelated key -> generic 404 (no existence leak)');
  }
  {
    // owner by durable fingerprint -> 200 full .psign with raw signatures.
    const d = makeDeps({ method: 'GET', path: '/v1/envelopes/envCompleted0000000001/receipt',
                         authHeader: bearer(OWNER_KEY) });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 200, 'owner receipt -> 200');
    const psign = d.res.json();
    assert.strictEqual(psign.type, 'parasign-envelope-receipt');
    assert.strictEqual(psign.parties[0].signature, 'SIG', 'raw per-party signature present');
    assert.ok(psign.notary_signature, 'notary counter-signature present');
    ok('receipt by owner (fingerprint) -> 200 full .psign');
  }
  {
    // participant via invite token header -> 200.
    const d = makeDeps({ method: 'GET', path: '/v1/envelopes/envCompleted0000000001/receipt',
                         authHeader: bearer(OTHER_KEY),
                         headers: { 'x-parasign-invite-token': 'invite-abc' },
                         envStore: { async isParticipantToken(_id, tok) { return tok === 'invite-abc' ? 0 : -1; } } });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 200, 'participant receipt -> 200');
    ok('receipt by participant (invite token) -> 200');
  }

  // ── AUTHORIZATION: status read is redaction-aware ───────────────────────────
  {
    // stranger -> redacted: no signer name, no metadata.
    const d = makeDeps({ method: 'GET', path: '/v1/envelopes/envCompleted0000000001',
                         authHeader: bearer(OTHER_KEY) });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 200, 'status -> 200 for any scoped key');
    const b = d.res.json();
    assert.strictEqual(b.signers[0].name, undefined, 'stranger sees no signer name');
    assert.strictEqual(b.metadata, undefined, 'stranger sees no metadata');
    ok('status by stranger -> redacted (no name/metadata)');
  }
  {
    // owner -> rich: signer name present.
    const d = makeDeps({ method: 'GET', path: '/v1/envelopes/envCompleted0000000001',
                         authHeader: bearer(OWNER_KEY) });
    await api.route(d);
    const b = d.res.json();
    assert.strictEqual(b.signers[0].name, 'A. Jansen', 'owner sees signer name');
    ok('status by owner -> rich (name present)');
  }

  // ── AUTHORIZATION: void is OWNER-ONLY (participant must not void) ────────────
  {
    // participant with a valid invite token must NOT be able to void.
    const d = makeDeps({ method: 'POST', path: '/v1/envelopes/envCompleted0000000001/void',
                         authHeader: bearer(OTHER_KEY),
                         headers: { 'x-parasign-invite-token': 'invite-abc' },
                         env: Object.assign(completedEnv(), { status: 'sent' }),
                         envStore: { async isParticipantToken() { return 0; } } });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 404, 'participant void -> 404 (owner-only)');
    ok('void by participant -> 404 (owner-only, not participant)');
  }
  {
    // owner can void an open envelope.
    const d = makeDeps({ method: 'POST', path: '/v1/envelopes/envCompleted0000000001/void',
                         authHeader: bearer(OWNER_KEY),
                         env: Object.assign(completedEnv(), { status: 'sent' }) });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 200, 'owner void -> 200');
    assert.strictEqual(d.res.json().status, 'void');
    ok('void by owner -> 200 void');
  }

  // ── document is owner/participant-gated + 409 when not complete ─────────────
  {
    const d = makeDeps({ method: 'GET', path: '/v1/envelopes/envCompleted0000000001/document',
                         authHeader: bearer(OTHER_KEY) });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 404, 'stranger document -> 404');
    ok('document by unrelated key -> generic 404');
  }

  // ── envelope-id shape validation ────────────────────────────────────────────
  {
    const d = makeDeps({ method: 'GET', path: '/v1/envelopes/short', authHeader: bearer(OWNER_KEY) });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 404, 'bad id shape -> 404');
    ok('malformed envelope id -> 404');
  }

  console.log(`\nPASS parasign-open-api: ${passed} checks`);
}

main().catch((e) => { console.error('FAIL', e && e.stack || e); process.exit(1); });
