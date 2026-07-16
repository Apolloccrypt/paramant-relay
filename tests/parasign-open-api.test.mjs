// Focused tests for the ParaSign Open Developer-API (/v1) auth + scope gate and
// the core create/status/void mapping. Dependency-injected: no redis, no crypto
// engine boot — the envelope store and notary are faked, so this runs fast and
// deterministically and asserts the 200/201/401/403 contract the spec requires.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import v1 from '../relay/lib/parasign-open-api.js';

// ---- mocks ------------------------------------------------------------------
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

function fakeStore() {
  const created = [];
  return {
    created,
    async create(args) {
      created.push(args);
      const id = 'AAAAAAAAAAAAAAAAAAAAAA'; // 22 chars, matches /^[A-Za-z0-9_-]{20,64}$/
      return {
        id,
        created_at: '2026-07-16T10:00:00Z',
        expires_at: '2026-08-15T10:00:00Z',
        binding_mode: args.bindingMode,
        recipe_version: 2,
        party_count: args.parties.length,
        party_links: args.parties.map((_, i) => ({
          party_index: i,
          sign_path: `/co-sign?env=${id}&p=${i}&t=tok${i}`,
          invite_token: `tok${i}`,
        })),
      };
    },
    async getRedacted(id) {
      if (id !== 'AAAAAAAAAAAAAAAAAAAAAA') return null;
      return {
        id, status: 'sent', doc_hash: 'a'.repeat(64), binding_mode: 'email',
        recipe_version: 2, original_filename: 'q.pdf',
        created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
        completed_at: null, voided_at: null, party_count: 2, signed_count: 1,
        parties: [
          { index: 0, label: 'Jan', status: 'signed', signed_at: '2026-07-16T11:00:00Z', signer_pk_hash: 'p0' },
          { index: 1, label: 'Piet', status: 'pending', signed_at: null, signer_pk_hash: null },
        ],
      };
    },
    async voidEnvelope() { return { ok: true, code: 'void', status: 'void', voided_at: '2026-07-16T12:00:00Z' }; },
  };
}

function baseDeps(over = {}) {
  return {
    req: {}, res: mockRes(), method: 'GET', path: '/v1/envelopes/AAAAAAAAAAAAAAAAAAAAAA',
    query: {}, clientIp: '203.0.113.5', authHeader: '',
    publicOrigin: 'https://sign.example',
    apiKeys: new Map(), envStore: fakeStore(), envCreateRateOk: () => true,
    safeHttpsRequest: async () => ({ status: 200, body: Buffer.from('%PDF-1.7 x') }),
    canonicalJSON, sigEngine, relayIdentity,
    readBody: async () => Buffer.from(over.__body || '{}'),
    J, log: noop,
    ...over,
  };
}

const PDF_B64 = Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n').toString('base64');

// ---- tests ------------------------------------------------------------------
test('401 when no Authorization header', async () => {
  const d = baseDeps({ authHeader: '' });
  await v1.route(d);
  assert.equal(d.res.statusCode, 401);
  assert.equal(d.res.json().error, 'unauthorized');
});

test('401 when key is not a psk_ key', async () => {
  const d = baseDeps({ authHeader: 'Bearer pgp_' + 'x'.repeat(40) });
  await v1.route(d);
  assert.equal(d.res.statusCode, 401);
});

test('401 when psk_ key is unknown', async () => {
  const d = baseDeps({ authHeader: 'Bearer psk_live_unknownkey' });
  await v1.route(d);
  assert.equal(d.res.statusCode, 401);
});

test('403 when valid key lacks the parasign scope', async () => {
  const apiKeys = new Map([['psk_live_noscope', { plan: 'pro', active: true, scope: 'full' }]]);
  const d = baseDeps({ authHeader: 'Bearer psk_live_noscope', apiKeys });
  await v1.route(d);
  assert.equal(d.res.statusCode, 403);
  assert.equal(d.res.json().error, 'forbidden_scope');
});

test('200 GET status when key has parasign scope', async () => {
  const apiKeys = new Map([['psk_live_ok', { plan: 'pro', active: true, scope: 'parasign' }]]);
  const d = baseDeps({ authHeader: 'Bearer psk_live_ok', apiKeys });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  const b = d.res.json();
  assert.equal(b.status, 'in_progress');       // signed_count>0, not complete
  assert.equal(b.signer_count, 2);
  assert.equal(b.signed_count, 1);
});

test('200 GET status when key has ONLY the admin-grant parasign field (scope=full)', async () => {
  // Admin grant path: /v2/admin/keys/set-parasign flips a boolean `parasign`
  // flag on the key record while leaving the single-scope enum on 'full'.
  // hasParaSignScope() must honour that boolean, so the gate opens.
  const apiKeys = new Map([['psk_live_adminok', { plan: 'pro', active: true, scope: 'full', parasign: true }]]);
  const d = baseDeps({ authHeader: 'Bearer psk_live_adminok', apiKeys });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.json().signer_count, 2);
});

test('403 when the admin-grant field is explicitly false and scope is full', async () => {
  const apiKeys = new Map([['psk_live_off', { plan: 'pro', active: true, scope: 'full', parasign: false }]]);
  const d = baseDeps({ authHeader: 'Bearer psk_live_off', apiKeys });
  await v1.route(d);
  assert.equal(d.res.statusCode, 403);
  assert.equal(d.res.json().error, 'forbidden_scope');
});

test('200 when parasign is expressed via a scopes[] array', async () => {
  const apiKeys = new Map([['psk_live_arr', { plan: 'pro', active: true, scope: 'full', scopes: ['read-only', 'parasign'] }]]);
  const d = baseDeps({ authHeader: 'Bearer psk_live_arr', apiKeys });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
});

test('403 outranks 404: bad key never learns whether an envelope exists', async () => {
  const d = baseDeps({ authHeader: 'Bearer psk_live_noscope',
    apiKeys: new Map([['psk_live_noscope', { active: true, scope: 'full' }]]),
    path: '/v1/envelopes/doesnotexist999999999' });
  await v1.route(d);
  assert.equal(d.res.statusCode, 403);
});

test('201 POST /v1/envelopes creates + hashes + maps signers', async () => {
  const apiKeys = new Map([['psk_live_ok', { plan: 'pro', active: true, parasign: true, account_id: 'acct1' }]]);
  const store = fakeStore();
  const body = J({
    document: { content_base64: PDF_B64 },
    original_filename: 'offerte.pdf',
    signers: [{ name: 'Jan', email: 'jan@x.nl', order: 1 }, { name: 'Piet', email: 'piet@y.nl', order: 2 }],
    webhook_url: 'https://hooks.example/p',
    metadata: { quote_id: 'Q-1' },
  });
  const d = baseDeps({ method: 'POST', path: '/v1/envelopes', authHeader: 'Bearer psk_live_ok',
    apiKeys, envStore: store, readBody: async () => Buffer.from(body) });
  await v1.route(d);
  assert.equal(d.res.statusCode, 201);
  const b = d.res.json();
  assert.equal(b.status, 'sent');
  assert.equal(b.mode, 'live');
  assert.match(b.doc_hash, /^[0-9a-f]{64}$/);
  assert.equal(b.signers.length, 2);
  assert.equal(b.signers[0].sign_url, 'https://sign.example/co-sign?env=AAAAAAAAAAAAAAAAAAAAAA&p=0&t=tok0');
  assert.ok(b.webhook_secret && b.webhook_secret.length === 64);
  // store.create received a 64-hex sha3 doc hash + 2 parties in email mode.
  assert.match(store.created[0].docHash, /^[0-9a-f]{64}$/);
  assert.equal(store.created[0].parties.length, 2);
  assert.equal(store.created[0].bindingMode, 'email');
});

test('422 POST with a non-PDF body', async () => {
  const apiKeys = new Map([['psk_live_ok', { active: true, parasign: true }]]);
  const body = J({ document: { content_base64: Buffer.from('not a pdf').toString('base64') },
    signers: [{ name: 'A', email: 'a@b.nl' }] });
  const d = baseDeps({ method: 'POST', path: '/v1/envelopes', authHeader: 'Bearer psk_live_ok',
    apiKeys, readBody: async () => Buffer.from(body) });
  await v1.route(d);
  assert.equal(d.res.statusCode, 422);
  assert.equal(d.res.json().error, 'not_a_pdf');
});

test('200 POST /v1/envelopes/:id/void', async () => {
  const apiKeys = new Map([['psk_live_ok', { active: true, parasign: true }]]);
  const d = baseDeps({ method: 'POST', path: '/v1/envelopes/AAAAAAAAAAAAAAAAAAAAAA/void',
    authHeader: 'Bearer psk_live_ok', apiKeys, readBody: async () => Buffer.from('{"reason":"superseded"}') });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.json().status, 'void');
});

test('psk_test_ key is accepted and reported as mode=test', async () => {
  const apiKeys = new Map([['psk_test_ok', { active: true, parasign: true }]]);
  const body = J({ document: { content_base64: PDF_B64 }, signers: [{ name: 'A', email: 'a@b.nl' }] });
  const d = baseDeps({ method: 'POST', path: '/v1/envelopes', authHeader: 'Bearer psk_test_ok',
    apiKeys, readBody: async () => Buffer.from(body) });
  await v1.route(d);
  assert.equal(d.res.statusCode, 201);
  assert.equal(d.res.json().mode, 'test');
});
