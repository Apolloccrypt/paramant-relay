// Focused tests for the ParaSign Open Developer-API (/v1) auth + scope gate and
// the core create/status/void mapping. Dependency-injected: no redis, no crypto
// engine boot - the envelope store and notary are faked, so this runs fast and
// deterministically and asserts the 200/201/401/403 contract the spec requires.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import v1 from '../relay/lib/parasign-open-api.js';
import envMod from '../relay/envelope.js';

const { EnvelopeStore, signMessageBytes, partyEmailHash } = envMod;

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
    async getForReceipt(id) {
      if (id !== 'AAAAAAAAAAAAAAAAAAAAAA') return null;
      // Superset of getRedacted with the durable creator fingerprint the status
      // handler needs for its owner check. Empty hash here -> the default keys
      // in these tests are NOT the owner, so they see the public redacted view.
      return {
        id, status: 'sent', doc_hash: 'a'.repeat(64), binding_mode: 'email',
        recipe_version: 2, effective_recipe: 2, original_filename: 'q.pdf',
        created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
        completed_at: null, voided_at: null, party_count: 2, signed_count: 1,
        creator_pk_hash: '', creator_api_hash: '',
        parties: [
          { index: 0, label: 'Jan', email_hash: '', status: 'signed', signed_at: '2026-07-16T11:00:00Z', signer_pk_hash: 'p0' },
          { index: 1, label: 'Piet', email_hash: '', status: 'pending', signed_at: null, signer_pk_hash: null },
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

test('200 POST /v1/envelopes/:id/void - the OWNER voids a non-completed envelope', async () => {
  // Owner-only gate: present the creating key (durable creator_api_hash match).
  const ID = 'EnvVoid0AAAAAAAAAAAAAAAAAAAA';
  const OWNER = 'psk_live_voidowner';
  const store = new EnvelopeStore(fakeRedis({
    id: ID, status: 'sent', doc_hash: 'a'.repeat(64), binding_mode: 'email',
    recipe_version: '2', party_count: '2', signed_count: '0',
    created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
    creator_api_hash: SHA3HEX(Buffer.from(OWNER)),
    p0_status: 'pending', p1_status: 'pending',
  }));
  const d = baseDeps({ method: 'POST', path: `/v1/envelopes/${ID}/void`,
    authHeader: 'Bearer ' + OWNER, req: { headers: {} },
    apiKeys: new Map([[OWNER, { active: true, parasign: true, account_id: 'acct_owner' }]]),
    envStore: store, readBody: async () => Buffer.from('{"reason":"superseded"}') });
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

// ===========================================================================
//  GET /v1/envelopes/:id/receipt - full multi-signer .psign + authorization
// ===========================================================================
// These exercise the REAL EnvelopeStore (over a fake Redis) so getForReceipt +
// isParticipantToken run for real, and a self-consistent fake ML-DSA engine so
// the returned .psign genuinely verifies (per-party signatures + notary).
const SHA3HEX = (buf) => crypto.createHash('sha3-256').update(buf).digest('hex');

// Fake ML-DSA-65 engine: sign(msg, sk) / verify(sig, msg, pub). Self-consistent
// via an internal pk->sk table so verify() succeeds from the public key alone.
function fakeSig() {
  const table = new Map(); // pk_b64 -> sk buffer
  const mac = (sk, msg) => crypto.createHash('sha3-256')
    .update(Buffer.concat([Buffer.from('FAKESIG'), sk, Buffer.from(msg)])).digest();
  return {
    keypair(seed) {
      const sk = crypto.createHash('sha3-256').update(Buffer.concat([Buffer.from('SK'), Buffer.from(seed)])).digest();
      const pk = crypto.createHash('sha3-256').update(Buffer.concat([Buffer.from('PK'), sk])).digest();
      table.set(pk.toString('base64'), sk);
      return { sk, pk, skB64: sk.toString('base64'), pkB64: pk.toString('base64') };
    },
    sign(msg, sk) { return mac(Buffer.from(sk), msg); },
    verify(sig, msg, pub) {
      const sk = table.get(Buffer.from(pub).toString('base64'));
      if (!sk) return false;
      const expect = mac(sk, msg);
      const s = Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
      return s.length === expect.length && crypto.timingSafeEqual(s, expect);
    },
  };
}

// Fake Redis exposing only what getForReceipt / isParticipantToken / void touch.
// hSet mutates the backing hash so the real EnvelopeStore.voidEnvelope state
// transition (sent -> void) round-trips through a subsequent read.
function fakeRedis(hash) {
  return {
    isReady: true,
    async hGetAll() { return { ...hash }; },
    async hGet(_k, f) { return hash[f]; },
    async hSet(_k, obj) { Object.assign(hash, obj); return Object.keys(obj || {}).length; },
  };
}

// Sorted-key canonical JSON (mirrors relay/parasign.canonicalJSON), used to sign
// AND verify the notary counter-signature so the round-trip is faithful.
function canon(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canon).join(',') + ']';
  return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canon(obj[k])).join(',') + '}';
}

// Build a COMPLETE multi-party envelope fixture with genuine fake signatures.
//   mode 'open'  -> effective recipe 4 (signer-pubkey bound), no email hashes.
//   mode 'email' -> recipe 2 (email-hash bound), per-party invite tokens.
function makeEnvelopeFixture(fs, { id, mode, ownerToken, emails }) {
  const docHash = 'a'.repeat(64);
  const relay = fs.keypair('relay-identity');
  const relayIdentity = { sk: relay.sk, pk: relay.pk, pk_hash: SHA3HEX(relay.pk) };
  const recipe = mode === 'open' ? 4 : 2;
  const hash = {
    id, status: 'complete', doc_hash: docHash, binding_mode: mode,
    recipe_version: mode === 'open' ? '1' : '2',
    party_count: '2', signed_count: '2',
    original_filename: 'contract.pdf',
    created_at: '2026-07-16T10:00:00Z', completed_at: '2026-07-16T12:00:00Z',
    expires_at: '2026-08-15T10:00:00Z',
    creator_pk_hash: 'ownerpkhash',
    creator_api_hash: SHA3HEX(Buffer.from(ownerToken)),
  };
  const inviteTokens = [];
  for (let i = 0; i < 2; i++) {
    const kp = fs.keypair('party-' + id + '-' + i);
    const emailHash = mode === 'email' ? partyEmailHash(emails[i]) : '';
    const msg = signMessageBytes(id, docHash, i, emailHash, recipe, kp.pkB64);
    const sigB64 = Buffer.from(fs.sign(msg, kp.sk)).toString('base64');
    hash['p' + i + '_label'] = 'Party ' + i;
    hash['p' + i + '_email_hash'] = emailHash;
    hash['p' + i + '_status'] = 'signed';
    hash['p' + i + '_signed_at'] = '2026-07-16T11:0' + i + ':00Z';
    hash['p' + i + '_sig'] = sigB64 + ':' + kp.pkB64;
    const tok = 'invite_tok_' + id + '_' + i;
    hash['p' + i + '_invite_token'] = tok;
    inviteTokens.push(tok);
  }
  const store = new EnvelopeStore(fakeRedis(hash));
  return { store, relayIdentity, docHash, inviteTokens, recipe };
}

function receiptDeps(fs, fx, { token, rec, id, query, headers }) {
  return baseDeps({
    method: 'GET', path: `/v1/envelopes/${id}/receipt`,
    authHeader: 'Bearer ' + token,
    apiKeys: new Map([[token, rec]]),
    envStore: fx.store,
    sigEngine: { sign: (msg, sk) => fs.sign(msg, sk) },
    relayIdentity: fx.relayIdentity,
    canonicalJSON: canon,
    query: query || {},
    req: { headers: headers || {} },
  });
}

const OPEN_ID  = 'EnvOpen0AAAAAAAAAAAAAAAAAAAA';
const EMAIL_ID = 'EnvMail0BBBBBBBBBBBBBBBBBBBB';

test('receipt: authorized OWNER gets the full multi-signer .psign with raw per-party signatures', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner01';
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: OWNER });
  const d = receiptDeps(fs, fx, {
    token: OWNER, id: OPEN_ID,
    rec: { active: true, parasign: true, account_id: 'acct_owner' },
  });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.headers['X-ParaSign-Receipt-Kind'], 'full-psign');
  const p = d.res.json();
  assert.equal(p.type, 'parasign-envelope-receipt');
  assert.equal(p.version, '2');
  assert.equal(p.parties.length, 2);
  // Raw per-party signatures + pubkeys are present (the whole point).
  for (const party of p.parties) {
    assert.ok(party.signature && party.signature.length > 10, 'party has raw signature');
    assert.ok(party.public_key && party.public_key.length > 10, 'party has raw pubkey');
  }
  assert.ok(p.notary_signature, 'notary counter-signature present');
});

test('receipt: returned .psign VALIDATES - every party signature + the notary signature verify', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner02';
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: OWNER });
  const d = receiptDeps(fs, fx, {
    token: OWNER, id: OPEN_ID,
    rec: { active: true, parasign: true, account_id: 'acct_owner' },
  });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  const p = d.res.json();

  // 1) Notary counter-signature over canonical(.psign minus notary_signature).
  const { notary_signature, ...rest } = p;
  const notaryOk = fs.verify(Buffer.from(notary_signature, 'base64'),
    Buffer.from(canon(rest), 'utf8'), fx.relayIdentity.pk);
  assert.equal(notaryOk, true, 'notary signature verifies against relay pubkey');

  // 2) Each party's raw ML-DSA signature over the reconstructed sign-message.
  for (const party of p.parties) {
    const msg = signMessageBytes(p.envelope_id, p.document_hash, party.index,
      party.email_hash || '', p.sign_recipe, party.public_key);
    const ok = fs.verify(Buffer.from(party.signature, 'base64'), msg,
      Buffer.from(party.public_key, 'base64'));
    assert.equal(ok, true, `party ${party.index} signature verifies`);
  }
});

test('receipt: authorized PARTICIPANT (valid invite token) gets the full .psign', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner03';
  const fx = makeEnvelopeFixture(fs, { id: EMAIL_ID, mode: 'email', ownerToken: OWNER,
    emails: ['jan@x.nl', 'piet@y.nl'] });
  // A DIFFERENT key/account, but it holds party 1's invite token -> participant.
  const d = receiptDeps(fs, fx, {
    token: 'psk_live_signer03', id: EMAIL_ID,
    rec: { active: true, parasign: true, account_id: 'acct_other' },
    query: { invite_token: fx.inviteTokens[1] },
  });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.json().parties.length, 2);
});

test('receipt: participant token accepted via X-ParaSign-Invite-Token header too', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner04';
  const fx = makeEnvelopeFixture(fs, { id: EMAIL_ID, mode: 'email', ownerToken: OWNER,
    emails: ['jan@x.nl', 'piet@y.nl'] });
  const d = receiptDeps(fs, fx, {
    token: 'psk_live_signer04', id: EMAIL_ID,
    rec: { active: true, parasign: true, account_id: 'acct_other' },
    headers: { 'x-parasign-invite-token': fx.inviteTokens[0] },
  });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
});

test('receipt: missing API key -> 401 (never reaches the store)', async () => {
  const fs = fakeSig();
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: 'psk_live_owner05' });
  const d = receiptDeps(fs, fx, { token: '', id: OPEN_ID, rec: {} });
  d.authHeader = '';
  await v1.route(d);
  assert.equal(d.res.statusCode, 401);
});

test('receipt: valid key WITHOUT parasign scope -> 403 (scope gate, before ownership)', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner06';
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: OWNER });
  // Present the OWNER key, but strip the scope: scope gate must still deny.
  const d = receiptDeps(fs, fx, {
    token: OWNER, id: OPEN_ID,
    rec: { active: true, scope: 'full' /* no parasign */ },
  });
  await v1.route(d);
  assert.equal(d.res.statusCode, 403);
  assert.equal(d.res.json().error, 'forbidden_scope');
});

test('receipt: valid key of ANOTHER account -> 404, does NOT leak that the envelope exists', async () => {
  const fs = fakeSig();
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: 'psk_live_owner07' });
  // A perfectly valid, scoped key - but neither the creator nor a participant.
  const d = receiptDeps(fs, fx, {
    token: 'psk_live_stranger07', id: OPEN_ID,
    rec: { active: true, parasign: true, account_id: 'acct_stranger' },
  });
  await v1.route(d);
  assert.equal(d.res.statusCode, 404);
  assert.equal(d.res.json().error, 'not_found');
  // Same 404 shape a genuinely-unknown id returns -> no existence oracle.
});

test('receipt: scoped key with a WRONG invite token (no participation) -> 404', async () => {
  const fs = fakeSig();
  const fx = makeEnvelopeFixture(fs, { id: EMAIL_ID, mode: 'email', ownerToken: 'psk_live_owner08',
    emails: ['jan@x.nl', 'piet@y.nl'] });
  const d = receiptDeps(fs, fx, {
    token: 'psk_live_stranger08', id: EMAIL_ID,
    rec: { active: true, parasign: true, account_id: 'acct_stranger' },
    query: { invite_token: 'not-a-real-token' },
  });
  await v1.route(d);
  assert.equal(d.res.statusCode, 404);
});

test('receipt: same-account sibling key (different key, same account_id) is authorized', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner09';
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: OWNER });
  // Seed the ephemeral meta side-record as create() would (owner's account).
  v1._meta.set(OPEN_ID, { accountId: 'acct_shared', ts: Date.now(), ttlMs: 3600_000 });
  const d = receiptDeps(fs, fx, {
    token: 'psk_live_sibling09', id: OPEN_ID,     // different key...
    rec: { active: true, parasign: true, account_id: 'acct_shared' }, // ...same account
  });
  await v1.route(d);
  v1._meta.delete(OPEN_ID);
  assert.equal(d.res.statusCode, 200);
});

test('receipt: not-completed envelope -> 409, but only AFTER authorization (no state leak to strangers)', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner10';
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: OWNER });
  // Force the fixture to look still-open by re-driving getForReceipt off a hash
  // whose status is 'sent'. Simplest: a stranger must get 404 (not 409) here.
  const strangerFx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: OWNER });
  // Owner sees 409 when incomplete:
  const incompleteStore = new EnvelopeStore(fakeRedis({
    id: OPEN_ID, status: 'sent', doc_hash: 'a'.repeat(64), binding_mode: 'open',
    recipe_version: '1', party_count: '2', signed_count: '1',
    created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
    creator_api_hash: SHA3HEX(Buffer.from(OWNER)),
    p0_status: 'signed', p1_status: 'pending',
  }));
  const dOwner = baseDeps({
    method: 'GET', path: `/v1/envelopes/${OPEN_ID}/receipt`, authHeader: 'Bearer ' + OWNER,
    apiKeys: new Map([[OWNER, { active: true, parasign: true, account_id: 'acct_owner' }]]),
    envStore: incompleteStore, sigEngine: { sign: (m, sk) => fs.sign(m, sk) },
    relayIdentity: fx.relayIdentity, canonicalJSON: canon, query: {}, req: { headers: {} },
  });
  await v1.route(dOwner);
  assert.equal(dOwner.res.statusCode, 409);

  // A stranger against the SAME incomplete envelope must get 404, not 409.
  const dStranger = baseDeps({
    method: 'GET', path: `/v1/envelopes/${OPEN_ID}/receipt`, authHeader: 'Bearer psk_live_stranger10',
    apiKeys: new Map([['psk_live_stranger10', { active: true, parasign: true, account_id: 'x' }]]),
    envStore: incompleteStore, sigEngine: { sign: (m, sk) => fs.sign(m, sk) },
    relayIdentity: fx.relayIdentity, canonicalJSON: canon, query: {}, req: { headers: {} },
  });
  await v1.route(dStranger);
  assert.equal(dStranger.res.statusCode, 404);
});

test('getForReceipt: exposes raw sig/pubkey split + creator fingerprints; getRedacted stays redacted', async () => {
  const fs = fakeSig();
  const OWNER = 'psk_live_owner11';
  const fx = makeEnvelopeFixture(fs, { id: OPEN_ID, mode: 'open', ownerToken: OWNER });
  const rec = await fx.store.getForReceipt(OPEN_ID);
  assert.equal(rec.party_count, 2);
  assert.equal(rec.effective_recipe, 4);                 // open -> v4
  assert.equal(rec.creator_api_hash, SHA3HEX(Buffer.from(OWNER)));
  for (const p of rec.parties) {
    assert.ok(p.sig_b64 && p.pk_b64, 'raw signature + pubkey split out');
    assert.ok(p.signer_pk_hash, 'signer_pk_hash derived');
  }
});

// ===========================================================================
//  POST /v1/envelopes/:id/void - OWNER-ONLY per-envelope authorization
// ===========================================================================
// void tears down the WHOLE envelope, so the gate is stricter than receipt:
// only the OWNER (creator fingerprint / same account) may void; a PARTICIPANT
// holding a valid invite token must NOT. Every failure collapses to a generic
// 404, and authorization runs BEFORE the store's state branches (the 409).

// A minimal, voidable envelope over the real EnvelopeStore + fakeRedis: carries
// the durable creator_api_hash and per-party invite tokens so both the owner
// (path a) and participant (path c, receipt-only) gates run for real.
function voidableStore({ id, status, ownerToken }) {
  const hash = {
    id, status, doc_hash: 'a'.repeat(64), binding_mode: 'email',
    recipe_version: '2', party_count: '2', signed_count: '0',
    original_filename: 'contract.pdf',
    created_at: '2026-07-16T10:00:00Z', expires_at: '2026-08-15T10:00:00Z',
    completed_at: status === 'complete' ? '2026-07-16T12:00:00Z' : null,
    creator_api_hash: SHA3HEX(Buffer.from(ownerToken)),
  };
  const inviteTokens = [];
  for (let i = 0; i < 2; i++) {
    hash['p' + i + '_status'] = status === 'complete' ? 'signed' : 'pending';
    const tok = 'invite_tok_' + id + '_' + i;
    hash['p' + i + '_invite_token'] = tok;
    inviteTokens.push(tok);
  }
  return { store: new EnvelopeStore(fakeRedis(hash)), inviteTokens };
}

function voidDeps({ token, rec, id, store, query, headers, body }) {
  return baseDeps({
    method: 'POST', path: `/v1/envelopes/${id}/void`,
    authHeader: token ? 'Bearer ' + token : '',
    apiKeys: new Map(rec ? [[token, rec]] : []),
    envStore: store, query: query || {}, req: { headers: headers || {} },
    readBody: async () => Buffer.from(body || '{}'),
  });
}

const VOID_ID = 'EnvVoidNAAAAAAAAAAAAAAAAAAAA';

test('void: missing API key -> 401 (never reaches the store)', async () => {
  const { store } = voidableStore({ id: VOID_ID, status: 'sent', ownerToken: 'psk_live_vo1' });
  const d = voidDeps({ token: '', rec: null, id: VOID_ID, store });
  d.authHeader = '';
  await v1.route(d);
  assert.equal(d.res.statusCode, 401);
});

test('void: valid key WITHOUT the parasign scope -> 403 (scope gate before ownership)', async () => {
  const OWNER = 'psk_live_vo2';
  const { store } = voidableStore({ id: VOID_ID, status: 'sent', ownerToken: OWNER });
  const d = voidDeps({ token: OWNER, rec: { active: true, scope: 'full' }, id: VOID_ID, store });
  await v1.route(d);
  assert.equal(d.res.statusCode, 403);
  assert.equal(d.res.json().error, 'forbidden_scope');
});

test('void: valid scoped key of ANOTHER account -> 404, no existence leak', async () => {
  const { store } = voidableStore({ id: VOID_ID, status: 'sent', ownerToken: 'psk_live_vo3owner' });
  const d = voidDeps({ token: 'psk_live_vo3stranger',
    rec: { active: true, parasign: true, account_id: 'acct_stranger' }, id: VOID_ID, store });
  await v1.route(d);
  assert.equal(d.res.statusCode, 404);
  assert.equal(d.res.json().error, 'not_found');
});

test('void: a PARTICIPANT with a VALID invite token may NOT void -> 404 (owner-only)', async () => {
  const { store, inviteTokens } = voidableStore({ id: VOID_ID, status: 'sent', ownerToken: 'psk_live_vo4owner' });
  // This exact token would PASS the receipt gate -- but void is owner-only.
  const d = voidDeps({ token: 'psk_live_vo4signer',
    rec: { active: true, parasign: true, account_id: 'acct_signer' }, id: VOID_ID, store,
    query: { invite_token: inviteTokens[1] } });
  await v1.route(d);
  assert.equal(d.res.statusCode, 404);
  assert.equal(d.res.json().error, 'not_found');
});

test('void: the OWNER voids a non-completed envelope -> 200 { status: void }', async () => {
  const OWNER = 'psk_live_vo5owner';
  const { store } = voidableStore({ id: VOID_ID, status: 'sent', ownerToken: OWNER });
  const d = voidDeps({ token: OWNER, rec: { active: true, parasign: true, account_id: 'acct_owner' },
    id: VOID_ID, store, body: '{"reason":"superseded"}' });
  await v1.route(d);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.json().status, 'void');
  assert.ok(d.res.json().voided_at, 'voided_at present');
});

test('void: already-completed -> 409 for the OWNER but 404 for a STRANGER (authorization before the 409)', async () => {
  const OWNER = 'psk_live_vo6owner';
  // Owner reaches the state branch: a completed envelope cannot be voided (409).
  const ownerFx = voidableStore({ id: VOID_ID, status: 'complete', ownerToken: OWNER });
  const dOwner = voidDeps({ token: OWNER, rec: { active: true, parasign: true, account_id: 'acct_owner' },
    id: VOID_ID, store: ownerFx.store });
  await v1.route(dOwner);
  assert.equal(dOwner.res.statusCode, 409);
  assert.equal(dOwner.res.json().error, 'already_complete');
  // A stranger against the SAME completed envelope must get 404, never the 409.
  const strangerFx = voidableStore({ id: VOID_ID, status: 'complete', ownerToken: OWNER });
  const dStranger = voidDeps({ token: 'psk_live_vo6stranger',
    rec: { active: true, parasign: true, account_id: 'acct_stranger' }, id: VOID_ID, store: strangerFx.store });
  await v1.route(dStranger);
  assert.equal(dStranger.res.statusCode, 404);
});

// ===========================================================================
//  GET /v1/envelopes/:id/document - OWNER-OR-PARTICIPANT (serves signed PDF)
// ===========================================================================
// The document route returns the actual signed PDF bytes, so it carries the
// SAME per-envelope gate as the receipt: OWNER or PARTICIPANT (valid invite
// token). A participant IS allowed here (a signer may fetch the final PDF) --
// that is where it differs from void. Failures collapse to a generic 404 and
// authorization precedes the 409 not_ready branch.

function docDeps({ token, rec, id, store, query, headers }) {
  return baseDeps({
    method: 'GET', path: `/v1/envelopes/${id}/document`,
    authHeader: token ? 'Bearer ' + token : '',
    apiKeys: new Map(rec ? [[token, rec]] : []),
    envStore: store, query: query || {}, req: { headers: headers || {} },
  });
}

const DOC_ID = 'EnvDoc00AAAAAAAAAAAAAAAAAAAA';

test('document: missing API key -> 401 (never reaches the store)', async () => {
  const { store } = voidableStore({ id: DOC_ID, status: 'complete', ownerToken: 'psk_live_do1' });
  const d = docDeps({ token: '', rec: null, id: DOC_ID, store });
  d.authHeader = '';
  await v1.route(d);
  assert.equal(d.res.statusCode, 401);
});

test('document: valid key WITHOUT the parasign scope -> 403 (scope gate before ownership)', async () => {
  const OWNER = 'psk_live_do2';
  const { store } = voidableStore({ id: DOC_ID, status: 'complete', ownerToken: OWNER });
  const d = docDeps({ token: OWNER, rec: { active: true, scope: 'full' }, id: DOC_ID, store });
  await v1.route(d);
  assert.equal(d.res.statusCode, 403);
  assert.equal(d.res.json().error, 'forbidden_scope');
});

test('document: valid scoped key of ANOTHER account -> 404 even with the blob present (no leak)', async () => {
  const { store } = voidableStore({ id: DOC_ID, status: 'complete', ownerToken: 'psk_live_do3owner' });
  v1._blobs.set(DOC_ID, { pdf: Buffer.from('%PDF-1.7 signed'), filename: 'contract.pdf' });
  const d = docDeps({ token: 'psk_live_do3stranger',
    rec: { active: true, parasign: true, account_id: 'acct_stranger' }, id: DOC_ID, store });
  await v1.route(d);
  v1._blobs.delete(DOC_ID);
  assert.equal(d.res.statusCode, 404);
  assert.equal(d.res.json().error, 'not_found');
});

test('document: an authorized PARTICIPANT (valid invite token) DOES get the signed PDF -> 200', async () => {
  const { store, inviteTokens } = voidableStore({ id: DOC_ID, status: 'complete', ownerToken: 'psk_live_do4owner' });
  v1._blobs.set(DOC_ID, { pdf: Buffer.from('%PDF-1.7 signed'), filename: 'contract.pdf' });
  const d = docDeps({ token: 'psk_live_do4signer',
    rec: { active: true, parasign: true, account_id: 'acct_signer' }, id: DOC_ID, store,
    headers: { 'x-parasign-invite-token': inviteTokens[0] } });
  await v1.route(d);
  v1._blobs.delete(DOC_ID);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.headers['Content-Type'], 'application/pdf');
});

test('document: the OWNER gets the signed PDF -> 200', async () => {
  const OWNER = 'psk_live_do5owner';
  const { store } = voidableStore({ id: DOC_ID, status: 'complete', ownerToken: OWNER });
  v1._blobs.set(DOC_ID, { pdf: Buffer.from('%PDF-1.7 signed'), filename: 'contract.pdf' });
  const d = docDeps({ token: OWNER, rec: { active: true, parasign: true, account_id: 'acct_owner' }, id: DOC_ID, store });
  await v1.route(d);
  v1._blobs.delete(DOC_ID);
  assert.equal(d.res.statusCode, 200);
  assert.equal(d.res.headers['Content-Type'], 'application/pdf');
});

test('document: not-completed -> 409 for the OWNER but 404 for a STRANGER (authorization before the 409)', async () => {
  const OWNER = 'psk_live_do6owner';
  const ownerFx = voidableStore({ id: DOC_ID, status: 'sent', ownerToken: OWNER });
  const dOwner = docDeps({ token: OWNER, rec: { active: true, parasign: true, account_id: 'acct_owner' },
    id: DOC_ID, store: ownerFx.store });
  await v1.route(dOwner);
  assert.equal(dOwner.res.statusCode, 409);
  assert.equal(dOwner.res.json().error, 'not_ready');
  const strangerFx = voidableStore({ id: DOC_ID, status: 'sent', ownerToken: OWNER });
  const dStranger = docDeps({ token: 'psk_live_do6stranger',
    rec: { active: true, parasign: true, account_id: 'acct_stranger' }, id: DOC_ID, store: strangerFx.store });
  await v1.route(dStranger);
  assert.equal(dStranger.res.statusCode, 404);
});

// ===========================================================================
//  GET /v1/envelopes/:id (status) - authorization-aware redaction
// ===========================================================================
// The status view stays reachable to any scoped key (a deliberate progress
// oracle: per-party pending/signed + counts + timestamps) but must NOT leak
// identities or commercial data. Only the OWNER or a PARTICIPANT gets the rich
// view (signer names + creator metadata); everyone else gets it redacted.

function statusDeps({ token, rec, id, store, query, headers }) {
  return baseDeps({
    method: 'GET', path: `/v1/envelopes/${id}`,
    authHeader: token ? 'Bearer ' + token : '',
    apiKeys: new Map(rec ? [[token, rec]] : []),
    envStore: store, query: query || {}, req: { headers: headers || {} },
  });
}

const STATUS_ID = 'EnvStat0AAAAAAAAAAAAAAAAAAAA';
// Seed the ephemeral side-record exactly as create() would: real signer names +
// commercial metadata. If redaction regressed, these strings would surface.
function seedStatusMeta(id) {
  v1._meta.set(id, { signers: [{ name: 'Jan Jansen' }, { name: 'Piet Peters' }],
    metadata: { quote_id: 'Q-42' }, ts: Date.now(), ttlMs: 3600_000 });
}

test('status: a scoped STRANGER key gets the PUBLIC view -> counts + per-party status, but NO names and NO metadata', async () => {
  const { store } = voidableStore({ id: STATUS_ID, status: 'sent', ownerToken: 'psk_live_st1owner' });
  seedStatusMeta(STATUS_ID);
  const d = statusDeps({ token: 'psk_live_st1stranger',
    rec: { active: true, parasign: true, account_id: 'acct_stranger' }, id: STATUS_ID, store });
  await v1.route(d);
  v1._meta.delete(STATUS_ID);
  const b = d.res.json();
  assert.equal(d.res.statusCode, 200);
  // Progress oracle IS present (the feature we keep).
  assert.equal(b.signer_count, 2);
  assert.equal(b.signers.length, 2);
  assert.ok(['pending', 'viewed', 'signed'].includes(b.signers[0].status));
  // But NOTHING identifying or commercial.
  for (const s of b.signers) assert.ok(!('name' in s), 'no signer name field in the public view');
  assert.ok(!('metadata' in b), 'no creator metadata field in the public view');
  const dump = JSON.stringify(b);
  assert.equal(dump.indexOf('Q-42'), -1, 'quote_id absent from the public view');
  assert.equal(dump.indexOf('Jansen'), -1, 'signer name absent from the public view');
});

test('status: the OWNER gets the RICH view -> signer names + creator metadata (quote_id)', async () => {
  const OWNER = 'psk_live_st2owner';
  const { store } = voidableStore({ id: STATUS_ID, status: 'sent', ownerToken: OWNER });
  seedStatusMeta(STATUS_ID);
  const d = statusDeps({ token: OWNER, rec: { active: true, parasign: true, account_id: 'acct_owner' }, id: STATUS_ID, store });
  await v1.route(d);
  v1._meta.delete(STATUS_ID);
  const b = d.res.json();
  assert.equal(d.res.statusCode, 200);
  assert.equal(b.signers[0].name, 'Jan Jansen');
  assert.equal(b.signers[1].name, 'Piet Peters');
  assert.equal(b.metadata.quote_id, 'Q-42');
});

test('status: an authorized PARTICIPANT (valid invite token) also gets the rich view', async () => {
  const { store, inviteTokens } = voidableStore({ id: STATUS_ID, status: 'sent', ownerToken: 'psk_live_st3owner' });
  seedStatusMeta(STATUS_ID);
  const d = statusDeps({ token: 'psk_live_st3signer',
    rec: { active: true, parasign: true, account_id: 'acct_signer' }, id: STATUS_ID, store,
    query: { invite_token: inviteTokens[0] } });
  await v1.route(d);
  v1._meta.delete(STATUS_ID);
  const b = d.res.json();
  assert.equal(d.res.statusCode, 200);
  assert.equal(b.signers[0].name, 'Jan Jansen');
  assert.equal(b.metadata.quote_id, 'Q-42');
});
