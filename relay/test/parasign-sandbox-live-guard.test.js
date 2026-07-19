'use strict';
// Sandbox acceptance (Mick's extra requirement):
//  A) a psk_live_ key NEVER reaches sandboxAutoSign (mode='live' -> no auto-sign):
//     the throwaway signing engine's generateKeyPair is never called on a live
//     create, the envelope stays 'sent', and there is no _sandbox_note.
//  B) a psk_test_ create DOES auto-sign (generateKeyPair called, status completed).
//  C) the sandbox/test nature is baked INTO the notary-signed .psign evidence
//     (mode:'test' + sandbox:true, inside the signed payload); a live receipt
//     carries NO such marker.
// Needs the ML-DSA-65 engine (@paramant/core); skips if it cannot load.

const assert = require('assert');
const crypto = require('crypto');
const openApi = require('../lib/parasign-open-api');
const parasign = require('../parasign');

const SHA3 = (b) => crypto.createHash('sha3-256').update(b).digest('hex');
let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

function loadEngine() {
  try {
    require('../crypto/bootstrap').bootstrap();
    const eng = require('../crypto/registry').getSig(0x0002);
    if (eng && typeof eng.generateKeyPair === 'function') return eng;
  } catch (_) {}
  return null;
}

function makeRes() {
  return { code: 0, headers: null, body: null,
    writeHead(c, h) { this.code = c; this.headers = h; return this; },
    end(b) { this.body = b; return this; } };
}

// A minimal in-memory side-store standing in for lib/parasign-store.js.
function memStore() {
  const blobs = new Map(), metas = new Map();
  return {
    async putBlob(id, buf) { blobs.set(id, buf); },
    async getBlob(id) { return blobs.get(id) || null; },
    async delBlob(id) { blobs.delete(id); },
    async putMeta(id, m) { metas.set(id, m); },
    async getMeta(id) { return metas.get(id) || null; },
    async getStamped() { return null; }, async putStamped() {},
  };
}

// Fake envelope store: create() hands back the shape createEnvelope consumes;
// sign() accepts every slot (we are testing the sandbox gate, not the crypto,
// which parasign-sandbox.test.js already verifies end to end).
function makeEnvStore(N) {
  let signed = 0;
  return {
    async create({ parties }) {
      return {
        id: 'env_' + crypto.randomBytes(6).toString('hex'),
        expires_at: new Date(Date.now() + 30 * 86400_000).toISOString(),
        binding_mode: 'email', recipe_version: 2,
        party_links: parties.map((_, i) => ({ party_index: i, sign_path: '/sign/x' + i })),
      };
    },
    async sign() {
      signed++;
      return { ok: true, code: 'new', signed_count: signed, party_count: N,
        status: signed >= N ? 'complete' : 'sent' };
    },
  };
}

function makeDeps(eng, gpCounter) {
  const store = memStore();
  const body = Buffer.from(JSON.stringify({
    document: { content_base64: Buffer.from('%PDF-1.4\n% test\n').toString('base64') },
    signers: [{ name: 'Alice', email: 'alice@example.com' }],
    binding_mode: 'email',
  }));
  return {
    res: makeRes(),
    req: {},
    apiKeys: new Map(),
    envStore: makeEnvStore(1),
    store,
    stamp: null,
    publicOrigin: 'https://paramant.app',
    envCreateRateOk: async () => true,
    safeHttpsRequest: async () => ({ status: 200, body: Buffer.from('') }),
    canonicalJSON: parasign.canonicalJSON,
    // Spy engine: count generateKeyPair calls -> proves whether the sandbox ran.
    sigEngine: {
      generateKeyPair() { gpCounter.n++; return eng.generateKeyPair(); },
      sign: (m, sk) => eng.sign(m, sk),
      verify: (s, m, p) => eng.verify(s, m, p),
    },
    signQuotaGate: async () => ({ allowed: true, over_limit: false }),
    readBody: async () => body,
    J: JSON.stringify,
    log: () => {},
  };
}

async function testLiveGuard(eng) {
  const gp = { n: 0 };
  const deps = makeDeps(eng, gp);
  await openApi.createEnvelope(deps, 'psk_live_abcdef', 'live', { account_id: 'acctLive' });
  const out = JSON.parse(deps.res.body);
  assert.strictEqual(deps.res.code, 201, 'live create returns 201');
  assert.strictEqual(gp.n, 0, 'LIVE key never called the sandbox signing engine (no auto-sign)');
  assert.strictEqual(out.status, 'sent', 'live envelope stays sent (not auto-completed)');
  assert.strictEqual(out._sandbox_note, undefined, 'live create carries no sandbox note');
  assert.strictEqual(out.documents, null, 'live create exposes no completed documents');
  assert.strictEqual(out.signers[0].status, 'pending', 'live signer stays pending');
  ok('psk_live_ NEVER reaches sandboxAutoSign (mode=live -> no auto-sign)');
}

async function testTestSandbox(eng) {
  const gp = { n: 0 };
  const deps = makeDeps(eng, gp);
  await openApi.createEnvelope(deps, 'psk_test_abcdef', 'test', { account_id: 'acctTest' });
  const out = JSON.parse(deps.res.body);
  assert.strictEqual(deps.res.code, 201, 'test create returns 201');
  assert.ok(gp.n >= 1, 'TEST key DID drive the sandbox signing engine');
  assert.strictEqual(out.status, 'completed', 'test envelope auto-completes');
  assert.ok(/sandbox/i.test(out._sandbox_note || ''), 'test create reports the sandbox note');
  assert.strictEqual(out.signers[0].status, 'completed', 'test signer marked completed');
  ok('psk_test_ create is auto-signed by the sandbox signer');
}

// Drive getReceipt against a completed envelope with a given meta.mode and read
// the emitted .psign. Verifies the marker lives INSIDE the notary-signed body.
async function receiptFor(eng, mode) {
  const relayKp = eng.generateKeyPair();
  const relayIdentity = { sk: relayKp.secretKey, pk_hash: SHA3(Buffer.from(relayKp.publicKey)) };
  const token = 'psk_' + mode + '_owner123';
  const id = 'env_' + crypto.randomBytes(6).toString('hex');
  const env = {
    id, doc_hash: SHA3(Buffer.from('doc')), binding_mode: 'email',
    recipe_version: 2, effective_recipe: 2, status: 'complete',
    created_at: new Date().toISOString(), completed_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 86400_000).toISOString(),
    creator_api_hash: SHA3(Buffer.from(token)),   // makes isEnvelopeOwner(a) pass
    parties: [{ index: 0, label: 'Alice', email_hash: null, status: 'signed',
                signed_at: new Date().toISOString(), pk_b64: null, signer_pk_hash: 'x' }],
  };
  const store = memStore();
  await store.putMeta(id, { mode });
  const res = makeRes();
  const deps = {
    res, req: { headers: {} }, query: {}, envStore: { async getForReceipt() { return env; } },
    store, canonicalJSON: parasign.canonicalJSON, sigEngine: eng, relayIdentity,
    publicOrigin: 'https://paramant.app', J: JSON.stringify, log: () => {},
  };
  await openApi.getReceipt(deps, id, token, { account_id: 'acctX' });
  assert.strictEqual(res.code, 200, `[${mode}] receipt 200`);
  const psign = JSON.parse(res.body);
  // The notary signature must verify over the canonical body WITHOUT the sig,
  // i.e. exactly the payload that carries (or omits) the marker.
  const sig = Buffer.from(psign.notary_signature, 'base64');
  const clone = { ...psign }; delete clone.notary_signature;
  const canonical = parasign.canonicalJSON(clone);
  assert.ok(eng.verify(sig, Buffer.from(canonical, 'utf8'), Buffer.from(relayKp.publicKey)),
    `[${mode}] notary signature verifies over the marker-bearing body`);
  return { psign, canonical };
}

async function testReceiptMarker(eng) {
  const t = await receiptFor(eng, 'test');
  assert.strictEqual(t.psign.mode, 'test', 'test .psign carries mode:test');
  assert.strictEqual(t.psign.sandbox, true, 'test .psign carries sandbox:true');
  assert.ok(t.canonical.includes('"sandbox":true'), 'sandbox marker is inside the SIGNED payload');
  ok('sandbox .psign is flagged mode:test + sandbox:true in the signed evidence');

  const l = await receiptFor(eng, 'live');
  assert.strictEqual(l.psign.mode, undefined, 'live .psign has NO mode marker');
  assert.strictEqual(l.psign.sandbox, undefined, 'live .psign has NO sandbox marker');
  assert.ok(!l.canonical.includes('sandbox'), 'live signed payload never mentions sandbox');
  ok('live .psign carries NO test/sandbox marker');
}

async function main() {
  const eng = loadEngine();
  if (!eng) { console.log('  skip - ML-DSA-65 engine unavailable'); return; }
  await testLiveGuard(eng);
  await testTestSandbox(eng);
  await testReceiptMarker(eng);
}

main()
  .then(() => console.log(`\nparasign-sandbox-live-guard: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
