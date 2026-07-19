'use strict';
// ParaSign /v1 END-TO-END through the real route() with a real EnvelopeStore, a
// real durable encrypted side-store, and the real ML-DSA-65 engine. Exercises,
// in one flow: durable-store persistence (Point 1), the sandbox auto-signer
// (Point 4), the server-side stamp-worker (Point 2), the full .psign receipt,
// and webhook_url validation at create (Point 6).
// Needs redis (REDIS_URL / 127.0.0.1:6399) + @paramant/core; skips otherwise.
//   docker run -d --rm -p 6399:6379 --name parasign-test-redis redis:alpine

const assert = require('assert');
const crypto = require('crypto');
const openApi = require('../lib/parasign-open-api');
const parasignStoreMod = require('../lib/parasign-store');
const parasignStamp = require('../lib/parasign-stamp');
const envelopeMod = require('../envelope');
const parasign = require('../parasign');
const { isSsrfSafeUrl } = require('../lib/ssrf-guard');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

function loadEngine() {
  try {
    require('../crypto/bootstrap').bootstrap();
    const registry = require('../crypto/registry');
    const eng = registry.getSig(0x0002);
    if (eng && typeof eng.generateKeyPair === 'function') return eng;
  } catch (_) {}
  return null;
}
async function tryRedis() {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6399';
  let createClient;
  try { ({ createClient } = require('redis')); } catch { return null; }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); return rc; } catch { try { await rc.disconnect(); } catch {} return null; }
}
async function makePdfB64() {
  const { PDFDocument, StandardFonts, rgb } = parasignStamp.loadPdfLib();
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const p = doc.addPage([595, 842]);
  p.drawText('Agreement', { x: 60, y: 780, size: 18, font, color: rgb(0, 0, 0) });
  return Buffer.from(await doc.save()).toString('base64');
}

function mockRes() {
  return {
    statusCode: null, headers: {}, chunks: [],
    writeHead(code, hdrs) { this.statusCode = code; Object.assign(this.headers, hdrs || {}); return this; },
    end(data) { if (data != null) this.chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data))); this.ended = true; return this; },
    body() { return Buffer.concat(this.chunks); },
    json() { return JSON.parse(this.body().toString()); },
  };
}

async function main() {
  const eng = loadEngine();
  const rc = await tryRedis();
  if (!eng || !rc) { console.log('  skip - need redis + ML-DSA-65 engine'); console.log(`\nparasign-open-api-e2e: ${passed} checks passed`); if (rc) try { await rc.disconnect(); } catch {} return; }

  const registry = require('../crypto/registry');
  try {
    const encKey = crypto.randomBytes(32);
    const store = parasignStoreMod.createParaSignStore({ redis: rc, encKey });
    const envStore = new envelopeMod.EnvelopeStore(rc, {
      ctAppend: () => null,
      sigVerify: (sig, msg, pub) => { try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch { return false; } },
    });
    const kp = eng.generateKeyPair();
    const relayIdentity = { sk: Buffer.from(kp.secretKey), pk: Buffer.from(kp.publicKey), pk_hash: crypto.createHash('sha3-256').update(kp.publicKey).digest('hex') };

    const TOKEN = 'psk_test_' + crypto.randomBytes(12).toString('hex');
    const apiKeys = new Map([[TOKEN, { active: true, parasign: true, account_id: 'acct_e2e', plan: 'pro' }]]);

    const webhookCalls = [];
    const baseDeps = (over) => Object.assign({
      apiKeys, envStore, store, stamp: parasignStamp,
      publicOrigin: 'https://paramant.app',
      authHeader: 'Bearer ' + TOKEN,
      query: {},
      envCreateRateOk: async () => true,
      canonicalJSON: parasign.canonicalJSON,
      sigEngine: eng, relayIdentity,
      safeHttpsRequest: async (url, o) => { webhookCalls.push({ url, event: o && o.headers && o.headers['X-Paramant-Event'] }); return { status: 200 }; },
      J: JSON.stringify, log: () => {},
    }, over);

    async function call(method, path, bodyObj, over) {
      const res = mockRes();
      const bodyBuf = bodyObj === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(bodyObj));
      const req = { headers: { authorization: 'Bearer ' + TOKEN }, };
      const deps = baseDeps(Object.assign({ req, res, method, path, readBody: async () => bodyBuf }, over));
      await openApi.route(deps);
      return res;
    }

    // ── 1) CREATE (test mode) -> sandbox auto-signs -> completed ──────────────
    const pdfB64 = await makePdfB64();
    let res = await call('POST', '/v1/envelopes', {
      document: { content_base64: pdfB64 },
      binding_mode: 'open',
      original_filename: 'agreement.pdf',
      signers: [{ name: 'Alice', email: 'alice@example.com' }, { name: 'Bob', email: 'bob@example.com' }],
    });
    assert.strictEqual(res.statusCode, 201, 'create returns 201');
    const created = res.json();
    assert.strictEqual(created.status, 'completed', 'test envelope auto-completed by the sandbox signer');
    assert.ok(created.signers.every(s => s.status === 'completed'), 'all signer slots completed');
    assert.ok(created.documents && created.documents.signed_pdf, 'documents links exposed on completion');
    const id = created.id;
    ok('CREATE (psk_test_) auto-signs to completed via the sandbox signer');

    // ── 1b) DURABILITY: a FRESH store instance (restart) still has the blob ───
    const store2 = parasignStoreMod.createParaSignStore({ redis: rc, encKey });
    assert.ok(await store2.getBlob(id), 'document blob survives a fresh store instance (restart-durable)');
    assert.ok((await store2.getMeta(id)).original_filename === 'agreement.pdf', 'meta survives restart');
    ok('document + meta persist across a simulated restart (durable, encrypted)');

    // ── 2) GET /document -> server-STAMPED PDF ───────────────────────────────
    res = await call('GET', `/v1/envelopes/${id}/document`);
    assert.strictEqual(res.statusCode, 200, 'document returns 200 to the owner');
    assert.strictEqual(res.headers['X-ParaSign-Stamped'], 'true', 'X-ParaSign-Stamped: true (real stamp)');
    assert.strictEqual(res.body().slice(0, 5).toString('latin1'), '%PDF-', 'body is a PDF');
    ok('GET /document returns a server-stamped PDF (X-ParaSign-Stamped: true)');

    // ── 3) GET /receipt -> full multi-signer .psign ──────────────────────────
    res = await call('GET', `/v1/envelopes/${id}/receipt`);
    assert.strictEqual(res.statusCode, 200, 'receipt returns 200');
    const psign = res.json();
    assert.strictEqual(psign.type, 'parasign-envelope-receipt', 'receipt is a parasign envelope receipt');
    assert.ok(psign.parties.length === 2 && psign.parties.every(p => p.signature && p.public_key), 'every party has a raw signature + pubkey');
    assert.ok(psign.notary_signature, 'notary counter-signature present');
    // verify the notary signature over canonical JSON minus the sig field
    const { notary_signature, ...rest } = psign;
    const nOk = eng.verify(Buffer.from(notary_signature, 'base64'), Buffer.from(parasign.canonicalJSON(rest), 'utf8'), relayIdentity.pk);
    assert.ok(nOk, 'notary signature verifies against the relay pubkey');
    ok('GET /receipt returns a full, notary-verifiable .psign');

    // ── 4) webhook_url validation at CREATE (Point 6) ────────────────────────
    for (const bad of ['http://example.com/hook', 'https://127.0.0.1/hook', 'https://localhost/x', 'ftp://x', 'https://10.0.0.5/h']) {
      const r = await call('POST', '/v1/envelopes', { document: { content_base64: pdfB64 }, binding_mode: 'open', signers: [{ name: 'A' }], webhook_url: bad });
      assert.strictEqual(r.statusCode, 400, `bad webhook_url rejected: ${bad}`);
      assert.strictEqual(r.json().error, 'invalid_webhook_url', `correct error for ${bad}`);
    }
    assert.ok(!isSsrfSafeUrl('http://example.com'), 'sanity: guard rejects http');
    const rGood = await call('POST', '/v1/envelopes', { document: { content_base64: pdfB64 }, binding_mode: 'open', signers: [{ name: 'A' }], webhook_url: 'https://hooks.example.com/paramant' });
    assert.strictEqual(rGood.statusCode, 201, 'a valid public https webhook_url is accepted');
    ok('webhook_url validated at create (bad -> 400, good public https -> 201)');

    // cleanup created envelopes
    for (const eid of [id, created.id]) { try { await rc.del('env:' + eid); await store.delBlob(eid); await store.delMeta(eid); } catch {} }
  } finally { try { await rc.disconnect(); } catch {} }
}

main()
  .then(() => console.log(`\nparasign-open-api-e2e: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
