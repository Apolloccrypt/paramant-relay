'use strict';
// ParaSign per-account envelope index + full per-envelope .psign audit-export.
// Exercises against a REAL EnvelopeStore + REAL redis + REAL ML-DSA-65 engine:
//   1. create() adds the envelope id to the account index (listAccountEnvelopeIds)
//   2. the Business+ audit-export returns the completed envelope's full .psign,
//      and a Pro key is still refused 403 even with the envelope deps present
//   3. backfillAccountIndex() rebuilds the index from an un-indexed env:* key
// Needs redis (REDIS_URL / 127.0.0.1:6396) + @paramant/core; skips otherwise.
//   docker run -d --rm -p 6396:6379 --name auditexp-redis redis:alpine

const assert = require('assert');
const crypto = require('crypto');
const envelopeMod = require('../envelope');
const openApi = require('../lib/parasign-open-api');
const ax = require('../lib/parasign-audit-export');
const parasign = require('../parasign');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };
const J = JSON.stringify;

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
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6396';
  let createClient;
  try { ({ createClient } = require('redis')); } catch { return null; }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); return rc; } catch { try { await rc.disconnect(); } catch {} return null; }
}
function fakeRes() {
  return {
    statusCode: null, headers: null, _body: '',
    writeHead(c, h) { this.statusCode = c; this.headers = h || {}; },
    end(b) { this._body = b == null ? '' : String(b); },
    json() { try { return JSON.parse(this._body); } catch { return null; } },
  };
}

async function completeOpenEnvelope(store, eng, out, docHash) {
  const kp = eng.generateKeyPair();
  const pubB64 = Buffer.from(kp.publicKey).toString('base64');
  const msg = envelopeMod.signMessageBytes(out.id, docHash, 0, '', 4, pubB64); // open -> recipe v4
  const sigB64 = Buffer.from(eng.sign(msg, kp.secretKey)).toString('base64');
  return store.sign(out.id, 0, pubB64, sigB64, {});
}

async function main() {
  const eng = loadEngine();
  const rc = await tryRedis();
  if (!eng || !rc) {
    console.log('  skip - need redis (127.0.0.1:6396) + ML-DSA-65 engine');
    console.log(`\nparasign-envelope-index: ${passed} checks passed`);
    if (rc) try { await rc.disconnect(); } catch {}
    return;
  }
  const registry = require('../crypto/registry');
  const store = new envelopeMod.EnvelopeStore(rc, {
    ctAppend: () => null,
    sigVerify: (sig, msg, pub) => { try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch { return false; } },
  });
  const rnd = crypto.randomBytes(6).toString('hex');
  const ACCT = 'acct_test_' + rnd;
  const ACCT2 = 'acct_legacy_' + rnd;
  const docHash = crypto.createHash('sha3-256').update(Buffer.from('doc-' + rnd)).digest('hex');

  try {
    // 1) create() indexes under the account ------------------------------------
    const out = await store.create({
      creatorApiKeyHash: crypto.createHash('sha3-256').update('psk_test_' + rnd).digest('hex'),
      accountId: ACCT, docHash, parties: [{ label: 'A', email: '' }], bindingMode: 'open',
    });
    const ids = await store.listAccountEnvelopeIds(ACCT, {});
    assert.ok(ids.includes(out.id), 'created envelope id is in the account index');
    ok('create() adds the envelope to the per-account index');

    const dashboardRows = await store.listAccountEnvelopes(ACCT, {});
    assert.strictEqual(dashboardRows.length, 1, 'dashboard lists one account envelope');
    assert.strictEqual(dashboardRows[0].id, out.id, 'dashboard summary carries the envelope id');
    assert.strictEqual(dashboardRows[0].status, 'sent', 'unsigned envelope stays sent');
    assert.strictEqual(dashboardRows[0].signed_count, 0, 'unsigned envelope has no signatures');
    assert.ok(!Object.hasOwn(dashboardRows[0], 'doc_hash'), 'dashboard summary omits document hash');
    assert.ok(!Object.hasOwn(dashboardRows[0].parties[0], 'email_hash'), 'dashboard summary omits email hash');
    ok('dashboard summary exposes status metadata without capabilities or hashes');

    const OTHER = 'acct_other_' + rnd;
    await rc.zAdd(store._acctIndexKey(OTHER), { score: Date.now(), value: out.id });
    assert.deepStrictEqual(await store.listAccountEnvelopes(OTHER, {}), [], 'stored account mismatch is rejected');
    ok('dashboard summary rejects a cross-account index entry');

    // 2) complete it, then the Business+ export returns its full .psign ---------
    const r = await completeOpenEnvelope(store, eng, out, docHash);
    assert.ok(r.ok && r.status === 'complete', 'envelope completed');

    const notaryKp = eng.generateKeyPair();
    const relayIdentity = { sk: notaryKp.secretKey, pk_hash: crypto.createHash('sha3-256').update(Buffer.from(notaryKp.publicKey)).digest('hex') };
    const exportDeps = (keyData) => ({
      res: fakeRes(), J, keyData, memberKeys: [], auditFor: () => [], ctHead: () => null, verifyChain: () => true, query: {},
      account: ACCT, envStore: store, metaStore: null, buildPsign: openApi.buildEnvelopePsign,
      sigEngine: eng, relayIdentity, canonicalJSON: parasign.canonicalJSON, publicOrigin: 'https://paramant.app',
    });

    const dBiz = exportDeps({ plan: 'business', active: true });
    await ax.handle(dBiz);
    assert.strictEqual(dBiz.res.statusCode, 200, 'Business export 200');
    const body = dBiz.res.json();
    assert.strictEqual(body.envelope_count, 1, 'one envelope in export');
    const ent = body.envelopes[0];
    assert.strictEqual(ent.envelope_id, out.id, 'export lists the created envelope');
    assert.strictEqual(ent.status, 'completed', 'completed envelope labelled completed');
    assert.ok(ent.psign && ent.psign.notary_signature, '.psign is notary-signed');
    assert.strictEqual(ent.psign.envelope_id, out.id, '.psign carries the envelope id');
    assert.strictEqual(ent.psign.document_hash, docHash, '.psign carries the doc hash');
    assert.ok(Array.isArray(ent.psign.parties) && ent.psign.parties[0].signature, '.psign has raw party signatures');
    ok('Business+ export returns the completed envelope full .psign');

    // Notary signature verifies against the relay pubkey over canonical JSON.
    const forVerify = { ...ent.psign }; delete forVerify.notary_signature;
    const verified = eng.verify(
      Buffer.from(ent.psign.notary_signature, 'base64'),
      Buffer.from(parasign.canonicalJSON(forVerify), 'utf8'),
      Buffer.from(notaryKp.publicKey),
    );
    assert.ok(verified, 'notary signature verifies over the canonical .psign');
    ok('exported .psign notary signature verifies');

    // Pro key -> 403 even with the envelope deps wired.
    const dPro = exportDeps({ plan: 'pro', active: true });
    await ax.handle(dPro);
    assert.strictEqual(dPro.res.statusCode, 403, 'Pro key refused');
    assert.strictEqual(dPro.res.json().feature, 'audit_export', 'refusal names audit_export');
    ok('Pro key -> 403 (Business+ gate holds with envelope export wired)');

    // 3) backfill rebuilds the index from an un-indexed env:* key --------------
    const legacyHash = crypto.createHash('sha3-256').update('psk_legacy_' + rnd).digest('hex');
    // Create WITHOUT accountId -> account_id field empty, no index entry written.
    const legacy = await store.create({
      creatorApiKeyHash: legacyHash, docHash, parties: [{ label: 'B', email: '' }], bindingMode: 'open',
    });
    const before = await store.listAccountEnvelopeIds(ACCT2, {});
    assert.ok(!before.includes(legacy.id), 'legacy envelope not indexed before backfill');

    const bf = await store.backfillAccountIndex({
      resolveAccount: (h) => (h.creator_api_hash === legacyHash ? ACCT2 : null),
    });
    assert.ok(bf.scanned >= 1 && bf.indexed >= 1, 'backfill scanned + indexed at least one');
    const after = await store.listAccountEnvelopeIds(ACCT2, {});
    assert.ok(after.includes(legacy.id), 'legacy envelope indexed after backfill');
    ok('backfillAccountIndex() rebuilds the index from existing env:* keys');

    // cleanup our test keys (leave other tests' keys untouched)
    try {
      await rc.del('env:' + out.id);
      await rc.del('env:' + legacy.id);
      await rc.del(store._acctIndexKey(ACCT));
      await rc.del(store._acctIndexKey(ACCT2));
      await rc.del(store._acctIndexKey('acct_other_' + rnd));
    } catch { /* best effort */ }
  } finally {
    try { await rc.quit(); } catch {}
  }

  console.log(`\nparasign-envelope-index: ${passed} checks passed`);
  if (passed < 7) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
