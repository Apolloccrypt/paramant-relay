'use strict';
// ParaSign per-account envelope index + full per-envelope .psign audit-export.
// Exercises against a REAL EnvelopeStore + REAL redis + REAL ML-DSA-65 engine:
//   1. create() adds the envelope id to the account index (listAccountEnvelopeIds)
//   1b. create() stores the requester's ONE requested signing position and hands
//      it back on the public view, and refuses a manifest that is out of bounds
//   2. the Business+ audit-export returns the completed envelope's full .psign,
//      and a Pro key is still refused 403 even with the envelope deps present
//   3. backfillAccountIndex() rebuilds the index from an un-indexed env:* key
// Needs the ML-DSA-65 engine (@paramant/core) and a redis at REDIS_URL /
// 127.0.0.1:6396. A missing one is a FAILURE unless the runner declared it
// absent via RELAY_TEST_SKIP; see test/_requires.js.
//   docker run -d --rm -p 6396:6379 --name auditexp-redis redis:alpine

const assert = require('assert');
const crypto = require('crypto');
const envelopeMod = require('../envelope');
const openApi = require('../lib/parasign-open-api');
const ax = require('../lib/parasign-audit-export');
const parasign = require('../parasign');
const { requireEngine, requireRedis, summary } = require('./_requires');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };
const J = JSON.stringify;

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
  const eng = requireEngine();
  const rc = await requireRedis('redis://127.0.0.1:6396');
  if (!eng || !rc) {
    if (rc) try { await rc.disconnect(); } catch (_) {}
    return summary('parasign-envelope-index', passed);
  }
  const registry = require('../crypto/registry');
  const store = new envelopeMod.EnvelopeStore(rc, {
    ctAppend: () => null,
    sigVerify: (sig, msg, pub) => { try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch { return false; } },
  });
  const rnd = crypto.randomBytes(6).toString('hex');
  const ACCT = 'acct_test_' + rnd;
  const ACCT2 = 'acct_legacy_' + rnd;
  const ACCT_REQ = 'acct_requested_' + rnd;   // its own account, so the export below still sees exactly one
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

    // 1b) the requested signing position ---------------------------------------
    // What the invite flow on /sign sends: one seal box, the same for every
    // party, normalized on the way in and durable across a read.
    const requestedEnv = await store.create({
      creatorApiKeyHash: crypto.createHash('sha3-256').update('psk_req_' + rnd).digest('hex'),
      accountId: ACCT_REQ, docHash, parties: [{ label: 'R', email: 'r@example.com' }],
      bindingMode: 'email', recipeVersion: 5,
      requestedAppearance: { version: 1, fields: [{ type: 'seal', page_index: 2, x: 0.4200004, y: 0.61, w: 0.4, h: 0.12 }] },
    });
    const requestedView = await store.getRedacted(requestedEnv.id);
    assert.deepStrictEqual(requestedView.requested_appearance, { version: 1, fields: [
      { type: 'seal', page_index: 2, x: 0.42, y: 0.61, w: 0.4, h: 0.12 },
    ] }, 'stored position is the normalized manifest');
    assert.match(requestedView.requested_appearance_hash, /^[0-9a-f]{64}$/, 'stored position carries its hash');
    const partyOfRequested = await store.getForParty(requestedEnv.id, 0, requestedEnv.party_links[0].invite_token);
    assert.deepStrictEqual(partyOfRequested.requested_appearance, requestedView.requested_appearance, 'the invited party sees the same position');
    assert.strictEqual(requestedView.parties[0].appearance, null, 'nobody has signed, so no party appearance exists');

    // Out of bounds is refused BEFORE an id is allocated: no half-made envelope.
    const envKeysBefore = (await rc.keys('env:*')).length;
    await assert.rejects(() => store.create({
      creatorApiKeyHash: 'x'.repeat(64), accountId: ACCT_REQ, docHash,
      parties: [{ label: 'R', email: 'r@example.com' }], bindingMode: 'email', recipeVersion: 5,
      requestedAppearance: { version: 1, fields: [{ type: 'seal', page_index: 0, x: 0.9, y: 0.5, w: 0.4, h: 0.12 }] },
    }), /outside page/, 'a box that runs off the page is refused');
    assert.strictEqual((await rc.keys('env:*')).length, envKeysBefore, 'the refused create left no envelope behind');

    // A security review found create() accepting a bare string and storing an
    // empty manifest for it. Through the real store, over real redis: it is a
    // refusal now, and so is a requested field type the product never issues.
    for (const bad of ['{"fields":[]}', 7, [{ type: 'seal' }], { version: 1, fields: [] },
      { version: 1, fields: [{ type: 'date', page_index: 0, x: 0.1, y: 0.1, w: 0.22, h: 0.055 }] }]) {
      await assert.rejects(() => store.create({
        creatorApiKeyHash: 'y'.repeat(64), accountId: ACCT_REQ, docHash,
        parties: [{ label: 'R', email: 'r@example.com' }], bindingMode: 'email', recipeVersion: 5,
        requestedAppearance: bad,
      }), /invalid requested appearance/, 'refused: ' + JSON.stringify(bad));
    }
    assert.strictEqual((await rc.keys('env:*')).length, envKeysBefore, 'none of the refusals left an envelope behind');
    ok('create() stores one normalized requested position and refuses a bad one');

    // 2) complete it, then the Business+ export returns its full .psign ---------
    const r = await completeOpenEnvelope(store, eng, out, docHash);
    assert.ok(r.ok && r.status === 'complete', 'envelope completed');

    const notaryKp = eng.generateKeyPair();
    const relayIdentity = {
      sk: notaryKp.secretKey,
      pk: notaryKp.publicKey,
      pk_hash: crypto.createHash('sha3-256').update(Buffer.from(notaryKp.publicKey)).digest('hex'),
    };
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
    assert.strictEqual(ent.psign.notary.relay_public_key, Buffer.from(notaryKp.publicKey).toString('base64'), '.psign embeds the relay public key');
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
      await rc.del('env:' + requestedEnv.id);
      await rc.del('env:' + legacy.id);
      await rc.del(store._acctIndexKey(ACCT));
      await rc.del(store._acctIndexKey(ACCT2));
      await rc.del(store._acctIndexKey(ACCT_REQ));
      await rc.del(store._acctIndexKey('acct_other_' + rnd));
    } catch { /* best effort */ }
  } finally {
    try { await rc.quit(); } catch {}
  }

  summary('parasign-envelope-index', passed);
  if (passed < 8) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
