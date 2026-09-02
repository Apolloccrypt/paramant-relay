'use strict';
// The whole ParaSign multi-party envelope, end to end, over HTTP, on a really
// booted relay: create, view, sign with a real ML-DSA-65 signature, collect the
// evidence bundle and verify it OFFLINE, then the three refusals that make the
// evidence worth anything (double sign, a forged signature, an expired record).
//
// WHY THIS SUITE EXISTS. The lifecycle was covered at two levels and never in
// the middle: unit tests call EnvelopeStore directly with a fake redis
// (envelope-binding, parasign-envelope-index), and Playwright drives a browser
// in sign-e2e. The HTTP layer between them, 400 lines of relay.js from 5665 to
// 6093, the part that decides who may sign what and what the receipt says, was
// loaded by no test. The 2026-09-02 audit measured relay.js at zero.
//
// The offline verification is the point of the whole product: a receipt is only
// evidence if someone who does not trust the relay can check it. So the last
// step here re-derives every signed message itself, verifies each party
// signature and the notary signature with the raw engine, and never asks the
// relay whether the receipt is good.
//
// NEEDS: a reachable redis (the envelope store is redis-only, relay.js:5650)
// and the ML-DSA-65 engine from @paramant/core. Both are declared preconditions
// via test/_requires.js, so a job without them fails loudly unless it says
// RELAY_TEST_SKIP=redis,engine.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-envelope-lifecycle.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');
const envelopeMod = require('../envelope');
const parasign = require('../parasign');

// A fresh key per run. Envelope creation is capped at 50 per key per hour and
// the counter lives in redis (relay.js:1426-1439), so a fixed key would make
// the fourth run of this suite in one hour fail on the limiter instead of on
// the code. The limiter is tested on purpose in route-env-rate-limits.test.js.
const RUN = crypto.randomBytes(6).toString('hex');
const OWNER = `pgp_owner_key_for_the_envelope_suite_${RUN}`;
const STRANGER = `pgp_stranger_key_for_the_envelope_suite_${RUN}`;
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';

let srv = null;
let eng = null;
let rc = null;
let checks = 0;
const did = () => { checks++; };

// A run without redis or without the engine cannot assert anything here, so
// every test returns early rather than pretending. _requires already made that
// visible (declared SKIP, or a hard failure).
const ready = () => srv !== null && eng !== null;

const docHash = () => crypto.createHash('sha3-256').update(crypto.randomBytes(32)).digest('hex');

// The view and sign routes are rate-limited per client IP (30/min and 10/min,
// relay.js:1406-1411) and the buckets are process-global, so a suite that signs
// two dozen times from one address would start measuring the limiter instead of
// the lifecycle. Each test takes its own address, exactly as nginx presents it
// (X-Real-IP, relay.js:1478-1484). The limiter itself is tested on purpose in
// route-env-rate-limits.test.js.
let _ipN = 0;
let IP = '10.0.0.1';
function nextIp() { _ipN++; return `10.0.${Math.floor(_ipN / 250)}.${(_ipN % 250) + 1}`; }
const asParty = (extra = {}) => ({ 'X-Real-IP': IP, ...extra });

before(async () => {
  eng = requireEngine();
  rc = await requireRedis(DEFAULT_REDIS);
  if (!eng || !rc) return;
  srv = await boot({
    tag: 'envelope',
    users: {
      api_keys: [
        { key: OWNER, plan: 'business', active: true, parasign: true, email: 'owner@example.test', account_id: 'acct_owner' },
        { key: STRANGER, plan: 'business', active: true, parasign: true, email: 'stranger@example.test', account_id: 'acct_stranger' },
      ],
    },
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS },
  });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('route-envelope-lifecycle', checks);
});

// Create an open-mode envelope and return { id, docHash, parties, body }.
async function createEnvelope(parties = [{ label: 'Alice' }, { label: 'Bob' }], extra = {}) {
  const dh = docHash();
  const r = await srv.post('/v2/envelopes', {
    headers: asParty({ 'X-Api-Key': OWNER }),
    body: { doc_hash: dh, parties, ...extra },
  });
  assert.strictEqual(r.status, 200, `create failed: ${r.status} ${r.text}`);
  return { id: r.json.envelope.id, docHash: dh, envelope: r.json.envelope };
}

// A real ML-DSA-65 signature over the exact message the relay will re-derive.
// Open envelopes are always verified at recipe 4 (envelope.js:806), which binds
// the signer's own public key into the message.
function signForParty(id, dh, partyIndex, keypair) {
  const kp = keypair || eng.generateKeyPair();
  const pubB64 = Buffer.from(kp.publicKey).toString('base64');
  const msg = envelopeMod.signMessageBytes(id, dh, partyIndex, '', 4, pubB64);
  const sigB64 = Buffer.from(eng.sign(msg, kp.secretKey)).toString('base64');
  return { kp, pubB64, sigB64, msg };
}

const submit = (id, body) => srv.post(`/v2/envelopes/${id}/sign`, { headers: asParty(), body });
const statusOf = (id) => srv.get(`/v2/envelopes/${id}`, { headers: asParty() });
const view = (id, body) => srv.post(`/v2/envelopes/${id}/view`, { headers: asParty(), body });
const receipt = (id, key) => srv.get(`/v2/envelopes/${id}/receipt`,
  { headers: key ? asParty({ 'X-Api-Key': key }) : asParty() });

// ── 1. create ────────────────────────────────────────────────────────────────

test('create returns one signing link per party and an expiry derived from ttl_days', async () => {
  if (!ready()) return;
  IP = nextIp();
  const before = Date.now();
  const { envelope } = await createEnvelope([{ label: 'Alice' }, { label: 'Bob' }], { ttl_days: 3 });
  assert.match(envelope.id, /^[A-Za-z0-9_-]{20,64}$/);
  assert.strictEqual(envelope.party_count, 2);
  assert.strictEqual(envelope.binding_mode, 'open');
  assert.strictEqual(envelope.party_links.length, 2);
  assert.strictEqual(envelope.party_links[0].party_index, 0);
  assert.match(envelope.party_links[1].sign_path, /^\/co-sign\?env=/);
  assert.strictEqual(envelope.party_links[0].invite_token, null, 'open mode issues no invite tokens');

  const expires = Date.parse(envelope.expires_at);
  const expected = before + 3 * 86_400_000;
  assert.ok(Math.abs(expires - expected) < 60_000, `expires_at should be created_at + 3 days, got ${envelope.expires_at}`);
  did();
});

test('create refuses a document hash that is not a sha3-256, and an empty party list', async () => {
  if (!ready()) return;
  IP = nextIp();
  const bad = await srv.post('/v2/envelopes', {
    headers: asParty({ 'X-Api-Key': OWNER }),
    body: { doc_hash: 'not-a-hash', parties: [{ label: 'A' }] },
  });
  assert.strictEqual(bad.status, 400);
  assert.match(String(bad.json.error), /doc_hash must be 64-char sha3-256 hex/);

  const none = await srv.post('/v2/envelopes', {
    headers: asParty({ 'X-Api-Key': OWNER }),
    body: { doc_hash: docHash(), parties: [] },
  });
  assert.strictEqual(none.status, 400);
  assert.match(String(none.json.error), /parties required/);
  did();
});

test('the relay never receives the document, only its hash', async () => {
  if (!ready()) return;
  IP = nextIp();
  // The whole zero-knowledge claim rests on this: what is stored under the
  // envelope key is the hash the client computed and nothing that could
  // reconstruct the file.
  const { id, docHash: dh } = await createEnvelope();
  const stored = await rc.hGetAll(`env:${id}`);
  assert.strictEqual(stored.doc_hash, dh);
  const blob = JSON.stringify(stored);
  assert.ok(!/document|plaintext|content/i.test(String(stored.doc_hash)));
  assert.ok(blob.length < 8000, 'an envelope record holds metadata, not a document');
  did();
});

// ── 2. view ──────────────────────────────────────────────────────────────────

test('a party marks itself viewed without any API key, and the status shows it', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id } = await createEnvelope();
  const before = await statusOf(id);
  assert.strictEqual(before.status, 200);
  assert.strictEqual(before.json.envelope.parties[0].status, 'pending');

  const v = await view(id, { party_index: 0 });
  assert.strictEqual(v.status, 200);
  assert.deepStrictEqual(v.json, { ok: true });

  const after = await statusOf(id);
  assert.strictEqual(after.json.envelope.parties[0].status, 'viewed');
  assert.strictEqual(after.json.envelope.parties[1].status, 'pending', 'only the party that opened it is marked');
  did();
});

test('the public status is redacted: no signatures, no raw keys, no account id', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope([{ label: 'Solo' }]);
  const { pubB64, sigB64 } = signForParty(id, dh, 0);
  assert.strictEqual((await submit(id, { party_index: 0, signer_public_key: pubB64, signature: sigB64 })).status, 200);

  const r = await statusOf(id);
  assert.strictEqual(r.status, 200);
  const text = r.text;
  assert.ok(!text.includes(sigB64), 'the raw signature must not be in the public status');
  assert.ok(!text.includes(pubB64), 'the raw public key must not be in the public status');
  assert.ok(!text.includes('acct_owner'), 'the owning account must not be in the public status');
  assert.match(r.json.envelope.parties[0].signer_pk_hash, /^[0-9a-f]{64}$/, 'only a hash of the key is published');
  assert.ok(r.json.sign_message_recipe, 'the recipe is published so a verifier can re-derive the message');
  did();
});

// ── 3. sign ──────────────────────────────────────────────────────────────────

test('a real ML-DSA-65 signature is accepted and completes the envelope when the last party signs', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope();

  const a = signForParty(id, dh, 0);
  const first = await submit(id, { party_index: 0, signer_public_key: a.pubB64, signature: a.sigB64 });
  assert.strictEqual(first.status, 200, first.text);
  assert.strictEqual(first.json.ok, true);
  assert.strictEqual(first.json.idempotent, false);
  assert.strictEqual(first.json.signed_count, 1);
  assert.strictEqual(first.json.status, 'sent', 'one of two parties is not a completed envelope');

  const b = signForParty(id, dh, 1);
  const second = await submit(id, { party_index: 1, signer_public_key: b.pubB64, signature: b.sigB64 });
  assert.strictEqual(second.status, 200, second.text);
  assert.strictEqual(second.json.signed_count, 2);
  assert.strictEqual(second.json.status, 'complete');
  did();
});

test('a signature over the WRONG message is refused, so the relay really verifies', async () => {
  if (!ready()) return;
  IP = nextIp();
  // The failure mode that would make every test above worthless is a relay that
  // stores whatever it is handed. Four forgeries, all rejected:
  const { id, docHash: dh } = await createEnvelope([{ label: 'Solo' }]);
  const good = signForParty(id, dh, 0);

  // (a) a signature over a different document
  const otherDoc = envelopeMod.signMessageBytes(id, docHash(), 0, '', 4, good.pubB64);
  const wrongDoc = Buffer.from(eng.sign(otherDoc, good.kp.secretKey)).toString('base64');
  // (b) a signature over a different party index
  const otherIdx = envelopeMod.signMessageBytes(id, dh, 7, '', 4, good.pubB64);
  const wrongIdx = Buffer.from(eng.sign(otherIdx, good.kp.secretKey)).toString('base64');
  // (c) a valid signature from a key that is not the one presented
  const impostor = eng.generateKeyPair();
  const msgForImpostor = envelopeMod.signMessageBytes(id, dh, 0, '', 4, good.pubB64);
  const wrongKey = Buffer.from(eng.sign(msgForImpostor, impostor.secretKey)).toString('base64');
  // (d) noise
  const noise = Buffer.from(crypto.randomBytes(3309)).toString('base64');

  for (const [name, sig] of [['other document', wrongDoc], ['other party index', wrongIdx], ['other key', wrongKey], ['noise', noise]]) {
    const r = await submit(id, { party_index: 0, signer_public_key: good.pubB64, signature: sig });
    assert.strictEqual(r.status, 400, `${name}: expected 400, got ${r.status} ${r.text}`);
    assert.deepStrictEqual(r.json, { error: 'bad_signature' }, name);
  }

  // The slot is still open after four refusals, and the good signature lands.
  const ok = await submit(id, { party_index: 0, signer_public_key: good.pubB64, signature: good.sigB64 });
  assert.strictEqual(ok.status, 200, ok.text);
  did();
});

test('DOUBLE SIGN: the same submission is idempotent, a different one is a conflict', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope([{ label: 'Alice' }, { label: 'Bob' }]);
  const a = signForParty(id, dh, 0);
  const first = await submit(id, { party_index: 0, signer_public_key: a.pubB64, signature: a.sigB64 });
  assert.strictEqual(first.status, 200);
  assert.strictEqual(first.json.idempotent, false);

  // Replaying the exact same signature is a retry, not a second signature: it
  // must not move the counter. (A network retry must be safe.)
  const replay = await submit(id, { party_index: 0, signer_public_key: a.pubB64, signature: a.sigB64 });
  assert.strictEqual(replay.status, 200);
  assert.strictEqual(replay.json.idempotent, true, 'an identical resubmission is a replay');
  assert.strictEqual(replay.json.signed_count, 1, 'a replay must never increase signed_count');

  // A DIFFERENT signer trying to take an occupied slot is refused outright.
  const other = signForParty(id, dh, 0);
  const conflict = await submit(id, { party_index: 0, signer_public_key: other.pubB64, signature: other.sigB64 });
  assert.strictEqual(conflict.status, 409);
  assert.deepStrictEqual(conflict.json, { error: 'conflict' });

  const status = await statusOf(id);
  assert.strictEqual(status.json.envelope.signed_count, 1, 'the conflict changed nothing');
  assert.strictEqual(status.json.envelope.parties[0].signer_pk_hash,
    crypto.createHash('sha3-256').update(Buffer.from(a.pubB64, 'base64')).digest('hex'),
    'the first signer still holds the slot');
  did();
});

test('a completed envelope is closed: nobody signs it again', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope([{ label: 'Solo' }]);
  const a = signForParty(id, dh, 0);
  assert.strictEqual((await submit(id, { party_index: 0, signer_public_key: a.pubB64, signature: a.sigB64 })).status, 200);

  const b = signForParty(id, dh, 0);
  const closed = await submit(id, { party_index: 0, signer_public_key: b.pubB64, signature: b.sigB64 });
  assert.strictEqual(closed.status, 410);
  assert.deepStrictEqual(closed.json, { error: 'closed' });
  did();
});

test('a party index outside the envelope is a generic not_found, not an out-of-range hint', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope([{ label: 'Solo' }]);
  const a = signForParty(id, dh, 3);
  const r = await submit(id, { party_index: 3, signer_public_key: a.pubB64, signature: a.sigB64 });
  assert.strictEqual(r.status, 404);
  assert.deepStrictEqual(r.json, { error: 'not_found' });

  // And an envelope id that never existed answers exactly the same way.
  const ghost = await submit('Zm9vYmFyZm9vYmFyZm9vYmFyZm9v', { party_index: 0, signer_public_key: a.pubB64, signature: a.sigB64 });
  assert.strictEqual(ghost.status, 404);
  assert.deepStrictEqual(ghost.json, { error: 'not_found' });
  did();
});

// ── 4. expiry ────────────────────────────────────────────────────────────────

test('EXPIRED: once the retention window closes the envelope is gone and cannot be signed', async () => {
  if (!ready()) return;
  IP = nextIp();
  // ttl_days is enforced by the redis TTL on the record (envelope.js:373); the
  // relay does not compare expires_at on every read. So the honest way to test
  // expiry is to let the record actually expire. The suite shortens the TTL to
  // 50 ms on the store rather than waiting a day.
  const { id, docHash: dh } = await createEnvelope([{ label: 'Alice' }], { ttl_days: 1 });

  const ttl = await rc.ttl(`env:${id}`);
  assert.ok(ttl > 86_000 && ttl <= 86_400, `a 1-day envelope should carry a ~1 day redis TTL, got ${ttl}`);

  await rc.pExpire(`env:${id}`, 50);
  await new Promise((r) => setTimeout(r, 250));
  assert.strictEqual(await rc.exists(`env:${id}`), 0, 'the record really expired');

  const a = signForParty(id, dh, 0);
  const signAfter = await submit(id, { party_index: 0, signer_public_key: a.pubB64, signature: a.sigB64 });
  assert.strictEqual(signAfter.status, 404, 'an expired envelope must not accept a signature');
  assert.deepStrictEqual(signAfter.json, { error: 'not_found' });

  const viewAfter = await view(id, { party_index: 0 });
  assert.strictEqual(viewAfter.status, 404, 'and it can no longer be viewed');
  const status = await statusOf(id);
  assert.strictEqual(status.status, 404, 'and it no longer has a public status');
  did();
});

// ── 5. the evidence bundle, verified offline ────────────────────────────────

test('the receipt is owner-only and only issued once the envelope is complete', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope([{ label: 'Alice' }, { label: 'Bob' }]);

  const early = await receipt(id, OWNER);
  assert.strictEqual(early.status, 409, 'an unfinished envelope has no evidence to hand out');
  assert.deepStrictEqual(early.json, { error: 'not_ready' });

  for (const i of [0, 1]) {
    const s = signForParty(id, dh, i);
    assert.strictEqual((await submit(id, { party_index: i, signer_public_key: s.pubB64, signature: s.sigB64 })).status, 200);
  }

  const stranger = await receipt(id, STRANGER);
  assert.strictEqual(stranger.status, 404, 'another tenant may not fetch the evidence, and learns nothing from trying');

  const anon = await receipt(id);
  assert.strictEqual(anon.status, 401, 'the receipt is not public');

  const owner = await receipt(id, OWNER);
  assert.strictEqual(owner.status, 200, owner.text);
  assert.match(String(owner.headers['content-disposition'] || ''), /\.psign"?$/);
  did();
});

test('OFFLINE VERIFICATION: the receipt checks out without asking the relay anything', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope([{ label: 'Alice' }, { label: 'Bob' }]);
  const signers = [];
  for (const i of [0, 1]) {
    const s = signForParty(id, dh, i);
    assert.strictEqual((await submit(id, { party_index: i, signer_public_key: s.pubB64, signature: s.sigB64 })).status, 200);
    signers.push(s);
  }
  const psign = (await receipt(id, OWNER)).json;

  assert.strictEqual(psign.type, 'parasign-envelope-receipt');
  assert.strictEqual(psign.algorithm, 'ML-DSA-65');
  assert.strictEqual(psign.envelope_id, id);
  assert.strictEqual(psign.document_hash, dh);
  assert.strictEqual(psign.document_hash_algo, 'sha3-256');
  assert.strictEqual(psign.parties.length, 2);

  // From here on nothing from the relay is trusted: every byte is re-derived.
  // (a) each party's signature, over the message this verifier builds itself
  //     from the receipt's own fields.
  for (const p of psign.parties) {
    const msg = envelopeMod.signMessageBytes(
      psign.envelope_id, psign.document_hash, p.index,
      p.email_hash || '', psign.sign_recipe, p.public_key, p.appearance_hash || '');
    const ok = eng.verify(
      Buffer.from(p.signature, 'base64'), msg, Buffer.from(p.public_key, 'base64'));
    assert.strictEqual(ok, true, `party ${p.index} signature does not verify offline`);
    assert.strictEqual(p.public_key, signers[p.index].pubB64, 'the receipt names the key that actually signed');
  }

  // (b) the notary signature, over the canonical JSON of the receipt with the
  //     signature field removed, the relay's own countersignature.
  const { notary_signature, ...unsigned } = psign;
  const notaryOk = eng.verify(
    Buffer.from(notary_signature, 'base64'),
    Buffer.from(parasign.canonicalJSON(unsigned), 'utf8'),
    Buffer.from(psign.notary.relay_public_key, 'base64'));
  assert.strictEqual(notaryOk, true, 'the notary signature does not verify offline');

  // (c) the notary key really is the one the relay publishes at /v2/pubkey, so
  //     a verifier can pin it without trusting the receipt it came in.
  assert.strictEqual(
    crypto.createHash('sha3-256').update(Buffer.from(psign.notary.relay_public_key, 'base64')).digest('hex'),
    psign.notary.relay_pk_hash);

  // (d) and the whole thing is tamper-evident: change one character of the
  //     document hash and the notary signature no longer holds.
  //
  //     The tamper must be a REAL change. This check used to write a literal
  //     'f' over the first character of the hash, which is a no-op on the 1 run
  //     in 16 where a sha3-256 hex hash already starts with 'f' -- the receipt
  //     was then unmodified, verified correctly, and the suite failed with
  //     "true !== false" (~6% of CI runs, measured at 9/100 locally). Flip to a
  //     character the original demonstrably is not, and assert that it differs.
  const flipped = (unsigned.document_hash[0] === 'f' ? '0' : 'f') + unsigned.document_hash.slice(1);
  assert.notStrictEqual(flipped, unsigned.document_hash, 'the tamper must actually change the hash');
  const tampered = { ...unsigned, document_hash: flipped };
  assert.strictEqual(eng.verify(
    Buffer.from(notary_signature, 'base64'),
    Buffer.from(parasign.canonicalJSON(tampered), 'utf8'),
    Buffer.from(psign.notary.relay_public_key, 'base64')), false,
    'a tampered receipt must not verify');
  did();
});

// (d) above proves ONE field is under the notary signature. This proves EVERY
// field is: it walks the receipt, sabotages exactly one leaf at a time with a
// value that is provably different, and demands the notary signature breaks on
// each. A field the relay adds to the receipt but leaves outside the signed
// bytes -- the thing that would make a receipt forgeable in the field -- fails
// here by name instead of hiding behind a check that only ever touched the
// document hash.
test('OFFLINE VERIFICATION: every notary-signed field is covered, one sabotage at a time', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, docHash: dh } = await createEnvelope([{ label: 'Alice' }, { label: 'Bob' }]);
  for (const i of [0, 1]) {
    const s = signForParty(id, dh, i);
    assert.strictEqual((await submit(id, { party_index: i, signer_public_key: s.pubB64, signature: s.sigB64 })).status, 200);
  }
  const psign = (await receipt(id, OWNER)).json;
  const { notary_signature, ...unsigned } = psign;

  const sig = Buffer.from(notary_signature, 'base64');
  const pk = Buffer.from(psign.notary.relay_public_key, 'base64');
  const verifies = (obj) => eng.verify(sig, Buffer.from(parasign.canonicalJSON(obj), 'utf8'), pk);

  // Sanity: the untouched receipt still verifies, so a `false` below is the
  // sabotage talking and not a broken harness.
  assert.strictEqual(verifies(unsigned), true, 'the unmodified receipt must verify');

  // Every leaf path in the signed object, arrays included.
  const leaves = [];
  (function walk(node, path) {
    if (node !== null && typeof node === 'object') {
      const keys = Array.isArray(node) ? node.map((_, i) => i) : Object.keys(node);
      if (keys.length === 0) { leaves.push(path); return; }
      for (const k of keys) walk(node[k], path.concat(k));
      return;
    }
    leaves.push(path);
  })(unsigned, []);

  // A receipt that quietly shrinks to a handful of fields must not pass this
  // test by having nothing left to sabotage.
  assert.ok(leaves.length >= 25, `expected a substantial receipt, got ${leaves.length} fields`);

  // A value of the same shape that is provably not the original.
  const otherValue = (v) => {
    if (typeof v === 'string') return v === 'paramant-tampered' ? 'paramant-tampered-2' : 'paramant-tampered';
    if (typeof v === 'number') return v + 1;
    if (typeof v === 'boolean') return !v;
    return 'paramant-tampered'; // null / undefined
  };

  for (const path of leaves) {
    const copy = JSON.parse(JSON.stringify(unsigned));
    let node = copy;
    for (const k of path.slice(0, -1)) node = node[k];
    const last = path[path.length - 1];
    const before = node[last];
    node[last] = otherValue(before);
    const label = path.join('.');
    assert.notDeepStrictEqual(node[last], before, `sabotage of ${label} must change the value`);
    assert.strictEqual(verifies(copy), false,
      `${label} is NOT covered by the notary signature: the receipt still verifies after it was changed`);
  }
  did();
});
