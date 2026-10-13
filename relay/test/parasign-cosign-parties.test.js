'use strict';
// Several people sign one document (2026-10-04, the customer case: two or more
// parties, a paraaf on every page and a signature on the last). Against a REAL
// EnvelopeStore, REAL redis and the REAL ML-DSA-65 engine:
//   1. a party signs a manifest with a paraaf (all_pages) AND a signature; the
//      encrypted ink is stored and handed only to holders of an invite token
//   2. the document key share is stored with the capsule and released with it
//   3. once a party has signed, the document stays available after the signing
//      window (for the complete PDF); for a party that has not signed it closes
//   4. the owner view and owner capsule are owner-only
//   5. a party can decline: the envelope ends (void, reason declined), the slot
//      says who, nobody can sign after, and a signed party cannot decline
// Needs @paramant/core and a redis at REDIS_URL (see test/_requires.js).

const assert = require('assert');
const crypto = require('crypto');
const envelopeMod = require('../envelope');
const { requireEngine, requireRedis, summary } = require('./_requires');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

async function main() {
  const eng = requireEngine();
  const rc = await requireRedis('redis://127.0.0.1:6396');
  if (!eng || !rc) {
    if (rc) try { await rc.disconnect(); } catch (_) {}
    return summary('parasign-cosign-parties', passed);
  }
  const registry = require('../crypto/registry');
  const store = new envelopeMod.EnvelopeStore(rc, {
    ctAppend: () => null,
    sigVerify: (sig, msg, pub) => { try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch { return false; } },
  });
  const rnd = crypto.randomBytes(6).toString('hex');
  const ACCT = 'acct_cosign_' + rnd;
  const docHash = crypto.createHash('sha3-256').update(Buffer.from('cosign-' + rnd)).digest('hex');
  const emails = ['a-' + rnd + '@example.com', 'b-' + rnd + '@example.com'];
  const created = [];

  const signAs = async (out, pi, appearance, ink) => {
    const kp = eng.generateKeyPair();
    const pubB64 = Buffer.from(kp.publicKey).toString('base64');
    const emailHash = envelopeMod.partyEmailHash(emails[pi]);
    const appHash = envelopeMod.appearanceHash(appearance);
    const msg = envelopeMod.signMessageBytes(out.id, docHash, pi, emailHash, 5, pubB64, appHash);
    const sigB64 = Buffer.from(eng.sign(msg, kp.secretKey)).toString('base64');
    return store.sign(out.id, pi, pubB64, sigB64, { internalTrusted: true, verifiedEmailHash: emailHash, appearance, ink });
  };
  const make = async () => {
    const out = await store.create({
      creatorApiKeyHash: crypto.createHash('sha3-256').update('k' + rnd + created.length).digest('hex'),
      accountId: ACCT, docHash, bindingMode: 'email', recipeVersion: 5,
      parties: [{ label: 'Sandeep', email: emails[0] }, { label: 'Partner', email: emails[1] }],
    });
    created.push(out.id);
    return out;
  };

  try {
    // 1) paraaf + signature in one manifest, with ink ---------------------------
    const env = await make();
    const manifest = { version: 2, fields: [
      { type: 'seal', page_index: 2, x: 0.08, y: 0.8, w: 0.3, h: 0.085 },
      { type: 'seal', page_index: 0, x: 0.845, y: 0.937, w: 0.12, h: 0.038, all_pages: true },
    ] };
    const ink = Buffer.from(crypto.randomBytes(80)).toString('base64url');
    const r0 = await signAs(env, 0, manifest, ink);
    assert.ok(r0.ok && r0.code === 'new', 'a paraaf and a signature in one manifest are accepted');
    assert.deepStrictEqual(r0.appearance, manifest, 'and bound byte for byte as normalised');
    const asB = await store.getForParty(env.id, 1, env.party_links[1].invite_token);
    assert.strictEqual(asB.parties[0].ink, ink, 'the other party receives the encrypted ink');
    assert.strictEqual(asB.parties[1].ink, null, 'an unsigned slot has no ink');
    const pub = await store.getRedacted(env.id);
    assert.strictEqual(pub.parties[0].ink, undefined, 'the public view carries no ink');
    const receipt = await store.getForReceipt(env.id);
    assert.strictEqual(receipt.parties[0].ink, undefined, 'the evidence view (.psign) is unchanged: no ink in it');
    const bad = await signAs(env, 1, { version: 1, fields: [] }, 'not base64url!!');
    assert.strictEqual(bad.code, 'invalid_ink', 'junk ink is refused before anything is stored');
    ok('a party signs a paraaf on every page plus a signature, with its ink stored for the others');

    // 2) key share stored with the capsule ---------------------------------------
    const capsule = crypto.randomBytes(200);
    const share = crypto.randomBytes(32).toString('base64url');
    const put = await store.putDocumentCapsule(env.id, ACCT, capsule, crypto.createHash('sha256').update(capsule).digest('hex'), share);
    assert.ok(put.ok, 'capsule with a key share stored');
    await assert.rejects(() => store.putDocumentCapsule(env.id, ACCT, capsule, crypto.createHash('sha256').update(capsule).digest('hex'), 'short'), /invalid key share/);
    const got = await store.getDocumentCapsule(env.id, 1, env.party_links[1].invite_token, envelopeMod.partyEmailHash(emails[1]));
    assert.ok(got.ok && got.keyShare === share, 'the invited mailbox gets the share with the ciphertext');
    const wrong = await store.getDocumentCapsule(env.id, 1, env.party_links[1].invite_token, envelopeMod.partyEmailHash('x@example.com'));
    assert.strictEqual(wrong.code, 'not_authorized', 'another mailbox gets neither');
    ok('the key share travels with the capsule to the invited mailbox only');

    // 3) the result outlives the signing window for whoever signed ----------------
    const eightDaysAgo = new Date(Date.now() - 8 * 86400_000).toISOString();
    await rc.hSet('env:' + env.id, 'created_at', eightDaysAgo);
    const signedParty = await store.getDocumentCapsule(env.id, 0, env.party_links[0].invite_token, envelopeMod.partyEmailHash(emails[0]));
    assert.ok(signedParty.ok, 'a party that signed still opens the document after the window');
    const unsignedParty = await store.getDocumentCapsule(env.id, 1, env.party_links[1].invite_token, envelopeMod.partyEmailHash(emails[1]));
    assert.strictEqual(unsignedParty.code, 'invite_expired', 'a party that did not sign is closed out');
    await rc.hSet('env:' + env.id, 'created_at', new Date().toISOString());
    ok('the document stays available for the complete PDF, not for a late signature');

    // 4) owner-only reads ----------------------------------------------------------
    const ov = await store.getOwnerView(env.id, ACCT);
    assert.ok(ov && ov.parties[0].ink === ink && ov.parties[0].label === 'Sandeep', 'the owner sees who signed, with inks');
    assert.strictEqual(await store.getOwnerView(env.id, 'acct_other'), null, 'another account sees nothing');
    const oc = await store.getOwnerDocumentCapsule(env.id, ACCT);
    assert.ok(oc.ok && oc.capsule.equals(capsule) && oc.keyShare === undefined, 'the owner capsule comes without the share');
    assert.strictEqual((await store.getOwnerDocumentCapsule(env.id, 'acct_other')).code, 'not_found');
    ok('the result page of the sender is owner-only');

    // 5) decline ---------------------------------------------------------------------
    const signedDecline = await store.declineParty(env.id, 0, env.party_links[0].invite_token, envelopeMod.partyEmailHash(emails[0]));
    assert.strictEqual(signedDecline.code, 'signed', 'a party that signed cannot decline');
    const wrongMailbox = await store.declineParty(env.id, 1, env.party_links[1].invite_token, envelopeMod.partyEmailHash('x@example.com'));
    assert.strictEqual(wrongMailbox.code, 'not_authorized', 'another mailbox cannot decline for the party');
    const badToken = await store.declineParty(env.id, 1, 'x'.repeat(43), envelopeMod.partyEmailHash(emails[1]));
    assert.strictEqual(badToken.code, 'not_found', 'nor can a wrong token');
    const d = await store.declineParty(env.id, 1, env.party_links[1].invite_token, envelopeMod.partyEmailHash(emails[1]));
    assert.ok(d.ok && d.code === 'declined' && d.status === 'void', 'the party declines');
    const again = await store.declineParty(env.id, 1, env.party_links[1].invite_token, envelopeMod.partyEmailHash(emails[1]));
    assert.ok(again.ok && again.code === 'idem', 'declining twice is idempotent');
    const after = await store.getForParty(env.id, 0, env.party_links[0].invite_token);
    assert.strictEqual(after.status, 'void');
    assert.strictEqual(after.void_reason, 'declined', 'the page can say WHY it stopped');
    assert.strictEqual(after.parties[1].status, 'declined', 'and who');
    const late = await signAs(env, 1, { version: 1, fields: [] });
    assert.strictEqual(late.code, 'voided', 'nobody signs a declined request');
    assert.strictEqual(await rc.get('envdoc:' + env.id), null, 'the ciphertext is gone with the request');
    const cancelEnv = await make();
    await store.voidEnvelope(cancelEnv.id, 'Cancelled by the account owner');
    const cv = await store.getForParty(cancelEnv.id, 0, cancelEnv.party_links[0].invite_token);
    assert.strictEqual(cv.void_reason, 'cancelled', 'a withdrawal reads as cancelled, not declined');
    ok('a party can decline, the sender sees who, and the request ends for everybody');
  } finally {
    for (const id of created) { try { await rc.del('env:' + id); await rc.del('envdoc:' + id); } catch (_) {} }
    try { await rc.del('parasign:acct:' + ACCT + ':envelopes'); } catch (_) {}
    for (const e of emails) { try { await rc.del('parasign:party:' + envelopeMod.partyEmailHash(e) + ':envelopes'); } catch (_) {} }
    try { await rc.disconnect(); } catch (_) {}
  }
  return summary('parasign-cosign-parties', passed);
}

main().catch((e) => { console.error(e); process.exit(1); });
