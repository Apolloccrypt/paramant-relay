'use strict';
// The recipient's side of a signing request: the party worklist index, the
// backfill that fills it for older envelopes, and the resend material.
//
// Until this index existed an envelope was reachable only through the per-party
// invite token in the invitation mail. A signed-in recipient could not learn a
// request existed, and losing the mail meant losing the document. These cases
// exercise a REAL EnvelopeStore against a REAL redis and the REAL ML-DSA-65
// engine, because the two properties that matter are both about real state:
//
//   1. the index shows a party exactly the envelopes still waiting on them, and
//      stops showing one the moment they sign it;
//   2. the backfill fills the index for envelopes made before it existed, is
//      idempotent, and does not resurrect a row that signing removed.
//
// Needs @paramant/core and a redis at REDIS_URL / 127.0.0.1:6396. A missing one
// is a FAILURE unless the runner declared it absent; see test/_requires.js.
//   docker run -d --rm -p 6396:6379 --name party-redis redis:alpine

const assert = require('assert');
const crypto = require('crypto');
const envelopeMod = require('../envelope');
const partyBackfill = require('../lib/parasign-party-backfill');
const { requireEngine, requireRedis, summary } = require('./_requires');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

async function signAs(store, eng, id, docHash, partyIndex, emailHash, inviteToken) {
  const kp = eng.generateKeyPair();
  const pubB64 = Buffer.from(kp.publicKey).toString('base64');
  // Email-bound slots are recipe v2: the message commits to the party's email hash.
  const msg = envelopeMod.signMessageBytes(id, docHash, partyIndex, emailHash, 2, pubB64);
  const sigB64 = Buffer.from(eng.sign(msg, kp.secretKey)).toString('base64');
  return store.sign(id, partyIndex, pubB64, sigB64, {
    internalTrusted: true, verifiedEmailHash: emailHash, inviteToken,
  });
}

async function main() {
  const eng = requireEngine();
  const rc = await requireRedis('redis://127.0.0.1:6396');
  if (!eng || !rc) {
    if (rc) try { await rc.disconnect(); } catch (_) {}
    return summary('parasign-party-index', passed);
  }
  const registry = require('../crypto/registry');
  const store = new envelopeMod.EnvelopeStore(rc, {
    ctAppend: () => null,
    sigVerify: (sig, msg, pub) => { try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch { return false; } },
  });

  const rnd = crypto.randomBytes(6).toString('hex');
  const ACCT = 'acct_demo_' + rnd;
  const A_EMAIL = `alpha-${rnd}@example.com`;
  const B_EMAIL = `beta-${rnd}@example.com`;
  const A_HASH = envelopeMod.partyEmailHash(A_EMAIL);
  const B_HASH = envelopeMod.partyEmailHash(B_EMAIL);
  const docHash = crypto.createHash('sha3-256').update(Buffer.from('doc-' + rnd)).digest('hex');
  const made = [];

  try {
    // 1) create() indexes both parties, and each sees only their own slot ------
    const out = await store.create({
      accountId: ACCT, docHash, bindingMode: 'email', recipeVersion: 2,
      originalFilename: 'Engagement letter.pdf',
      parties: [{ label: 'Signer Demo', email: A_EMAIL }, { label: 'Signer Acme', email: B_EMAIL }],
    });
    made.push(out.id);

    const forA = await store.listPartyEnvelopes(A_HASH, {});
    assert.strictEqual(forA.length, 1, 'party A sees the envelope they are invited to');
    assert.strictEqual(forA[0].id, out.id, 'the row names the envelope');
    assert.strictEqual(forA[0].document, 'Engagement letter.pdf', 'the row names the document');
    assert.strictEqual(forA[0].party_count, 2, 'the row says how many parties there are');
    assert.strictEqual(forA[0].signed_count, 0, 'nobody has signed yet');
    ok('create() puts an email-bound envelope on every invited party worklist');

    // The row is knowing-THAT. Anything that would let a reader OPEN or FORGE
    // the document has to be absent, and absent by name, not by accident.
    for (const field of ['invite_token', 'doc_hash', 'party_email_hash', 'sender_account_id', 'parties']) {
      assert.ok(!Object.hasOwn(forA[0], field), `the worklist row must not carry ${field}`);
    }
    assert.ok(forA[0].signing_closes_at && Date.parse(forA[0].signing_closes_at) > Date.now(),
      'the row says when signing closes');
    ok('the worklist row carries no invite token, no document hash and no capability');

    // 2) the sender is resolved by the caller, never held by the store --------
    const named = await store.listPartyEnvelopes(A_HASH, { resolveSender: (a) => (a === ACCT ? 'sender@example.com' : null) });
    assert.strictEqual(named[0].sender, 'sender@example.com', 'the injected resolver names the sender');
    const unnamed = await store.listPartyEnvelopes(A_HASH, { resolveSender: () => { throw new Error('boom'); } });
    assert.strictEqual(unnamed[0].sender, null, 'a resolver that throws leaves the sender null');
    assert.strictEqual(unnamed.length, 1, 'and never drops a document somebody is waiting on');
    ok('the sender is named by the caller, and an unnameable one still shows the row');

    // 3) a stranger sees nothing, and index membership is not authority -------
    const stranger = envelopeMod.partyEmailHash(`nobody-${rnd}@example.com`);
    assert.deepStrictEqual(await store.listPartyEnvelopes(stranger, {}), [],
      'an address that is not a party sees nothing');
    // Write the member into the stranger's set by hand: the read must still
    // refuse it, because the email hash is re-checked against the record.
    await rc.zAdd(store._partyIndexKey(stranger), { score: Date.now(), value: out.id + '#0' });
    assert.deepStrictEqual(await store.listPartyEnvelopes(stranger, { prune: false }), [],
      'a hand-written index member shows nobody anything');
    await rc.del(store._partyIndexKey(stranger));
    ok('index membership is not authority: the record decides');

    // 4) signing removes the slot, and only that slot -------------------------
    const inviteA = await store.getPartyInvite(out.id, A_HASH);
    assert.ok(inviteA && inviteA.invite_token, 'the resend material carries the stored invite token');
    assert.strictEqual(inviteA.party_index, 0, 'and names which slot it is for');
    const created = await rc.hGetAll('env:' + out.id);
    assert.strictEqual(inviteA.invite_token, created.p0_invite_token,
      'the resend returns the token create() stored; it mints nothing');
    ok('getPartyInvite() hands back the stored invite token and mints no new one');

    const signed = await signAs(store, eng, out.id, docHash, 0, A_HASH, inviteA.invite_token);
    assert.strictEqual(signed.ok, true, 'party A signs: ' + signed.code);
    assert.deepStrictEqual(await store.listPartyEnvelopes(A_HASH, {}), [],
      'the envelope leaves the signer worklist the moment they sign');
    const forB = await store.listPartyEnvelopes(B_HASH, {});
    assert.strictEqual(forB.length, 1, 'the other party is still waiting');
    assert.strictEqual(forB[0].signed_count, 1, 'and can see that one signature is in');
    assert.strictEqual(await rc.zScore(store._partyIndexKey(A_HASH), out.id + '#0'), null,
      'the member is gone from the index, not merely filtered out of the read');
    ok('signing takes the envelope off that party worklist and leaves the others');

    assert.strictEqual(await store.getPartyInvite(out.id, A_HASH), null,
      'a party who signed can no longer ask for the invitation again');
    ok('the resend refuses a slot that is no longer waiting');

    // 5) completion closes it for everyone ------------------------------------
    const inviteB = await store.getPartyInvite(out.id, B_HASH);
    const done = await signAs(store, eng, out.id, docHash, 1, B_HASH, inviteB.invite_token);
    assert.strictEqual(done.status, 'complete', 'the last signature completes the envelope');
    assert.deepStrictEqual(await store.listPartyEnvelopes(B_HASH, {}), [],
      'a completed envelope waits on nobody');
    ok('a completed envelope leaves every worklist');

    // 6) withdrawing closes it too -------------------------------------------
    const two = await store.create({
      accountId: ACCT, docHash, bindingMode: 'email', recipeVersion: 2,
      originalFilename: 'Withdrawn.pdf',
      parties: [{ label: 'Signer Demo', email: A_EMAIL }],
    });
    made.push(two.id);
    assert.strictEqual((await store.listPartyEnvelopes(A_HASH, {})).length, 1, 'the second envelope is waiting');
    const voided = await store.voidEnvelope(two.id, 'no longer needed');
    assert.strictEqual(voided.ok, true, 'the envelope is withdrawn');
    assert.deepStrictEqual(await store.listPartyEnvelopes(A_HASH, {}), [],
      'a withdrawn envelope waits on nobody');
    assert.strictEqual(await store.getPartyInvite(two.id, A_HASH), null,
      'and its invitation cannot be resent');
    ok('withdrawing an envelope takes it off every worklist');

    // 7) an open envelope has no bound party, so it indexes nobody ------------
    const open = await store.create({
      accountId: ACCT, docHash, bindingMode: 'open',
      originalFilename: 'Open.pdf', parties: [{ label: 'Anyone', email: '' }],
    });
    made.push(open.id);
    const emptyHash = envelopeMod.partyEmailHash('');
    assert.strictEqual(emptyHash, '', 'an absent address has no party hash');
    assert.deepStrictEqual(await store.listPartyEnvelopes(A_HASH, {}), [],
      'an open envelope puts nobody on a worklist');
    ok('an open envelope, which is bound to no address, indexes nobody');

    // 8) the backfill ---------------------------------------------------------
    // An envelope written the way one was before the index existed: create()
    // then delete the index members, so only the record remains.
    const older = await store.create({
      accountId: ACCT, docHash, bindingMode: 'email', recipeVersion: 2,
      originalFilename: 'Older request.pdf',
      parties: [{ label: 'Signer Demo', email: A_EMAIL }],
    });
    made.push(older.id);
    await rc.zRem(store._partyIndexKey(A_HASH), older.id + '#0');
    assert.deepStrictEqual(await store.listPartyEnvelopes(A_HASH, {}), [],
      'an un-indexed envelope is invisible, which is the bug the backfill fixes');

    const first = await store.backfillPartyIndex({});
    assert.ok(first.indexed >= 1, 'the backfill indexed at least the un-indexed slot');
    const afterFill = await store.listPartyEnvelopes(A_HASH, {});
    assert.strictEqual(afterFill.length, 1, 'the older envelope is on the worklist now');
    assert.strictEqual(afterFill[0].id, older.id, 'and it is the right one');
    ok('backfillPartyIndex() fills the index from the envelope records');

    const before = await rc.zRangeWithScores(store._partyIndexKey(A_HASH), 0, -1);
    const second = await store.backfillPartyIndex({});
    const after = await rc.zRangeWithScores(store._partyIndexKey(A_HASH), 0, -1);
    assert.deepStrictEqual(after, before, 'a second run changes no member and no score');
    assert.strictEqual(second.scanned >= first.scanned, true, 'the second run still scanned the keyspace');
    ok('the backfill is idempotent: a second run leaves the index byte for byte alone');

    // The one thing a re-run must never do is undo a signature's effect.
    assert.strictEqual(await rc.zScore(store._partyIndexKey(B_HASH), made[0] + '#1'), null,
      'the completed envelope stays off the worklist after a re-run');
    ok('a re-run does not resurrect a row that signing or completion removed');

    // 9) the lock and the done marker ----------------------------------------
    await rc.del(partyBackfill.DONE_KEY);
    await rc.del(partyBackfill.LOCK_KEY);
    const ran = await partyBackfill.runPartyIndexBackfill({ redis: rc, store, log: () => {} });
    assert.strictEqual(ran.ran, true, 'the first run does the work');
    assert.ok(await rc.get(partyBackfill.DONE_KEY), 'a finished run writes the marker');
    const again = await partyBackfill.runPartyIndexBackfill({ redis: rc, store, log: () => {} });
    assert.strictEqual(again.ran, false, 'the second run does nothing');
    assert.strictEqual(again.reason, 'done', 'and says why');
    assert.strictEqual(await rc.get(partyBackfill.LOCK_KEY), null, 'the lock is released');
    ok('the migration runs once across restarts, on a redis marker and not on process memory');

    // A container that already holds the lock is the expected answer on four
    // relays out of five, and it is not an error.
    await rc.del(partyBackfill.DONE_KEY);
    await rc.set(partyBackfill.LOCK_KEY, 'someone-else', { PX: 60000 });
    const blocked = await partyBackfill.runPartyIndexBackfill({ redis: rc, store, log: () => {} });
    assert.strictEqual(blocked.ran, false, 'a second container does not run the scan');
    assert.strictEqual(blocked.reason, 'locked', 'and says the lock is held');
    assert.strictEqual(await rc.get(partyBackfill.LOCK_KEY), 'someone-else',
      'and never releases a lock it does not hold');
    ok('one container of five does the scan; the others stand down without touching the lock');
  } finally {
    try {
      await rc.del(partyBackfill.DONE_KEY);
      await rc.del(partyBackfill.LOCK_KEY);
      await rc.del(store._partyIndexKey(A_HASH));
      await rc.del(store._partyIndexKey(B_HASH));
      await rc.del(store._acctIndexKey(ACCT));
      for (const id of made) await rc.del('env:' + id);
    } catch (_) { /* teardown is best effort */ }
    try { await rc.disconnect(); } catch (_) {}
  }
  return summary('parasign-party-index', passed);
}

main().catch((e) => { console.error(e); process.exit(1); });
