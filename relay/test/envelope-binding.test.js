'use strict';
// Unit test for the ParaSign invite-binding primitives in relay/envelope.js
// (ADR R018): canonical party-email hash, versioned sign-message (v1/v2),
// per-party invite tokens, token-gated party view, and email-binding
// enforcement on sign(). Run: node relay/test/envelope-binding.test.js
// (no deps, exits non-zero on failure).

const assert = require('assert');
const crypto = require('crypto');
const {
  EnvelopeStore, signMessageBytes, partyEmailHash,
} = require('../envelope');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

// ── minimal in-memory redis double (only the methods sign()/getForParty use) ──
function fakeRedis(hash, evalResult) {
  return {
    isReady: true,
    async hGetAll() { return { ...hash }; },
    async hGet(_k, f) { return hash[f]; },
    async scriptLoad() { return 'sha-stub'; },
    async evalSha() { return evalResult || ['new', '1', '1', 'complete']; },
  };
}

const ID = 'envIdABC';
const DOC = 'a'.repeat(64);                 // 64-hex doc hash
const EMAIL = 'Alice@Example.COM';
const EMAIL_HASH = partyEmailHash(EMAIL);   // canonical
const emailHashOf = (h) => ({
  id: ID, doc_hash: DOC, status: 'sent', binding_mode: 'email', recipe_version: '2',
  party_count: '1', signed_count: '0', p0_email_hash: h, p0_status: 'pending',
});

async function main() {
  // 1. partyEmailHash: namespaced, case/space-normalized, deterministic, '' empty
  assert.match(EMAIL_HASH, /^[0-9a-f]{64}$/, 'email hash is sha3-256 hex');
  assert.strictEqual(partyEmailHash('  alice@example.com  '), EMAIL_HASH, 'trim+lowercase normalized');
  assert.strictEqual(partyEmailHash(''), '', 'empty email -> empty hash');
  assert.strictEqual(partyEmailHash(null), '', 'null email -> empty hash');
  const bare = crypto.createHash('sha3-256').update('alice@example.com').digest('hex');
  assert.notStrictEqual(EMAIL_HASH, bare, 'hash is namespaced, not bare sha3(email)');
  ok('partyEmailHash normalization + namespacing');

  // 2. signMessageBytes v1 regression: equals the original recipe, ignores email
  const v1 = signMessageBytes(ID, DOC, 2);
  const manual = crypto.createHash('sha3-256')
    .update(Buffer.from(ID, 'utf8'))
    .update(Buffer.from(DOC, 'hex'))
    .update(Buffer.from('2', 'utf8'))
    .digest();
  assert.ok(v1.equals(manual), 'v1 message matches original sha3(id||doc||pi)');
  assert.ok(signMessageBytes(ID, DOC, 2, EMAIL_HASH, 1).equals(manual), 'v1 ignores email hash');
  ok('signMessageBytes v1 regression');

  // 3. signMessageBytes v2 commits to the email hash
  const v2 = signMessageBytes(ID, DOC, 2, EMAIL_HASH, 2);
  assert.ok(!manual.equals(v2), 'v2 differs from v1 when an email hash is present');
  const v2other = signMessageBytes(ID, DOC, 2, partyEmailHash('bob@example.com'), 2);
  assert.ok(!v2.equals(v2other), 'v2 changes with a different email hash');
  assert.ok(signMessageBytes(ID, DOC, 2, '', 2).equals(signMessageBytes(ID, DOC, 2)), 'v2 empty-email == v1');
  ok('signMessageBytes v2 email commitment');

  // 3b. signMessageBytes v4 commits to the SIGNER pubkey (open-mode binding).
  const PUB_A = 'cHViQQ==', PUB_B = 'cHViQg==';
  const v4a = signMessageBytes(ID, DOC, 0, '', 4, PUB_A);
  const v4b = signMessageBytes(ID, DOC, 0, '', 4, PUB_B);
  assert.ok(!v4a.equals(v4b), 'v4 changes with a different signer pubkey');
  assert.ok(!v4a.equals(signMessageBytes(ID, DOC, 0, '', 3, PUB_A)), 'v4 differs from v3 (pubkey appended)');
  assert.ok(!v4a.equals(signMessageBytes(ID, DOC, 0)), 'v4 differs from the unbound v1 recipe');
  ok('signMessageBytes v4 signer-pubkey commitment');

  // 4. sign(): email-bound slot rejects a public (non-internal) caller
  {
    const store = new EnvelopeStore(fakeRedis(emailHashOf(EMAIL_HASH)), { sigVerify: () => true });
    const r = await store.sign(ID, 0, 'cHVi', 'c2ln');   // no opts => public caller
    assert.strictEqual(r.code, 'email_binding_required', 'public caller rejected on email-bound slot');
    ok('sign() rejects public caller on email-bound envelope');
  }

  // 5. sign(): email-bound slot rejects internal caller with a mismatched email
  {
    const store = new EnvelopeStore(fakeRedis(emailHashOf(EMAIL_HASH)), { sigVerify: () => true });
    const r = await store.sign(ID, 0, 'cHVi', 'c2ln', {
      internalTrusted: true, verifiedEmailHash: partyEmailHash('mallory@example.com'),
    });
    assert.strictEqual(r.code, 'email_mismatch', 'mismatched verified email rejected');
    ok('sign() rejects email mismatch');
  }

  // 6. sign(): email-bound slot accepts a matching internal caller, verifies v2 msg
  {
    let seenMsg = null;
    const store = new EnvelopeStore(fakeRedis(emailHashOf(EMAIL_HASH)), {
      sigVerify: (_sig, msg) => { seenMsg = msg; return true; },
    });
    const r = await store.sign(ID, 0, 'cHVi', 'c2ln', {
      internalTrusted: true, verifiedEmailHash: EMAIL_HASH,
    });
    assert.strictEqual(r.ok, true, 'matching internal caller accepted');
    assert.strictEqual(r.code, 'new', 'recorded as a new signature');
    assert.ok(seenMsg && seenMsg.equals(signMessageBytes(ID, DOC, 0, EMAIL_HASH, 2)), 'verified the v2 message');
    ok('sign() accepts matching internal caller with v2 message');
  }

  // 6b. sign(): audit 1.1 fail-closed. A slot created with an EMPTY email hash
  //     (the dead-end the old UI/create path could mint) can NEVER be signed in
  //     email mode -- not by a public caller, and not even by a trusted internal
  //     caller asserting an empty verified hash. So even if a doomed slot leaked
  //     past the new create-time guard, it stays unsignable (no accidental sign).
  {
    const store = new EnvelopeStore(fakeRedis(emailHashOf('')), { sigVerify: () => true });
    const pub = await store.sign(ID, 0, 'cHVi', 'c2ln');
    assert.strictEqual(pub.code, 'email_binding_required', 'empty-hash slot rejects public caller');
    const internalEmpty = await store.sign(ID, 0, 'cHVi', 'c2ln', { internalTrusted: true, verifiedEmailHash: '' });
    assert.strictEqual(internalEmpty.code, 'email_mismatch', 'empty verified hash never matches an empty slot (fail-closed)');
    const internalReal = await store.sign(ID, 0, 'cHVi', 'c2ln', { internalTrusted: true, verifiedEmailHash: EMAIL_HASH });
    assert.strictEqual(internalReal.code, 'email_mismatch', 'a real email can never claim an empty-hash slot either');
    ok('sign() empty-email slot is fail-closed (audit 1.1 dead-end unsignable)');
  }

  // 7. sign(): open envelope (no binding_mode) works via the public path but is
  //    now SIGNER-BOUND (recipe v4): the verified message appends the signer's
  //    public key, so the signature commits to the exact key that produced it.
  {
    const SIGNER_PUB = 'cHViMQ==';   // base64('pub1')
    const hash = {
      id: ID, doc_hash: DOC, status: 'sent',   // no binding_mode, no recipe_version
      party_count: '1', signed_count: '0', p0_email_hash: '', p0_status: 'pending',
    };
    let seenMsg = null;
    const store = new EnvelopeStore(fakeRedis(hash), {
      sigVerify: (_sig, msg) => { seenMsg = msg; return true; },
    });
    const r = await store.sign(ID, 0, SIGNER_PUB, 'c2ln');   // public, no opts
    assert.strictEqual(r.ok, true, 'open envelope accepts public caller');
    // The verified message is the v4 recipe bound to THIS signer pubkey...
    assert.ok(seenMsg && seenMsg.equals(signMessageBytes(ID, DOC, 0, '', 4, SIGNER_PUB)),
      'open envelope verifies the signer-bound v4 message');
    // ...and is provably NOT the old (signer-agnostic) v1 message.
    assert.ok(!seenMsg.equals(signMessageBytes(ID, DOC, 0)),
      'open-mode message is no longer the unbound v1 recipe');
    ok('sign() open envelope is signer-bound (v4, public)');
  }

  // 8. getForParty: email mode is token-gated and never leaks the invite token
  {
    const TOKEN = crypto.randomBytes(32).toString('base64url');
    const hash = {
      id: ID, doc_hash: DOC, status: 'sent', binding_mode: 'email', recipe_version: '2',
      party_count: '1', signed_count: '0',
      p0_label: 'Alice', p0_email_hash: EMAIL_HASH, p0_status: 'pending', p0_invite_token: TOKEN,
    };
    const store = new EnvelopeStore(fakeRedis(hash), {});
    assert.strictEqual(await store.getForParty(ID, 0, 'wrong-token'), null, 'wrong token -> null');
    assert.strictEqual(await store.getForParty(ID, 0, undefined), null, 'missing token -> null');
    const view = await store.getForParty(ID, 0, TOKEN);
    assert.ok(view, 'correct token returns the party view');
    assert.strictEqual(view.party.email_hash, EMAIL_HASH, 'view exposes the email hash for client recompute');
    assert.strictEqual(view.recipe_version, 2, 'view carries recipe_version');
    assert.ok(!JSON.stringify(view).includes(TOKEN), 'view never leaks the invite token');
    assert.strictEqual(await store.checkInviteToken(ID, 0, TOKEN), true, 'checkInviteToken true on match');
    assert.strictEqual(await store.checkInviteToken(ID, 0, 'nope'), false, 'checkInviteToken false on miss');
    ok('getForParty token gating + no token leak');
  }

  // 9. sign(): the 7-day signing-invite window (email mode only). A fresh invite
  //    still signs; one created >7d ago is rejected with 'invite_expired'; an
  //    open/legacy envelope ignores the window (only the 30d hash TTL bounds it).
  //    getForParty exposes sign_expires_at (created_at + 7d) for email mode.
  {
    const day = 86400_000;
    const old = new Date(Date.now() - 8 * day).toISOString();
    const fresh = new Date(Date.now() - 1 * day).toISOString();
    const emailHashAt = (createdAt) => ({
      id: ID, doc_hash: DOC, status: 'sent', binding_mode: 'email', recipe_version: '3',
      party_count: '1', signed_count: '0', p0_email_hash: EMAIL_HASH, p0_status: 'pending', created_at: createdAt,
    });
    const opts = { internalTrusted: true, verifiedEmailHash: EMAIL_HASH };

    const expired = new EnvelopeStore(fakeRedis(emailHashAt(old)), { sigVerify: () => true });
    assert.strictEqual((await expired.sign(ID, 0, 'cHVi', 'c2ln', opts)).code, 'invite_expired', 'email invite past 7d rejected');

    const within = new EnvelopeStore(fakeRedis(emailHashAt(fresh)), { sigVerify: () => true });
    assert.strictEqual((await within.sign(ID, 0, 'cHVi', 'c2ln', opts)).ok, true, 'email invite within 7d still signs');

    // open/legacy envelope with an OLD created_at is NOT subject to the invite window
    const openOld = { id: ID, doc_hash: DOC, status: 'sent', party_count: '1', signed_count: '0', p0_email_hash: '', p0_status: 'pending', created_at: old };
    const open = new EnvelopeStore(fakeRedis(openOld), { sigVerify: () => true });
    assert.strictEqual((await open.sign(ID, 0, 'cHVi', 'c2ln')).ok, true, 'open/legacy envelope ignores the 7d invite window');

    // getForParty exposes sign_expires_at for email mode (created_at + 7d), in the future for a fresh invite
    const TOKEN = crypto.randomBytes(32).toString('base64url');
    const vstore = new EnvelopeStore(fakeRedis({ ...emailHashAt(fresh), p0_invite_token: TOKEN }), {});
    const view = await vstore.getForParty(ID, 0, TOKEN);
    assert.ok(view.sign_expires_at && Date.parse(view.sign_expires_at) > Date.now(), 'sign_expires_at set + in the future for a fresh email invite');
    ok('sign() enforces the 7-day signing-invite window (email mode; open unaffected)');
  }

  // 10. sign(): open-mode signer-substitution is rejected. A real ML-DSA verify
  //     only passes when the signature matches the message AND the submitted
  //     pubkey. We model that: the verifier accepts iff the message equals the
  //     v4 recipe for the *submitted* pubkey. An attacker who signs the legacy
  //     (signer-agnostic) message, or presents a signature minted for a
  //     different key, no longer validates against any other key/slot.
  {
    const hash = {
      id: ID, doc_hash: DOC, status: 'sent',   // open envelope
      party_count: '1', signed_count: '0', p0_email_hash: '', p0_status: 'pending',
    };
    // Honest verifier: bind sig<->(message, pubkey). Here a "signature" is just
    // the v4 message the signer committed to; it verifies only if it equals the
    // v4 message recomputed for the pubkey actually submitted to sign().
    const honest = (committedMsgB64) => (sigBuf, msg, pubBuf) => {
      const submittedPub = pubBuf.toString('base64');
      const expected = signMessageBytes(ID, DOC, 0, '', 4, submittedPub);
      return Buffer.from(committedMsgB64, 'base64').equals(msg) && msg.equals(expected);
    };

    const PUB_A = 'cHViQQ==';   // base64('pubA')
    const PUB_B = 'cHViQg==';   // base64('pubB')

    // (a) Honest signer A: commits to v4 message for PUB_A, submits PUB_A -> ok.
    const msgA = signMessageBytes(ID, DOC, 0, '', 4, PUB_A).toString('base64');
    const okStore = new EnvelopeStore(fakeRedis(hash), { sigVerify: honest(msgA) });
    assert.strictEqual((await okStore.sign(ID, 0, PUB_A, msgA)).ok, true, 'honest signer with matching v4 commitment accepted');

    // (b) Attacker captured A's signature (committed to PUB_A) but submits PUB_B
    //     to claim the slot as a different identity -> rejected (message for
    //     PUB_B differs, so the captured commitment no longer verifies).
    const subStore = new EnvelopeStore(fakeRedis(hash), { sigVerify: honest(msgA) });
    assert.strictEqual((await subStore.sign(ID, 0, PUB_B, msgA)).code, 'bad_signature', 'key-substituted signature rejected');

    // (c) Legacy attack: sign the OLD signer-agnostic v1 message -> rejected,
    //     because open mode now verifies the signer-bound v4 message only.
    const legacyMsg = signMessageBytes(ID, DOC, 0).toString('base64');
    const legacyStore = new EnvelopeStore(fakeRedis(hash), { sigVerify: honest(legacyMsg) });
    assert.strictEqual((await legacyStore.sign(ID, 0, PUB_A, legacyMsg)).code, 'bad_signature', 'legacy signer-agnostic signature rejected');

    // (d) Empty signer key is rejected before verify (v4 mixes the pubkey).
    const emptyStore = new EnvelopeStore(fakeRedis(hash), { sigVerify: () => true });
    assert.strictEqual((await emptyStore.sign(ID, 0, '', 'c2ln')).code, 'bad_signature', 'empty signer key rejected');

    ok('sign() open-mode signer binding blocks key substitution + legacy replay');
  }
}

main()
  .then(() => { console.log(`\nenvelope-binding: ${passed} checks passed`); })
  .catch((e) => { console.error('\nFAILED:', e && e.message ? e.message : e); process.exit(1); });
