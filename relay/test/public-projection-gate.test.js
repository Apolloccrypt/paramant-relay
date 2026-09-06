'use strict';
// THE PUBLIC PROJECTION GATE. An answer that needed no credential may not
// carry a value that a credentialled answer treats as identifying, and may not
// carry a value that some OTHER credential-free route resolves into a person.
//
// WHY THIS EXISTS. The 2026-09-05 hostile review, findings 4 and 5.
// GET /v2/envelopes/:id is public on purpose: the receiver of a signing invite
// is an outsider with no API key, and the page they open has to be able to ask
// the relay what it is looking at. The route answered that question with the
// same projection the owner sees. So the envelope id, which travels in links,
// in mailboxes, in access logs and over shoulders, bought a passer-by:
//
//   doc_hash            the full SHA3-256 of the document. That is a
//                       confirmation oracle: anyone holding a candidate PDF
//                       proves offline that this exact file is the one being
//                       signed. The whole point of storing a hash instead of a
//                       document is undone by publishing the hash.
//   original_filename   up to 200 characters chosen by the sender, and senders
//                       name files after what is in them.
//   parties[].label     the name the sender typed for each party.
//   parties[].signed_at who had signed, and when.
//   parties[].signer_pk_hash
//                       the worst of the four, because it is not a fact about
//                       the envelope, it is a JOIN KEY. GET /v2/lookup-signer/
//                       :pk_hash also sits in front of the auth gate, and it
//                       answered with the signer's real email address. Two
//                       unauthenticated GETs turned an envelope id into the
//                       mailbox of everyone who had signed it.
//
// WHAT THE GATE LOCKS DOWN, AS A CLASS. Not "signer_pk_hash is gone": that is
// the instance, and the next field to leak has a different name. The class is
//
//   (1) the anonymous answer is a SUBSET of the authorized one, never a
//       separate universe with its own extras;
//   (2) values an authorized answer treats as identifying are demonstrably in
//       the authorized answer and demonstrably absent from the anonymous one;
//   (3) nothing in the anonymous answer can be walked into an identity by
//       another route that also takes no credential. This is asserted by
//       REPLAYING THE ATTACK, not by naming the field: every 64-hex string in
//       the public answer is fed to /v2/lookup-signer without a key;
//   (4) the public field set is an explicit allowlist. A field added to the
//       envelope later cannot become public by accident: it turns this red and
//       somebody has to decide.
//
// HOW TO ANSWER A RED
//   A new field in the anonymous answer: decide whether an outsider holding
//   only the id may have it. Almost always the answer is no, and the fix is to
//   put it behind `authorized` in envelope.js getRedacted (and, if a party
//   needs it, in getForParty, which is reached only with that party's invite
//   token). If it genuinely may be public, add it to PUBLIC_TOP or
//   PUBLIC_PARTY below with a reason a reviewer can check.
//   A failing chain assertion: some anonymous route resolves a value the
//   public projection hands out. Close the identity end of that route, and
//   stop publishing the value. Both, not either: the review had to do both.
//
// NEEDS a reachable redis (the envelope store is redis-only) and the ML-DSA-65
// engine (the differential is measured on a really signed slot), both declared
// through test/_requires.js.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test test/public-projection-gate.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');
const envelopeMod = require('../envelope');
const userSigning = require('../lib/user-signing');

const RUN = crypto.randomBytes(6).toString('hex');
const OWNER = `pgp_owner_key_for_the_projection_gate_${RUN}`;
const OWNER_ACCT = `acct_demo_${RUN}`;
const INTERNAL = `internal_${RUN}`;
const SIGNER_USER = `acct_demo_signer_${RUN}`;
const SIGNER_EMAIL = 'demo@example.com';
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';

// The identifying strings this suite plants and then hunts for. Chosen so a
// substring search over a response body cannot match by luck.
const FILENAME = `Vaststellingsovereenkomst Acme definitief ${RUN}.pdf`;
const LABELS = [`Demo ${RUN}`, `Acme ${RUN}`];

let srv = null;
let eng = null;
let rc = null;
let checks = 0;
const did = () => { checks++; };
const ready = () => srv !== null && eng !== null && rc !== null;

// Every test takes its own client address: /v2/lookup-signer is rate limited
// 30/min/IP and the bucket is global to the relay process, so a suite that
// shares one address ends up measuring the limiter instead of the projection.
let _ipN = 0;
let IP = '10.7.0.1';
const nextIp = () => { _ipN++; return `10.7.${Math.floor(_ipN / 250)}.${(_ipN % 250) + 1}`; };
const asParty = (extra = {}) => ({ 'X-Real-IP': IP, ...extra });

// The one envelope every test reads, set up once in before(): two parties, a
// filename, labels, and party 0 really signed with a real ML-DSA-65 key that is
// really enrolled under an account with a real address. Every leak the review
// found is therefore reachable here if the code lets it be.
const FIX = {
  id: null, docHash: null, tokens: [], pkHash: null, pkB64: null,
};

before(async () => {
  eng = requireEngine();
  rc = await requireRedis(DEFAULT_REDIS);
  if (!eng || !rc) return;
  srv = await boot({
    tag: 'projection',
    users: {
      api_keys: [
        { key: OWNER, plan: 'community', active: true, parasign: true, email: 'owner@example.com', account_id: OWNER_ACCT },
      ],
    },
    env: {
      REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS,
      INTERNAL_AUTH_TOKEN: INTERNAL,
    },
  });

  // Create the envelope.
  IP = nextIp();
  FIX.docHash = crypto.createHash('sha3-256').update(`doc-${RUN}`).digest('hex');
  const created = await srv.post('/v2/envelopes', {
    headers: asParty({ 'X-Api-Key': OWNER }),
    body: {
      doc_hash: FIX.docHash,
      original_filename: FILENAME,
      parties: [{ label: LABELS[0] }, { label: LABELS[1] }],
    },
  });
  assert.strictEqual(created.status, 200, `create failed: ${created.status} ${created.text}`);
  FIX.id = created.json.envelope.id;
  FIX.tokens = created.json.envelope.party_links.map((p) => p.invite_token);

  // Party 0 signs for real. Open-mode slots are recipe v4: the signer's own
  // public key is mixed into the message, so the signature commits to the key.
  const kp = eng.generateKeyPair();
  FIX.pkB64 = Buffer.from(kp.publicKey).toString('base64');
  FIX.pkHash = crypto.createHash('sha3-256').update(Buffer.from(kp.publicKey)).digest('hex');
  const msg = envelopeMod.signMessageBytes(FIX.id, FIX.docHash, 0, '', 4, FIX.pkB64);
  const signed = await srv.post(`/v2/envelopes/${FIX.id}/sign`, {
    headers: asParty(),
    body: {
      party_index: 0,
      signer_public_key: FIX.pkB64,
      signature: Buffer.from(eng.sign(msg, kp.secretKey)).toString('base64'),
      token: FIX.tokens[0],
    },
  });
  assert.strictEqual(signed.status, 200, `sign failed: ${signed.status} ${signed.text}`);

  // Enroll that very key under an account with an address, so the join key at
  // the end of the chain really does lead somewhere. Without this the chain
  // assertion would pass because the destination is empty, which proves
  // nothing about the door.
  await userSigning.storeSigningPk(rc, SIGNER_USER, { pk_b64: FIX.pkB64, label: 'Demo' });
  await rc.set(`paramant:user:meta:${SIGNER_USER}`, JSON.stringify({ email: SIGNER_EMAIL }));
});

after(async () => {
  if (rc) {
    try {
      await rc.del(`paramant:user:meta:${SIGNER_USER}`);
      await rc.del(`paramant:user:signing_pk:${SIGNER_USER}`);
      if (FIX.pkHash) await rc.del(`paramant:signing_pk_index:${FIX.pkHash}`);
    } catch (_) {}
  }
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('public-projection-gate', checks);
});

// ── helpers ────────────────────────────────────────────────────────────────

// Every primitive anywhere in a JSON value, typed so the number 0 and the
// string "0" are not confused for one another.
function values(node, out = new Set()) {
  if (node === null || typeof node !== 'object') { out.add(`${typeof node}:${String(node)}`); return out; }
  if (Array.isArray(node)) { for (const v of node) values(v, out); return out; }
  for (const v of Object.values(node)) values(v, out);
  return out;
}

const anon = () => srv.get(`/v2/envelopes/${FIX.id}`, { headers: asParty() });
const asPartyView = (i = 0) =>
  srv.get(`/v2/envelopes/${FIX.id}?p=${i}&t=${encodeURIComponent(FIX.tokens[i])}`, { headers: asParty() });

// ── 1. the differential ────────────────────────────────────────────────────

// Fields the public projection carries that the party projection happens not
// to. The party view is not a superset by construction, it is a different
// hand-written projection, so a bare subset assertion would go red on a field
// that leaks nothing. Every exemption is a field name plus the reason it is
// not identifying, and the list is deliberately tiny: a long one means the two
// projections have drifted apart and the subset property has stopped meaning
// anything.
const SUBSET_EXEMPT = {
  created_at: 'when the envelope was made. Says nothing about who is on it, and the party view simply does not carry it.',
};

test('PROJECTION: the anonymous answer is a subset of the party answer, not a universe of its own', async () => {
  if (!ready()) return;
  IP = nextIp();
  const a = await anon();
  const p = await asPartyView(0);
  assert.strictEqual(a.status, 200, a.text);
  assert.strictEqual(p.status, 200, p.text);

  const partyValues = values(p.json);
  const exempt = new Set();
  for (const [field, reason] of Object.entries(SUBSET_EXEMPT)) {
    assert.ok(reason, `${field} needs a reason`);
    values(a.json.envelope[field], exempt);
  }

  const extras = [...values(a.json.envelope)].filter((v) => !partyValues.has(v) && !exempt.has(v));
  assert.deepStrictEqual(extras, [],
    'the public answer carries values the party answer does not:\n  ' + extras.join('\n  ') +
    '\nThe public projection is meant to be the authorized one with things REMOVED. A value\n' +
    'that only the anonymous caller sees is either dead weight or a leak, and either way\n' +
    'nobody decided to put it there.');
  did();
});

test('PROJECTION: every value the review named is in the party answer and in no public one', async () => {
  if (!ready()) return;
  IP = nextIp();
  const a = await anon();
  const p = await asPartyView(0);

  // doc_hash (the confirmation oracle), the filename, both labels, and the
  // signer's pk hash (the join key). Each is checked against the raw body, not
  // against a field name, so moving a leak to a new key does not hide it.
  const identifying = {
    doc_hash: FIX.docHash,
    original_filename: FILENAME,
    'parties[0].label': LABELS[0],
    'parties[1].label': LABELS[1],
    'parties[0].signer_pk_hash': FIX.pkHash,
  };

  for (const [what, value] of Object.entries(identifying)) {
    assert.ok(p.text.includes(value),
      `${what} is missing from the PARTY view. Either the fixture is broken or the fix for\n` +
      'findings 4 and 5 has over-corrected: the holder of a party invite token is entitled to\n' +
      'all of this, and /co-sign cannot render the page without it. A test that only proves\n' +
      'the field is gone everywhere proves nothing about the redaction.');
    assert.ok(!a.text.includes(value),
      `${what} is readable by anyone holding only the envelope id:\n  ${value}\n` +
      'Put it behind the `authorized` flag in envelope.js getRedacted.');
  }

  // The signed_at moment is a value, not a constant, so it is checked through
  // the field rather than by substring.
  assert.ok(p.json.envelope.parties[0].signed_at, 'the party view carries signed_at');
  assert.strictEqual(a.json.envelope.parties[0].signed_at, undefined,
    'who signed WHEN is a fact about a person and is not public');
  did();
});

test('PROJECTION: an API key does not upgrade this route, and the owner reads its own through the account-scoped one', async () => {
  if (!ready()) return;
  IP = nextIp();
  const bare = await anon();
  const keyed = await srv.get(`/v2/envelopes/${FIX.id}`, { headers: asParty({ 'X-Api-Key': OWNER }) });
  assert.strictEqual(keyed.status, 200, keyed.text);
  assert.deepStrictEqual(keyed.json, bare.json,
    'GET /v2/envelopes/:id answers the same to everyone. It is the public door: if it ever starts\n' +
    'reading X-Api-Key to decide what to show, the redaction has moved into route code and the\n' +
    'default in getRedacted has stopped being the thing that protects it.');

  // Where the owner DOES get the identifying view: the account-scoped list,
  // behind internal auth, which passes authorized: true. This is the other end
  // of the differential. It is a summary, so it carries the filename and the
  // labels but not doc_hash or signer_pk_hash; those two are asserted above
  // through the party view instead.
  const own = await srv.post('/v2/user/envelopes', {
    headers: asParty({ 'X-Internal-Auth': INTERNAL }),
    body: { user_id: OWNER_ACCT },
  });
  assert.strictEqual(own.status, 200, own.text);
  const row = (own.json.documents || []).find((r) => r.id === FIX.id);
  assert.ok(row, 'the owning account must find its own envelope in its worklist');
  assert.strictEqual(row.original_filename, FILENAME,
    'the owner sees the filename, which is what makes hiding it from a stranger a redaction');
  assert.deepStrictEqual(row.parties.map((x) => x.label), LABELS,
    'and the owner sees the labels it typed itself');
  did();
});

// ── 2. the chain that was the attack ───────────────────────────────────────

test('CHAIN: nothing in the public answer walks into an identity through another keyless route', async () => {
  if (!ready()) return;
  IP = nextIp();
  const a = await anon();

  // The attack as it was actually available: take the public answer, find
  // anything shaped like a SHA3-256 hex digest, and try each one on the other
  // route that needs no key. This is deliberately written as a sweep over the
  // BODY rather than as a check on a field, because the finding was not "this
  // field is bad", it was "this answer contains a join key".
  const candidates = [...new Set((a.text.match(/[0-9a-f]{64}/g) || []))];
  for (const h of candidates) {
    const r = await srv.get(`/v2/lookup-signer/${h}`, { headers: asParty() });
    assert.notStrictEqual(r.status, 429, 'ran out of lookup budget; give this test its own address');
    const email = r.json && r.json.email;
    assert.ok(!email,
      `a 64-hex value from the PUBLIC envelope answer resolved to ${email} with no API key.\n` +
      `  hash: ${h}\n` +
      'That is the two-GET chain from finding 4, whatever the field it came out of is called.');
  }

  // The sweep above is only worth having if the sweep itself works. The same
  // scan over the PARTY answer must find the join key, which proves the regex
  // and the loop are live and that the public answer is quiet because it is
  // quiet, not because the scanner is broken.
  const p = await asPartyView(0);
  const partyHashes = new Set(p.text.match(/[0-9a-f]{64}/g) || []);
  assert.ok(partyHashes.has(FIX.pkHash),
    'the scanner must be able to see a pk hash when one is there; it did not find it in the party view');
  assert.ok(!candidates.includes(FIX.pkHash),
    'and the public answer must not be where it comes from');
  did();
});

test('CHAIN: the lookup route hands out the address only against a live API key', async () => {
  if (!ready()) return;
  IP = nextIp();

  // Straight at the real join key, which is what an attacker who got it some
  // other way (out of a .psign file, say) would do.
  const open = await srv.get(`/v2/lookup-signer/${FIX.pkHash}`, { headers: asParty() });
  assert.strictEqual(open.status, 200, open.text);
  assert.strictEqual(open.json.found, true,
    'the enrollment fact stays public: a verifier checking a signature needs to know the key is enrolled');
  assert.strictEqual(open.json.email, null,
    'but the mailbox behind it is not something a keyless caller gets. This is finding 4 head on.');

  // And the positive control. Without this the assertion above is satisfied by
  // a route that is simply broken, and the gate would stay green through a
  // regression that breaks lookup for the verifiers it exists for.
  const keyed = await srv.get(`/v2/lookup-signer/${FIX.pkHash}`, { headers: asParty({ 'X-Api-Key': OWNER }) });
  assert.strictEqual(keyed.status, 200, keyed.text);
  assert.strictEqual(keyed.json.email, SIGNER_EMAIL,
    'a caller with a live key still resolves the address, so the assertion above is measuring the gate\n' +
    'and not a dead route');
  did();
});

// ── 3. the allowlist, so the next field cannot slip in ─────────────────────

// What an outsider holding nothing but the envelope id may know, and why. Every
// entry is a decision somebody made; adding one is how this gate is meant to be
// answered, and it costs a line of reasoning that a reviewer can disagree with.
const PUBLIC_TOP = {
  id: 'the caller already has it; it is what they asked with',
  status: 'sent / completed / voided. The co-signer page has to say whether it is still signable',
  binding_mode: 'open or email. Decides which sign-message recipe the page must reproduce',
  recipe_version: 'same reason: the recipe is public by design, it is a formula and not a fact about anyone',
  created_at: 'a moment, no subject',
  expires_at: 'a moment, and a signer needs to know how long they have',
  completed_at: 'a moment; whether the round is over is already implied by status',
  voided_at: 'a moment; a voided envelope must be able to say so, or a signer signs into nothing',
  party_count: 'how many slots. A number with no names on it',
  signed_count: 'how far along. The progress bar the invite page shows before the party opens their link',
  parties: 'the per-slot array, allowlisted separately below',
};

const PUBLIC_PARTY = {
  index: 'the slot number, which the caller supplies anyway when it signs',
  status: 'pending / signed. Progress, not identity: it says a slot is filled, not by whom',
};

// The keys of the HTTP answer itself, so a leak cannot be parked next to the
// envelope instead of inside it.
const PUBLIC_ENVELOPE_TOP = {
  ok: 'the success flag',
  envelope: 'the projection, allowlisted above',
  sign_message_recipe: 'the formula the co-signer recomputes. Public by design and identical for every envelope in a mode',
};

test('ALLOWLIST: the public projection has exactly the fields somebody decided it may have', async () => {
  if (!ready()) return;
  IP = nextIp();
  const a = await anon();
  assert.strictEqual(a.status, 200, a.text);

  const check = (obj, allow, where) => {
    const extra = Object.keys(obj).filter((k) => !(k in allow));
    const missing = Object.keys(allow).filter((k) => !(k in obj));
    assert.deepStrictEqual(extra, [],
      `${where}: field(s) [${extra.join(', ')}] are answered to a caller with no credential and no\n` +
      'entry in the allowlist in this file. Decide: put it behind `authorized` in getRedacted, or\n' +
      'add it here with the reason it may be public. A field must not become public by being added.');
    assert.deepStrictEqual(missing, [],
      `${where}: allowlisted field(s) [${missing.join(', ')}] are gone. Either the projection shrank\n` +
      '(good, drop the line here) or a rename happened and the old name is now unguarded.');
  };

  check(a.json, PUBLIC_ENVELOPE_TOP, 'the answer body');
  check(a.json.envelope, PUBLIC_TOP, 'envelope');
  assert.strictEqual(a.json.envelope.parties.length, 2, 'the fixture has two parties');
  a.json.envelope.parties.forEach((p, i) => check(p, PUBLIC_PARTY, `envelope.parties[${i}]`));

  // One of the two slots is signed and the other is not, so the loop above ran
  // over both shapes. A projection that only adds fields once a slot is filled
  // would otherwise be checked in its empty form only.
  assert.deepStrictEqual(a.json.envelope.parties.map((p) => p.status), ['signed', 'pending'],
    'the fixture must cover a filled slot and an empty one');
  did();
});
