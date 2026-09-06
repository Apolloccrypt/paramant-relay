'use strict';
// THE OMISSION GATE, behavioural half. Over HTTP, on a really booted relay:
// leaving a field out of a privileged request must never be the cheapest way
// through it.
//
// The static half (authz-omission-gate.test.js) reads the source for the shape.
// This one reads the answers. It exists because a linter can be satisfied by
// moving code around, and what the 2026-09-05 review actually found was three
// requests that a stranger could send from the open internet:
//
//   1. POST /v2/envelopes/:id/sign with nothing but the envelope id: a signature
//      placed in a named party's slot by whoever knew the id.
//   2. the same request with account_id left out: the quota pre-gate and the
//      counter both skipped, the signature accepted anyway. Unlimited signing on
//      a plan that sells two a month.
//   3. POST /v2/pubkey on an invite slot that is already filled: both key slots
//      of a ParaShare session overwritten by a passer-by, who then reads along.
//
// Each is asserted here as a property rather than as a reproduction, so the
// assertions survive the routes being rewritten:
//
//   CAPABILITY  drop any one caller-supplied field from a request that works,
//               and it must stop working. Field by field, mechanically.
//   METERING    a signature is counted against a real account even when the
//               request names none, and the plan cap still bites.
//   FIRST WINS  a filled slot is not re-fillable with different content.
//
// One fixture in DOOR 3 changed on 5 September 2026 and the reason is worth
// writing down, because the assertion looks weakened and is not. The `_ready`
// half of a ParaShare session was being filled with two runs of hex, as though
// it held keys like the slot above it. It does not: it holds the handshake
// record, which used to carry the sender's file name in the clear for an hour,
// readable by anyone with the session token, against what /dpa promises. That
// field now has a grammar (relay/lib/handshake-record.js) and the arbitrary hex
// is no longer a thing the slot accepts. The fixture is a real record now, the
// FIRST WINS property is asserted exactly as before, and the refusal of a
// malformed record is asserted alongside it: a passer-by must not be able to
// fill the slot with rubbish either, since first-wins would then lock the
// honest sender out.
//
// NEEDS a reachable redis (the envelope store and the quota counters are both
// redis-only) and the ML-DSA-65 engine, both declared through test/_requires.js.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-omission-gate.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');
const envelopeMod = require('../envelope');
const quota = require('../lib/quota');

const RUN = crypto.randomBytes(6).toString('hex');
const OWNER = `pgp_owner_key_for_the_omission_gate_${RUN}`;
const OWNER_ACCT = `acct_omission_${RUN}`;
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';

let srv = null;
let eng = null;
let rc = null;
let checks = 0;
const did = () => { checks++; };
const ready = () => srv !== null && eng !== null;

// Every test takes its own client address, exactly as nginx presents it, because
// the view and sign routes are rate-limited per IP and the buckets are global to
// the process. Measuring the limiter instead of the gate is not the point here.
let _ipN = 0;
let IP = '10.9.0.1';
const nextIp = () => { _ipN++; return `10.9.${Math.floor(_ipN / 250)}.${(_ipN % 250) + 1}`; };
const asParty = (extra = {}) => ({ 'X-Real-IP': IP, ...extra });

before(async () => {
  eng = requireEngine();
  rc = await requireRedis(DEFAULT_REDIS);
  if (!eng || !rc) return;
  srv = await boot({
    tag: 'omission',
    users: {
      api_keys: [
        // community: signs_month is 2, which is what makes the cap observable.
        { key: OWNER, plan: 'community', active: true, parasign: true, email: 'owner@example.test', account_id: OWNER_ACCT },
      ],
    },
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS },
  });
});

after(async () => {
  if (rc) {
    try { await rc.del(`paramant:quota:signs:${OWNER_ACCT}:${quota.ymKey()}`); } catch (_) {}
  }
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('route-omission-gate', checks);
});

const docHash = () => crypto.createHash('sha3-256').update(crypto.randomBytes(32)).digest('hex');

async function createEnvelope(parties = [{ label: 'Alice' }], extra = {}) {
  const dh = docHash();
  const r = await srv.post('/v2/envelopes', {
    headers: asParty({ 'X-Api-Key': OWNER }),
    body: { doc_hash: dh, parties, ...extra },
  });
  assert.strictEqual(r.status, 200, `create failed: ${r.status} ${r.text}`);
  const env = r.json.envelope;
  return { id: env.id, docHash: dh, tokens: env.party_links.map((p) => p.invite_token) };
}

// A real ML-DSA-65 signature over the message the relay will re-derive for an
// open slot (recipe 4: the signer's own public key is mixed in).
function signForParty(id, dh, partyIndex) {
  const kp = eng.generateKeyPair();
  const pubB64 = Buffer.from(kp.publicKey).toString('base64');
  const msg = envelopeMod.signMessageBytes(id, dh, partyIndex, '', 4, pubB64);
  return { pubB64, sigB64: Buffer.from(eng.sign(msg, kp.secretKey)).toString('base64') };
}

const signsUsed = async () => {
  const u = await quota.readUsage(rc, OWNER_ACCT);
  return u.available ? u.signs_this_month : null;
};
const resetSigns = () => rc.del(`paramant:quota:signs:${OWNER_ACCT}:${quota.ymKey()}`);

// ── CAPABILITY: omission is never the way in ────────────────────────────────

test('OMISSION: dropping any single field from a working sign request breaks it', async () => {
  if (!ready()) return;
  IP = nextIp();
  await resetSigns();
  const { id, docHash: dh, tokens } = await createEnvelope();
  const { pubB64, sigB64 } = signForParty(id, dh, 0);
  const full = { party_index: 0, signer_public_key: pubB64, signature: sigB64, token: tokens[0] };

  // One field at a time, everything else intact. Whichever field is missing, the
  // answer must be a refusal: a caller may not shop for the field whose absence
  // the handler happens to read as consent.
  for (const drop of Object.keys(full)) {
    const partial = { ...full };
    delete partial[drop];
    const r = await srv.post(`/v2/envelopes/${id}/sign`, { headers: asParty(), body: partial });
    assert.ok(r.status >= 400,
      `omitting "${drop}" was accepted with ${r.status} ${r.text}; omission must be the safest outcome`);
  }

  // And with nothing dropped the request works, so the loop above measured the
  // omissions and not a broken fixture.
  const ok = await srv.post(`/v2/envelopes/${id}/sign`, { headers: asParty(), body: full });
  assert.strictEqual(ok.status, 200, ok.text);
  did();
});

test('OMISSION: dropping any single field from a working view request breaks it', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, tokens } = await createEnvelope();
  const full = { party_index: 0, token: tokens[0] };

  for (const drop of Object.keys(full)) {
    const partial = { ...full };
    delete partial[drop];
    const r = await srv.post(`/v2/envelopes/${id}/view`, { headers: asParty(), body: partial });
    assert.ok(r.status >= 400,
      `omitting "${drop}" from /view was accepted with ${r.status}; a view is written to the CT log as evidence`);
  }
  const ok = await srv.post(`/v2/envelopes/${id}/view`, { headers: asParty(), body: full });
  assert.strictEqual(ok.status, 200, ok.text);
  did();
});

// ── DOOR 1: a signature is bound to the party allowed to place it ───────────

test('DOOR 1: knowing the envelope id does not let a stranger sign in a party name', async () => {
  if (!ready()) return;
  IP = nextIp();
  await resetSigns();
  const { id, docHash: dh, tokens } = await createEnvelope([{ label: 'Alice' }, { label: 'Bob' }]);

  // The whole of what an outsider gets for free: the id, from a link, a log, a
  // shoulder. Everything else here is honestly computed with their own key.
  const outsider = signForParty(id, dh, 0);
  const attempt = await srv.post(`/v2/envelopes/${id}/sign`, {
    headers: asParty(),
    body: { party_index: 0, signer_public_key: outsider.pubB64, signature: outsider.sigB64 },
  });
  assert.strictEqual(attempt.status, 403, attempt.text);
  assert.deepStrictEqual(attempt.json, { error: 'invite_token_required' });

  // A guessed token is no better than none.
  const guess = await srv.post(`/v2/envelopes/${id}/sign`, {
    headers: asParty(),
    body: { party_index: 0, signer_public_key: outsider.pubB64, signature: outsider.sigB64, token: 'x'.repeat(43) },
  });
  assert.strictEqual(guess.status, 403);

  // Bob's token does not open Alice's slot: the tokens are per party, so a real
  // participant cannot sign for the other one either.
  const cross = await srv.post(`/v2/envelopes/${id}/sign`, {
    headers: asParty(),
    body: { party_index: 0, signer_public_key: outsider.pubB64, signature: outsider.sigB64, token: tokens[1] },
  });
  assert.strictEqual(cross.status, 403, 'one party may not sign in the other party slot');

  // Nothing above touched the record.
  const status = await srv.get(`/v2/envelopes/${id}`, { headers: asParty() });
  assert.strictEqual(status.json.envelope.signed_count, 0, 'three refusals left the envelope untouched');
  assert.strictEqual(status.json.envelope.parties[0].status, 'pending');

  // And the invited party signs its own slot.
  const alice = signForParty(id, dh, 0);
  const good = await srv.post(`/v2/envelopes/${id}/sign`, {
    headers: asParty(),
    body: { party_index: 0, signer_public_key: alice.pubB64, signature: alice.sigB64, token: tokens[0] },
  });
  assert.strictEqual(good.status, 200, good.text);
  did();
});

test('DOOR 1: the public status never publishes the tokens it now depends on', async () => {
  if (!ready()) return;
  IP = nextIp();
  const { id, tokens } = await createEnvelope([{ label: 'Alice' }, { label: 'Bob' }]);

  const pub = await srv.get(`/v2/envelopes/${id}`, { headers: asParty() });
  assert.strictEqual(pub.status, 200);
  for (const t of tokens) {
    assert.ok(!pub.text.includes(t), 'the redacted status must not hand out an invite token');
  }
  // The party-scoped view carries the recipe but never echoes the credential.
  const party = await srv.get(`/v2/envelopes/${id}?p=0&t=${encodeURIComponent(tokens[0])}`, { headers: asParty() });
  assert.strictEqual(party.status, 200, party.text);
  for (const t of tokens) {
    assert.ok(!party.text.includes(t), 'the party view must not echo an invite token either');
  }
  // Without one it is a plain 404, indistinguishable from an envelope that never existed.
  const bare = await srv.get(`/v2/envelopes/${id}?p=0`, { headers: asParty() });
  assert.strictEqual(bare.status, 404);
  did();
});

// ── DOOR 2: the meter cannot be switched off from the request ───────────────

test('DOOR 2: a signature that names no account is still metered, against the envelope owner', async () => {
  if (!ready()) return;
  IP = nextIp();
  await resetSigns();
  assert.strictEqual(await signsUsed(), 0, 'the counter starts at 0');

  const { id, docHash: dh, tokens } = await createEnvelope();
  const { pubB64, sigB64 } = signForParty(id, dh, 0);
  // Exactly the request the review describes: no account_id anywhere.
  const r = await srv.post(`/v2/envelopes/${id}/sign`, {
    headers: asParty(),
    body: { party_index: 0, signer_public_key: pubB64, signature: sigB64, token: tokens[0] },
  });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(await signsUsed(), 1,
    'leaving account_id out used to skip both the pre-gate and the counter; the account now comes off the envelope');
  did();
});

test('DOOR 2: the plan cap bites even when every request omits account_id', async () => {
  if (!ready()) return;
  IP = nextIp();
  await resetSigns();
  // community includes 2 signatures a month. Three envelopes, three anonymous
  // sign requests: the third must be refused, or the cap is decorative.
  const statuses = [];
  for (let i = 0; i < 3; i++) {
    const { id, docHash: dh, tokens } = await createEnvelope();
    const { pubB64, sigB64 } = signForParty(id, dh, 0);
    const r = await srv.post(`/v2/envelopes/${id}/sign`, {
      headers: asParty(),
      body: { party_index: 0, signer_public_key: pubB64, signature: sigB64, token: tokens[0] },
    });
    statuses.push(r.status);
    if (r.status === 402) {
      assert.strictEqual(r.json.error, 'monthly_sign_quota_reached');
      assert.strictEqual(r.json.dimension, 'signs_month');
    }
  }
  assert.deepStrictEqual(statuses, [200, 200, 402],
    `two included signatures then a refusal; got ${statuses.join(',')}`);
  assert.strictEqual(await signsUsed(), 2, 'the refused signature was not counted');
  await resetSigns();
  did();
});

test('DOOR 2: a public caller cannot name someone else account to be metered', async () => {
  if (!ready()) return;
  IP = nextIp();
  await resetSigns();
  const { id, docHash: dh, tokens } = await createEnvelope();
  const { pubB64, sigB64 } = signForParty(id, dh, 0);
  const r = await srv.post(`/v2/envelopes/${id}/sign`, {
    headers: asParty(),
    body: {
      party_index: 0, signer_public_key: pubB64, signature: sigB64, token: tokens[0],
      account_id: 'acct_somebody_else',
    },
  });
  assert.strictEqual(r.status, 200, r.text);
  // The body was ignored: the envelope owner paid, not the account named.
  assert.strictEqual(await signsUsed(), 1, 'the envelope owner is metered, whatever the body claims');
  const victim = await quota.readUsage(rc, 'acct_somebody_else');
  assert.strictEqual(victim.available ? victim.signs_this_month : 0, 0,
    'a stranger account named in the body must not be charged');
  await resetSigns();
  did();
});

// ── DOOR 3: a filled key slot stays filled ─────────────────────────────────

test('DOOR 3: an invite pubkey slot is first-registration-wins, and a refresh still works', async () => {
  if (!ready()) return;
  IP = nextIp();
  const session = 'inv_' + crypto.randomBytes(16).toString('hex');
  const honest = { device_id: session, ecdh_pub: 'aa'.repeat(32), kyber_pub: 'bb'.repeat(32) };

  const first = await srv.post('/v2/pubkey', { headers: asParty(), body: honest });
  assert.strictEqual(first.status, 200, first.text);
  const fp = first.json.fingerprint;

  // The receiver reloads its page. Its keypair is restored from sessionStorage,
  // so the identical registration is a replay and must keep working.
  const replay = await srv.post('/v2/pubkey', { headers: asParty(), body: { ...honest } });
  assert.strictEqual(replay.status, 200, 'an identical re-registration is a refresh, not a takeover');
  assert.strictEqual(replay.json.fingerprint, fp, 'and it is the same key, so the same fingerprint');

  // Whoever saw the ?s= token in the share link tries to substitute their keys.
  const attacker = { device_id: session, ecdh_pub: 'cc'.repeat(32), kyber_pub: 'dd'.repeat(32) };
  const hijack = await srv.post('/v2/pubkey', { headers: asParty(), body: attacker });
  assert.strictEqual(hijack.status, 409, hijack.text);

  // The stored key is still the honest one, so both sides keep encrypting to it.
  const read = await srv.get(`/v2/pubkey/${session}`, { headers: asParty() });
  assert.strictEqual(read.status, 200, read.text);
  assert.strictEqual(read.json.ecdh_pub, honest.ecdh_pub, 'the honest ECDH key survived');
  assert.strictEqual(read.json.kyber_pub, honest.kyber_pub, 'the honest ML-KEM key survived');
  assert.strictEqual(read.json.fingerprint, fp, 'and the fingerprint the parties compared still matches');

  // The sender half of the same session is a separate slot with the same rule.
  //
  // It does NOT hold keys, whatever its two field names say: it holds the
  // handshake record, and since 5 September 2026 that record has a grammar
  // (relay/lib/handshake-record.js) because it used to carry the file name in
  // the clear. So the fixture here is a real record and not two runs of hex.
  // The property under test is unchanged: fill the slot, and it stays filled.
  const ready_ = session + '_ready';
  const token = (c) => String(c).repeat(48);
  const manifest = { device_id: ready_, ecdh_pub: token('a'), kyber_pub: 'file|1|3600000' };

  // Before anything else: a record that is not a record does not get in at all,
  // so the slot cannot be filled with a file name and cannot be filled with
  // rubbish that would then block the honest sender by first-wins.
  assert.strictEqual((await srv.post('/v2/pubkey', {
    headers: asParty(), body: { ...manifest, kyber_pub: 'opzegging-huurcontract.pdf|1|3600000' },
  })).status, 400, 'a file name in the handshake field is refused, not stored');
  assert.strictEqual((await srv.post('/v2/pubkey', {
    headers: asParty(),
    body: { ...manifest, kyber_pub: 'vault|2|3600000', ecdh_pub: JSON.stringify([{ name: 'loonstrook.pdf', tokens: [token('a')] }]) },
  })).status, 400, 'a vault manifest that names its files is refused too');

  assert.strictEqual((await srv.post('/v2/pubkey', {
    headers: asParty(), body: manifest,
  })).status, 200, 'a well-formed handshake record fills the slot');
  assert.strictEqual((await srv.post('/v2/pubkey', {
    headers: asParty(), body: { ...manifest, ecdh_pub: token('b'), kyber_pub: 'file|2|3600000' },
  })).status, 409, 'the _ready slot is one-shot too, so a manifest cannot be swapped either');
  did();
});
