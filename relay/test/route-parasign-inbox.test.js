'use strict';
// GET /v2/parasign/inbox and POST /v2/parasign/inbox/:id/resend, over HTTP, on a
// really booted relay with a real redis.
//
// The store rules are pinned in parasign-party-index.test.js. What can only be
// seen on the wire is who the relay thinks is asking:
//
//   * the address is DERIVED from the authenticated key. The request never
//     names it, so a caller cannot read somebody else's worklist by asking for
//     a hash. This is the property that lets the route sit in a session-token
//     scope at all, and it cannot be read off the store;
//   * the answer carries no invite token, so the page that shows the worklist
//     cannot become a second way into the document;
//   * the resend is internal-auth plus an asserted verified email hash, and
//     hands back the token that was already stored. A browser cannot reach it,
//     an assertion for the wrong address gets the same 404 as a missing
//     envelope, and nothing is minted.
//
// Needs @paramant/core and a redis. Run:
//   REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-parasign-inbox.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');
const envelopeMod = require('../envelope');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const INTERNAL = 'internal-token-for-the-parasign-inbox-suite';
const SUFFIX = crypto.randomBytes(6).toString('hex');

// The reader: a signed-in account that was INVITED to sign.
const READER_KEY = `pgp_reader_key_for_the_inbox_suite_${SUFFIX}`;
const READER_EMAIL = `reader-${SUFFIX}@example.com`;
const READER_HASH = envelopeMod.partyEmailHash(READER_EMAIL);
// The sender: a different account, so "who sent it" is a real lookup and not
// the reader's own address handed back.
const SENDER_KEY = `pgp_sender_key_for_the_inbox_suite_${SUFFIX}`;
const SENDER_EMAIL = `sender-${SUFFIX}@example.com`;
// A third party on the same envelope, to prove one signature does not clear the
// other slot.
const OTHER_EMAIL = `other-${SUFFIX}@example.com`;
const OTHER_HASH = envelopeMod.partyEmailHash(OTHER_EMAIL);

let rc = null;
let eng = null;
let srv;
let store;
let env0 = null;
let docHash;
let checks = 0;
const did = () => { checks++; };

const users = () => ({
  api_keys: [
    { key: READER_KEY, plan: 'community', active: true, email: READER_EMAIL, account_id: READER_KEY },
    { key: SENDER_KEY, plan: 'community', active: true, email: SENDER_EMAIL, account_id: SENDER_KEY },
  ],
});

before(async () => {
  eng = requireEngine();
  rc = await requireRedis(DEFAULT_REDIS);
  if (!rc) return;
  srv = await boot({
    tag: 'inbox',
    users: users(),
    usersFile: true,
    env: { INTERNAL_AUTH_TOKEN: INTERNAL, REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS },
  });
  const registry = require('../crypto/registry');
  store = new envelopeMod.EnvelopeStore(rc, {
    ctAppend: () => null,
    sigVerify: (sig, msg, pub) => { try { return registry.getSig(0x0002).verify(sig, msg, pub); } catch { return false; } },
  });
  docHash = crypto.createHash('sha3-256').update(Buffer.from('doc-' + SUFFIX)).digest('hex');
  // Planted through the store rather than through POST /v2/envelopes: this suite
  // is about who may READ the worklist, and creating over HTTP would drag the
  // whole tier gate in for no assertion.
  env0 = await store.create({
    accountId: SENDER_KEY, docHash, bindingMode: 'email', recipeVersion: 2,
    originalFilename: 'Engagement letter.pdf',
    parties: [{ label: 'Signer Demo', email: READER_EMAIL }, { label: 'Signer Acme', email: OTHER_EMAIL }],
  });
});

after(async () => {
  if (rc) {
    try {
      await rc.del(store._partyIndexKey(READER_HASH));
      await rc.del(store._partyIndexKey(OTHER_HASH));
      await rc.del(store._acctIndexKey(SENDER_KEY));
      if (env0) await rc.del('env:' + env0.id);
    } catch (_) { /* teardown is best effort */ }
    try { await rc.disconnect(); } catch (_) {}
  }
  await killAll();
  summary('route-parasign-inbox', checks);
});

test('the invited account is shown the request, named by its sender', async (t) => {
  if (!rc || !eng) return t.skip('no redis or no engine');
  const r = await srv.req('GET', '/v2/parasign/inbox', { headers: { 'X-Api-Key': READER_KEY } });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.count, 1, r.text);
  const row = r.json.documents[0];
  assert.strictEqual(row.id, env0.id, 'the row names the envelope');
  assert.strictEqual(row.document, 'Engagement letter.pdf', 'the row names the document');
  assert.strictEqual(row.sender, SENDER_EMAIL, 'the row names the account that sent it');
  assert.ok(row.sent_at && row.signing_closes_at, 'the row is dated at both ends');
  did();
});

test('the answer carries no capability: no invite token, no document hash', async (t) => {
  if (!rc || !eng) return t.skip('no redis or no engine');
  const r = await srv.req('GET', '/v2/parasign/inbox', { headers: { 'X-Api-Key': READER_KEY } });
  assert.doesNotMatch(r.text, /invite_token/, 'the worklist must never carry an invite token');
  assert.doesNotMatch(r.text, new RegExp(docHash), 'the worklist must never carry the document hash');
  assert.doesNotMatch(r.text, new RegExp(READER_HASH), 'the worklist must never carry a party email hash');
  did();
});

test('the address is derived from the key, so nobody can ask for another worklist', async (t) => {
  if (!rc || !eng) return t.skip('no redis or no engine');
  // The sender holds a real, active key and is party to nothing.
  const mine = await srv.req('GET', '/v2/parasign/inbox', { headers: { 'X-Api-Key': SENDER_KEY } });
  assert.strictEqual(mine.status, 200, mine.text);
  assert.strictEqual(mine.json.count, 0, 'the sender is a party to nothing and sees nothing');
  // And asserting somebody else's hash on the wire changes nothing: the route
  // never reads one. If it ever did, this is the case that would go red.
  const spoofed = await srv.req('GET', '/v2/parasign/inbox', {
    headers: { 'X-Api-Key': SENDER_KEY, 'X-Verified-Email-Hash': READER_HASH },
  });
  assert.strictEqual(spoofed.json.count, 0, 'a header cannot buy another account\'s worklist');
  did();
});

test('an unauthenticated request gets the ordinary 401, not a worklist', async (t) => {
  if (!rc || !eng) return t.skip('no redis or no engine');
  const r = await srv.req('GET', '/v2/parasign/inbox');
  assert.strictEqual(r.status, 401, r.text);
  did();
});

test('resend hands the stored invite token to the trusted admin, and mints nothing', async (t) => {
  if (!rc || !eng) return t.skip('no redis or no engine');
  const stored = await rc.hGet('env:' + env0.id, 'p0_invite_token');
  const r = await srv.req('POST', `/v2/parasign/inbox/${env0.id}/resend`, {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Verified-Email-Hash': READER_HASH },
    body: {},
  });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.party_index, 0, 'it names the slot to invite again');
  assert.strictEqual(r.json.invite_token, stored, 'it hands back the token that was already stored');
  assert.strictEqual(r.json.sender, SENDER_EMAIL, 'and names the sender for the mail');
  assert.strictEqual(await rc.hGet('env:' + env0.id, 'p0_invite_token'), stored,
    'the stored token is unchanged: a resend mints no new capability');
  did();
});

test('resend refuses a browser, and refuses the wrong address the same way as a missing one', async (t) => {
  if (!rc || !eng) return t.skip('no redis or no engine');
  const noAuth = await srv.req('POST', `/v2/parasign/inbox/${env0.id}/resend`, {
    headers: { 'X-Api-Key': READER_KEY, 'X-Verified-Email-Hash': READER_HASH }, body: {},
  });
  assert.strictEqual(noAuth.status, 401, 'an api-key is not internal auth: ' + noAuth.text);
  assert.doesNotMatch(noAuth.text, /invite_token/, 'and it says nothing about a token');

  const wrong = envelopeMod.partyEmailHash(`stranger-${SUFFIX}@example.com`);
  const notMine = await srv.req('POST', `/v2/parasign/inbox/${env0.id}/resend`, {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Verified-Email-Hash': wrong }, body: {},
  });
  assert.strictEqual(notMine.status, 404, notMine.text);
  const missing = await srv.req('POST', `/v2/parasign/inbox/${'M'.repeat(24)}/resend`, {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Verified-Email-Hash': READER_HASH }, body: {},
  });
  assert.strictEqual(missing.status, 404, 'a non-existent envelope answers the same way');
  assert.deepStrictEqual(notMine.json, missing.json, 'and says the same thing, so neither is an oracle');
  did();
});

test('once the reader signs, the request leaves their worklist and not the other party\'s', async (t) => {
  if (!rc || !eng) return t.skip('no redis or no engine');
  const token = await rc.hGet('env:' + env0.id, 'p0_invite_token');
  const kp = eng.generateKeyPair();
  const pubB64 = Buffer.from(kp.publicKey).toString('base64');
  const msg = envelopeMod.signMessageBytes(env0.id, docHash, 0, READER_HASH, 2, pubB64);
  const sigB64 = Buffer.from(eng.sign(msg, kp.secretKey)).toString('base64');
  const out = await store.sign(env0.id, 0, pubB64, sigB64, {
    internalTrusted: true, verifiedEmailHash: READER_HASH, inviteToken: token,
  });
  assert.strictEqual(out.ok, true, 'the reader signs: ' + out.code);

  const after = await srv.req('GET', '/v2/parasign/inbox', { headers: { 'X-Api-Key': READER_KEY } });
  assert.strictEqual(after.json.count, 0, 'nothing is waiting on the reader any more');
  const still = await store.listPartyEnvelopes(OTHER_HASH, {});
  assert.strictEqual(still.length, 1, 'the other party is still waiting');

  const resend = await srv.req('POST', `/v2/parasign/inbox/${env0.id}/resend`, {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Verified-Email-Hash': READER_HASH }, body: {},
  });
  assert.strictEqual(resend.status, 404, 'and a signer cannot ask for the invitation again');
  did();
});
