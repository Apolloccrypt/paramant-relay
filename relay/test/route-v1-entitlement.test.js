'use strict';
// THE /v1 API FOLLOWS THE ACCOUNT, NOT THE KEY.
//
// WHY THIS SUITE EXISTS. Finding R1 of the payment-flow test of 2026-09-25. A
// psk_ key carries scope 'parasign' for as long as it exists. The right it was
// minted under does not: a chargeback or a refund floors the account, and a
// paid term runs out. POST /v2/user/parasign-keys asked the account and said
// 403 in both cases. The /v1 router asked only the key, so every key minted
// before the money went back kept working: after a chargeback the same key
// created three more envelopes, 201 each, and read the old one back with a 200.
// After a term had ended, the same.
//
// So this suite boots the real relay.js and walks the three cases over HTTP:
//   1. an account that pays: the key it minted creates and reads envelopes;
//   2. the money goes back: the same key is refused, for a new envelope and for
//      an old one. The chargeback is driven through the admin set-product-plan
//      route, which calls the same setProductPlan that the revoke branch of
//      lib/billing.js calls, and leaves the same records behind: every member
//      key on the floor tier with its parasign flag gone, and the psk_ key
//      still carrying scope 'parasign', because nothing can take that off;
//   3. the term runs out on the clock: the key is refused, with no restart and
//      no write, because expiry is enforced on read.
// In both refusals the mint route must give the same answer, because it is the
// same question.
//
// NEEDS: redis and the ML-DSA-65 engine. A 201 on POST /v1/envelopes needs the
// envelope store, and a refusal only means something next to a 201 for the
// same key a moment earlier. Both are declared preconditions (test/_requires.js).
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-v1-entitlement.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');

const ADMIN = 'admin-token-for-the-v1-entitlement-suite';
const INTERNAL = 'internal-token-for-the-v1-entitlement-suite';
const BOTH = { 'X-Admin-Token': ADMIN, 'X-Internal-Auth': INTERNAL };
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';

// Fresh names per run: the envelope-create limiter counts per key in redis, and
// a shared redis outlives a single run.
const RUN = crypto.randomBytes(6).toString('hex');
const FUTURE = new Date(Date.now() + 20 * 86_400_000).toISOString();
const PDF_B64 = Buffer.from('%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n').toString('base64');

let eng = null;
let rc = null;
let checks = 0;
const did = () => { checks++; };
const ready = () => eng !== null && rc !== null;

before(async () => {
  eng = requireEngine();
  rc = await requireRedis(DEFAULT_REDIS);
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('route-v1-entitlement', checks);
});

// One relay per case, on its own users.json, holding one account that pays for
// ParaSign until `paidUntil`. The account has a legacy plan of community, as
// every self-serve buyer does: billing moves plan_parasign, never `plan`.
function withPayingAccount(tag, paidUntil) {
  const primary = `pgp_${tag}_${RUN}_${crypto.randomBytes(8).toString('hex')}`;
  const account = `acct_${tag}_${RUN}`;
  return boot({
    tag,
    usersFile: true,
    users: { api_keys: [{
      key: primary, plan: 'community', active: true, parasign: true, is_primary: true,
      account_id: account, email: `${tag}@example.test`,
      plan_parasign: 'pro', paid_until_parasign: paidUntil,
    }] },
    env: {
      ADMIN_TOKEN: ADMIN,
      INTERNAL_AUTH_TOKEN: INTERNAL,
      REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS,
    },
  }).then((srv) => ({ srv, primary, account }));
}

const mint = (srv, account) =>
  srv.post('/v2/user/parasign-keys', { headers: BOTH, body: { user_id: account, label: 'v1-entitlement' } });
const createEnvelope = (srv, psk) => srv.post('/v1/envelopes', {
  headers: { Authorization: `Bearer ${psk}` },
  body: { document: { content_base64: PDF_B64 }, signers: [{ name: 'Signer Demo', email: 'signer@example.test' }] },
});
const readEnvelope = (srv, psk, id) =>
  srv.get(`/v1/envelopes/${encodeURIComponent(id)}`, { headers: { Authorization: `Bearer ${psk}` } });
const parasignTier = async (srv, account) =>
  (await srv.get(`/v2/admin/entitlements/${account}`, { headers: BOTH })).json.entitlements.parasign.tier;

// Mint a key while the account pays, and prove it works, so that a refusal
// later in the test is about the account and not about a broken key.
async function mintWorkingKey(srv, account) {
  const minted = await mint(srv, account);
  assert.strictEqual(minted.status, 201, `precondition: a paying account mints a key: ${minted.text}`);
  const psk = minted.json.key;
  assert.match(psk, /^psk_live_[0-9a-f]{64}$/);
  const first = await createEnvelope(srv, psk);
  assert.strictEqual(first.status, 201, `precondition: the fresh key creates an envelope: ${first.text}`);
  return { psk, envelopeId: first.json.id };
}

function assertRefused(r, what) {
  assert.strictEqual(r.status, 403, `${what}: expected 403, got ${r.status} ${r.text}`);
  assert.strictEqual(r.json && r.json.error, 'parasign_not_entitled', `${what}: wrong refusal: ${r.text}`);
}

test('an account that pays: the key it minted creates and reads envelopes', async () => {
  if (!ready()) return;
  const { srv, account } = await withPayingAccount('v1paid', FUTURE);
  const { psk, envelopeId } = await mintWorkingKey(srv, account);

  const again = await createEnvelope(srv, psk);
  assert.strictEqual(again.status, 201, again.text);
  const read = await readEnvelope(srv, psk, envelopeId);
  assert.strictEqual(read.status, 200, read.text);
  assert.strictEqual(read.json.id, envelopeId);
  await srv.stop();
  did();
});

test('after a chargeback the key minted before it is refused, and so is a new mint', async () => {
  if (!ready()) return;
  const { srv, primary, account } = await withPayingAccount('v1back', FUTURE);
  const { psk, envelopeId } = await mintWorkingKey(srv, account);

  // The money goes back. Same setProductPlan as the webhook's revoke branch.
  const floored = await srv.post('/v2/admin/keys/set-product-plan', {
    headers: BOTH, body: { key: primary, product: 'parasign', tier: 'free' },
  });
  assert.strictEqual(floored.status, 200, floored.text);
  assert.strictEqual(await parasignTier(srv, account), 'free', 'precondition: the account is floored');

  assertRefused(await createEnvelope(srv, psk), 'a new envelope after the chargeback');
  assertRefused(await readEnvelope(srv, psk, envelopeId), 'reading an old envelope after the chargeback');
  assertRefused(await mint(srv, account), 'a new key after the chargeback');
  await srv.stop();
  did();
});

test('after the term runs out the key minted during it is refused, with no restart', async () => {
  if (!ready()) return;
  // The term ends a few seconds from now: long enough to boot, mint and create
  // while it still runs, short enough to wait for.
  const ends = Date.now() + 6000;
  const { srv, account } = await withPayingAccount('v1lapse', new Date(ends).toISOString());
  const { psk, envelopeId } = await mintWorkingKey(srv, account);
  assert.ok(Date.now() < ends, 'precondition: the key was minted and used while the term still ran');

  while (Date.now() < ends + 250) await new Promise((r) => setTimeout(r, 100));
  assert.strictEqual(await parasignTier(srv, account), 'free', 'precondition: the term has ended');

  assertRefused(await createEnvelope(srv, psk), 'a new envelope after the term ended');
  assertRefused(await readEnvelope(srv, psk, envelopeId), 'reading an old envelope after the term ended');
  assertRefused(await mint(srv, account), 'a new key after the term ended');
  await srv.stop();
  did();
});
