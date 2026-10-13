'use strict';
// A NEW ENVELOPE NEEDS AN ACCOUNT THAT PAYS. WHAT IT ALREADY HAS, IT KEEPS.
//
// WHY THIS SUITE EXISTS. Finding R1 of the payment-flow test of 2026-09-25. A
// psk_ key carries scope 'parasign' for as long as it exists. The right it was
// minted under does not: a chargeback or a refund floors the account, and a
// paid term runs out. POST /v2/user/parasign-keys asked the account and said
// 403 in both cases. The /v1 router asked only the key, so every key minted
// before the money went back went on creating envelopes: after a chargeback
// the same key created three more, 201 each. After a term had ended, the same.
//
// The line is drawn at new work. Creating an envelope sends invitations,
// collects new signatures and, on a psk_test_ key, runs the sandbox signer: that
// is refused. Reading, fetching the evidence of and voiding the account's own
// earlier envelopes answer exactly as they do for a paying account, because the
// evidence is proof of contracts that were already signed, and a customer
// whose term ended or whose money went back may not lose it.
//
// So this suite boots the real relay.js and walks three accounts over HTTP:
//   1. one that pays: it creates, reads, fetches evidence and voids;
//   2. one whose money goes back: creating is refused, the rest answers as in
//      case 1. The chargeback is driven through the admin set-product-plan
//      route, which calls the same setProductPlan that the revoke branch of
//      lib/billing.js calls, and leaves the same records behind: every member
//      key on the floor tier with its parasign flag gone, and the psk_ keys
//      still carrying scope 'parasign', because nothing can take that off;
//   3. one whose term runs out on the clock: the same as case 2, with no restart
//      and no write, because expiry is enforced on read.
// In both refusals the mint route must give the same answer, because it is the
// same question.
//
// NEEDS: redis and the ML-DSA-65 engine. A 201 on POST /v1/envelopes needs the
// envelope store, and evidence needs an envelope the sandbox signer completed.
// Both are declared preconditions (test/_requires.js).
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

// What an account's own earlier envelopes answer while it pays. Case 1 asserts
// it for a paying account; cases 2 and 3 assert that losing the right changes
// none of it.
const OWN_WHILE_PAYING = { read: 200, receipt: 200, document: 200 };

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

const bearer = (psk) => ({ Authorization: `Bearer ${psk}` });
const mint = (srv, account, testKey = false) => srv.post('/v2/user/parasign-keys', {
  headers: BOTH, body: { user_id: account, label: 'v1-entitlement', test: testKey },
});
const createEnvelope = (srv, psk) => srv.post('/v1/envelopes', {
  headers: bearer(psk),
  body: { document: { content_base64: PDF_B64 }, signers: [{ name: 'Signer Demo', email: 'signer@example.test' }] },
});
const envPath = (id, sub = '') => `/v1/envelopes/${encodeURIComponent(id)}${sub}`;
const parasignTier = async (srv, account) =>
  (await srv.get(`/v2/admin/entitlements/${account}`, { headers: BOTH })).json.entitlements.parasign.tier;

// While the account pays: a live key with an envelope still out for signature,
// and a sandbox key with an envelope the sandbox signer completed, so there is
// evidence to fetch. Each step is a precondition, so that a refusal later in a
// test is about the account and not about a broken key.
async function mintAndCreate(srv, account) {
  const live = await mint(srv, account, false);
  assert.strictEqual(live.status, 201, `precondition: a paying account mints a live key: ${live.text}`);
  assert.match(live.json.key, /^psk_live_[0-9a-f]{64}$/);
  const sandbox = await mint(srv, account, true);
  assert.strictEqual(sandbox.status, 201, `precondition: a paying account mints a sandbox key: ${sandbox.text}`);
  assert.match(sandbox.json.key, /^psk_test_[0-9a-f]{64}$/);

  const open = await createEnvelope(srv, live.json.key);
  assert.strictEqual(open.status, 201, `precondition: the live key creates an envelope: ${open.text}`);
  assert.strictEqual(open.json.status, 'sent');
  const done = await createEnvelope(srv, sandbox.json.key);
  assert.strictEqual(done.status, 201, `precondition: the sandbox key creates an envelope: ${done.text}`);
  assert.strictEqual(done.json.status, 'completed', 'precondition: the sandbox signer completed it');
  return { live: live.json.key, sandbox: sandbox.json.key, openId: open.json.id, doneId: done.json.id };
}

// Read the open envelope, and fetch the evidence of the completed one, each with
// the key that created it. Returns the statuses and checks that a 200 carries
// the real thing.
async function ownEnvelopes(srv, k) {
  const read = await srv.get(envPath(k.openId), { headers: bearer(k.live) });
  if (read.status === 200) assert.strictEqual(read.json.id, k.openId);
  const receipt = await srv.get(envPath(k.doneId, '/receipt'), { headers: bearer(k.sandbox) });
  if (receipt.status === 200) {
    assert.strictEqual(receipt.json.type, 'parasign-envelope-receipt');
    assert.strictEqual(receipt.json.envelope_id, k.doneId);
  }
  const doc = await srv.get(envPath(k.doneId, '/document'), { headers: bearer(k.sandbox) });
  if (doc.status === 200) assert.strictEqual(doc.buf.slice(0, 5).toString('latin1'), '%PDF-');
  return { read: read.status, receipt: receipt.status, document: doc.status };
}

async function assertVoids(srv, k, what) {
  const r = await srv.post(envPath(k.openId, '/void'), { headers: bearer(k.live), body: { reason: 'test' } });
  assert.strictEqual(r.status, 200, `${what}: void of an own envelope: ${r.text}`);
  assert.strictEqual(r.json.status, 'void');
}

function assertRefused(r, what) {
  assert.strictEqual(r.status, 403, `${what}: expected 403, got ${r.status} ${r.text}`);
  assert.strictEqual(r.json && r.json.error, 'parasign_not_entitled', `${what}: wrong refusal: ${r.text}`);
}

// After the right is gone: no new work with either key, and no new key; the
// own envelopes answer as they did while the account paid.
async function assertOnlyNewWorkRefused(srv, account, k, when) {
  assertRefused(await createEnvelope(srv, k.live), `a new envelope with the live key ${when}`);
  assertRefused(await createEnvelope(srv, k.sandbox), `a new envelope with the sandbox key ${when}`);
  assert.deepStrictEqual(await ownEnvelopes(srv, k), OWN_WHILE_PAYING,
    `the account's own envelopes ${when} must answer as they do for a paying account`);
  await assertVoids(srv, k, when);
  assertRefused(await mint(srv, account), `a new key ${when}`);
}

test('an account that pays: creates, reads, fetches evidence and voids', async () => {
  if (!ready()) return;
  const { srv, account } = await withPayingAccount('v1paid', FUTURE);
  const k = await mintAndCreate(srv, account);

  assert.deepStrictEqual(await ownEnvelopes(srv, k), OWN_WHILE_PAYING);
  await assertVoids(srv, k, 'while paying');
  const again = await createEnvelope(srv, k.live);
  assert.strictEqual(again.status, 201, again.text);
  await srv.stop();
  did();
});

test('after a chargeback: no new envelope and no new key, the own envelopes answer as before', async () => {
  if (!ready()) return;
  const { srv, primary, account } = await withPayingAccount('v1back', FUTURE);
  const k = await mintAndCreate(srv, account);

  // The money goes back. Same setProductPlan as the webhook's revoke branch.
  const floored = await srv.post('/v2/admin/keys/set-product-plan', {
    headers: BOTH, body: { key: primary, product: 'parasign', tier: 'free' },
  });
  assert.strictEqual(floored.status, 200, floored.text);
  assert.strictEqual(await parasignTier(srv, account), 'free', 'precondition: the account is floored');

  await assertOnlyNewWorkRefused(srv, account, k, 'after the chargeback');
  await srv.stop();
  did();
});

test('after the term runs out: no new envelope and no new key, the own envelopes answer as before', async () => {
  if (!ready()) return;
  // The term ends a few seconds from now: long enough to boot, mint and create
  // while it still runs, short enough to wait for.
  const ends = Date.now() + 8000;
  const { srv, account } = await withPayingAccount('v1lapse', new Date(ends).toISOString());
  const k = await mintAndCreate(srv, account);
  assert.ok(Date.now() < ends, 'precondition: the keys were minted and used while the term still ran');

  while (Date.now() < ends + 250) await new Promise((r) => setTimeout(r, 100));
  assert.strictEqual(await parasignTier(srv, account), 'free', 'precondition: the term has ended');

  await assertOnlyNewWorkRefused(srv, account, k, 'after the term ended');
  await srv.stop();
  did();
});
