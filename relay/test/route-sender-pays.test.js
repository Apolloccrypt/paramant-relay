'use strict';
// Three platform rules, over HTTP on a booted relay (2026-10-04 test round).
//
//   SENDER PAYS   a signature on an envelope counts on the envelope owner's
//                 month, within the owner's plan. It used to count on the
//                 SIGNER, so a Firm customer's client spent his own two free
//                 signatures and was shown a paywall at the third invitation.
//                 Solo signing (owner == signer) counts exactly as before.
//   CLIENT IP     the admin names the customer in X-Paramant-Client-IP. The
//                 relay believes it next to a valid X-Internal-Auth and never
//                 without, so per-IP limits are per customer and the header
//                 cannot be used from outside to pick a bucket.
//   PLAN          /v2/admin/keys keeps 'business' (it was silently community)
//                 and refuses an unknown plan; envelope create reads the party
//                 cap from the ParaSign entitlement, not the key's old plan.
//
// NEEDS redis and the ML-DSA-65 engine (test/_requires.js).
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-sender-pays.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');
const envelopeMod = require('../envelope');
const quota = require('../lib/quota');
const userSigning = require('../lib/user-signing');

const RUN = crypto.randomBytes(6).toString('hex');
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const ADMIN = `adm_${RUN}_${crypto.randomBytes(16).toString('hex')}`;
const INTERNAL = `int_${RUN}_${crypto.randomBytes(16).toString('hex')}`;

// A paying sender (Firm = ParaSign pro on the key's own plan), a free signer,
// and a ParaSign Business buyer whose key still says community: the shape a
// Mollie purchase leaves behind (plan_parasign moves, plan does not).
const FIRM = `pgp_firm_${RUN}`;            const FIRM_ACCT = `acct_firm_${RUN}`;
const FREE = `pgp_free_${RUN}`;            const FREE_ACCT = FREE;
const BIZ = `pgp_biz_${RUN}`;              const BIZ_ACCT = `acct_biz_${RUN}`;

let srv = null; let eng = null; let rc = null; let checks = 0;
const did = () => { checks++; };
const ready = () => srv !== null && eng !== null;

let _ipN = 0;
const nextIp = () => { _ipN++; return `10.77.${Math.floor(_ipN / 250)}.${(_ipN % 250) + 1}`; };

const signKey = (acct) => `paramant:quota:signs:${acct}:${quota.ymKey()}`;
const used = async (acct) => Number(await rc.get(signKey(acct)) || 0);

before(async () => {
  eng = requireEngine();
  rc = await requireRedis(DEFAULT_REDIS);
  if (!eng || !rc) return;
  srv = await boot({
    tag: 'sender-pays',
    users: {
      api_keys: [
        { key: FIRM, plan: 'pro', active: true, parasign: true, email: 'firm@example.test', account_id: FIRM_ACCT },
        { key: FREE, plan: 'community', active: true, email: 'free@example.test', account_id: FREE_ACCT },
        { key: BIZ, plan: 'community', plan_parasign: 'business', active: true, email: 'biz@example.test', account_id: BIZ_ACCT },
      ],
    },
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS, ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: INTERNAL, MAIL_PROVIDER: 'dryrun' },
    captureLog: true,
  });
});

after(async () => {
  if (rc) {
    for (const a of [FIRM_ACCT, FIRM, FREE_ACCT, BIZ_ACCT]) { try { await rc.del(signKey(a)); } catch (_) {} }
    try { await rc.del(`paramant:user:signing_pk:${FREE}`); await rc.del(`paramant:user:signing_pk:${FIRM}`); } catch (_) {}
  }
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('route-sender-pays', checks);
});

const docHash = () => crypto.createHash('sha3-256').update(crypto.randomBytes(32)).digest('hex');

async function createEnvelope(ownerKey, parties) {
  const dh = docHash();
  const r = await srv.post('/v2/envelopes', { headers: { 'X-Api-Key': ownerKey, 'X-Real-IP': nextIp() }, body: { doc_hash: dh, parties } });
  return { r, id: r.json && r.json.envelope && r.json.envelope.id, docHash: dh, tokens: r.json && r.json.envelope ? r.json.envelope.party_links.map((p) => p.invite_token) : [] };
}

// A keypair enrolled on `account` (the M1 pin), and a real signature for slot pi.
async function enrolledSigner(account) {
  const kp = eng.generateKeyPair();
  const pubB64 = Buffer.from(kp.publicKey).toString('base64');
  await userSigning.storeSigningPk(rc, account, { pk_b64: pubB64, label: 'test' });
  return { pubB64, kp };
}
function sigFor(signer, id, dh, pi) {
  const msg = envelopeMod.signMessageBytes(id, dh, pi, '', 4, signer.pubB64);
  return Buffer.from(eng.sign(msg, signer.kp.secretKey)).toString('base64');
}

// The admin proxy's call: internal auth, the signer's account named.
const adminSign = (env, pi, signer, account) => srv.post(`/v2/envelopes/${env.id}/sign`, {
  headers: { 'X-Internal-Auth': INTERNAL, 'X-Paramant-Client-IP': nextIp() },
  body: { party_index: pi, signer_public_key: signer.pubB64, signature: sigFor(signer, env.id, env.docHash, pi), token: env.tokens[pi], account_id: account },
});

// ── SENDER PAYS ──────────────────────────────────────────────────────────────

test('SENDER PAYS: an invited free signer spends nothing; the Firm sender is counted', async () => {
  if (!ready()) return;
  await rc.del(signKey(FREE_ACCT)); await rc.del(signKey(FIRM_ACCT));
  const signer = await enrolledSigner(FREE);
  // Three invitations in one month: the third used to be a paywall for him.
  for (let i = 0; i < 3; i++) {
    const env = await createEnvelope(FIRM, [{ label: 'Client' }]);
    assert.strictEqual(env.r.status, 200, `create: ${env.r.status} ${env.r.text}`);
    const r = await adminSign(env, 0, signer, FREE);
    assert.strictEqual(r.status, 200, `invitation ${i + 1}: the free signer was refused: ${r.status} ${r.text}`);
    assert.ok(!('quota' in r.json), 'the signer must not be shown the sender\'s usage');
    did();
  }
  assert.strictEqual(await used(FREE_ACCT), 0, 'the free signer\'s own month moved');
  assert.strictEqual(await used(FIRM_ACCT), 3, 'the sender was not counted once per signature');
  did();
});

test('SENDER PAYS: a full sender month stops the signature, and says it is the sender\'s', async () => {
  if (!ready()) return;
  const signer = await enrolledSigner(FREE);
  const env = await createEnvelope(FIRM, [{ label: 'Client' }]);
  await rc.set(signKey(FIRM_ACCT), '100');   // Firm includes 100
  const r = await adminSign(env, 0, signer, FREE);
  assert.strictEqual(r.status, 402);
  assert.strictEqual(r.json.error, 'sender_sign_quota_reached');
  assert.strictEqual(r.json.billed_to, 'sender');
  assert.ok(!('used' in r.json) && !('limit' in r.json) && !('plan' in r.json), 'the sender\'s numbers leaked to the signer');
  assert.ok(/afzender/.test(r.json.message), 'the refusal must say whose month is full');
  assert.strictEqual(await used(FREE_ACCT), 0, 'a refused signature was charged to the signer');
  assert.strictEqual(await used(FIRM_ACCT), 100, 'a refused signature still took a slot');
  // Acceptance r2, 6: the signer's page says the sender is told; now the sender
  // really gets a mail, once a day per envelope, to the sender's address.
  await new Promise((res) => setTimeout(res, 400));
  const log1 = srv.log();
  const mails = (log1.match(/mail_dryrun[^\n]*firm@example\.test/g) || []).length;
  assert.ok(mails >= 1, 'no mail to the sender: ' + log1.slice(-1500));
  assert.ok(!/mail_dryrun[^\n]*free@example\.test/.test(log1), 'the signer got the sender\'s mail');
  const again = await adminSign(env, 0, signer, FREE);
  assert.strictEqual(again.status, 402);
  await new Promise((res) => setTimeout(res, 400));
  const mails2 = (srv.log().match(/mail_dryrun[^\n]*firm@example\.test/g) || []).length;
  assert.strictEqual(mails2, mails, 'a second try the same day mails again');
  await rc.del(signKey(FIRM_ACCT));
  did();
});

test('SOLO: the owner signing his own envelope counts on his own month, as before', async () => {
  if (!ready()) return;
  await rc.del(signKey(FREE_ACCT));
  const signer = await enrolledSigner(FREE);
  const env = await createEnvelope(FREE, [{ label: 'Me' }]);
  assert.strictEqual(env.r.status, 200, env.r.text);
  const r = await adminSign(env, 0, signer, FREE);
  assert.strictEqual(r.status, 200, r.text);
  assert.deepStrictEqual({ used: r.json.quota.used, included: r.json.quota.included }, { used: 1, included: 2 }, 'solo signing must keep its own quota field');
  assert.strictEqual(await used(FREE_ACCT), 1);
  // And the free cap still bites on his own envelopes.
  await rc.set(signKey(FREE_ACCT), '2');
  const env2 = await createEnvelope(FREE, [{ label: 'Me' }]);
  const r2 = await adminSign(env2, 0, signer, FREE);
  assert.strictEqual(r2.status, 402);
  assert.strictEqual(r2.json.error, 'monthly_sign_quota_reached', 'solo over the cap is the ordinary upgrade moment');
  await rc.del(signKey(FREE_ACCT));
  did();
});

// ── CLIENT IP ────────────────────────────────────────────────────────────────
// The sign route allows 10 a minute per client address, checked before the
// body is read, so an empty body is enough to measure the bucket.

const poke = (id, headers) => srv.post(`/v2/envelopes/${id}/sign`, { headers, body: {} });

test('CLIENT IP: with internal auth, each named customer has a bucket of his own', async () => {
  if (!ready()) return;
  const id = `ipbucket${RUN}aaaaaaaaaaaa`;
  const edge = nextIp();
  for (let i = 0; i < 15; i++) {
    const r = await poke(id, { 'X-Real-IP': edge, 'X-Internal-Auth': INTERNAL, 'X-Paramant-Client-IP': nextIp() });
    assert.notStrictEqual(r.status, 429, `customer ${i + 1} behind one admin was rate limited`);
  }
  did();
});

test('CLIENT IP: without valid internal auth the header is ignored, so it cannot pick a bucket', async () => {
  if (!ready()) return;
  const id = `ipspoof${RUN}aaaaaaaaaaaaa`;
  const edge = nextIp();
  const statuses = [];
  for (let i = 0; i < 12; i++) {
    const r = await poke(id, { 'X-Real-IP': edge, 'X-Internal-Auth': i % 2 ? 'wrong' : '', 'X-Paramant-Client-IP': nextIp() });
    statuses.push(r.status);
  }
  assert.ok(statuses.slice(10).every((s) => s === 429), `a rotated X-Paramant-Client-IP escaped the limit: ${statuses.join(',')}`);
  did();
});

test('CLIENT IP: something that is not an address falls back to the edge rule', async () => {
  if (!ready()) return;
  const id = `ipjunk${RUN}aaaaaaaaaaaaaa`;
  const edge = nextIp();
  const statuses = [];
  for (let i = 0; i < 12; i++) {
    const r = await poke(id, { 'X-Real-IP': edge, 'X-Internal-Auth': INTERNAL, 'X-Paramant-Client-IP': `not-an-ip-${i}` });
    statuses.push(r.status);
  }
  assert.ok(statuses.slice(10).every((s) => s === 429), `junk in the header made new buckets: ${statuses.join(',')}`);
  did();
});

// ── PLAN ─────────────────────────────────────────────────────────────────────

const adminHdr = { 'X-Admin-Token': ADMIN, Authorization: `Bearer ${ADMIN}` };

test('PLAN: /v2/admin/keys keeps business, maps free, refuses the unknown', async () => {
  if (!ready()) return;
  const biz = await srv.post('/v2/admin/keys', { headers: adminHdr, body: { label: `biz-${RUN}`, plan: 'business' } });
  assert.strictEqual(biz.status, 200, biz.text);
  assert.strictEqual(biz.json.plan, 'business', 'a Business key was stored as something else');
  const free = await srv.post('/v2/admin/keys', { headers: adminHdr, body: { label: `free-${RUN}`, plan: 'free' } });
  assert.strictEqual(free.status, 200, free.text);
  assert.strictEqual(free.json.plan, 'community');
  // (No-plan stays community too; not asserted here because the community
  // edition caps a relay at five keys and this fixture already holds five.)
  const bad = await srv.post('/v2/admin/keys', { headers: adminHdr, body: { label: `bad-${RUN}`, plan: 'platinum' } });
  assert.strictEqual(bad.status, 400, 'an unknown plan was silently downgraded instead of refused');
  assert.strictEqual(bad.json.error, 'invalid_plan');
  did();
});

test('PLAN: the party cap follows the ParaSign entitlement, not the key\'s old plan', async () => {
  if (!ready()) return;
  const parties = (n) => Array.from({ length: n }, (_, i) => ({ label: `P${i}` }));
  // BIZ's key says community, its ParaSign entitlement says business (30).
  const biz = await createEnvelope(BIZ, parties(25));
  assert.strictEqual(biz.r.status, 200, `a ParaSign Business buyer was held to twenty: ${biz.r.text}`);
  // Firm (pro) is twenty by the table, and stays twenty.
  const firm = await createEnvelope(FIRM, parties(21));
  assert.strictEqual(firm.r.status, 400);
  assert.match(firm.r.json.error, /max 20 on the pro plan/);
  // A free account keeps the community twenty, and the message names it so.
  const free = await createEnvelope(FREE, parties(21));
  assert.strictEqual(free.r.status, 400);
  assert.match(free.r.json.error, /max 20 on the community plan/);
  did();
});
