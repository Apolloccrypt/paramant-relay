'use strict';
// Gift codes, through a really booted relay and a real redis.
//
// WHY THIS SUITE AND NOT THE UNIT ONE. relay/test/coupon.test.js proves the
// rules; it cannot prove the one that matters most. The cap is enforced by a
// Lua script that redis runs to completion, and a Map stand-in cannot tell you
// whether that script is atomic, whether HLEN counts what you think it counts,
// or whether the hundred and first customer really gets a no.
//
// THE HUNDRED SEATS ARE TESTED AGAINST THE STORE, NOT THROUGH HTTP, and that is
// deliberate rather than a shortcut. The community edition of this relay caps a
// self-hosted install at five active API keys (relay.js COMMUNITY_KEY_LIMIT,
// fixed and not overridable by env, BUSL 4), so a hundred accounts cannot be
// booted at all: key six answers 402 before any route runs. The cap is a
// property of the coupon store, so it is proved there, with a hundred and fifty
// CONCURRENT claims against a cap of a hundred, which is a harder question than
// a hundred serial ones and the only one that catches a non-atomic claim.
// The route then proves the same refusal end to end, with a cap the relay can
// actually hold, so the shape a customer sees is pinned as well.
//
// The other half is the promise on /pricing: a code gives a term and charges
// nothing. Both directions are here. The account really comes out on the Pro
// entitlements (a gift that grants nothing is the mirror untruth), and there
// really is no invoice, no credit note and no document number afterwards.
//
// Needs: a reachable redis. Nothing else, no network, no Mollie.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-coupon.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const couponLib = require('../lib/coupon');
const sessionTokens = require('../lib/session-token');
const planExpiry = require('../lib/plan-expiry');
const entitlements = require('../lib/entitlements');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const ADMIN = 'admin-token-for-the-coupon-suite';
const INTERNAL = 'internal-token-for-the-coupon-suite';
const ADMIN_H = { 'X-Admin-Token': ADMIN };
const BOTH = { 'X-Admin-Token': ADMIN, 'X-Internal-Auth': INTERNAL };

// The redis a developer runs is shared with every other suite and with whatever
// else is on the machine, so every code this run creates carries a nonce and is
// deleted again in after(). A test that leaves state behind is a test that
// passes once.
const RUN = crypto.randomBytes(3).toString('hex').toUpperCase();
const CODE = (name) => `${name}-${RUN}`;

const SEATS = 100;
const FUTURE = new Date(Date.now() + 200 * 86_400_000).toISOString();

let rc = null;
let srv = null;
let checks = 0;
const did = () => { checks++; };
const madeCodes = [];

// Five accounts, which is every key a community relay will serve. Each one has
// a job: three fill a cap-of-three code, one is the request that arrives after
// the last seat, and one already has a paid term to be added to.
function users() {
  const mk = (name, extra) => Object.assign({
    key: `pgp_${name}`, plan: 'community', active: true,
    account_id: `acct_${name}`, email: `${name}@example.test`,
  }, extra || {});
  return {
    api_keys: [
      mk('a'), mk('b'), mk('c'), mk('over'),
      mk('paying', { plan_parasign: 'pro', paid_until_parasign: FUTURE }),
    ],
  };
}

const ACCOUNTS = ['acct_a', 'acct_b', 'acct_c', 'acct_over', 'acct_paying'];

// Everything this suite writes outside the coupon keyspace, on the fixed
// account ids it uses. Run before AND after: a previous run that failed halfway
// left rows behind, and a suite that reads them counts two gifts where it
// granted one.
async function clearAccounts() {
  if (!rc) return;
  // The pst_ tokens this suite mints, and the per-owner index they live in.
  // Every account is capped at twenty live tokens, and nothing here used to
  // clean them up, so against a redis that outlives the run (a laptop, a
  // container left up between runs) the cap was reached after a handful of
  // runs. The mint then failed, the redeem call carried `Bearer undefined`, and
  // the suite reported "expected 403, got 401 Invalid API key" as though the
  // scope gate had broken. CI never saw it, because its redis service is new
  // every time, which is exactly what makes a failure like this expensive: it
  // only ever appears on the machine of whoever is trying to change something
  // else. The tokens carry their own hour-long TTL; this is about the index.
  for (const name of ['a', 'b', 'c', 'over', 'paying']) {
    const idx = sessionTokens.ownerKey(`pgp_${name}`);
    try {
      for (const t of await rc.sMembers(idx)) { try { await rc.del(sessionTokens.tokenKey(t)); } catch (_) { /* best effort */ } }
      await rc.del(idx);
    } catch (_) { /* best effort */ }
  }
  for (const accountId of ACCOUNTS) {
    try { await rc.del(`paramant:billing:gift:list:${accountId}`); } catch (_) { /* best effort */ }
    for (const product of entitlements.PRODUCTS) {
      const member = planExpiry.memberOf(accountId, product);
      try { await rc.zRem(planExpiry.INDEX_ZSET, member); } catch (_) { /* best effort */ }
      try { await rc.hDel(planExpiry.META_HASH, member); } catch (_) { /* best effort */ }
    }
  }
}

before(async () => {
  rc = await requireRedis(DEFAULT_REDIS);
  await clearAccounts();
  srv = await boot({
    tag: 'coupon',
    usersFile: true,
    users: users(),
    env: {
      ADMIN_TOKEN: ADMIN,
      INTERNAL_AUTH_TOKEN: INTERNAL,
      REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS,
    },
  });
});

after(async () => {
  await clearAccounts();
  if (rc) {
    for (const code of madeCodes) {
      try { await rc.del(couponLib.K.doc(code)); } catch (_) { /* best effort */ }
      try { await rc.del(couponLib.K.redeemed(code)); } catch (_) { /* best effort */ }
      try { await rc.sRem(couponLib.K.all, code); } catch (_) { /* best effort */ }
    }
  }
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-coupon', checks);
});

const createCoupon = (body) => {
  if (body && body.code) madeCodes.push(String(body.code).toUpperCase());
  return srv.post('/v2/admin/coupons', { headers: ADMIN_H, body });
};
const redeem = (name, code) =>
  srv.post('/v2/billing/redeem', { headers: { 'X-Api-Key': `pgp_${name}` }, body: { code } });
const entitlementsOf = (name) =>
  srv.get(`/v2/admin/entitlements/acct_${name}`, { headers: BOTH });

// The record as it landed on DISK, which is the half #315 was about: a period
// that lives only in memory hands every account an unbounded grant on the next
// restart. setProductPlan queues that write, so a read straight after the route
// answered can be a moment early; this waits for the field rather than sleeping
// a fixed amount and hoping.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function recordOf(name, waitFor) {
  const read = () => (srv.readUsersFile().api_keys || []).find((k) => k.key === `pgp_${name}`) || {};
  for (let i = 0; i < 60; i++) {
    const rec = read();
    if (!waitFor || rec[waitFor]) return rec;
    await sleep(50);
  }
  return read();
}

// ── 1. the admin surface is admin-only ───────────────────────────────────────

test('minting a code is admin-only: it is the ability to give the product away', async (t) => {
  if (!rc) return t.skip('no redis');
  for (const [method, headers] of [
    ['POST', {}],
    ['POST', { 'X-Admin-Token': 'wrong-token' }],
    // A customer key is not an admin, however paid it is.
    ['POST', { 'X-Api-Key': 'pgp_a' }],
    ['GET', {}],
  ]) {
    const r = await srv.req(method, '/v2/admin/coupons', { headers, body: method === 'GET' ? undefined : { code: CODE('NOPE') } });
    assert.strictEqual(r.status, 401, `${method} with ${JSON.stringify(headers)} answered ${r.status}: ${r.text}`);
  }
  // The withdraw and the redemption list sit under the same gate.
  for (const [method, path] of [
    ['DELETE', `/v2/admin/coupons/${CODE('NOPE')}`],
    ['GET', `/v2/admin/coupons/${CODE('NOPE')}/redemptions`],
  ]) {
    const r = await srv.req(method, path, { headers: {} });
    assert.strictEqual(r.status, 401, `${method} ${path} answered ${r.status}: ${r.text}`);
  }
  did();
});

test('a code is created once, described in English, and never re-created under people', async (t) => {
  if (!rc) return t.skip('no redis');
  const code = CODE('COFFEE');
  const made = await createCoupon({
    code: code.toLowerCase(), // upper-cased at the door
    max_redemptions: 3,
    valid_until: '2026-12-31T23:59:59Z',
    created_by: 'the suite',
  });
  assert.strictEqual(made.status, 201, made.text);
  assert.strictEqual(made.json.coupon.code, code, 'a code is stored upper-cased, whatever was typed');
  assert.strictEqual(made.json.coupon.max_redemptions, 3);
  assert.strictEqual(made.json.coupon.used, 0);
  assert.strictEqual(made.json.coupon.describes, '3 months of ParaSign Pro and ParaSend Pro',
    'omitting grants means the campaign default, and the panel prints this sentence');

  // Re-creating it would reset a cap people are already redeeming against.
  const again = await createCoupon({ code, max_redemptions: 9999 });
  assert.strictEqual(again.status, 409, again.text);
  assert.strictEqual(again.json.error, 'code_exists');

  // And the cap really did not move.
  const list = await srv.get('/v2/admin/coupons', { headers: ADMIN_H });
  assert.strictEqual(list.status, 200, list.text);
  const stored = list.json.coupons.find((c) => c.code === code);
  assert.strictEqual(stored.max_redemptions, 3, 'a refused re-create must not have changed the cap');
  did();
});

test('a code that grants nothing, or a tier nobody sells, is refused at the door', async (t) => {
  if (!rc) return t.skip('no redis');
  for (const [body, error] of [
    [{ code: 'no spaces allowed' }, 'bad_code'],
    [{ code: CODE('BAD1'), grants: [{ product: 'parasignn', tier: 'pro', days: 90 }] }, 'invalid_product'],
    [{ code: CODE('BAD2'), grants: [{ product: 'parasign', tier: 'platinum', days: 90 }] }, 'invalid_tier'],
    [{ code: CODE('BAD3'), grants: [{ product: 'parasign', tier: 'free', days: 90 }] }, 'floor_tier'],
    [{ code: CODE('BAD4'), max_redemptions: 0 }, 'bad_max_redemptions'],
    [{ code: CODE('BAD5'), valid_until: 'next christmas' }, 'bad_valid_until'],
  ]) {
    const r = await srv.post('/v2/admin/coupons', { headers: ADMIN_H, body });
    assert.strictEqual(r.status, 400, `${JSON.stringify(body)} answered ${r.status}: ${r.text}`);
    assert.strictEqual(r.json.error, error, `${JSON.stringify(body)} -> ${r.json.error}, expected ${error}`);
  }
  did();
});

// ── 2. THE CAP ───────────────────────────────────────────────────────────────

test('a hundred accounts each get a seat, and the hundred and first really gets a no', async (t) => {
  if (!rc) return t.skip('no redis');
  const code = CODE('HUNDRED');
  madeCodes.push(code);
  const made = await couponLib.createCoupon(rc, { code, max_redemptions: SEATS, created_by: 'the suite' });
  assert.strictEqual(made.ok, true, JSON.stringify(made));

  // A hundred and fifty accounts reach for a hundred seats AT THE SAME TIME.
  // Serial claims would pass even a read-then-write implementation; this is the
  // question that only an atomic claim answers correctly.
  const results = await Promise.all(Array.from({ length: 150 }, (_, i) =>
    couponLib.claim(rc, { code, accountId: `acct_rush${i}`, now: new Date() })));
  const granted = results.filter((r) => r.ok);
  const refused = results.filter((r) => !r.ok);
  assert.strictEqual(granted.length, SEATS,
    `${granted.length} of 150 concurrent claims were granted against a cap of ${SEATS}; the claim is not atomic`);
  assert.strictEqual(refused.length, 50);
  for (const r of refused) assert.strictEqual(r.error, 'exhausted', `a refusal said ${r.error}`);

  // Every seat went to a different account, and the counter is the count.
  const seatNumbers = granted.map((r) => r.used).sort((a, b) => a - b);
  assert.deepStrictEqual(seatNumbers, Array.from({ length: SEATS }, (_, i) => i + 1),
    'two claims were handed the same seat number, so the count was read outside the atomic step');
  const stored = await couponLib.getCoupon(rc, code);
  assert.strictEqual(stored.used, SEATS);
  assert.strictEqual(stored.remaining, 0);

  // And once more, serially, for the plain reading of the rule: the hundred and
  // first customer to arrive gets a no.
  const overflow = await couponLib.claim(rc, { code, accountId: 'acct_rush_late', now: new Date() });
  assert.strictEqual(overflow.ok, false);
  assert.strictEqual(overflow.error, 'exhausted');
  assert.strictEqual((await couponLib.getCoupon(rc, code)).used, SEATS,
    'a refused claim must not have taken a seat');
  did();
});

test('the refusal after the last seat is what a customer sees, through the route', async (t) => {
  if (!rc) return t.skip('no redis');
  const code = CODE('COFFEE'); // capped at three above
  for (const name of ['a', 'b', 'c']) {
    const r = await redeem(name, code);
    assert.strictEqual(r.status, 200, `${name} was refused: ${r.text}`);
    assert.strictEqual(r.json.ok, true);
    assert.strictEqual(r.json.granted.length, 2, 'the campaign code grants both products');
  }

  // The request after the last seat. Not a warning, not a partial grant: a
  // refusal, in a sentence, with nothing written to the account.
  const over = await redeem('over', code);
  assert.strictEqual(over.status, 409, over.text);
  assert.strictEqual(over.json.error, 'exhausted');
  assert.match(over.json.message, /run out/i, over.json.message);
  const ent = await entitlementsOf('over');
  assert.strictEqual(ent.json.entitlements.parasign.tier, 'free',
    'a refused redemption must leave the account exactly where it was');
  assert.strictEqual(ent.json.entitlements.parasend.tier, 'community');

  const list = await srv.get('/v2/admin/coupons', { headers: ADMIN_H });
  const stored = list.json.coupons.find((c) => c.code === code);
  assert.strictEqual(stored.used, 3, `the counter says ${stored.used}, and three seats were taken`);
  assert.strictEqual(stored.remaining, 0);
  did();
});

test('one redemption per account: the same code twice is refused, and grants no second term', async (t) => {
  if (!rc) return t.skip('no redis');
  const code = CODE('COFFEE');
  const wasUntil = (await recordOf('a', 'paid_until_parasign')).paid_until_parasign;
  assert.ok(wasUntil, 'the first redemption must have written a period to compare against');

  const again = await redeem('a', code);
  assert.strictEqual(again.status, 409, again.text);
  assert.strictEqual(again.json.error, 'already_used');
  assert.match(again.json.message, /already used/i, again.json.message);

  assert.strictEqual((await recordOf('a')).paid_until_parasign, wasUntil,
    '"give it to a hundred people" must not become "one person takes a hundred terms"');
  did();
});

test('a code we never heard of, and one whose end date has passed, are told apart', async (t) => {
  if (!rc) return t.skip('no redis');
  const unknown = await redeem('over', CODE('NOSUCH'));
  assert.strictEqual(unknown.status, 404, unknown.text);
  assert.strictEqual(unknown.json.error, 'unknown');
  assert.match(unknown.json.message, /spelling/i, unknown.json.message);

  const code = CODE('LAPSED');
  const made = await createCoupon({ code, max_redemptions: 10, valid_until: '2020-01-01T00:00:00Z' });
  assert.strictEqual(made.status, 201, made.text);
  const late = await redeem('over', code);
  assert.strictEqual(late.status, 409, late.text);
  assert.strictEqual(late.json.error, 'expired');
  assert.match(late.json.message, /expired/i, late.json.message);
  // An expired code costs no seat: it was never spent.
  const list = await srv.get('/v2/admin/coupons', { headers: ADMIN_H });
  assert.strictEqual(list.json.coupons.find((c) => c.code === code).used, 0);
  // And the account it was refused to is still where it was.
  assert.strictEqual((await entitlementsOf('over')).json.entitlements.parasign.tier, 'free');
  did();
});

test('a withdrawn code stops being redeemable, and takes nothing back that was given', async (t) => {
  if (!rc) return t.skip('no redis');
  const code = CODE('PULLED');
  assert.strictEqual((await createCoupon({ code, max_redemptions: 10 })).status, 201);
  assert.strictEqual((await redeem('b', code)).status, 200, 'the code works before it is withdrawn');

  const gone = await srv.req('DELETE', `/v2/admin/coupons/${code}`, { headers: ADMIN_H });
  assert.strictEqual(gone.status, 200, gone.text);
  assert.ok(gone.json.coupon.revoked_at, 'withdrawing stamps a date rather than deleting the record');
  assert.strictEqual(gone.json.coupon.used, 1, 'the redemptions are the record of what was given away');

  const after3 = await redeem('over', code);
  assert.strictEqual(after3.status, 409, after3.text);
  assert.strictEqual(after3.json.error, 'revoked');

  // The account that redeemed it before the withdrawal keeps its term.
  assert.strictEqual((await entitlementsOf('b')).json.entitlements.parasign.tier, 'pro',
    'withdrawing a code must not take back a term somebody already has');

  // And the trail is readable: who took a seat, and when.
  const seats = await srv.get(`/v2/admin/coupons/${code}/redemptions`, { headers: ADMIN_H });
  assert.strictEqual(seats.status, 200, seats.text);
  assert.deepStrictEqual(seats.json.redemptions.map((r) => r.account), ['acct_b']);
  assert.ok(seats.json.redemptions[0].at, 'a redemption records when it happened');
  did();
});

// ── 3. what the account actually gets ────────────────────────────────────────

test('a redeemed code puts the account on the Pro entitlements, both products', async (t) => {
  if (!rc) return t.skip('no redis');
  const ent = await entitlementsOf('a');
  assert.strictEqual(ent.status, 200, ent.text);
  assert.strictEqual(ent.json.entitlements.parasign.tier, 'pro');
  assert.strictEqual(ent.json.entitlements.parasend.tier, 'pro');
  // Not just the label: the numbers a gate reads have to be the Pro numbers, or
  // the gift is a word on a page and nothing else.
  assert.deepStrictEqual(ent.json.entitlements.parasign.quotas, entitlements.PARASIGN.pro.quotas);
  assert.deepStrictEqual(ent.json.entitlements.parasend.limits, entitlements.PARASEND.pro.limits);

  // And the term is bounded, ON DISK. An unbounded grant is the bug #315 was
  // about, and a gift must not be the way it comes back.
  const rec = await recordOf('a', 'paid_until_parasign');
  assert.strictEqual(rec.parasign, true, 'a paid parasign tier flips the access flag, as a payment does');
  const days = Math.round((Date.parse(rec.paid_until_parasign) - Date.now()) / 86_400_000);
  assert.strictEqual(days, 90, `the gift runs ${days} days, and the code promises 90`);
  assert.strictEqual(rec.paid_until_parasend, rec.paid_until_parasign,
    'both products were given the same ninety days');
  did();
});

test('an account with a term still running gets the gift AFTER it, never instead of it', async (t) => {
  if (!rc) return t.skip('no redis');
  const code = CODE('ONTOP');
  assert.strictEqual((await createCoupon({ code, max_redemptions: 5 })).status, 201);

  const r = await redeem('paying', code);
  assert.strictEqual(r.status, 200, r.text);

  const rec = await recordOf('paying', 'paid_until_parasend');
  const until = Date.parse(rec.paid_until_parasign);
  const expected = Date.parse(FUTURE) + 90 * 86_400_000;
  assert.ok(Math.abs(until - expected) < 3_600_000,
    `the term ends ${new Date(until).toISOString()}, and the gift should have added ninety days to ${FUTURE}`);
  assert.ok(until > Date.parse(FUTURE),
    'the gift must never be shorter than the term the customer already paid for');

  // The product he did NOT already pay for starts from today, not from his
  // ParaSign date: the two terms are independent and always have been.
  const sendDays = Math.round((Date.parse(rec.paid_until_parasend) - Date.now()) / 86_400_000);
  assert.strictEqual(sendDays, 90, `ParaSend got ${sendDays} days; it had no term to be added to`);
  did();
});

// ── 4. the books: a gift is not a sale ───────────────────────────────────────

test('a gift leaves a line in the billing history and NO document of any kind', async (t) => {
  if (!rc) return t.skip('no redis');
  const h = { 'X-Api-Key': 'pgp_a' };

  const hist = await srv.get('/v2/billing/history', { headers: h });
  assert.strictEqual(hist.status, 200, hist.text);
  const gifts = hist.json.history.filter((row) => row.type === 'gift');
  assert.strictEqual(gifts.length, 1, `expected one gift row, got ${JSON.stringify(hist.json.history)}`);
  assert.strictEqual(gifts[0].label, `Gift: 3 months of ParaSign Pro and ParaSend Pro, code ${CODE('COFFEE')}`);
  assert.strictEqual(gifts[0].detail, 'No payment, no invoice');
  // The money columns are empty and stay empty. A 0.00 would add up correctly
  // and still read as a sale of nothing.
  assert.strictEqual(gifts[0].amount, null);
  assert.strictEqual(gifts[0].currency, null);
  assert.strictEqual(gifts[0].document, null);

  // Nothing was sold, so nothing was numbered. No invoice, no receipt, no
  // credit note, and no number drawn out of either series.
  const docs = await srv.get('/v2/billing/invoices', { headers: h });
  assert.strictEqual(docs.status, 200, docs.text);
  assert.deepStrictEqual(docs.json.invoices, [], 'a gift may never draw an invoice number');
  assert.ok(!hist.json.history.some((row) => row.type === 'invoice' || row.type === 'credit_note'),
    'a gift may never appear in the money rows');
  did();
});

test('the paid term a gift writes is indexed for the expiry mails, like any other term', async (t) => {
  if (!rc) return t.skip('no redis');
  // The seven-day warning and the "your plan has ended" mail work off one redis
  // index (lib/plan-expiry), fed by setProductPlan. A gift goes through the
  // same call, so it is in the index without anything here knowing about gifts.
  const member = planExpiry.memberOf('acct_a', 'parasign');
  const score = await rc.zScore(planExpiry.INDEX_ZSET, member);
  assert.ok(score, 'a gift term is not in the expiry index; the customer would get no warning at all');
  const meta = JSON.parse(await rc.hGet(planExpiry.META_HASH, member) || 'null');
  assert.strictEqual(meta.tier, 'pro');
  assert.strictEqual(meta.email, 'a@example.test', 'the index needs an address or the mail cannot go out');

  // And the mail that follows is not wrong about the money. It says nothing was
  // charged, which on a gift term is not a slip: nothing was.
  const mail = planExpiry.expiryMail({ product: 'parasign', tier: 'pro', paidUntil: meta.paid_until, kind: 'ended' });
  assert.ok(mail.text.includes('Nothing was charged.'),
    'the ended mail must keep saying nothing was charged; on a gift term that is literally true');
  assert.ok(!/refund/i.test(mail.text), 'a gift term leaves nothing to refund and the mail must not offer one');
  const warn = planExpiry.expiryMail({ product: 'parasign', tier: 'pro', paidUntil: meta.paid_until, kind: 'warn' });
  assert.ok(warn.text.includes('nothing is charged automatically'),
    'the warning mail must not read as a threat of a charge on a term nobody paid for');
  did();
});

// ── 5. the credential ────────────────────────────────────────────────────────

test('a ParaSend session token is 403 on the redeem route; an app token is not', async (t) => {
  if (!rc) return t.skip('no redis');
  const mint = async (purpose) => (await srv.post('/v2/session-token', {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Api-Key': 'pgp_over' },
    body: { purpose },
  })).json.token;

  const transfer = await srv.post('/v2/billing/redeem', {
    headers: { Authorization: `Bearer ${await mint('parasend')}` },
    body: { code: CODE('NOSUCH') },
  });
  assert.strictEqual(transfer.status, 403, transfer.text);
  assert.strictEqual(transfer.json.error, 'session_token_out_of_scope',
    'a token minted on /parashare must not be able to change what an account is entitled to');

  // The app token reaches the route: it is answered by the coupon store (this
  // code does not exist), not by the scope gate.
  const app = await srv.post('/v2/billing/redeem', {
    headers: { Authorization: `Bearer ${await mint('app')}` },
    body: { code: CODE('NOSUCH') },
  });
  assert.strictEqual(app.status, 404, app.text);
  assert.strictEqual(app.json.error, 'unknown');
  did();
});

test('the redeem route needs an account, and spends the code on THAT account only', async (t) => {
  if (!rc) return t.skip('no redis');
  const anon = await srv.post('/v2/billing/redeem', { body: { code: CODE('COFFEE') } });
  assert.strictEqual(anon.status, 401, anon.text);

  // The body cannot name an account. A code is spent on the account the relay
  // resolved from the credential or not at all.
  const code = CODE('MINEONLY');
  assert.strictEqual((await createCoupon({ code, max_redemptions: 5 })).status, 201);
  const r = await srv.post('/v2/billing/redeem', {
    headers: { 'X-Api-Key': 'pgp_over' },
    body: { code, accountId: 'acct_a', account_id: 'acct_a' },
  });
  assert.strictEqual(r.status, 200, r.text);
  const seats = await rc.hGetAll(couponLib.K.redeemed(code));
  assert.deepStrictEqual(Object.keys(seats), ['acct_over'],
    'the seat went to the account named in the body instead of the one that authenticated');
  did();
});
