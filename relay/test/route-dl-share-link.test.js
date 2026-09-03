'use strict';
// route-dl-share-link.test.js: the asynchronous half of ParaSend, against a
// real relay and a real redis.
//
// WHAT THIS SUITE IS FOR. /parashare grew a "Send a link" stand so an office
// can mail a payslip to somebody who is not online. That stand rests on three
// promises the relay has to keep, and the browser suite
// (tests/parasend-send-a-link.test.mjs) cannot measure any of them, because
// there the relay is a stub:
//
//   1. a pst_ session token, the credential the page really runs on, may upload
//      -- POST /v2/inbound is in its allowlist, and this is the test that fails
//      if somebody ever narrows that list without reading the page
//   2. the link works exactly once, and the second attempt is refused with a
//      sentence a receiver can act on rather than a stack trace
//   3. the times the page prints per plan come off tiers.js through the plan
//      API, so a tier change moves the copy and a stale hour cannot be shipped
//
// It also pins the two things a caller has to get right and would otherwise
// find out about in production: that GET /v2/dl/:token/info needs no credential
// at all (the receiver has none), and that the relay clamps the requested TTL
// to the account's tier rather than honouring what was asked.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-dl-share-link.test.js
//   (docker run --rm -d -p 6399:6379 redis:7.4.8-alpine)

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const tiers = require('../lib/tiers');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const DL_INTERNAL = 'internal-token-for-the-dl-share-link-suite';
// Fresh per run: every route suite shares one redis, and the quota counters
// below are keyed on the account id.
const DL_SUFFIX = crypto.randomBytes(6).toString('hex');
const DL_OWNER = `pgp_owner_key_for_the_dl_share_link_suite_${DL_SUFFIX}`;
const DL_ACCT = `acct_dlshare_${DL_SUFFIX}`;

let dlRc = null;
let dlSrv;
let dlChecks = 0;
const dlDid = () => { dlChecks++; };

before(async () => {
  dlRc = await requireRedis(DEFAULT_REDIS);
  dlSrv = await boot({
    tag: 'dlshare',
    users: { api_keys: [{ key: DL_OWNER, plan: 'community', active: true, email: 'owner@example.test', account_id: DL_ACCT }] },
    env: { INTERNAL_AUTH_TOKEN: DL_INTERNAL, REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS },
    usersFile: true,
  });
});

after(async () => {
  await killAll();
  if (dlRc) { try { await dlRc.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-dl-share-link', dlChecks);
});

async function dlMint() {
  const r = await dlSrv.post('/v2/session-token', {
    headers: { 'X-Internal-Auth': DL_INTERNAL, 'X-Api-Key': DL_OWNER },
  });
  assert.equal(r.status, 200, 'the suite cannot run without a session token');
  return r.json.token;
}

// The sealed bytes the "Send a link" stand uploads: opaque to the relay, and
// hashed exactly as sent, which POST /v2/inbound verifies before it stores.
function dlSealed(label) {
  const payload = Buffer.from(`${label}-${crypto.randomBytes(24).toString('hex')}`);
  return { payload, hash: crypto.createHash('sha256').update(payload).digest('hex') };
}

// ── 1. The credential the web app really runs on may park a file ─────────────

test('a pst_ session token can upload, and gets a download token back', async (t) => {
  if (!dlRc) return t.skip('no redis');
  const token = await dlMint();
  const b = dlSealed('payslip');
  const r = await dlSrv.post('/v2/inbound', {
    headers: { Authorization: `Bearer ${token}` },
    body: { hash: b.hash, payload: b.payload.toString('base64'), ttl_ms: 3_600_000 },
  });
  assert.equal(r.status, 200, 'POST /v2/inbound refused a pst_ token; the "Send a link" stand cannot upload at all');
  assert.equal(r.json.ok, true);
  assert.match(r.json.download_token, /^[a-f0-9]{48}$/,
    'the upload no longer mints a download token, so there is no link to hand to a receiver who arrives later');
  dlDid();
});

// ── 2. The link works once ───────────────────────────────────────────────────

test('the share link serves the sealed bytes once and refuses the second time', async (t) => {
  if (!dlRc) return t.skip('no redis');
  const token = await dlMint();
  const b = dlSealed('once');
  const up = await dlSrv.post('/v2/inbound', {
    headers: { Authorization: `Bearer ${token}` },
    body: { hash: b.hash, payload: b.payload.toString('base64'), ttl_ms: 3_600_000 },
  });
  assert.equal(up.status, 200);
  const dl = up.json.download_token;

  // The receiver carries NO credential. That is the whole feature: an office
  // mails a link to a client who has no account and never will have one.
  const info = await dlSrv.get(`/v2/dl/${dl}/info`);
  assert.equal(info.status, 200, 'GET /v2/dl/:token/info refused an anonymous caller; the receiver has no credential to offer');
  assert.equal(info.json.used, false);
  assert.ok(info.json.ttl_left_s > 0, 'the link reports no time left while it is still live');

  const first = await dlSrv.get(`/v2/dl/${dl}/get`);
  assert.equal(first.status, 200, 'the first download failed; the link a sender handed out does not work');
  assert.equal(Buffer.compare(first.buf, b.payload), 0,
    'the bytes came back changed; a receiver decrypting these would get a GCM failure and be told the link was tampered with');
  assert.equal(first.headers['x-burned'], 'true');

  const second = await dlSrv.get(`/v2/dl/${dl}/get`);
  assert.equal(second.status, 410,
    'the link served a second download; "works once" is on the page and in the docs, and this is the only thing that makes it true');
  assert.match(second.text, /already been downloaded and burned/i,
    'the second attempt must say what happened in a sentence a receiver can act on');

  // And the status route agrees, which is what the sender-side "sent links"
  // list reads. It cannot tell burned from expired -- both are 404 -- which is
  // why the page separates them on its own recorded expiry and says so.
  const after = await dlSrv.get(`/v2/dl/${dl}/info`);
  assert.equal(after.status, 404, 'a spent link still reports itself live; the sent-links list would say "waiting" forever');
  dlDid();
});

test('a link the sender never handed out still expires on its own', async (t) => {
  if (!dlRc) return t.skip('no redis');
  const token = await dlMint();
  const b = dlSealed('ttl');
  // 30 seconds is the shortest the page offers. Asking for it proves the relay
  // honours a request UNDER the ceiling exactly as asked, which is the other
  // half of the clamp measured below.
  const up = await dlSrv.post('/v2/inbound', {
    headers: { Authorization: `Bearer ${token}` },
    body: { hash: b.hash, payload: b.payload.toString('base64'), ttl_ms: 30_000 },
  });
  assert.equal(up.status, 200);
  assert.equal(up.json.ttl_ms, 30_000, 'a TTL under the tier ceiling must be honoured as asked, not rounded up to the ceiling');
  const info = await dlSrv.get(`/v2/dl/${up.json.download_token}/info`);
  assert.ok(info.json.ttl_left_s <= 30, 'the link reports more time than the upload was given');
  dlDid();
});

// ── 3. The TTL the sender is shown is the one the relay applied ──────────────

test('the relay clamps a too-long link to the tier, and says so in the response', async (t) => {
  if (!dlRc) return t.skip('no redis');
  const token = await dlMint();
  const b = dlSealed('clamp');
  // The account is community: tiers.js gives it a 1 hour link. Ask for a week.
  const up = await dlSrv.post('/v2/inbound', {
    headers: { Authorization: `Bearer ${token}` },
    body: { hash: b.hash, payload: b.payload.toString('base64'), ttl_ms: 604_800_000 },
  });
  assert.equal(up.status, 200);
  assert.equal(up.json.ttl_ms, tiers.tierLimit('community', 'view_ttl_ms'),
    'the upload no longer clamps to the tier ceiling, or no longer reports the value it applied; the expiry the sender shows a receiver would then be a number the relay never agreed to');
  dlDid();
});

// ── 4. The chooser sentence comes off tiers.js ───────────────────────────────

test('the plan API serves the per-plan link lifetimes the chooser prints', async (t) => {
  if (!dlRc) return t.skip('no redis');
  const r = await dlSrv.get('/v2/check-key', { headers: { 'X-Api-Key': DL_OWNER } });
  assert.equal(r.status, 200);
  assert.equal(r.json.valid, true);
  assert.equal(r.json.link_ttl_ms, tiers.tierLimit('community', 'view_ttl_ms'),
    'GET /v2/check-key no longer reports the link lifetime this key is really held to');
  for (const plan of ['community', 'pro', 'business', 'enterprise']) {
    assert.equal(r.json.link_ttl_ms_by_plan[plan], tiers.tierLimit(plan, 'view_ttl_ms'),
      `GET /v2/check-key reports a ${plan} link lifetime that is not the tiers.js row; the /parashare chooser prints these numbers and would print a stale one`);
  }
  // The three the chooser names out loud, so a tier edit that changes what the
  // sentence should say fails here and not in front of a buyer.
  assert.equal(r.json.link_ttl_ms_by_plan.community, 3_600_000, 'the chooser says "1 hour on Community"');
  assert.equal(r.json.link_ttl_ms_by_plan.pro, 86_400_000, 'the chooser says "24 hours on Pro"');
  assert.equal(r.json.link_ttl_ms_by_plan.business, 604_800_000, 'the chooser says "7 days on Business"');
  dlDid();
});
