'use strict';
// route-dl-claim.test.js: a one-time link burns when the receiver HAS the file,
// not when somebody touched it. Against a real relay and a real redis.
//
// WHY. The 2026-10-04 ParaSend test round (tester 4) found that /get burned a
// one-time link three ways that cost the receiver the file:
//   2. a mail scanner opened the link and its JavaScript fetched it
//   3. a slow or broken download: GET /v2/dl/:token/get burned on 'finish',
//      which is "handed to the kernel or the proxy", not "arrived"
//   8. a key with one wrong character: the page fetched (and burned) first and
//      found out the key did not fit afterwards
// And every gone link said "already downloaded", also when it had expired or
// the relay had restarted (finding 4).
//
// The relay half of the repair is claim mode: GET .../get?claim=<id> serves the
// bytes and burns nothing; POST .../ack with that id burns; POST .../release
// gives the claim back. /info and a gone /get carry a `reason`. The browser half
// (no fetch before a click) is pinned in tests/get-claim-flow.test.mjs.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-dl-claim.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const CL_SUFFIX = crypto.randomBytes(6).toString('hex');
const CL_OWNER = `pgp_owner_key_for_the_dl_claim_suite_${CL_SUFFIX}`;

let clRc = null;
let clSrv;
let clChecks = 0;
const clDid = () => { clChecks++; };

before(async () => {
  clRc = await requireRedis(DEFAULT_REDIS);
  clSrv = await boot({
    tag: 'dlclaim',
    users: { api_keys: [{ key: CL_OWNER, plan: 'pro', active: true, email: 'claim@example.test', account_id: `acct_dlclaim_${CL_SUFFIX}` }] },
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS },
    usersFile: true,
  });
});

after(async () => {
  await killAll();
  if (clRc) { try { await clRc.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-dl-claim', clChecks);
});

const claimId = () => crypto.randomBytes(16).toString('hex');

async function clUpload(label, extra = {}, size = 0) {
  const payload = size ? crypto.randomBytes(size) : Buffer.from(`${label}-${crypto.randomBytes(24).toString('hex')}`);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const up = await clSrv.post('/v2/inbound', {
    headers: { 'X-Api-Key': CL_OWNER },
    body: { hash, payload: payload.toString('base64'), ...extra },
  });
  assert.equal(up.status, 200, `upload refused: ${up.text}`);
  return { token: up.json.download_token, payload, hash };
}

const info = (tk) => clSrv.get(`/v2/dl/${tk}/info`);
const claimGet = (tk, c) => clSrv.get(`/v2/dl/${tk}/get?claim=${c}`);
const ack = (tk, c) => clSrv.post(`/v2/dl/${tk}/ack`, { body: { claim: c } });
const release = (tk, c) => clSrv.post(`/v2/dl/${tk}/release`, { body: { claim: c } });

test('claim mode serves the exact bytes and burns nothing until the ack', async (t) => {
  if (!clRc) return t.skip('no redis');
  const { token, payload } = await clUpload('ack');
  const c = claimId();
  const got = await claimGet(token, c);
  assert.equal(got.status, 200);
  assert.ok(got.buf.equals(payload), 'the claimed bytes differ from what was uploaded');
  assert.equal(got.headers['x-burned'], 'pending-ack');
  const sha = crypto.createHash('sha256').update(got.buf).digest('hex');
  assert.equal(sha, crypto.createHash('sha256').update(payload).digest('hex'), 'sha256 roundtrip broke');

  const live = await info(token);
  assert.equal(live.status, 200, 'a claimed but unconfirmed download must not burn the link');

  const a = await ack(token, c);
  assert.equal(a.status, 200);
  assert.equal(a.json.burned, true);
  const again = await ack(token, c);
  assert.equal(again.status, 200, 'a repeated ack for the same claim is idempotent');

  const gone = await info(token);
  assert.equal(gone.status, 404);
  assert.equal(gone.json.reason, 'downloaded');
  const get2 = await claimGet(token, claimId());
  assert.equal(get2.status, 410);
  assert.equal(get2.json.reason, 'downloaded', 'a burned link must say it was downloaded');
  clDid();
});

// Finding 3: a download that stops halfway costs nothing.
test('an interrupted claimed download burns nothing, and the link opens again', async (t) => {
  if (!clRc) return t.skip('no redis');
  const { token, payload } = await clUpload('abort', {}, 4 * 1024 * 1024);
  const c = claimId();
  // Read one chunk, then drop the connection.
  await new Promise((resolve, reject) => {
    const r = http.get(`${clSrv.base}/v2/dl/${token}/get?claim=${c}`, (res) => {
      assert.equal(res.statusCode, 200);
      res.once('data', () => { r.destroy(); setTimeout(resolve, 200); });
    });
    r.on('error', () => {});
    setTimeout(() => reject(new Error('no data')), 5000);
  });
  assert.equal((await info(token)).status, 200, 'the interrupted download burned the link');
  // The same page tries again with its own claim and gets the whole file. (On
  // loopback the relay may already have seen 'finish' for the broken attempt,
  // so the claim can still be held; the holder is never locked out by it.)
  const got = await claimGet(token, c);
  assert.equal(got.status, 200);
  assert.ok(got.buf.equals(payload));
  assert.equal((await ack(token, c)).status, 200);
  clDid();
});

// Finding 8: a wrong key costs nothing. The page decrypts first, fails, and
// releases; the receiver with the right link still gets the file.
test('a release gives the claim back without burning, and a held claim keeps others out', async (t) => {
  if (!clRc) return t.skip('no redis');
  const { token, payload } = await clUpload('release');
  const bad = claimId();
  assert.equal((await claimGet(token, bad)).status, 200);
  const other = await claimGet(token, claimId());
  assert.equal(other.status, 409, 'a second claimant must wait while a claim is held');
  assert.equal(other.json.reason, 'busy');
  const legacy = await clSrv.get(`/v2/dl/${token}/get`);
  assert.equal(legacy.status, 409, 'an old client must not burn a file somebody else is downloading');

  assert.equal((await release(token, bad)).status, 200);
  assert.equal((await info(token)).status, 200, 'a release must not burn');
  const good = claimId();
  const got = await claimGet(token, good);
  assert.equal(got.status, 200);
  assert.ok(got.buf.equals(payload));
  const wrongAck = await ack(token, bad);
  assert.equal(wrongAck.status, 409, 'an ack with somebody else\'s claim must not burn');
  assert.equal((await ack(token, good)).status, 200);
  clDid();
});

test('retries are bounded: the sixth claimed fetch burns the link as exhausted', async (t) => {
  if (!clRc) return t.skip('no redis');
  const { token } = await clUpload('bound');
  for (let i = 0; i < 5; i++) {
    const c = claimId();
    assert.equal((await claimGet(token, c)).status, 200, `fetch ${i + 1} refused`);
    await release(token, c);
  }
  const sixth = await claimGet(token, claimId());
  assert.equal(sixth.status, 410);
  assert.equal(sixth.json.reason, 'exhausted');
  assert.equal((await info(token)).json.reason, 'exhausted');
  clDid();
});

test('the old burn-on-read path is unchanged for clients that send no claim', async (t) => {
  if (!clRc) return t.skip('no redis');
  const { token, payload } = await clUpload('legacy');
  const got = await clSrv.get(`/v2/dl/${token}/get`);
  assert.equal(got.status, 200);
  assert.ok(got.buf.equals(payload));
  assert.equal(got.headers['x-burned'], 'true');
  await new Promise((r) => setTimeout(r, 100));
  const i = await info(token);
  assert.equal(i.status, 404);
  assert.equal(i.json.reason, 'downloaded');
  clDid();
});

test('malformed claims and acks are refused without burning', async (t) => {
  if (!clRc) return t.skip('no redis');
  const { token } = await clUpload('malformed');
  assert.equal((await clSrv.post(`/v2/dl/${token}/ack`, { body: { claim: 'nope' } })).status, 400);
  assert.equal((await clSrv.post(`/v2/dl/${token}/ack`, { body: 'not json' })).status, 400);
  assert.equal((await ack(token, claimId())).status, 409, 'an ack without a fetch must not burn');
  assert.equal((await info(token)).status, 200);
  clDid();
});

// Finding 4: every gone link used to read "already downloaded".
test('an expired link says expired, not downloaded', async (t) => {
  if (!clRc) return t.skip('no redis');
  const { token } = await clUpload('expire', { ttl_ms: 1200 });
  await new Promise((r) => setTimeout(r, 1700));
  const i = await info(token);
  assert.equal(i.status, 404);
  assert.equal(i.json.reason, 'expired');
  const g = await claimGet(token, claimId());
  assert.equal(g.status, 410);
  assert.equal(g.json.reason, 'expired');
  clDid();
});

test('an unknown token says unknown, and a withdrawn file says withdrawn', async (t) => {
  if (!clRc) return t.skip('no redis');
  const u = await info('0'.repeat(48));
  assert.equal(u.json.reason, 'unknown');
  const { token, hash } = await clUpload('withdraw');
  const del = await clSrv.req('DELETE', `/v2/inbound/${hash}`, { headers: { 'X-Api-Key': CL_OWNER } });
  assert.equal(del.status, 200);
  assert.equal((await info(token)).json.reason, 'withdrawn');
  clDid();
});

test('after a relay restart a live link says lost and a burned one still says downloaded', async (t) => {
  if (!clRc) return t.skip('no redis');
  const live = await clUpload('restart-live');
  const burned = await clUpload('restart-burned');
  const c = claimId();
  assert.equal((await claimGet(burned.token, c)).status, 200);
  assert.equal((await ack(burned.token, c)).status, 200);
  // The redis writes are fire-and-forget; give them a moment.
  await new Promise((r) => setTimeout(r, 200));
  clSrv = await clSrv.restart();
  const l = await info(live.token);
  assert.equal(l.status, 404);
  assert.equal(l.json.reason, 'lost', 'a link lost in a restart must not read as downloaded');
  const g = await claimGet(live.token, claimId());
  assert.equal(g.json.reason, 'lost');
  assert.equal((await info(burned.token)).json.reason, 'downloaded');
  clDid();
});
