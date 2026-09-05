'use strict';
// ParaSend over HTTP on a really booted relay: upload, download, burn-on-read,
// the download-link flow, and the per-tier ceilings.
//
// WHY THIS SUITE EXISTS. Burn-on-read is the product's central promise: the
// blob is gone after the read, and a second read finds nothing. It was proved
// only by the hourly transfer canary against LIVE production (tests/transfer-
// canary.test.mjs), which measures the running server and not the commit being
// merged. So a change to the burn could go green through CI and only be caught
// by a canary an hour after deploy, on production, by a check that opens a
// GitHub issue. That is the wrong order. Everything here runs against the
// relay.js in the working tree, offline, in about a second.
//
// The relay boots WITHOUT redis, which is exactly what the blob path needs: the
// blob store is an in-process Map (relay.js:blobStore) and the monthly quota
// gate fails open without redis (lib/quota.js:170-197), so the transfer path is
// fully exercisable with no service. The per-tier CEILINGS asserted here
// (view_ttl_ms and max_views from lib/tiers.js) are the two that relay.js
// really enforces on upload.
// Run: node --test relay/test/route-transfer-burn.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';

const PRO = 'pgp_pro_key_for_the_transfer_suite';
const COMMUNITY = 'pgp_community_key_for_the_transfer_suite';
const OTHER = 'pgp_other_tenant_key_for_the_transfer_suite';
// A key with NO plan field at all. Real users.json entries in this shape exist:
// every key minted before the plan field did, plus anything an import wrote.
const NOPLAN = 'pgp_no_plan_key_for_the_transfer_suite';
// A Business account. It is the tier the pricing page sells for the highest
// volume, and the one the old three-key outbound table left out entirely.
const BUSINESS = 'pgp_business_key_for_the_transfer_suite';

let srv;
let checks = 0;
const did = () => { checks++; };

// A fresh blob every time: the store is keyed on the sha256 and rejects a
// repeat with 409, so tests must not share one.
function blob(label) {
  const payload = Buffer.from(`${label}-${crypto.randomBytes(8).toString('hex')}`);
  return { payload, hash: crypto.createHash('sha256').update(payload).digest('hex') };
}

function upload(key, b, extra = {}) {
  return srv.post('/v2/inbound', {
    headers: { 'X-Api-Key': key },
    body: { hash: b.hash, payload: b.payload.toString('base64'), ...extra },
  });
}

const download = (key, hash) => srv.get(`/v2/outbound/${hash}`, { headers: { 'X-Api-Key': key } });

before(async () => {
  srv = await boot({
    tag: 'transfer',
    users: {
      api_keys: [
        { key: PRO, plan: 'pro', active: true, email: 'pro@example.test', account_id: 'acct_pro' },
        { key: COMMUNITY, plan: 'community', active: true, email: 'com@example.test', account_id: 'acct_com' },
        { key: OTHER, plan: 'pro', active: true, email: 'other@example.test', account_id: 'acct_other' },
        { key: NOPLAN, active: true, email: 'noplan@example.test', account_id: 'acct_noplan' },
        { key: BUSINESS, plan: 'business', active: true, email: 'biz@example.test', account_id: 'acct_biz' },
      ],
    },
  });
});

after(async () => { await killAll(); summary('route-transfer-burn', checks); });

// ── 1. upload ────────────────────────────────────────────────────────────────

test('an upload returns the hash, the size, a download token and a merkle proof', async () => {
  const b = blob('happy');
  const r = await upload(PRO, b, { ttl_ms: 60_000 });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.ok, true);
  assert.strictEqual(r.json.hash, b.hash);
  assert.strictEqual(r.json.size, b.payload.length);
  assert.match(r.json.download_token, /^[0-9a-f]{48}$/, 'the link credential is 24 random bytes in hex');
  const p = r.json.merkle_proof;
  assert.ok(p && typeof p.leaf_index === 'number' && p.tree_size >= 1, 'an inclusion proof travels with the upload');
  assert.match(p.leaf_hash, /^[0-9a-f]{64}$/);
  did();
});

test('the relay checks the hash it was given against the bytes it received', async () => {
  // The hash is the blob's name in the store and the leaf in the CT log, so a
  // caller must not be able to file bytes under someone else's name.
  const b = blob('mismatch');
  const other = blob('other');
  const r = await srv.post('/v2/inbound', {
    headers: { 'X-Api-Key': PRO },
    body: { hash: other.hash, payload: b.payload.toString('base64') },
  });
  assert.strictEqual(r.status, 400);
  assert.deepStrictEqual(r.json, { error: 'hash_mismatch' });
  did();
});

test('a hash that is already stored is refused with 409, not silently overwritten', async () => {
  const b = blob('dup');
  assert.strictEqual((await upload(PRO, b)).status, 200);
  const again = await upload(PRO, b);
  assert.strictEqual(again.status, 409, 'a second upload under the same hash must not replace the first');
  did();
});

test('a malformed hash is refused', async () => {
  const b = blob('badhash');
  const r = await srv.post('/v2/inbound', {
    headers: { 'X-Api-Key': PRO },
    body: { hash: 'not-a-sha256', payload: b.payload.toString('base64') },
  });
  assert.strictEqual(r.status, 400);
  did();
});

// ── 2. burn-on-read ──────────────────────────────────────────────────────────

test('BURN ON READ: the first download returns the bytes, the second finds nothing', async () => {
  const b = blob('burn');
  assert.strictEqual((await upload(PRO, b)).status, 200);

  const first = await download(PRO, b.hash);
  assert.strictEqual(first.status, 200);
  assert.ok(first.buf.equals(b.payload), 'the bytes come back exactly as uploaded');
  assert.strictEqual(first.headers['x-paramant-burned'], 'true', 'the response says the blob was burned');
  assert.strictEqual(first.headers['x-paramant-hash'], b.hash);

  const second = await download(PRO, b.hash);
  assert.strictEqual(second.status, 404, 'a burned blob must be gone, not merely hidden');
  assert.deepStrictEqual(second.json, { error: 'Not found. Expired, burned, or never stored.' });

  // And a third read is the same 404: no state was left behind that a retry
  // could revive.
  assert.strictEqual((await download(PRO, b.hash)).status, 404);
  did();
});

test('the 404 after a burn is the same 404 as for a hash that never existed', async () => {
  // Otherwise the download route is an oracle for "this file existed once".
  const burned = blob('oracle');
  await upload(PRO, burned);
  await download(PRO, burned.hash);
  const afterBurn = await download(PRO, burned.hash);
  const neverStored = await download(PRO, crypto.randomBytes(32).toString('hex'));
  assert.strictEqual(afterBurn.status, neverStored.status);
  assert.deepStrictEqual(afterBurn.json, neverStored.json);
  did();
});

test('the download carries a signed delivery receipt with a burn confirmation', async () => {
  const b = blob('receipt');
  await upload(PRO, b);
  const r = await download(PRO, b.hash);
  assert.strictEqual(r.status, 200);
  // The download hands over a REFERENCE now; the receipt itself is fetched.
  const id = r.headers['x-paramant-receipt-id'];
  assert.match(id || '', /^[0-9a-f]{32}$/, 'every delivery is receipted');
  assert.strictEqual(r.headers['x-paramant-receipt-url'], `/v2/transfers/${id}/receipt`);

  const fetched = await srv.get(`/v2/transfers/${id}/receipt`, { headers: { 'X-Api-Key': PRO } });
  assert.strictEqual(fetched.status, 200, fetched.text);
  // The hash in the header is over the exact bytes that come back, so the
  // handover cannot be tampered with in between.
  assert.strictEqual(fetched.json.receipt_hash, r.headers['x-paramant-receipt-hash']);
  assert.strictEqual('sha3-256:' + crypto.createHash('sha3-256').update(fetched.json.receipt).digest('hex'),
    r.headers['x-paramant-receipt-hash'], 'the advertised hash really is the hash of the receipt');

  const receipt = JSON.parse(Buffer.from(fetched.json.receipt, 'base64url').toString('utf8'));
  assert.strictEqual(receipt.blob_hash, b.hash);
  assert.strictEqual(receipt.burn_confirmed, true);
  assert.ok(receipt.signature, 'the receipt is signed by the relay identity');
  assert.ok(receipt.inclusion_proof, 'and carries the CT inclusion proof for the blob');

  // And it is still the thing /v2/verify-receipt was built to check.
  const verified = await srv.post('/v2/verify-receipt', {
    headers: { 'X-Api-Key': PRO }, body: { receipt: fetched.json.receipt },
  });
  assert.strictEqual(verified.status, 200, verified.text);
  assert.strictEqual(verified.json.valid, true, 'the fetched receipt verifies as delivered');
  did();
});

test('a download answers with less than 8 KB of response headers', async () => {
  // PR #341, finding 2. X-Paramant-Receipt carried the whole signed receipt:
  // 18551 bytes for that one header, 19560 for the block. Two hard consequences,
  // neither of them theoretical:
  //   Node's default maxHeaderSize is 16384, so fetch() and a default
  //   http.request threw UND_ERR_HEADERS_OVERFLOW on every single download.
  //   nginx's default proxy_buffer_size is 4k/8k and that one buffer must hold
  //   the whole upstream header block, so a proxied download is a 502.
  // 8 KB is the ceiling here because it is the larger of the two nginx defaults:
  // stay under it and the smallest realistic proxy still passes the response.
  const b = blob('header-size');
  await upload(PRO, b);
  const r = await download(PRO, b.hash);
  assert.strictEqual(r.status, 200);
  assert.ok(r.headers['x-paramant-receipt-id'], 'measured on a download that really is receipted');

  // Reconstruct the wire bytes of the header block: "Name: value\r\n" each,
  // plus the closing CRLF. The status line is a few dozen bytes on top.
  let bytes = 2;
  for (const [name, value] of Object.entries(r.headers)) {
    for (const v of Array.isArray(value) ? value : [value]) {
      bytes += Buffer.byteLength(`${name}: ${v}\r\n`);
    }
  }
  assert.ok(bytes < 8192,
    `a download must fit a default proxy buffer, got ${bytes} bytes of headers`);
  assert.ok(!('x-paramant-receipt' in r.headers),
    'and the fat header is gone by default, not merely smaller');
  // The removal is announced ON the response, because a client that reads the
  // old header and finds nothing cannot tell "no receipt" from "it moved". The
  // Python SDK turns an absent header into a silent receipt=None, which is a
  // delivery proof quietly becoming nothing.
  assert.strictEqual(r.headers['x-paramant-receipt-deprecated'],
    `removed 2026-12-01; GET /v2/transfers/${r.headers['x-paramant-receipt-id']}/receipt`,
    'a download says out loud that the old header is gone and where the receipt went');
  did();
});

test('a receipt reference is single-tenant, and unknown or foreign ids give one 404', async () => {
  const b = blob('receipt-auth');
  await upload(PRO, b);
  const id = (await download(PRO, b.hash)).headers['x-paramant-receipt-id'];

  const foreign = await srv.get(`/v2/transfers/${id}/receipt`, { headers: { 'X-Api-Key': OTHER } });
  const unknown = await srv.get(`/v2/transfers/${'0'.repeat(32)}/receipt`, { headers: { 'X-Api-Key': OTHER } });
  assert.strictEqual(foreign.status, 404, 'another tenant may not read the receipt for a delivery it did not make');
  assert.deepStrictEqual(foreign.json, unknown.json,
    'and it answers exactly like an id that never existed, so it is no oracle');

  const noKey = await srv.get(`/v2/transfers/${id}/receipt`);
  assert.strictEqual(noKey.status, 401, 'the route sits behind the same auth gate as the download');

  // The owner can still read it, and more than once: nothing was consumed.
  for (let i = 0; i < 2; i++) {
    assert.strictEqual((await srv.get(`/v2/transfers/${id}/receipt`, { headers: { 'X-Api-Key': PRO } })).status, 200);
  }
  did();
});

test('a busy tenant cannot evict a quiet tenant\'s receipt', async () => {
  // The receipt store started as ONE shared LRU. That is a cross-tenant
  // eviction channel: enough downloads by B push A's receipt out inside A's own
  // 15 minute window, and before this route existed the receipt was guaranteed
  // to be on the response itself, so this would be a regression paid for by a
  // stranger. The budget is per account now, and the global ceiling takes from
  // the LARGEST holder, which can never be the tenant it would be protecting.
  //
  // The caps are driven down here so the RULE is measured rather than the
  // numbers: with a shared queue of 8, B's ninth receipt evicts A's first.
  const A = 'pgp_quiet_tenant_receipt_suite';
  const B = 'pgp_busy_tenant_receipt_suite';
  const srv2 = await boot({
    tag: 'transfer-receipt-budget',
    env: { PARAMANT_RECEIPT_PER_ACCOUNT_MAX: '4', PARAMANT_RECEIPT_TOTAL_MAX: '8' },
    users: { api_keys: [
      { key: A, plan: 'pro', active: true, email: 'quiet@example.test', account_id: 'acct_quiet' },
      { key: B, plan: 'business', active: true, email: 'busy@example.test', account_id: 'acct_busy' },
    ] },
  });
  const put = async (key) => {
    const b = blob(`budget-${crypto.randomBytes(4).toString('hex')}`);
    assert.strictEqual((await srv2.post('/v2/inbound', {
      headers: { 'X-Api-Key': key }, body: { hash: b.hash, payload: b.payload.toString('base64') },
    })).status, 200);
    const r = await srv2.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': key } });
    assert.strictEqual(r.status, 200);
    return r.headers['x-paramant-receipt-id'];
  };

  const quiet = await put(A);
  assert.ok(quiet, 'the quiet tenant has exactly one receipt outstanding');
  // Three times the whole store, all from one account.
  const busy = [];
  for (let i = 0; i < 24; i++) busy.push(await put(B));

  const still = await srv2.get(`/v2/transfers/${quiet}/receipt`, { headers: { 'X-Api-Key': A } });
  assert.strictEqual(still.status, 200,
    'a stranger\'s download burst must not take the quiet tenant\'s receipt away');

  // And the busy tenant is held to its OWN budget, so the burst is bounded.
  const survivors = [];
  for (const id of busy) {
    const r = await srv2.get(`/v2/transfers/${id}/receipt`, { headers: { 'X-Api-Key': B } });
    if (r.status === 200) survivors.push(id);
  }
  assert.strictEqual(survivors.length, 4, 'the busy tenant keeps its own 4 newest and no more');
  assert.deepStrictEqual(survivors, busy.slice(-4), 'and they are the newest, not an arbitrary four');
  srv2.stop();
  did();
});

test('the global backstop takes from the biggest holder, never from the quiet one', async () => {
  // The per-account cap bounds one tenant. The GLOBAL cap is what happens when
  // the store is full anyway, and an oldest-first global eviction there would
  // reintroduce exactly the cross-tenant channel the per-account cap closes:
  // the quiet tenant's single receipt is, by definition, the oldest one.
  const SMALL = 'pgp_small_holder_receipt_suite';
  const HUGE = 'pgp_huge_holder_receipt_suite';
  const srv2 = await boot({
    tag: 'transfer-receipt-backstop',
    // Per-account room for 6 each but only 5 slots in the whole store, so the
    // two caps cannot both be satisfied and the GLOBAL backstop is the rule
    // under test rather than the per-account one.
    env: { PARAMANT_RECEIPT_PER_ACCOUNT_MAX: '6', PARAMANT_RECEIPT_TOTAL_MAX: '5' },
    users: { api_keys: [
      { key: SMALL, plan: 'pro', active: true, email: 'small@example.test', account_id: 'acct_small' },
      { key: HUGE, plan: 'pro', active: true, email: 'huge@example.test', account_id: 'acct_huge' },
    ] },
  });
  const put = async (key) => {
    const b = blob(`backstop-${crypto.randomBytes(4).toString('hex')}`);
    assert.strictEqual((await srv2.post('/v2/inbound', {
      headers: { 'X-Api-Key': key }, body: { hash: b.hash, payload: b.payload.toString('base64') },
    })).status, 200);
    const r = await srv2.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': key } });
    assert.strictEqual(r.status, 200);
    return r.headers['x-paramant-receipt-id'];
  };
  const alive = async (id, key) =>
    (await srv2.get(`/v2/transfers/${id}/receipt`, { headers: { 'X-Api-Key': key } })).status === 200;

  // The quiet tenant goes FIRST, so under an oldest-first global rule it is the
  // first thing evicted. That is the regression this test exists for.
  const small = [await put(SMALL), await put(SMALL)];
  const huge = [];
  for (let i = 0; i < 6; i++) huge.push(await put(HUGE));

  for (const id of small) {
    assert.ok(await alive(id, SMALL),
      'the store filled up and the small holder still has both of its receipts');
  }
  const hugeAlive = [];
  for (const id of huge) if (await alive(id, HUGE)) hugeAlive.push(id);
  assert.strictEqual(hugeAlive.length, 3,
    'the biggest holder paid for the whole overflow: 5 slots, 2 of them the small holder\'s');
  assert.deepStrictEqual(hugeAlive, huge.slice(-3), 'and it lost its oldest, not an arbitrary set');
  srv2.stop();
  did();
});

test('with redis, a receipt outlives the process that issued it', async () => {
  // The store used to be a bare in-process Map, so every restart 404d every
  // outstanding receipt. A deploy in the middle of somebody's 15 minute window
  // silently cost them their proof of delivery, and restarting is a thing
  // operators do on purpose. The envelope store already runs on redis; so does
  // this now, with the Map kept only as the fallback for a relay without one.
  const rc = await requireRedis(DEFAULT_REDIS);
  if (!rc) return;
  // The client is closed in a finally: an open redis connection keeps the test
  // runner alive, so a FAILING assertion would hang the run instead of
  // reporting, which is a worse outcome than the failure itself.
  try {
  const KEY = 'pgp_restart_receipt_suite';
  const env = { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS };
  // usersFile mode: restart() re-reads users.json from the same scratch dir, so
  // the key has to be on disk and not only in USERS_JSON.
  let srv2 = await boot({
    tag: 'transfer-receipt-restart',
    env,
    usersFile: true,
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'restart@example.test', account_id: 'acct_restart' }] },
  });
  const b = blob('restart-receipt');
  assert.strictEqual((await srv2.post('/v2/inbound', {
    headers: { 'X-Api-Key': KEY }, body: { hash: b.hash, payload: b.payload.toString('base64') },
  })).status, 200);
  const dl = await srv2.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.strictEqual(dl.status, 200);
  const id = dl.headers['x-paramant-receipt-id'];
  const hash = dl.headers['x-paramant-receipt-hash'];
  assert.ok(id, 'the download was receipted');

  const before = await srv2.get(`/v2/transfers/${id}/receipt`, { headers: { 'X-Api-Key': KEY } });
  assert.strictEqual(before.status, 200, before.text);

  srv2 = await srv2.restart();
  const after = await srv2.get(`/v2/transfers/${id}/receipt`, { headers: { 'X-Api-Key': KEY } });
  assert.strictEqual(after.status, 200, 'a restart must not take an outstanding receipt away');
  assert.deepStrictEqual(after.json, before.json, 'and it is the same receipt, byte for byte');
  assert.strictEqual(after.json.receipt_hash, hash,
    'still matching the hash the download promised, across the process boundary');
  srv2.stop();
  did();
  } finally {
    try { await rc.quit(); } catch (_) { /* already gone */ }
  }
});

test('the fat header comes back only when an operator asks for it, and it is deprecated', async () => {
  // The removal is not silent: an out-of-tree client that still reads
  // X-Paramant-Receipt gets one release to move, behind an explicit opt-in.
  const legacy = await boot({
    tag: 'transfer-legacy-receipt',
    env: { PARAMANT_INLINE_RECEIPT_HEADER: '1' },
    users: { api_keys: [{ key: PRO, plan: 'pro', active: true, email: 'pro@example.test', account_id: 'acct_pro' }] },
  });
  const b = blob('legacy-header');
  assert.strictEqual((await legacy.post('/v2/inbound', {
    headers: { 'X-Api-Key': PRO }, body: { hash: b.hash, payload: b.payload.toString('base64') },
  })).status, 200);
  // Reading it back needs room Node does not give by default. That IS the bug:
  // a client cannot ask for this without knowing about it first.
  const r = await legacy.get(`/v2/outbound/${b.hash}`, {
    headers: { 'X-Api-Key': PRO }, maxHeaderSize: 96 * 1024,
  });
  assert.strictEqual(r.status, 200);
  assert.ok(r.headers['x-paramant-receipt'], 'the opt-in really puts the old header back');
  assert.ok(Buffer.byteLength(r.headers['x-paramant-receipt']) > 16384,
    'and it is still the header that does not fit, which is why it is going away');
  assert.ok(r.headers['x-paramant-receipt-id'], 'the reference is served alongside it during the window');
  assert.ok(!('x-paramant-receipt-deprecated' in r.headers),
    'and while the opt-in is on there is nothing to announce: the old header is really there');
  legacy.stop();
  did();
});

test('one tenant cannot download another tenant\'s blob', async () => {
  const b = blob('tenant');
  await upload(PRO, b);
  const thief = await download(OTHER, b.hash);
  assert.strictEqual(thief.status, 403, 'the blob is bound to the uploading key');
  // And the refused attempt must not have burned it for the rightful owner.
  const owner = await download(PRO, b.hash);
  assert.strictEqual(owner.status, 200, 'a refused read must not consume the view');
  did();
});

// ── 3. per-tier ceilings ─────────────────────────────────────────────────────

test('max_views is clamped to the tier ceiling: community gets one read, pro gets ten', async () => {
  // lib/tiers.js: community.max_views = 1, pro.max_views = 10. The relay clamps
  // whatever the client asks for (relay.js:4391), so a community key asking for
  // 5 still burns on the first read.
  const c = blob('views-community');
  assert.strictEqual((await upload(COMMUNITY, c, { max_views: 5 })).status, 200);
  assert.strictEqual((await download(COMMUNITY, c.hash)).status, 200);
  assert.strictEqual((await download(COMMUNITY, c.hash)).status, 404,
    'community asked for 5 views and must still be held to 1');

  const p = blob('views-pro');
  assert.strictEqual((await upload(PRO, p, { max_views: 5 })).status, 200);
  for (let i = 1; i <= 5; i++) {
    const r = await download(PRO, p.hash);
    assert.strictEqual(r.status, 200, `pro read ${i} of 5`);
    assert.strictEqual(r.headers['x-paramant-burned'], i === 5 ? 'true' : 'false',
      'only the last permitted read reports the burn');
  }
  assert.strictEqual((await download(PRO, p.hash)).status, 404, 'the sixth read of a 5-view blob is gone');
  did();
});

test('a pro key cannot exceed its own ceiling either: 99 requested, 10 granted', async () => {
  const b = blob('views-cap');
  assert.strictEqual((await upload(PRO, b, { max_views: 99 })).status, 200);
  for (let i = 1; i <= 10; i++) {
    assert.strictEqual((await download(PRO, b.hash)).status, 200, `read ${i}`);
  }
  assert.strictEqual((await download(PRO, b.hash)).status, 404, 'the eleventh read is past the pro ceiling of 10');
  did();
});

test('the TTL is clamped to the tier ceiling: community 1 hour, pro 24 hours', async () => {
  // lib/tiers.js: community.view_ttl_ms = 3_600_000, pro.view_ttl_ms =
  // 86_400_000. A client asking for a week gets its tier's ceiling back in the
  // upload response, so the clamp is visible to the caller and not silent.
  const week = 7 * 86_400_000;
  const c = await upload(COMMUNITY, blob('ttl-c'), { ttl_ms: week });
  assert.strictEqual(c.json.ttl_ms, 3_600_000);
  const p = await upload(PRO, blob('ttl-p'), { ttl_ms: week });
  assert.strictEqual(p.json.ttl_ms, 86_400_000);
  // A request below the ceiling is honoured as asked.
  const small = await upload(PRO, blob('ttl-small'), { ttl_ms: 30_000 });
  assert.strictEqual(small.json.ttl_ms, 30_000);
  did();
});

test('a key with no plan is held to ONE ceiling, the strictest, on both dimensions', async () => {
  // The two ceilings are taken one line apart and used to disagree about what a
  // missing plan means: the TTL fell back to 'community' (1 hour) and max_views
  // to 'pro' (10 reads). So an unplanned key got the community link lifetime and
  // the Pro read count in the same upload. A missing plan is not evidence of a
  // paid one, so both must land on community: 1 hour, 1 read.
  const week = 7 * 86_400_000;
  const t = await upload(NOPLAN, blob('noplan-ttl'), { ttl_ms: week });
  assert.strictEqual(t.status, 200, t.text);
  assert.strictEqual(t.json.ttl_ms, 3_600_000, 'the TTL ceiling for a missing plan is the community hour');

  const v = blob('noplan-views');
  assert.strictEqual((await upload(NOPLAN, v, { max_views: 10 })).status, 200);
  const first = await download(NOPLAN, v.hash);
  assert.strictEqual(first.status, 200);
  assert.strictEqual(first.headers['x-paramant-burned'], 'true',
    'and the views ceiling is the community one too: the first read is the last');
  assert.strictEqual((await download(NOPLAN, v.hash)).status, 404,
    'a missing plan must not quietly buy the pro ceiling of 10 reads');
  did();
});

test('a Business key is not rate limited at the free 50 downloads per hour', async () => {
  // relay.js:1607 used to hold its own three-key table, { free, pro,
  // enterprise }, keyed on the raw plan string with a `?? free` fallback.
  // 'business' was not a key in it, so a Business account, which pays for the
  // highest volume of all, was capped at the free 50 per hour. The ceiling now
  // comes from lib/tiers.js (outbound_per_hour), which has a row per tier and
  // normalises the aliases, so the 51st download goes through.
  const tiers = require('../lib/tiers');
  const FREE_CEILING = tiers.tierLimitNum('community', 'outbound_per_hour');
  assert.strictEqual(FREE_CEILING, 50, 'the free ceiling this test is measuring against');
  assert.ok(tiers.tierLimitNum('business', 'outbound_per_hour') > FREE_CEILING,
    'business must buy more outbound than community, not the same');

  for (let i = 1; i <= FREE_CEILING + 1; i++) {
    const b = blob(`biz-${i}`);
    assert.strictEqual((await upload(BUSINESS, b)).status, 200, `upload ${i}`);
    const r = await download(BUSINESS, b.hash);
    assert.strictEqual(r.status, 200,
      `download ${i} of ${FREE_CEILING + 1}: a Business key must not hit the free hourly ceiling`);
  }
  did();
});

test('every tier the pricing page sells has its own outbound ceiling, and they only go up', async () => {
  // The regression this pins is a table with a hole in it. Any tier missing
  // from lib/tiers.js falls back to the community row, which is how 'business'
  // silently got the free rate for as long as the local table existed.
  const tiers = require('../lib/tiers');
  const ladder = ['community', 'pro', 'business', 'enterprise'];
  assert.deepStrictEqual(Object.keys(tiers.TIER_LIMITS), ladder,
    'the tier list this assertion walks must be the whole tier list');
  let previous = 0;
  for (const tier of ladder) {
    const raw = tiers.tierLimit(tier, 'outbound_per_hour');
    assert.notStrictEqual(raw, null, `${tier} has no outbound_per_hour, so it silently gets the community rate`);
    const rate = tiers.tierLimitNum(tier, 'outbound_per_hour');
    assert.ok(rate > previous, `${tier} must buy more outbound than the tier below it, got ${rate} after ${previous}`);
    previous = rate;
  }
  // And the aliases the relay really sees on a key record resolve to a row.
  for (const [alias, canonical] of [['free', 'community'], ['dev', 'community'], ['licensed', 'enterprise']]) {
    assert.strictEqual(tiers.tierLimitNum(alias, 'outbound_per_hour'), tiers.tierLimitNum(canonical, 'outbound_per_hour'),
      `the legacy plan name ${alias} must resolve to the ${canonical} ceiling`);
  }
  did();
});

// ── 4. the download-link flow ────────────────────────────────────────────────

test('the /v2/dl link needs no API key, burns once, and is 410 afterwards', async () => {
  // The 48-hex token IS the credential; a recipient has no key. This is the
  // flow behind every "someone sent you a file" mail.
  const b = blob('link');
  const up = await upload(PRO, b);
  const token = up.json.download_token;

  const info = await srv.get(`/v2/dl/${token}/info`);
  assert.strictEqual(info.status, 200);
  assert.strictEqual(info.json.used, false);
  assert.strictEqual(info.json.file_size, b.payload.length);

  const got = await srv.get(`/v2/dl/${token}/get`);
  assert.strictEqual(got.status, 200);
  assert.ok(got.buf.equals(b.payload));
  assert.strictEqual(got.headers['x-burned'], 'true');

  const again = await srv.get(`/v2/dl/${token}/get`);
  assert.strictEqual(again.status, 410, 'a used link is gone for good');

  const infoAfter = await srv.get(`/v2/dl/${token}/info`);
  assert.strictEqual(infoAfter.status, 404, 'and the probe no longer describes it');
  did();
});

test('an unknown download token is refused, and the info probe never burns', async () => {
  const b = blob('probe');
  const token = (await upload(PRO, b)).json.download_token;
  // Three probes in a row must all still say "not used".
  for (let i = 0; i < 3; i++) {
    const info = await srv.get(`/v2/dl/${token}/info`);
    assert.strictEqual(info.json.used, false, 'probing must not consume the download');
  }
  assert.strictEqual((await srv.get(`/v2/dl/${token}/get`)).status, 200, 'the blob survived three probes');

  const unknown = await srv.get(`/v2/dl/${'0'.repeat(48)}/get`);
  assert.strictEqual(unknown.status, 410);
  did();
});

// ── 5. the blob is opaque ────────────────────────────────────────────────────

test('a caller may delete its own blob before anyone reads it, and only its own', async () => {
  const b = blob('abort');
  await upload(PRO, b);
  const wrongTenant = await srv.req('DELETE', `/v2/inbound/${b.hash}`, { headers: { 'X-Api-Key': OTHER } });
  assert.strictEqual(wrongTenant.status, 403);
  const owner = await srv.req('DELETE', `/v2/inbound/${b.hash}`, { headers: { 'X-Api-Key': PRO } });
  assert.strictEqual(owner.status, 200);
  assert.strictEqual((await download(PRO, b.hash)).status, 404, 'the aborted blob is really gone');
  did();
});

// ── 6. every ParaSend ceiling rides the PRODUCT axis, not the unified plan ────
//
// THE FAULT THIS SECTION PINS. Billing moves a customer with setProductPlan ->
// entitlements.applyProductTier, which writes plan_parasend (or plan_parasign)
// and never the unified `plan`. Four ceilings still resolved off `plan`:
//   relay.js  view_ttl_ms and max_views on POST /v2/inbound
//   relay.js  the device cap on POST /v2/pubkey
//   relay.js  transfers_month, the only one already on the product axis
// So the moment self-serve billing goes live, a ParaSend Pro customer keeps a
// 1 hour link, 1 read and 5 devices while /pricing sells 24 hours, 10 reads and
// 50 devices. It is invisible today only because billing still runs through the
// admin route, which sets `plan` as well.
//
// Everything this section needs lives inside this function. Two parallel merges
// broke main by each adding their own file-scope binding, so a new block earns
// no new top-level name here.
(function productAxisSection() {

  // THE SHAPE THE MOLLIE WEBHOOK WRITES. setProductPlan -> applyProductTier moves
  // plan_parasend only and deliberately leaves the unified `plan` alone, so a
  // ParaSend Pro buyer's record still reads plan: 'community'. Every ceiling that
  // resolved off `plan` was blind to this record.
  const WEBHOOK = 'pgp_webhook_shape_key_for_the_transfer_suite';
  // The shape POST /v2/admin/keys/update-plan writes: the unified plan set AND
  // the per-product plans derived from it. It means the same thing as WEBHOOK and
  // must be answered identically.
  const ADMIN_SHAPE = 'pgp_admin_shape_key_for_the_transfer_suite';
  // A key with no plan. The suite's shared relay already sits at the community
  // edition's fixed 5-key ceiling (relay.js COMMUNITY_KEY_LIMIT), where key 6
  // answers 402 to everything, so this section boots its own relay.
  const AXIS_NOPLAN = 'pgp_no_plan_key_for_the_axis_section';

  // One relay for the section, booted on first use and killed by the suite's
  // after() hook along with everything else.
  let axis = null;
  async function axisSrv() {
    if (!axis) {
      axis = await boot({
        tag: 'transfer-axis',
        users: { api_keys: [
          { key: WEBHOOK, plan: 'community', plan_parasend: 'pro', active: true, email: 'hook@example.test', account_id: 'acct_hook' },
          { key: ADMIN_SHAPE, plan: 'pro', plan_parasend: 'pro', plan_parasign: 'pro', active: true, email: 'adm@example.test', account_id: 'acct_admin_shape' },
          { key: AXIS_NOPLAN, active: true, email: 'axisnoplan@example.test', account_id: 'acct_axis_noplan' },
        ] },
      });
    }
    return axis;
  }
  const axisUpload = (a, key, b, extra = {}) => a.post('/v2/inbound', {
    headers: { 'X-Api-Key': key },
    body: { hash: b.hash, payload: b.payload.toString('base64'), ...extra },
  });
  const axisDownload = (a, key, hash) => a.get(`/v2/outbound/${hash}`, { headers: { 'X-Api-Key': key } });

  test('a ParaSend Pro tier bought through the webhook is honoured, though `plan` still reads community', async () => {
    const a = await axisSrv();
    const week = 7 * 86_400_000;
    const t = await axisUpload(a, WEBHOOK, blob('hook-ttl'), { ttl_ms: week });
    assert.strictEqual(t.status, 200, t.text);
    assert.strictEqual(t.json.ttl_ms, 86_400_000,
      'the Pro day the customer paid for, not the community hour his unified plan still says');

    const v = blob('hook-views');
    assert.strictEqual((await axisUpload(a, WEBHOOK, v, { max_views: 10 })).status, 200);
    for (let i = 1; i <= 10; i++) {
      const r = await axisDownload(a, WEBHOOK, v.hash);
      assert.strictEqual(r.status, 200, `read ${i} of the ten a Pro tier buys`);
      assert.strictEqual(r.headers['x-paramant-burned'], i === 10 ? 'true' : 'false');
    }
    assert.strictEqual((await axisDownload(a, WEBHOOK, v.hash)).status, 404, 'and the eleventh is past the Pro ceiling');
    did();
  });

  test('the device cap follows the ParaSend tier, and a plan-less key gets the community five', async () => {
    // lib/tiers.js: community.devices = 5, pro.devices = 50. The read here used to
    // be `keyData.plan || 'pro'`, so it missed the webhook record AND handed a key
    // with no plan at all the Pro cap: the mirror image of the default fixed on
    // the inbound ceilings.
    const a = await axisSrv();
    const dev = (key, n) => {
      const id = `${key}-device-${n}`;
      return a.post('/v2/pubkey', {
        headers: { 'X-Api-Key': key },
        body: { device_id: id, ecdh_pub: Buffer.from(id.padEnd(32, 'x')).toString('base64') },
      });
    };
    for (let n = 1; n <= 5; n++) {
      assert.strictEqual((await dev(AXIS_NOPLAN, n)).status, 200, `plan-less device ${n} of the community five`);
    }
    const sixth = await dev(AXIS_NOPLAN, 6);
    assert.strictEqual(sixth.status, 429, 'a missing plan must not quietly buy the Pro cap of fifty devices');
    assert.strictEqual(sixth.json.limit, 5);
    assert.strictEqual(sixth.json.plan, 'community', 'and the 429 names the tier that decided');

    for (let n = 1; n <= 6; n++) {
      assert.strictEqual((await dev(WEBHOOK, n)).status, 200,
        `device ${n} on a webhook-written Pro tier, which the community five would have refused at 6`);
    }
    did();
  });

  test('the device cap governs adding a device, never re-registering one it already holds', async () => {
    // The cap check used to run BEFORE the already-registered check, so an
    // account over its cap got 429 on every re-registration of a device it
    // already had. That is the normal path, not an edge: a community device
    // pubkey lives 7 days and the expiry sweep runs hourly, so a device comes
    // back to this route routinely. An account over its cap would have been
    // locked out one device at a time, and being over the cap is a real state:
    // the counter matched nothing until this branch, so an account could hold
    // any number, and a tier change can put an account over it at any time.
    const KEY = 'pgp_over_cap_key_for_the_axis_section';
    const over = await boot({
      tag: 'transfer-axis-cap',
      env: { ADMIN_TOKEN: 'admin-token-for-the-axis-section', INTERNAL_AUTH_TOKEN: 'internal-token-for-the-axis-section' },
      users: { api_keys: [
        // Starts uncapped, so the eight devices below can be registered at all.
        { key: KEY, plan: 'community', plan_parasend: 'enterprise', active: true, email: 'cap@example.test', account_id: 'acct_over_cap' },
      ] },
    });
    const reg = (n) => {
      const id = `over-cap-device-${n}`;
      return over.post('/v2/pubkey', {
        headers: { 'X-Api-Key': KEY },
        body: { device_id: id, ecdh_pub: Buffer.from(id.padEnd(32, 'x')).toString('base64') },
      });
    };
    for (let n = 1; n <= 8; n++) assert.strictEqual((await reg(n)).status, 200, `device ${n} while uncapped`);

    // Now move the account down to Community, whose cap is 5. It holds 8.
    const moved = await over.post('/v2/admin/keys/set-product-plan', {
      headers: { 'X-Admin-Token': 'admin-token-for-the-axis-section', 'X-Internal-Auth': 'internal-token-for-the-axis-section' },
      body: { key: KEY, product: 'parasend', tier: 'community' },
    });
    assert.strictEqual(moved.status, 200, moved.text);

    // Every device it already holds still answers on its own merits. The live
    // entry answers 409 (first registration wins, the guard further down the
    // route); what matters is that it is the device answer and not the quota
    // answer. An entry whose TTL has passed but which the hourly sweep has not
    // reached yet takes the same skip and is renewed with a 200.
    for (let n = 1; n <= 8; n++) {
      const again = await reg(n);
      assert.notStrictEqual(again.status, 429,
        `re-registering held device ${n} must not be refused for the cap the account is already over`);
      assert.strictEqual(again.status, 409, `held device ${n} answers on device identity, not on quota`);
    }

    // A device it does NOT hold is a new one, and the cap applies to it.
    const ninth = await reg(9);
    assert.strictEqual(ninth.status, 429, 'a ninth device is an addition, and an account 3 over its cap gets none');
    assert.strictEqual(ninth.json.limit, 5);
    assert.strictEqual(ninth.json.plan, 'community');
    over.stop();
    did();
  });

  test('the admin route\'s record shape and the webhook\'s answer identically', async () => {
    // update-plan sets `plan` and derives the per-product plans; the webhook sets
    // plan_parasend alone. Both mean ParaSend Pro, so no ceiling may disagree.
    const a = await axisSrv();
    const week = 7 * 86_400_000;
    const hook = await axisUpload(a, WEBHOOK, blob('shape-hook-ttl'), { ttl_ms: week });
    const admin = await axisUpload(a, ADMIN_SHAPE, blob('shape-admin-ttl'), { ttl_ms: week });
    assert.strictEqual(hook.json.ttl_ms, admin.json.ttl_ms, 'the two shapes must buy the same link lifetime');
    assert.strictEqual(hook.json.ttl_ms, 86_400_000);

    const hv = blob('shape-hook-views');
    const av = blob('shape-admin-views');
    assert.strictEqual((await axisUpload(a, WEBHOOK, hv, { max_views: 10 })).status, 200);
    assert.strictEqual((await axisUpload(a, ADMIN_SHAPE, av, { max_views: 10 })).status, 200);
    const h1 = await axisDownload(a, WEBHOOK, hv.hash);
    const a1 = await axisDownload(a, ADMIN_SHAPE, av.hash);
    assert.strictEqual(h1.headers['x-paramant-burned'], a1.headers['x-paramant-burned'],
      'the two shapes must buy the same read count');
    assert.strictEqual(h1.headers['x-paramant-burned'], 'false',
      'ten reads on both, so neither burns on the first');
    did();
  });

  test('with redis counting, the monthly transfer quota is the one the ParaSend tier bought', async () => {
    // transfers_month is the one ceiling that was already on the product axis, so
    // this pins the axis end to end: the same record shape, the same tier, four
    // ceilings, one source. The gate fails open without redis (lib/quota.js), so
    // this is the one test in the section that needs a real counter.
    const rc = await requireRedis(DEFAULT_REDIS);
    if (!rc) return;
    try {
      // Fresh account ids per run: the counter is a calendar-month key in redis
      // and a rerun would otherwise start where the previous one stopped.
      const tag = crypto.randomBytes(6).toString('hex');
      const HOOK = 'pgp_quota_hook_shape';
      const COM = 'pgp_quota_community';
      const srv2 = await boot({
        tag: 'transfer-quota-axis',
        env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS },
        users: { api_keys: [
          { key: HOOK, plan: 'community', plan_parasend: 'pro', active: true, email: 'qh@example.test', account_id: `acct_q_hook_${tag}` },
          { key: COM, plan: 'community', active: true, email: 'qc@example.test', account_id: `acct_q_com_${tag}` },
        ] },
      });
      const send = (key) => {
        const b = blob('quota');
        return srv2.post('/v2/inbound', { headers: { 'X-Api-Key': key }, body: { hash: b.hash, payload: b.payload.toString('base64') } });
      };
      // The community cap, read from the table that enforces it rather than
      // typed. It moved from 10 to 50 and a literal here would have gone on
      // asserting that the eleventh transfer is refused, which is a claim about
      // a number this tier no longer has.
      const tiers = require('../lib/tiers');
      const cap = tiers.tierLimit('community', 'transfers_month');
      for (let i = 1; i <= cap; i++) assert.strictEqual((await send(COM)).status, 200, `community transfer ${i}`);
      const over = await send(COM);
      assert.strictEqual(over.status, 402, `community transfer ${cap + 1} is over the monthly cap`);
      assert.strictEqual(over.json.limit, cap);
      assert.strictEqual(over.json.plan, 'community', 'the 402 names the tier that decided, not the unified plan');

      // The webhook-shaped record has the same unified plan and must not stop at
      // the community cap: one past it is the whole point.
      for (let i = 1; i <= cap + 1; i++) {
        assert.strictEqual((await send(HOOK)).status, 200,
          `transfer ${i} on a webhook-written ParaSend Pro tier (its own ceiling, not the community ${cap})`);
      }
      srv2.stop();
      did();
    } finally {
      try { await rc.quit(); } catch (_) { /* already gone */ }
    }
  });

})();
