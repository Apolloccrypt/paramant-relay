'use strict';
// ParaSend session tokens over HTTP, on a really booted relay with a real redis.
//
// WHY THIS SUITE EXISTS. The security review of #397 said the account key must
// stop reaching the browser at all, and this is the credential that replaces
// it. Everything that makes it safer than the key is a property of a REQUEST:
// which routes it opens, which account it counts against, what happens when the
// key behind it is revoked, and what the relay says when the store is gone.
// None of that can be read off the source, so none of it is asserted from the
// source here.
//
// The pure decisions (the allowlist, the token shape, the store contract) are
// session-token.test.js, which needs nothing and runs in the unit job. This one
// needs redis and the installed deps, so it rides in the route job.
//
// What is pinned, and why:
//   * minting needs BOTH X-Internal-Auth and a live X-Api-Key, and a relay with
//     no INTERNAL_AUTH_TOKEN mints nothing at all (fail closed);
//   * a token authenticates AS the owner key on the five ParaSend routes;
//   * and on nothing else: /v2/keys, /v2/user/*, /v2/outbound, /v2/audit,
//     /v2/admin/* and a second mint are all 403, above every route handler;
//   * QUOTA AND AUDIT SEE THE OWNER. An upload made with a token increments the
//     owner's monthly counter and lands in the owner's audit chain, and the
//     owner's 402 over quota is the token's 402 too. If this were wrong the
//     token would be a free account hiding inside a paid one;
//   * expiry is honoured, in both directions: the store's TTL and the wall
//     clock inside the record;
//   * revoking the key kills every live token, and does so twice over: swept
//     from the store, and refused on lookup even when the sweep is undone;
//   * an X-Api-Key on the request always wins, so a token can never widen or
//     narrow a request that carries a real key;
//   * redis unreachable is 503 with Retry-After, never 401.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-session-token.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const sessionTokens = require('../lib/session-token');
const quota = require('../lib/quota');

const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const INTERNAL = 'internal-token-for-the-session-token-suite';
const ADMIN = 'admin-token-for-the-session-token-suite';
// Fresh per run: this suite shares one redis with every other route suite, and
// the quota counters below are keyed on the account id.
const SUFFIX = crypto.randomBytes(6).toString('hex');
const OWNER = `pgp_owner_key_for_the_session_token_suite_${SUFFIX}`;
const OWNER_ACCT = `acct_sesstok_${SUFFIX}`;
const DEAD = `pgp_dead_key_for_the_session_token_suite_${SUFFIX}`;
const REVOKE_ME = `pgp_revoke_key_for_the_session_token_suite_${SUFFIX}`;
const REVOKE_ACCT = `acct_sesstok_rev_${SUFFIX}`;

let rc = null;      // this suite's own redis handle, for planting and reading
let srv;            // relay with INTERNAL_AUTH_TOKEN + ADMIN_TOKEN + redis
let noInternal;     // relay with neither, to prove the mint fails closed
let checks = 0;
const did = () => { checks++; };

const users = () => ({
  api_keys: [
    { key: OWNER, plan: 'community', active: true, email: 'owner@example.test', account_id: OWNER_ACCT },
    { key: DEAD, plan: 'pro', active: false, email: 'dead@example.test', account_id: `acct_dead_${SUFFIX}` },
    { key: REVOKE_ME, plan: 'community', active: true, email: 'rev@example.test', account_id: REVOKE_ACCT },
  ],
});

before(async () => {
  rc = await requireRedis(DEFAULT_REDIS);
  const env = {
    INTERNAL_AUTH_TOKEN: INTERNAL,
    ADMIN_TOKEN: ADMIN,
    REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS,
  };
  srv = await boot({ tag: 'sesstok', users: users(), env, usersFile: true });
  noInternal = await boot({ tag: 'sesstok-noint', users: users(), env: { REDIS_URL: env.REDIS_URL } });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* already gone */ } }
  summary('route-session-token', checks);
});

// Mint the way the admin does: the internal header plus the session's own key.
async function mint(key = OWNER, server = srv) {
  const r = await server.post('/v2/session-token', {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Api-Key': key },
  });
  return r;
}
const bearer = (token) => ({ Authorization: `Bearer ${token}` });

// A fresh blob every time: the store is keyed on the sha256 and rejects a
// repeat with 409.
function blob(label) {
  const payload = Buffer.from(`${label}-${crypto.randomBytes(8).toString('hex')}`);
  return { payload, hash: crypto.createHash('sha256').update(payload).digest('hex') };
}
const upload = (headers, b) => srv.post('/v2/inbound', {
  headers, body: { hash: b.hash, payload: b.payload.toString('base64') },
});

// ── 1. Minting ───────────────────────────────────────────────────────────────

test('the admin mints a token with the internal header and the account key', async (t) => {
  if (!rc) return t.skip('no redis');
  const r = await mint();
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.ok, true);
  assert.match(r.json.token, /^pst_[0-9a-f]{64}$/);
  assert.strictEqual(r.json.expires_in_s, 900, 'fifteen minutes, the number SECURITY.md states');
  assert.ok(r.json.expires_ms > Date.now(), 'the expiry is in the future');
  assert.ok(!r.text.includes(OWNER), 'THE WHOLE POINT: the mint response must never carry the api-key');
  did();
});

test('the mint needs the internal header, and needs it to be right', async (t) => {
  if (!rc) return t.skip('no redis');
  for (const headers of [
    { 'X-Api-Key': OWNER },
    { 'X-Api-Key': OWNER, 'X-Internal-Auth': '' },
    { 'X-Api-Key': OWNER, 'X-Internal-Auth': INTERNAL + 'x' },
    // The admin token is a different credential and must not stand in for it.
    { 'X-Api-Key': OWNER, 'X-Internal-Auth': ADMIN },
  ]) {
    const r = await srv.post('/v2/session-token', { headers });
    assert.strictEqual(r.status, 401, `${JSON.stringify(headers)} minted a token`);
    assert.deepStrictEqual(r.json, { error: 'unauthorized' });
  }
  did();
});

test('the mint needs a LIVE account key, and says nothing about which failed', async (t) => {
  if (!rc) return t.skip('no redis');
  const none = await srv.post('/v2/session-token', { headers: { 'X-Internal-Auth': INTERNAL } });
  const unknown = await mint('pgp_no_such_key_anywhere');
  const revoked = await mint(DEAD);
  for (const [name, r] of [['no key', none], ['unknown key', unknown], ['revoked key', revoked]]) {
    assert.strictEqual(r.status, 401, `${name} minted a token`);
  }
  assert.deepStrictEqual(revoked.json, unknown.json,
    'a de-activated key must answer exactly like an unknown one, or the mint is a key-existence oracle');
  did();
});

test('a relay with no INTERNAL_AUTH_TOKEN mints nothing: unconfigured is closed, not open', async (t) => {
  if (!rc) return t.skip('no redis');
  for (const headers of [{ 'X-Api-Key': OWNER }, { 'X-Api-Key': OWNER, 'X-Internal-Auth': 'anything' }]) {
    const r = await noInternal.post('/v2/session-token', { headers });
    assert.strictEqual(r.status, 401, `unconfigured relay answered ${r.status}`);
  }
  did();
});

// ── 2. The token is the owner, on the routes it opens ────────────────────────

test('a token authenticates as the owner on all five ParaSend routes', async (t) => {
  if (!rc) return t.skip('no redis');
  const { token } = (await mint()).json;
  const h = bearer(token);

  // Sector discovery. This is the one that used to read the raw X-Api-Key
  // header rather than the resolved principal: with a token it would have
  // reported valid:false and the page would have refused its own credential.
  const ck = await srv.get('/v2/check-key', { headers: h });
  assert.strictEqual(ck.status, 200);
  assert.deepStrictEqual(ck.json, { valid: true, plan: 'community' },
    'a token must report the owner as valid, with the owner plan');

  const ticket = await srv.post('/v2/ws-ticket', { headers: h });
  assert.strictEqual(ticket.status, 200, ticket.text);
  assert.match(ticket.json.ticket, /^wst_/);

  const device = `inv_${crypto.randomBytes(16).toString('hex')}`;
  const pub = await srv.post('/v2/pubkey', {
    headers: h, body: { device_id: device, ecdh_pub: 'aa'.repeat(32), kyber_pub: 'bb'.repeat(32) },
  });
  assert.strictEqual(pub.status, 200, pub.text);

  const read = await srv.get(`/v2/pubkey/${device}`, { headers: h });
  assert.strictEqual(read.status, 200, read.text);
  assert.strictEqual(read.json.ecdh_pub, 'aa'.repeat(32));

  const up = await upload(h, blob('token-upload'));
  assert.strictEqual(up.status, 200, up.text);
  assert.strictEqual(up.json.ok, true);
  assert.ok(up.json.download_token, 'the upload really stored a blob');
  did();
});

// ── 3. And on nothing else ───────────────────────────────────────────────────

test('THE SCOPE: every route outside the transfer path is 403, above the handler', async (t) => {
  if (!rc) return t.skip('no redis');
  const { token } = (await mint()).json;
  const h = bearer(token);
  const shut = [
    // Credentials.
    ['GET', '/v2/keys', undefined],
    // The account's own session surface.
    ['GET', '/v2/user/signing-key', undefined],
    ['POST', '/v2/user/signing-key', { user_id: OWNER, public_key: 'AA==' }],
    ['POST', '/v2/user/envelopes', { user_id: OWNER }],
    ['GET', '/v2/user/history', undefined],
    ['POST', '/v2/user/setup-totp', { user_id: OWNER }],
    // The receiver's half, and the account's history.
    ['GET', `/v2/outbound/${'a'.repeat(64)}`, undefined],
    ['GET', '/v2/audit', undefined],
    // Admin.
    ['GET', '/v2/admin/keys', undefined],
    ['POST', '/v2/admin/keys/revoke', { key: OWNER }],
    // ParaSign, a different product on the same account.
    ['POST', '/v2/envelopes', { doc_hash: 'a'.repeat(64), parties: [{ label: 'Demo' }] }],
  ];
  for (const [method, path, body] of shut) {
    const r = await srv.req(method, path, { headers: h, body });
    assert.strictEqual(r.status, 403, `${method} ${path} answered ${r.status}, not 403: ${r.text}`);
    assert.strictEqual(r.json.error, 'session_token_out_of_scope');
  }
  did();
});

test('a token cannot mint another token, even holding the internal header', async (t) => {
  if (!rc) return t.skip('no redis');
  // The fifteen minutes are a ceiling on what a script that got onto the page
  // can do. A token that could roll them forward would have no ceiling at all.
  const { token } = (await mint()).json;
  const r = await srv.post('/v2/session-token', {
    headers: { ...bearer(token), 'X-Internal-Auth': INTERNAL },
  });
  assert.strictEqual(r.status, 403, r.text);
  assert.strictEqual(r.json.error, 'session_token_out_of_scope');
  did();
});

test('the refusal is a scope refusal, not a 404: the routes exist and stay reachable with the key', async (t) => {
  if (!rc) return t.skip('no redis');
  // A 403 that was really "no such route" would make the scope test vacuous.
  // The same paths, with the owner's real api-key, must not be 403.
  const withKey = await srv.get('/v2/audit', { headers: { 'X-Api-Key': OWNER } });
  assert.strictEqual(withKey.status, 200, `the audit route must work with the key: ${withKey.text}`);
  const admin = await srv.get('/v2/admin/keys', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(admin.status, 200);
  did();
});

// ── 4. Quota and audit see the owner ─────────────────────────────────────────

test('QUOTA: an upload made with a token counts on the owner account', async (t) => {
  if (!rc) return t.skip('no redis');
  const counter = quota.transfersKey(OWNER_ACCT);
  const before = parseInt((await rc.get(counter)) || '0', 10);

  const { token } = (await mint()).json;
  const up = await upload(bearer(token), blob('quota-owner'));
  assert.strictEqual(up.status, 200, up.text);

  const after = parseInt((await rc.get(counter)) || '0', 10);
  assert.strictEqual(after, before + 1,
    `the transfer must be counted on ${OWNER_ACCT}; a token that counted somewhere else would be a free account hiding inside a paid one`);
  did();
});

test('QUOTA: the owner over its monthly cap is the token over its cap too', async (t) => {
  if (!rc) return t.skip('no redis');
  // community transfers_month is 10 (relay/lib/tiers.js). Planted directly, so
  // the suite does not have to spend ten uploads to reach it.
  const counter = quota.transfersKey(OWNER_ACCT);
  const saved = await rc.get(counter);
  await rc.set(counter, '10', { EX: 300 });
  try {
    const { token } = (await mint()).json;
    const r = await upload(bearer(token), blob('quota-over'));
    assert.strictEqual(r.status, 402, `over the cap the token must be declined like the key: ${r.text}`);
    assert.strictEqual(r.json.error, 'monthly_transfer_quota_reached');
    assert.strictEqual(r.json.dimension, 'transfers_month');
    assert.strictEqual(r.json.limit, 10);
  } finally {
    if (saved === null) await rc.del(counter); else await rc.set(counter, saved, { EX: 300 });
  }
  did();
});

test('AUDIT: the upload lands in the owner chain, under the owner key', async (t) => {
  if (!rc) return t.skip('no redis');
  const { token } = (await mint()).json;
  const b = blob('audit-owner');
  assert.strictEqual((await upload(bearer(token), b)).status, 200);

  // Read the chain the way the owner does: with the key. If the token had
  // opened a chain of its own, this would not find the entry.
  const audit = await srv.get('/v2/audit?limit=50', { headers: { 'X-Api-Key': OWNER } });
  assert.strictEqual(audit.status, 200, audit.text);
  const found = (audit.json.entries || []).some(e =>
    e.event === 'inbound' && String(e.hash || '').startsWith(b.hash.slice(0, 16)));
  assert.ok(found, `the token upload is missing from the owner audit chain: ${audit.text.slice(0, 400)}`);
  did();
});

// ── 5. Expiry ────────────────────────────────────────────────────────────────

test('the store expires the token, and the relay refuses it the moment it is gone', async (t) => {
  if (!rc) return t.skip('no redis');
  const { token } = (await mint()).json;
  assert.strictEqual((await srv.get('/v2/check-key', { headers: bearer(token) })).json.valid, true);

  // The TTL redis is really holding, rather than the one the response claimed.
  const ttl = await rc.ttl(sessionTokens.tokenKey(token));
  assert.ok(ttl > 800 && ttl <= 900, `the token record must carry the 900 s TTL; redis reports ${ttl}`);

  await rc.del(sessionTokens.tokenKey(token));
  const gone = await srv.get('/v2/check-key', { headers: bearer(token) });
  assert.strictEqual(gone.status, 200, 'check-key is public, so an expired token is simply not a principal');
  assert.strictEqual(gone.json.valid, false, 'an expired token must not authenticate anybody');
  // And on a gated route it is the ordinary 401, the same one an unknown key
  // gets: nothing here says "this token expired" to whoever is holding it.
  const up = await upload(bearer(token), blob('expired'));
  assert.strictEqual(up.status, 401);
  assert.deepStrictEqual(up.json, { error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' });
  did();
});

test('a record that outlived its own TTL is refused on the wall clock inside it', async (t) => {
  if (!rc) return t.skip('no redis');
  // Redis is what expires a token; this is the second lock, for a record that
  // came back from a backup or from a replica that lagged through the expiry.
  const token = `pst_${crypto.randomBytes(32).toString('hex')}`;
  await rc.set(sessionTokens.tokenKey(token),
    JSON.stringify({ key: OWNER, exp: Date.now() - 1000 }), { EX: 300 });
  const r = await upload(bearer(token), blob('stale-record'));
  assert.strictEqual(r.status, 401, 'a record past its own exp must not authenticate, TTL or no TTL');
  await rc.del(sessionTokens.tokenKey(token));
  did();
});

// ── 6. Revocation, twice over ────────────────────────────────────────────────

test('revoking the key sweeps its live tokens out of the shared store', async (t) => {
  if (!rc) return t.skip('no redis');
  const a = (await mint(REVOKE_ME)).json.token;
  const b = (await mint(REVOKE_ME)).json.token;
  assert.strictEqual((await srv.get('/v2/check-key', { headers: bearer(a) })).json.valid, true);

  const rev = await srv.post('/v2/admin/keys/revoke', {
    headers: { 'X-Admin-Token': ADMIN }, body: { key: REVOKE_ME },
  });
  assert.strictEqual(rev.status, 200, rev.text);

  // The sweep is fire-and-forget, so give it a moment to land in redis.
  for (let i = 0; i < 40 && await rc.exists(sessionTokens.tokenKey(a)); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.strictEqual(await rc.exists(sessionTokens.tokenKey(a)), 0, 'the first token is gone from the store');
  assert.strictEqual(await rc.exists(sessionTokens.tokenKey(b)), 0, 'and so is the second');
  assert.strictEqual((await srv.get('/v2/check-key', { headers: bearer(a) })).json.valid, false);
  did();
});

test('and a token whose owner is revoked is refused even when the sweep never ran', async (t) => {
  if (!rc) return t.skip('no redis');
  // The belt to the sweep's braces. A sector that was restarting, or a redis
  // that was briefly unreachable, can miss the sweep. So the record is put back
  // by hand here, exactly as the sweep failing would leave it, and the relay
  // must still refuse: a resolved token is looked up in apiKeys like any other
  // credential, and a revoked key is not there.
  const token = `pst_${crypto.randomBytes(32).toString('hex')}`;
  await rc.set(sessionTokens.tokenKey(token),
    JSON.stringify({ key: REVOKE_ME, exp: Date.now() + 600_000 }), { EX: 600 });
  const r = await upload(bearer(token), blob('revoked-owner'));
  assert.strictEqual(r.status, 401, 'a live record for a revoked key must not authenticate');
  assert.strictEqual((await srv.get('/v2/check-key', { headers: bearer(token) })).json.valid, false);
  await rc.del(sessionTokens.tokenKey(token));
  did();
});

// ── 7. A token never overrides a key ─────────────────────────────────────────

test('an X-Api-Key on the request always wins: a token cannot widen or narrow it', async (t) => {
  if (!rc) return t.skip('no redis');
  const { token } = (await mint()).json;

  // A request that carries a bad key is that key's request, and stays a 401.
  // Reading the Bearer here would let a page smuggle a working credential past
  // a caller that thought it was sending its own.
  const wrong = await srv.post('/v2/inbound', {
    headers: { ...bearer(token), 'X-Api-Key': 'pgp_wrong_key' },
    body: { hash: 'a'.repeat(64), payload: 'AA==' },
  });
  assert.strictEqual(wrong.status, 401, 'the api-key decides; the token must not rescue it');

  // And with the real key present, the token does not narrow the request
  // either: a route outside the token scope stays open to the key.
  const audit = await srv.get('/v2/audit', { headers: { ...bearer(token), 'X-Api-Key': OWNER } });
  assert.strictEqual(audit.status, 200, `the scope gate must not fire on a key-authenticated request: ${audit.text}`);
  did();
});

test('a malformed or foreign Bearer is simply not a credential', async (t) => {
  if (!rc) return t.skip('no redis');
  for (const value of [
    'Bearer pst_short',
    `Bearer pst_${'z'.repeat(64)}`,
    `Bearer ${OWNER}`,                       // the api-key, offered as a Bearer
    `Basic pst_${'a'.repeat(64)}`,
    'Bearer',
  ]) {
    const r = await upload({ Authorization: value }, blob('bad-bearer'));
    assert.strictEqual(r.status, 401, `${value} was accepted as a credential`);
  }
  did();
});

// ── 8. No store ──────────────────────────────────────────────────────────────

test('FAIL CLOSED: a relay with no store answers 503 to a token, never 401', async (t) => {
  if (!rc) return t.skip('no redis');
  // A 401 during an outage tells a sender holding a perfectly good token that
  // it is bad, and sends them to sign in again over a store that cannot answer
  // that either. 503 with Retry-After is the honest answer, and it is the one
  // the page's refresh path is written against.
  const noRedis = await boot({ tag: 'sesstok-nostore', users: users(), env: { INTERNAL_AUTH_TOKEN: INTERNAL } });
  t.after(() => noRedis.stop());

  const token = `pst_${crypto.randomBytes(32).toString('hex')}`;
  const used = await noRedis.get('/v2/check-key', { headers: bearer(token) });
  assert.strictEqual(used.status, 503, used.text);
  assert.strictEqual(used.json.error, 'redis_unavailable');
  assert.strictEqual(used.headers['retry-after'], '5');

  // And no token is handed out that no relay could ever check.
  const minted = await noRedis.post('/v2/session-token', {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Api-Key': OWNER },
  });
  assert.strictEqual(minted.status, 503, minted.text);
  assert.strictEqual(minted.json.error, 'redis_unavailable');
  did();
});
