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
async function mint(key = OWNER, server = srv, purpose = undefined) {
  const r = await server.post('/v2/session-token', {
    headers: { 'X-Internal-Auth': INTERNAL, 'X-Api-Key': key },
    ...(purpose === undefined ? {} : { body: { purpose } }),
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

// ── 3b. The other purpose, over HTTP ─────────────────────────────────────────
// /pricing and /dashboard run on a token minted with purpose `app`. What matters
// on the wire is that the two purposes are not interchangeable: each opens its
// own three-or-five routes and is 403 on the other's. A single flat allowlist
// would pass the "app routes work" half of this and fail the wall below, which
// is why both halves are here.

test('an app-purpose token opens the three app routes and nothing from the transfer path', async (t) => {
  if (!rc) return t.skip('no redis');
  const minted = await mint(OWNER, srv, 'app');
  assert.strictEqual(minted.status, 200, minted.text);
  assert.strictEqual(minted.json.purpose, 'app', 'the relay must say what it minted');
  const h = bearer(minted.json.token);

  // In scope. The statuses are the routes' own answers (a community account is
  // not entitled to history or the export, and checkout needs a real body), and
  // any of them is proof the scope gate let the request through: the gate
  // answers 403 with error session_token_out_of_scope and nothing else does.
  for (const [method, path, body] of [
    ['GET', '/v2/user/history', undefined],
    ['GET', '/v2/parasign/audit-export', undefined],
    ['POST', '/v2/billing/checkout', { product: 'parasend', plan: 'pro', interval: 'month' }],
  ]) {
    const r = await srv.req(method, path, { headers: h, body });
    assert.notStrictEqual(r.json && r.json.error, 'session_token_out_of_scope',
      `${method} ${path} was refused by scope, and it is what an app token is for: ${r.text}`);
  }

  // Out of scope: the whole ParaSend transfer path, which this token was never
  // minted to walk.
  for (const [method, path, body] of [
    ['POST', '/v2/ws-ticket', undefined],
    ['POST', '/v2/pubkey', { device_id: 'inv_' + 'a'.repeat(32), ecdh_pub: 'aa'.repeat(32), kyber_pub: 'bb'.repeat(32) }],
    ['POST', '/v2/inbound', undefined],
  ]) {
    const r = await srv.req(method, path, { headers: h, body });
    assert.strictEqual(r.status, 403, `${method} ${path} answered ${r.status}, not 403: ${r.text}`);
    assert.strictEqual(r.json.error, 'session_token_out_of_scope');
  }
  did();
});

test('a ParaSend token is 403 on every app route: the two lists are disjoint', async (t) => {
  if (!rc) return t.skip('no redis');
  const { token } = (await mint()).json;
  const h = bearer(token);
  for (const [method, path, body] of [
    ['GET', '/v2/user/history', undefined],
    ['GET', '/v2/parasign/audit-export', undefined],
    ['POST', '/v2/billing/checkout', { product: 'parasend', plan: 'pro', interval: 'month' }],
  ]) {
    const r = await srv.req(method, path, { headers: h, body });
    assert.strictEqual(r.status, 403, `${method} ${path} answered ${r.status}, not 403: ${r.text}`);
    assert.strictEqual(r.json.error, 'session_token_out_of_scope');
  }
  did();
});

test('an unknown purpose is refused at the mint, so no unusable token is ever handed out', async (t) => {
  if (!rc) return t.skip('no redis');
  const r = await mint(OWNER, srv, 'admin');
  assert.strictEqual(r.status, 400, r.text);
  assert.strictEqual(r.json.error, 'unknown_purpose');
  // And the default is still the ParaSend one, so the admin route that predates
  // purposes keeps working without sending a purpose at all.
  const plain = await mint();
  assert.strictEqual(plain.status, 200, plain.text);
  assert.strictEqual(plain.json.purpose, 'parasend');
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
  const entry = (audit.json.entries || []).find(e =>
    e.event === 'inbound' && String(e.hash || '').startsWith(b.hash.slice(0, 16)));
  assert.ok(entry, `the token upload is missing from the owner audit chain: ${audit.text.slice(0, 400)}`);

  // And it is marked. `via` names the credential, not a second identity: the
  // chain is still the owner's, keyed on the owner's api-key. Without the field
  // an owner reading their own log cannot tell a transfer made from a browser
  // session apart from one made with the key itself.
  assert.strictEqual(entry.via, 'pst',
    'an upload made with a session token must be marked in the audit chain');

  // The other half, and the one that makes the first mean something: the same
  // upload with the key carries no such field.
  const k = blob('audit-with-key');
  assert.strictEqual((await upload({ 'X-Api-Key': OWNER }, k)).status, 200);
  const after = await srv.get('/v2/audit?limit=50', { headers: { 'X-Api-Key': OWNER } });
  const plain = (after.json.entries || []).find(e =>
    e.event === 'inbound' && String(e.hash || '').startsWith(k.hash.slice(0, 16)));
  assert.ok(plain, 'the key upload must be in the chain too');
  assert.strictEqual(plain.via, undefined,
    'a transfer made with the api-key must carry no via field, or the marker says nothing');
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
    JSON.stringify({ kh: sessionTokens.keyHash(OWNER), exp: Date.now() - 1000 }), { EX: 300 });
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
    JSON.stringify({ kh: sessionTokens.keyHash(REVOKE_ME), exp: Date.now() + 600_000 }), { EX: 600 });
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

// ── 8. What the store actually holds ─────────────────────────────────────────

test('THE STORE HOLDS NO KEY: a leak of redis is a leak of hashes', async (t) => {
  if (!rc) return t.skip('no redis');
  // The threat is read-only and unexciting: an RDB snapshot, a replica, a
  // backup on a laptop, a MONITOR session. Before the record was hashed, every
  // one of those carried live pgp_ credentials for every account that had sent
  // a file in the last fifteen minutes. This reads the real store the same way
  // any of those would.
  const { token } = (await mint()).json;
  const raw = await rc.get(sessionTokens.tokenKey(token));
  assert.ok(raw, 'the record must be there to be inspected');
  assert.ok(!raw.includes(OWNER), 'the record body carries the api-key in the clear');
  assert.ok(!/pgp_/.test(raw), 'nothing shaped like an api-key may be in the record');
  const rec = JSON.parse(raw);
  assert.strictEqual(rec.kh, sessionTokens.keyHash(OWNER), 'the owner is named by sha256 of the key');
  assert.strictEqual(rec.key, undefined, 'and by nothing else');

  // Key names as well as values, because SCAN, the keyspace listing and the
  // slowlog all show names. Scanned over the whole prefix, so the sweep index
  // is included.
  const names = [];
  for await (const k of rc.scanIterator({ MATCH: 'paramant:pst:*', COUNT: 500 })) {
    names.push(...(Array.isArray(k) ? k : [k]));
  }
  assert.ok(names.length > 0, 'the scan must find something, or this asserts nothing');
  assert.ok(!names.some((n) => /pgp_/.test(String(n))), 'a redis key NAME carries an api-key');

  // And resolution still works, which is the half that makes the hash useful
  // rather than merely safe: the relay looks the hash up in the api-key table
  // it already has in memory.
  const ck = await srv.get('/v2/check-key', { headers: bearer(token) });
  assert.deepStrictEqual(ck.json, { valid: true, plan: 'community' },
    'hashing the record must not cost the relay the ability to resolve it');
  did();
});

test('a hash that resolves to no key in the table is refused, whatever the store says', async (t) => {
  if (!rc) return t.skip('no redis');
  // Written by hand, well-formed, unexpired, and pointing at a key this relay
  // has never heard of. The resolver is a lookup in the live api-key table, so
  // key deletion and revocation arrive here for free.
  const token = `pst_${crypto.randomBytes(32).toString('hex')}`;
  await rc.set(sessionTokens.tokenKey(token),
    JSON.stringify({ kh: sessionTokens.keyHash('pgp_this_key_never_existed'), exp: Date.now() + 600_000 }),
    { EX: 300 });
  const r = await upload(bearer(token), blob('unknown-owner'));
  assert.strictEqual(r.status, 401);
  await rc.del(sessionTokens.tokenKey(token));
  did();
});

test('EXP IS REQUIRED over HTTP too: a record without one authenticates nobody', async (t) => {
  if (!rc) return t.skip('no redis');
  const kh = sessionTokens.keyHash(OWNER);
  for (const rec of [{ kh }, { kh, exp: null }, { kh, exp: 'soon' }, { kh, exp: '9999999999999' }]) {
    const token = `pst_${crypto.randomBytes(32).toString('hex')}`;
    // A 300 s redis TTL on purpose: the store says this record is live, and the
    // missing expiry is the only reason it must not be.
    await rc.set(sessionTokens.tokenKey(token), JSON.stringify(rec), { EX: 300 });
    const r = await upload(bearer(token), blob('no-exp'));
    assert.strictEqual(r.status, 401, `${JSON.stringify(rec)} authenticated somebody`);
    await rc.del(sessionTokens.tokenKey(token));
  }
  did();
});

test('a key created AFTER boot still resolves: the hash index heals itself', async (t) => {
  if (!rc) return t.skip('no redis');
  // The index is rebuilt on load and on /v2/reload-users, which is where the
  // api-key table normally changes. It is not the only way it changes: keys are
  // also created at run time through /v2/admin/keys, the team route and the
  // claim flow, none of which go near either. A token minted for such a key
  // would carry a hash the index had never seen, and without the self-healing
  // rebuild it would resolve to nothing, which is a credential that mints fine
  // and then does not work.
  const created = await srv.post('/v2/admin/keys', {
    headers: { 'X-Admin-Token': ADMIN },
    body: { plan: 'community', label: 'fresh', email: `fresh-${SUFFIX}@example.com` },
  });
  assert.strictEqual(created.status, 200, created.text);
  const fresh = created.json.key;
  assert.match(fresh, /^pgp_/);

  const minted = await mint(fresh);
  assert.strictEqual(minted.status, 200, minted.text);
  const ck = await srv.get('/v2/check-key', { headers: bearer(minted.json.token) });
  assert.strictEqual(ck.json.valid, true,
    'a token for a key created after boot must resolve; the hash index has to rebuild on a miss');

  const up = await upload(bearer(minted.json.token), blob('fresh-key'));
  assert.strictEqual(up.status, 200, up.text);
  did();
});

test('a users reload does not break the tokens already in flight', async (t) => {
  if (!rc) return t.skip('no redis');
  // /v2/reload-users clears and refills the whole api-key table, and the hash
  // index is rebuilt with it. A reload that left the index behind would strand
  // every live token on the relay at once, which is the kind of outage a deploy
  // would cause and nobody would connect to the reload.
  //
  // Said honestly: the self-healing rebuild above would carry this case too, so
  // deleting the explicit rebuild in the reload handler does NOT turn this red.
  // What this pins is the PROPERTY -- a reload does not strand live tokens --
  // and that property has two mechanisms behind it on purpose. The explicit
  // rebuild is also what keeps a reload costing one rebuild instead of a
  // rebuild per miss for the second after it.
  const { token } = (await mint()).json;
  assert.strictEqual((await srv.get('/v2/check-key', { headers: bearer(token) })).json.valid, true);

  const reload = await srv.post('/v2/reload-users', { headers: { 'X-Api-Key': ADMIN } });
  assert.strictEqual(reload.status, 200, reload.text);
  assert.ok(reload.json.loaded > 0, 'the reload must actually load the table');

  const after = await srv.get('/v2/check-key', { headers: bearer(token) });
  assert.strictEqual(after.json.valid, true, 'a live token must survive a users reload');
  const up = await upload(bearer(token), blob('after-reload'));
  assert.strictEqual(up.status, 200, up.text);
  did();
});

// ── 9. The ceiling ───────────────────────────────────────────────────────────

test('an account is held to twenty live tokens, and the twenty-first is a 429', async (t) => {
  if (!rc) return t.skip('no redis');
  // A separate key, so the cap this test fills does not sit on OWNER for the
  // rest of the suite.
  const CAP_KEY = `pgp_cap_key_for_the_session_token_suite_${SUFFIX}`;
  const capSrv = await boot({
    tag: 'sesstok-cap',
    // OWNER rides along so the per-account claim below is made on the SAME
    // relay and the SAME store as the account that is at its ceiling.
    users: { api_keys: [
      { key: CAP_KEY, plan: 'community', active: true, email: 'cap@example.test', account_id: `acct_cap_${SUFFIX}` },
      { key: OWNER, plan: 'community', active: true, email: 'owner@example.test', account_id: OWNER_ACCT },
    ] },
    env: { INTERNAL_AUTH_TOKEN: INTERNAL, REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS },
  });
  t.after(async () => {
    await capSrv.stop();
    try { await rc.del(sessionTokens.ownerKey(CAP_KEY)); } catch (_) { /* gone */ }
  });

  const first = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await mint(CAP_KEY, capSrv);
    assert.strictEqual(r.status, 200, `mint ${i + 1} answered ${r.status}: ${r.text}`);
    first.push(r.json.token);
  }
  const over = await mint(CAP_KEY, capSrv);
  assert.strictEqual(over.status, 429, over.text);
  assert.strictEqual(over.json.error, 'session_token_cap_reached');
  assert.strictEqual(over.json.cap, 20);
  assert.strictEqual(over.headers['retry-after'], '60', 'a cap that clears on its own says when to come back');
  assert.ok(!over.text.includes(CAP_KEY), 'and the refusal names no key');

  // A cap is not a revocation: everything already minted keeps working.
  const still = await capSrv.get('/v2/check-key', { headers: bearer(first[0]) });
  assert.strictEqual(still.json.valid, true, 'tokens minted under the cap must keep working');

  // Another account is not affected by this one's ceiling.
  const other = await mint(OWNER, capSrv);
  assert.strictEqual(other.status, 200, `the cap must be per account: ${other.text}`);

  // And room made by an expiry is room again. Two of the twenty are removed the
  // way redis would remove them, and the next mint succeeds through the prune.
  await rc.del(sessionTokens.tokenKey(first[0]));
  await rc.del(sessionTokens.tokenKey(first[1]));
  const again = await mint(CAP_KEY, capSrv);
  assert.strictEqual(again.status, 200, `with two expired there is room again: ${again.text}`);
  did();
});

// ── 10. No store ─────────────────────────────────────────────────────────────

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
