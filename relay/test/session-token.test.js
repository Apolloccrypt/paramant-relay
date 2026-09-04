'use strict';
// The decision layer of ParaSend session tokens: relay/lib/session-token.js.
//
// This suite is the one that needs nothing -- no relay, no redis, no native
// binding -- so it runs in the unit job and gates the rules a reviewer would
// otherwise have to read the route for. The HTTP behaviour of the same rules,
// against a real relay and a real redis, is route-session-token.test.js.
//
// What is pinned here, and why each line earns its place:
//   * the scope allowlist, from both ends: the five routes a transfer walks are
//     open, and the routes the review named as the danger (/v2/keys,
//     /v2/user/*, /v2/outbound, /v2/admin/*, minting another token) are shut.
//     The closed half is asserted by name, because an allowlist that is only
//     tested from the open side passes just as well when it is `() => true`;
//   * the token shape, so a malformed Authorization header never reaches the
//     store;
//   * the Bearer parse, including the forms that are NOT a token;
//   * mint/resolve/revoke against a fake store, including the TTL that is
//     written and the expiry that is honoured even when the store forgot it;
//   * a store that is absent or broken THROWS rather than returning null,
//     which is what makes the route answer 503 instead of 401.
//
// Verified by sabotage:
//   * make scopeAllows return true and the six closed-route cases go red;
//   * drop the OPTIONS branch and the preflight case goes red;
//   * loosen TOKEN_RE to /^pst_/ and the shape case goes red;
//   * return null instead of throwing on a missing client and the fail-closed
//     case goes red, which is the exact bug that would turn an outage into a
//     silent 401 storm;
//   * drop the `exp` check in resolve and the "store forgot the TTL" case goes
//     red.
// Run: node --test relay/test/session-token.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const st = require('../lib/session-token');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('session-token', checks));

// A redis stand-in with the four commands this module uses. TTLs are recorded
// rather than slept through, and `fail` turns the whole thing into the outage.
function fakeRedis() {
  const store = new Map();   // key -> string
  const ttls = new Map();    // key -> seconds
  const sets = new Map();    // key -> Set
  const api = {
    fail: null,
    calls: [],
    _guard(op) { api.calls.push(op); if (api.fail) throw api.fail; },
    async get(k) { api._guard(['get', k]); return store.has(k) ? store.get(k) : null; },
    async set(k, v, opts) { api._guard(['set', k]); store.set(k, v); if (opts && opts.EX) ttls.set(k, opts.EX); },
    async sAdd(k, v) { api._guard(['sAdd', k]); if (!sets.has(k)) sets.set(k, new Set()); sets.get(k).add(v); },
    async sMembers(k) { api._guard(['sMembers', k]); return [...(sets.get(k) || [])]; },
    async sCard(k) { api._guard(['sCard', k]); return (sets.get(k) || new Set()).size; },
    async sRem(k, v) {
      api._guard(['sRem', k]);
      const set = sets.get(k); if (!set) return 0;
      let n = 0; for (const one of (Array.isArray(v) ? v : [v])) { if (set.delete(one)) n++; }
      return n;
    },
    async exists(k) { api._guard(['exists', k]); return store.has(k) ? 1 : 0; },
    async expire(k, s) { api._guard(['expire', k]); ttls.set(k, s); },
    async del(k) {
      api._guard(['del', k]);
      const keys = Array.isArray(k) ? k : [k];
      let n = 0;
      for (const one of keys) { if (store.delete(one)) n++; sets.delete(one); ttls.delete(one); }
      return n;
    },
    store, ttls, sets,
  };
  return api;
}

// The resolver relay.js injects: a lookup in the api-key table it already holds.
// Written out here rather than stubbed with `() => key`, because the point of
// hashing the record is that resolution needs a table, and a test that handed
// the key straight back would prove nothing about that.
function ownerTable(...keys) {
  const byHash = new Map(keys.map((k) => [st.keyHash(k), k]));
  return (hash) => byHash.get(hash) || null;
}
const OWNERS = ownerTable('pgp_owner_demo', 'pgp_owner_other');

// ── 1. The scope allowlist, from the open side ───────────────────────────────

test('the five routes a ParaSend transfer walks are the routes the token opens', () => {
  const walk = [
    // Sector discovery races four hosts and reads valid/plan.
    ['GET', '/v2/check-key'],
    // The one-time ticket for the signalling socket.
    ['POST', '/v2/ws-ticket'],
    // The sender publishes its half of the handshake and polls the receiver's.
    ['POST', '/v2/pubkey'],
    ['GET', '/v2/pubkey/inv_0123456789abcdef0123456789abcdef'],
    // And the upload.
    ['POST', '/v2/inbound'],
  ];
  for (const [method, path] of walk) {
    assert.strictEqual(st.scopeAllows(method, path), true,
      `${method} ${path} is on the path a sender walks; a token that cannot do it is not a usable credential`);
  }
  did();
});

test('a preflight is never refused by scope: it carries no credential to judge', () => {
  assert.strictEqual(st.scopeAllows('OPTIONS', '/v2/keys'), true);
  assert.strictEqual(st.scopeAllows('options', '/v2/user/signing-key'), true);
  did();
});

// ── 2. The closed side, which is the whole point ─────────────────────────────

test('THE POINT: everything the security review named is shut, by name', () => {
  const shut = [
    // The credential surface. A token minted to send a file must never be able
    // to list, mint or reveal a key.
    ['GET', '/v2/keys'],
    ['POST', '/v2/keys'],
    // The account's own session surface. Enrolling a signing key with a token
    // stolen from a page would be the whole ParaSign trust model, gone.
    ['POST', '/v2/user/signing-key'],
    ['GET', '/v2/user/signing-key'],
    ['DELETE', '/v2/user/signing-key'],
    ['POST', '/v2/user/setup-totp'],
    ['POST', '/v2/user/envelopes'],
    ['GET', '/v2/user/history'],
    // Downloading is the receiver's half and needs no account credential.
    ['GET', '/v2/outbound/' + 'a'.repeat(64)],
    // The account's history.
    ['GET', '/v2/audit'],
    // Admin, under any credential but ADMIN_TOKEN.
    ['GET', '/v2/admin/keys'],
    ['POST', '/v2/admin/keys/revoke'],
    // A token may not roll its own fifteen minutes forward.
    ['POST', '/v2/session-token'],
    // ParaSign, which is a different product on the same account.
    ['POST', '/v2/envelopes'],
    ['POST', '/v1/envelopes'],
  ];
  for (const [method, path] of shut) {
    assert.strictEqual(st.scopeAllows(method, path), false,
      `${method} ${path} is reachable with a session token; the allowlist is the only thing that makes this credential narrower than an API key`);
  }
  did();
});

test('the method is part of the rule, not decoration', () => {
  // POST /v2/pubkey publishes; GET /v2/pubkey is the RELAY's identity key and
  // is not on the sender's path. The one that is on the path is the per-device
  // read below it.
  assert.strictEqual(st.scopeAllows('GET', '/v2/pubkey'), false,
    'GET /v2/pubkey is the relay identity route, not a step in a transfer');
  assert.strictEqual(st.scopeAllows('DELETE', '/v2/inbound'), false);
  assert.strictEqual(st.scopeAllows('GET', '/v2/inbound'), false);
  assert.strictEqual(st.scopeAllows('GET', '/v2/ws-ticket'), false);
  did();
});

test('the per-device pubkey read is exactly one path segment deep', () => {
  assert.strictEqual(st.scopeAllows('GET', '/v2/pubkey/inv_abc'), true);
  // Not a prefix match: a deeper path is a different route and gets no ride.
  assert.strictEqual(st.scopeAllows('GET', '/v2/pubkey/inv_abc/secret'), false);
  assert.strictEqual(st.scopeAllows('GET', '/v2/pubkey/'), false, 'an empty device id is not a route');
  // POST under the same prefix is /v2/pubkey/verify, and it is not in scope.
  assert.strictEqual(st.scopeAllows('POST', '/v2/pubkey/verify'), false);
  did();
});

// ── 2b. The second purpose, and the wall between the two ─────────────────────
// /pricing and /dashboard stopped fetching the account's pgp_ key and now run
// on a session token of their own. The whole reason that was allowed to happen
// is that it is a DIFFERENT token, not a wider one: the two allowlists are
// disjoint, and neither page can do the other's work with the credential it
// holds. If that ever stops being true, the honest thing is for these cases to
// go red rather than for the send page to quietly gain a checkout.

test('the app purpose opens exactly the five routes the signed-in pages need', () => {
  const open = [
    // /pricing: pressing a price button creates the Mollie payment.
    ['POST', '/v2/billing/checkout'],
    // /pricing and /account, "Have a code?": spending a gift code on the
    // account the relay resolved from the token, never one the body names.
    ['POST', '/v2/billing/redeem'],
    // /dashboard: the account's own history, and its own signing-audit export.
    ['GET', '/v2/user/history'],
    ['GET', '/v2/parasign/audit-export'],
    // The homepage and /dashboard: what is waiting for this account's signature.
    ['GET', '/v2/parasign/inbox'],
  ];
  for (const [method, path] of open) {
    assert.strictEqual(st.scopeAllows(method, path, 'app'), true,
      `${method} ${path} is what an app-purpose token exists for`);
  }
  assert.strictEqual(st.APP_SCOPE.length, 5,
    'the app allowlist grew; /privacy names five requests, so change the page with the code');
  // The resend beside the inbox reads a stored invite token back so it can be
  // mailed. A route that produces a capability must not be reachable from a
  // browser, so it is behind internal auth and in NO token scope.
  assert.strictEqual(st.scopeAllows('POST', '/v2/parasign/inbox/EnvelopeIdPlaceholder00/resend', 'app'), false,
    'the resend hands back an invite token; no session token may reach it');
  did();
});

test('THE WALL: neither purpose can do the other\'s work', () => {
  for (const [method, path] of [['POST', '/v2/inbound'], ['POST', '/v2/ws-ticket'],
    ['POST', '/v2/pubkey'], ['GET', '/v2/check-key']]) {
    assert.strictEqual(st.scopeAllows(method, path, 'app'), false,
      `${method} ${path} is a transfer route; a token minted on /pricing must not walk it`);
  }
  for (const [method, path] of [['POST', '/v2/billing/checkout'], ['POST', '/v2/billing/redeem'],
    ['GET', '/v2/user/history'], ['GET', '/v2/parasign/audit-export']]) {
    assert.strictEqual(st.scopeAllows(method, path, 'parasend'), false,
      `${method} ${path} is an app route; a token minted on /parashare must not reach it. ` +
      'Merging the two lists is how a narrow credential becomes an api-key again.');
  }
  did();
});

test('the app purpose shuts everything the review named, exactly as parasend does', () => {
  const shut = [
    ['GET', '/v2/keys'], ['POST', '/v2/keys'],
    ['POST', '/v2/user/signing-key'], ['GET', '/v2/user/signing-key'],
    ['POST', '/v2/user/setup-totp'], ['POST', '/v2/user/envelopes'],
    ['GET', '/v2/outbound/' + 'a'.repeat(64)],
    ['GET', '/v2/audit'],
    ['GET', '/v2/admin/keys'], ['POST', '/v2/admin/keys/revoke'],
    // No token mints another one, whatever it was minted for.
    ['POST', '/v2/session-token'],
    ['POST', '/v2/envelopes'], ['POST', '/v1/envelopes'],
  ];
  for (const [method, path] of shut) {
    assert.strictEqual(st.scopeAllows(method, path, 'app'), false,
      `${method} ${path} is reachable with an app session token`);
  }
  // /v2/user/history is named ON ITS OWN, never as a prefix: the rest of
  // /v2/user/* stays shut, and a deeper path under history is a different route.
  assert.strictEqual(st.scopeAllows('GET', '/v2/user/history/all', 'app'), false);
  assert.strictEqual(st.scopeAllows('POST', '/v2/user/history', 'app'), false);
  assert.strictEqual(st.scopeAllows('POST', '/v2/parasign/audit-export', 'app'), false);
  // The redeem route is named on its own too. The rest of /v2/billing/* is the
  // Mollie webhook, the admin export and the cancel path, and a browser
  // credential may reach none of them.
  assert.strictEqual(st.scopeAllows('POST', '/v2/billing/webhook', 'app'), false);
  assert.strictEqual(st.scopeAllows('POST', '/v2/billing/cancel', 'app'), false);
  assert.strictEqual(st.scopeAllows('GET', '/v2/admin/coupons', 'app'), false);
  assert.strictEqual(st.scopeAllows('POST', '/v2/admin/coupons', 'app'), false);
  assert.strictEqual(st.scopeAllows('GET', '/v2/billing/redeem', 'app'), false);
  did();
});

test('an absent purpose is parasend; an unknown purpose opens nothing at all', () => {
  // A record written before purposes existed carries no `p` and can only be a
  // ParaSend token, so the default has to be parasend or every live token dies
  // on deploy. An unknown word is the other direction and must fail CLOSED: a
  // build that does not know the purpose cannot know the scope either.
  assert.strictEqual(st.normalisePurpose(undefined), 'parasend');
  assert.strictEqual(st.normalisePurpose(''), 'parasend');
  assert.strictEqual(st.normalisePurpose('parasend'), 'parasend');
  assert.strictEqual(st.normalisePurpose('app'), 'app');
  // null is NOT the absent case. Only `undefined` folds onto parasend, so a
  // purpose that arrived as an explicit null opens nothing rather than the
  // transfer list.
  for (const bogus of [null, 'admin', 'APP', 'app ', 'toString', '__proto__', 0, {}]) {
    assert.strictEqual(st.normalisePurpose(bogus), null, `${JSON.stringify(bogus)} is not a purpose`);
    assert.strictEqual(st.scopeAllows('POST', '/v2/inbound', bogus), false,
      'an unknown purpose must open nothing, not fall back to the transfer list');
    assert.strictEqual(st.scopeAllows('POST', '/v2/billing/checkout', bogus), false);
  }
  did();
});

test('mint records the purpose, resolve hands it back, and an unknown one is never written', async () => {
  const r = fakeRedis();
  const app = await st.mint(r, 'pgp_owner_demo', 5_000, 'app');
  assert.strictEqual(app.purpose, 'app');
  assert.deepStrictEqual(await st.resolve(r, app.token, OWNERS, 6_000),
    { key: 'pgp_owner_demo', expires_ms: app.expires_ms, purpose: 'app' });

  const send = await st.mint(r, 'pgp_owner_demo', 5_000);
  assert.strictEqual(send.purpose, 'parasend', 'the default is the purpose that predates purposes');

  // A record with no `p` at all: the shape redis still holds from the build
  // before this one. It must resolve, and it must resolve as parasend.
  const legacy = 'pst_' + '7'.repeat(64);
  await r.set(st.tokenKey(legacy), JSON.stringify({ kh: st.keyHash('pgp_owner_demo'), exp: 9_000 }));
  assert.deepStrictEqual(await st.resolve(r, legacy, OWNERS, 6_000),
    { key: 'pgp_owner_demo', expires_ms: 9_000, purpose: 'parasend' });

  // A record with a purpose this build does not know is no principal at all. It
  // must NOT come back as a parasend token, which is what a lenient default
  // would have made it.
  const alien = 'pst_' + '8'.repeat(64);
  await r.set(st.tokenKey(alien), JSON.stringify({ kh: st.keyHash('pgp_owner_demo'), exp: 9_000, p: 'admin' }));
  assert.strictEqual(await st.resolve(r, alien, OWNERS, 6_000), null,
    'a token whose purpose this build cannot judge must authenticate nobody');

  await assert.rejects(() => st.mint(r, 'pgp_owner_demo', 5_000, 'admin'), /unknown purpose/,
    'minting a token nothing can use is a support ticket, so it is refused at the mint');
  did();
});

// ── 3. The token shape ───────────────────────────────────────────────────────

test('only a pst_ token of the exact minted shape is ever looked up', () => {
  assert.strictEqual(st.isSessionToken('pst_' + 'a'.repeat(64)), true);
  const no = [
    '', null, undefined, 42, {},
    'pgp_a_real_api_key_would_be_a_disaster_here',
    'pst_',
    'pst_' + 'a'.repeat(63),          // one short
    'pst_' + 'a'.repeat(65),          // one long
    'pst_' + 'A'.repeat(64),          // uppercase is not what randomBytes.hex makes
    'pst_' + 'g'.repeat(64),          // not hex
    ' pst_' + 'a'.repeat(64),         // leading space
    'pst_' + 'a'.repeat(64) + '\n',
  ];
  for (const v of no) {
    assert.strictEqual(st.isSessionToken(v), false, `${JSON.stringify(v)} must not be treated as a token`);
  }
  did();
});

test('the Bearer parse takes the token and nothing else', () => {
  const tok = 'pst_' + 'b'.repeat(64);
  assert.strictEqual(st.bearerToken(`Bearer ${tok}`), tok);
  assert.strictEqual(st.bearerToken(`bearer ${tok}`), tok, 'the scheme is case-insensitive per RFC 7235');
  assert.strictEqual(st.bearerToken(`  Bearer ${tok}  `), tok, 'surrounding whitespace is not part of the credential');
  assert.strictEqual(st.bearerToken(`Bearer\t${tok}`), tok);
  for (const bad of ['', null, undefined, 42, tok, `Basic ${tok}`, `Bearer ${tok} extra`, 'Bearer']) {
    assert.strictEqual(st.bearerToken(bad), '', `${JSON.stringify(bad)} is not a Bearer credential`);
  }
  did();
});

// ── 4. Mint ──────────────────────────────────────────────────────────────────

test('mint writes one record under the token, with the TTL it promises', async () => {
  const r = fakeRedis();
  const out = await st.mint(r, 'pgp_owner_demo', 1_000_000);

  assert.ok(st.isSessionToken(out.token), 'a minted token must satisfy the shape the resolver demands');
  assert.strictEqual(out.expires_in_s, st.TTL_S);
  assert.strictEqual(st.TTL_S, 900, 'fifteen minutes is the number SECURITY.md and /privacy both state');
  assert.strictEqual(out.expires_ms, 1_000_000 + 900_000);

  const rk = st.tokenKey(out.token);
  assert.deepStrictEqual(JSON.parse(r.store.get(rk)),
    { kh: st.keyHash('pgp_owner_demo'), exp: 1_900_000, p: 'parasend' });
  assert.strictEqual(r.ttls.get(rk), 900, 'redis must be the thing that expires the token, not a sweeper');
  did();
});

test('THE RECORD HOLDS NO KEY. Everything written to the store is a hash', async () => {
  // A read-only leak of redis is an RDB snapshot, a replica, a backup on
  // someone's laptop, a MONITOR session. Before this, every one of those
  // carried live pgp_ credentials for every account that had sent a file in the
  // last fifteen minutes. Now they carry hashes, and a hash is only a key to
  // somebody who already holds the api-key table.
  const r = fakeRedis();
  const out = await st.mint(r, 'pgp_owner_demo');

  const everything = [...r.store.keys(), ...r.store.values(), ...r.sets.keys(),
    ...[...r.sets.values()].flatMap((set) => [...set])].join('\n');
  assert.ok(!everything.includes('pgp_owner_demo'),
    'the api-key appears somewhere in the store. Key names AND values must both be hashes.');
  assert.ok(!/pgp_/.test(everything), 'nothing shaped like an api-key may be written to the store');

  // And the hash really is the sha256 of the key, not some other digest that
  // happens not to contain the string.
  const rec = JSON.parse(r.store.get(st.tokenKey(out.token)));
  assert.strictEqual(rec.kh, require('crypto').createHash('sha256').update('pgp_owner_demo').digest('hex'));
  assert.strictEqual(Object.keys(rec).sort().join(','), 'exp,kh,p',
    'the record carries exactly the hash, the expiry and the purpose');
  did();
});

test('two mints are two different tokens, and the owner key is never a redis key name', async () => {
  const r = fakeRedis();
  const a = await st.mint(r, 'pgp_owner_demo');
  const b = await st.mint(r, 'pgp_owner_demo');
  assert.notStrictEqual(a.token, b.token, 'a token that repeats is a token an attacker can wait for');

  // Key NAMES show up in SCAN output, slowlog entries and keyspace listings. An
  // api-key in a key name is an api-key in every one of those.
  for (const name of r.store.keys()) assert.ok(!name.includes('pgp_owner_demo'), `redis key name leaks the api-key: ${name}`);
  for (const name of r.sets.keys()) assert.ok(!name.includes('pgp_owner_demo'), `redis set name leaks the api-key: ${name}`);
  assert.match(st.ownerKey('pgp_owner_demo'), /^paramant:pst:owner:[0-9a-f]{64}$/);
  did();
});

test('the sweep index holds both tokens and outlives neither by much', async () => {
  const r = fakeRedis();
  const a = await st.mint(r, 'pgp_owner_demo');
  const b = await st.mint(r, 'pgp_owner_demo');
  const idx = st.ownerKey('pgp_owner_demo');
  assert.deepStrictEqual([...r.sets.get(idx)].sort(), [a.token, b.token].sort());
  assert.strictEqual(r.ttls.get(idx), st.TTL_S + 60,
    'the index must expire on its own; a set that lives forever is a slow leak with an api-key hash in the name');
  did();
});

// ── 5. Resolve ───────────────────────────────────────────────────────────────

test('a minted token resolves to the api-key it was minted for, through the table', async () => {
  const r = fakeRedis();
  const { token, expires_ms } = await st.mint(r, 'pgp_owner_demo', 5_000);
  assert.deepStrictEqual(await st.resolve(r, token, OWNERS, 6_000),
    { key: 'pgp_owner_demo', expires_ms, purpose: 'parasend' });
  did();
});

test('a hash the api-key table does not know resolves to nothing', async () => {
  // This is revocation and key deletion arriving for free: the resolver is a
  // lookup in the live table, so a key that is gone from it cannot be reached
  // through a token, whatever the store still holds.
  const r = fakeRedis();
  const { token } = await st.mint(r, 'pgp_owner_gone', 5_000);
  assert.strictEqual(await st.resolve(r, token, OWNERS, 6_000), null,
    'the record is live and well-formed; the owner is simply not in the table any more');
  // And a resolver that answers with something that is not a key is refused
  // rather than trusted.
  for (const bad of [() => null, () => undefined, () => '', () => 42, () => ({})]) {
    assert.strictEqual(await st.resolve(r, token, bad, 6_000), null);
  }
  did();
});

test('every refusal looks the same: null, with no way to tell them apart', async () => {
  const r = fakeRedis();
  const { token } = await st.mint(r, 'pgp_owner_demo', 5_000);

  // Never minted.
  assert.strictEqual(await st.resolve(r, 'pst_' + 'c'.repeat(64), OWNERS), null);
  // Not even a token.
  assert.strictEqual(await st.resolve(r, 'pgp_a_real_key', OWNERS), null);
  assert.strictEqual(await st.resolve(r, '', OWNERS), null);
  // Revoked out from under it.
  await r.del(st.tokenKey(token));
  assert.strictEqual(await st.resolve(r, token, OWNERS), null);
  did();
});

test('an expired record is refused even when the store still holds it', async () => {
  // Redis is what expires a token. This is the second lock: a record restored
  // from a backup, or served by a replica that lagged through the expiry, still
  // carries the wall-clock expiry it was minted with, and that is checked.
  const r = fakeRedis();
  const { token, expires_ms } = await st.mint(r, 'pgp_owner_demo', 5_000);
  assert.ok(await st.resolve(r, token, OWNERS, expires_ms), 'a token AT its expiry ms is still live');
  assert.strictEqual(await st.resolve(r, token, OWNERS, expires_ms + 1), null, 'one millisecond past it, it is not');
  did();
});

test('EXP IS REQUIRED: a record without a usable expiry is refused, not given the store default', async () => {
  // It used to be optional, guarded with a typeof, so a record that lost the
  // field fell back to whatever TTL redis happened to have on it, and one
  // written by hand with no field never expired on the wall clock at all. A
  // credential whose lifetime is a property of the store alone has no lifetime
  // when the store is wrong.
  const r = fakeRedis();
  const tok = 'pst_' + 'f'.repeat(64);
  const kh = st.keyHash('pgp_owner_demo');
  for (const exp of [undefined, null, 'soon', '1900000', {}, [], NaN, Infinity, -Infinity]) {
    const rec = exp === undefined ? { kh } : { kh, exp };
    await r.set(st.tokenKey(tok), JSON.stringify(rec));
    assert.strictEqual(await st.resolve(r, tok, OWNERS, 1000), null,
      `a record with exp=${JSON.stringify(exp)} must not authenticate anybody`);
  }
  // The control: the same record with a real expiry does resolve, so the case
  // above is measuring the expiry and not some other refusal.
  await r.set(st.tokenKey(tok), JSON.stringify({ kh, exp: 2000 }));
  assert.deepStrictEqual(await st.resolve(r, tok, OWNERS, 1000),
    { key: 'pgp_owner_demo', expires_ms: 2000, purpose: 'parasend' });
  did();
});

test('a record that is not the shape this module writes is refused, not trusted', async () => {
  const r = fakeRedis();
  const tok = 'pst_' + 'd'.repeat(64);
  const junk = [
    'not json', 'null', '[]', '{}',
    '{"kh":""}', '{"kh":123}',
    // The old shape, with the owner in the clear. It must be refused rather
    // than read: accepting it would keep a plaintext record working, which is
    // the thing this shape exists to stop.
    '{"key":"pgp_owner_demo","exp":9999999999999}',
    // A hash that is not one.
    '{"kh":"not-a-hash","exp":9999999999999}',
    `{"kh":"${'g'.repeat(64)}","exp":9999999999999}`,
    `{"kh":"${'A'.repeat(64)}","exp":9999999999999}`,
  ];
  for (const one of junk) {
    await r.set(st.tokenKey(tok), one);
    assert.strictEqual(await st.resolve(r, tok, OWNERS), null, `a record of ${one} must not yield a principal`);
  }
  did();
});

// ── 6. Fail closed ───────────────────────────────────────────────────────────

test('FAIL CLOSED: no store is a throw, never a quiet null', async () => {
  // The distinction is the whole difference between a 503 and a 401. A null
  // here would tell a sender holding a perfectly good token that it is bad, and
  // send them back to sign in, during an outage where signing in cannot work.
  await assert.rejects(() => st.resolve(null, 'pst_' + 'e'.repeat(64), OWNERS), /no redis client/);
  await assert.rejects(() => st.mint(null, 'pgp_owner_demo'), /no redis client/);
  // And a caller that forgot the resolver is a programming error, not a silent
  // refusal: without a table there is no way to turn a hash back into a key,
  // and returning null would look exactly like a bad token.
  const r = fakeRedis();
  const { token } = await st.mint(r, 'pgp_owner_demo');
  await assert.rejects(() => st.resolve(r, token), /no owner resolver/);
  did();
});

test('a broken store propagates, so the route can answer 503 instead of 401', async () => {
  const r = fakeRedis();
  const { token } = await st.mint(r, 'pgp_owner_demo');
  r.fail = new Error('redis command timed out after 1000ms');
  await assert.rejects(() => st.resolve(r, token, OWNERS), /timed out/);
  await assert.rejects(() => st.mint(r, 'pgp_owner_demo'), /timed out/);
  did();
});

test('mint refuses to hand out a token with no owner on it', async () => {
  const r = fakeRedis();
  for (const bad of ['', null, undefined, 42]) {
    await assert.rejects(() => st.mint(r, bad), /no owner key/);
  }
  did();
});

// ── 7. Revoke ────────────────────────────────────────────────────────────────

test('revoking a key takes every one of its live tokens with it', async () => {
  const r = fakeRedis();
  const a = await st.mint(r, 'pgp_owner_demo');
  const b = await st.mint(r, 'pgp_owner_demo');
  const other = await st.mint(r, 'pgp_owner_other');

  const n = await st.revokeForKey(r, 'pgp_owner_demo');
  assert.strictEqual(n, 2, 'both tokens are reported swept');
  assert.strictEqual(await st.resolve(r, a.token, OWNERS), null);
  assert.strictEqual(await st.resolve(r, b.token, OWNERS), null);
  assert.ok(await st.resolve(r, other.token, OWNERS), 'another account is untouched: revocation is per key, not per store');
  assert.strictEqual(r.sets.has(st.ownerKey('pgp_owner_demo')), false, 'the index goes too, or it grows forever');
  did();
});

test('revoking a key with no tokens is a no-op, not an error', async () => {
  const r = fakeRedis();
  assert.strictEqual(await st.revokeForKey(r, 'pgp_owner_never_used'), 0);
  // And a caller with no store at all (a relay without REDIS_URL) gets 0 rather
  // than a throw: the revocation itself has already happened in users.json, and
  // a relay with no store has no tokens to sweep.
  assert.strictEqual(await st.revokeForKey(null, 'pgp_owner_demo'), 0);
  assert.strictEqual(await st.revokeForKey(fakeRedis(), ''), 0);
  did();
});

// ── 8. The ceiling on live tokens per account ────────────────────────────────

test('an account can hold twenty live tokens, and the twenty-first is refused', async () => {
  // A ceiling, not a rate limit. The page mints one per load and one per
  // refresh, so twenty is far above honest use; what it stops is a signed-in
  // session being run as a credential factory, each token good for fifteen
  // minutes on five routes.
  const r = fakeRedis();
  assert.strictEqual(st.MAX_LIVE_PER_ACCOUNT, 20);
  const minted = [];
  for (let i = 0; i < st.MAX_LIVE_PER_ACCOUNT; i += 1) {
    const out = await st.mint(r, 'pgp_owner_demo');
    assert.ok(out.token, `mint ${i + 1} of the cap must succeed`);
    minted.push(out.token);
  }
  const over = await st.mint(r, 'pgp_owner_demo');
  assert.strictEqual(over.capped, true, 'the twenty-first must be refused');
  assert.strictEqual(over.cap, 20);
  assert.strictEqual(over.token, undefined, 'a refused mint hands out no token');
  // The tokens already minted keep working: a cap is not a revocation.
  assert.ok(await st.resolve(r, minted[0], OWNERS));
  did();
});

test('the cap is per account, and it counts LIVE tokens, not names left in the index', async () => {
  const r = fakeRedis();
  for (let i = 0; i < st.MAX_LIVE_PER_ACCOUNT; i += 1) await st.mint(r, 'pgp_owner_demo');
  // Another account is unaffected.
  assert.ok((await st.mint(r, 'pgp_owner_other')).token, 'one account at its cap must not block another');

  // Redis expires the RECORDS, not the names in the sweep index, so the set
  // drifts upward. A caller refused because of tokens that no longer exist
  // would be locked out for the rest of the window by nothing at all. The
  // prune runs before the cap is believed.
  const idx = st.ownerKey('pgp_owner_demo');
  const names = [...r.sets.get(idx)];
  for (const n of names.slice(0, 5)) await r.del(st.tokenKey(n));   // redis expiry, by hand
  assert.strictEqual(r.sets.get(idx).size, 20, 'the index still names all twenty');

  const out = await st.mint(r, 'pgp_owner_demo');
  assert.ok(out.token, 'with five of the twenty expired there is room, and the mint must succeed');
  assert.strictEqual(r.sets.get(idx).size, 16, 'and the dead names are gone from the index: 20 - 5 + 1');
  did();
});

test('the prune only ever removes names whose record is gone', async () => {
  const r = fakeRedis();
  const a = await st.mint(r, 'pgp_owner_demo');
  const b = await st.mint(r, 'pgp_owner_demo');
  const idx = st.ownerKey('pgp_owner_demo');
  assert.strictEqual(await st.pruneOwnerIndex(r, idx), 2, 'nothing to prune when both are live');
  await r.del(st.tokenKey(a.token));
  assert.strictEqual(await st.pruneOwnerIndex(r, idx), 1);
  assert.deepStrictEqual([...r.sets.get(idx)], [b.token], 'the live one survives the prune');
  assert.ok(await st.resolve(r, b.token, OWNERS), 'and it still resolves');
  // An index that is empty or absent is not an error.
  assert.strictEqual(await st.pruneOwnerIndex(r, st.ownerKey('pgp_never_minted')), 0);
  did();
});

test('the cheap count is what runs on the ordinary path: no prune under the cap', async () => {
  // The prune is O(live) round trips. Paying it on every mint would make the
  // common case the expensive one for a ceiling almost nobody reaches.
  const r = fakeRedis();
  await st.mint(r, 'pgp_owner_demo');
  r.calls.length = 0;
  await st.mint(r, 'pgp_owner_demo');
  const ops = r.calls.map(([op]) => op);
  assert.ok(ops.includes('sCard'), 'the cap is checked');
  assert.ok(!ops.includes('sMembers'), `an under-cap mint must not walk the index; it ran ${ops.join(', ')}`);
  assert.ok(!ops.includes('exists'), 'and must not probe every token');
  did();
});
