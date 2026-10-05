'use strict';
// The auth gate of relay.js, over HTTP, on a really booted relay.
//
// WHY THIS SUITE EXISTS. The gate is fifteen lines at relay.js:4194-4218 and it
// is the only thing standing between the open internet and 68 routes. It had no
// unit test at all: the 2026-09-02 audit measured relay.js at 0 % coverage,
// loaded by no test in the suite. The ParaID bypass earlier this year was
// exactly a route that answered before the gate had a say, so the rule this
// suite pins is the ParaID rule: AUTH FIRST, VALIDATION SECOND. A 400 on a
// keyless request is a leak, it tells an unauthenticated caller what the body
// should have looked like.
//
// What is asserted here, and why each line earns its place:
//   * a gated route answers 401 to no key, an unknown key and a de-activated
//     key, with the same body every time (no oracle that separates them);
//   * a garbage body plus a missing key is still a 401, never a 400;
//   * the three envelope recipient routes are public BY DESIGN (an external
//     signer has no key) and POST /v2/envelopes is NOT, which is the exact
//     distinction isEnvelopePublic draws;
//   * /v2/admin* is 401 without ADMIN_TOKEN and reachable with it, and the
//     double-gated admin routes need X-Internal-Auth on top;
//   * an admin route stays closed when ADMIN_TOKEN is not configured at all
//     (fail closed, not open).
//
// Runs against a relay booted WITHOUT redis, so the envelope store is absent
// and an authenticated envelope call answers 503. That is deliberate: this
// suite is about who gets past the gate, not about what is behind it. The
// lifecycle behind it is route-envelope-lifecycle.test.js.
// Run: node --test relay/test/route-auth-gate.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const ADMIN = 'admin-token-for-the-auth-gate-suite';
const INTERNAL = 'internal-token-for-the-auth-gate-suite';
const LIVE_KEY = 'pgp_live_key_for_the_auth_gate_suite';
const DEAD_KEY = 'pgp_dead_key_for_the_auth_gate_suite';

let srv;      // relay with ADMIN_TOKEN + INTERNAL_AUTH_TOKEN configured
let noAdmin;  // relay with neither configured
let checks = 0;
const did = () => { checks++; };

before(async () => {
  const users = {
    api_keys: [
      { key: LIVE_KEY, plan: 'pro', active: true, label: 'live', email: 'live@example.test', account_id: 'acct_live' },
      // active:false is how a revoked key looks on disk. loadUsers skips it
      // entirely (relay.js:1829), so it must be indistinguishable from a key
      // that never existed.
      { key: DEAD_KEY, plan: 'pro', active: false, label: 'dead', email: 'dead@example.test', account_id: 'acct_dead' },
    ],
  };
  srv = await boot({ tag: 'authgate', users, env: { ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: INTERNAL } });
  noAdmin = await boot({ tag: 'authgate-noadmin', users });
});

after(async () => { await killAll(); summary('route-auth-gate', checks); });

// ── 1. the gate itself ───────────────────────────────────────────────────────

test('POST /v2/envelopes without a key is 401, and the body says only that', async () => {
  const r = await srv.post('/v2/envelopes', { body: { doc_hash: 'a'.repeat(64), parties: [{ label: 'A' }] } });
  assert.strictEqual(r.status, 401);
  assert.deepStrictEqual(r.json, { error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' });
  did();
});

test('an unknown key and a de-activated key are the same 401 (no existence oracle)', async () => {
  const body = { doc_hash: 'a'.repeat(64), parties: [{ label: 'A' }] };
  const unknown = await srv.post('/v2/envelopes', { headers: { 'X-Api-Key': 'pgp_no_such_key' }, body });
  const revoked = await srv.post('/v2/envelopes', { headers: { 'X-Api-Key': DEAD_KEY }, body });
  assert.strictEqual(unknown.status, 401);
  assert.strictEqual(revoked.status, 401);
  assert.deepStrictEqual(revoked.json, unknown.json,
    'a de-activated key must answer exactly like an unknown one, or the 401 is a key-existence oracle');
  did();
});

test('THE ParaID RULE: auth runs before validation, so a bad body never turns a 401 into a 400', async () => {
  // Four shapes that would each be a 400 from the handler if it ever saw them:
  // no body at all, invalid JSON, valid JSON with nothing in it, and a doc_hash
  // of the wrong length. All four must still be 401 without a key.
  const cases = [
    ['no body', undefined],
    ['invalid json', '{ this is not json'],
    ['empty object', {}],
    ['short doc_hash', { doc_hash: 'abc', parties: [] }],
  ];
  for (const [name, body] of cases) {
    const r = await srv.post('/v2/envelopes', {
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : body,
    });
    assert.strictEqual(r.status, 401, `${name}: expected 401, got ${r.status} ${r.text}`);
    assert.notStrictEqual(r.status, 400, `${name}: a keyless caller learned something about the body shape`);
  }
  did();
});

test('a WRONG key also cannot reach validation: still 401, not 400', async () => {
  const r = await srv.post('/v2/envelopes', {
    headers: { 'X-Api-Key': 'pgp_wrong', 'Content-Type': 'application/json' },
    body: '{ broken',
  });
  assert.strictEqual(r.status, 401);
  did();
});

test('a Bearer that looks like a session token opens nothing on a relay with no store', async () => {
  // The gate now has a second credential in front of it: an Authorization
  // Bearer pst_ token, resolved against redis (relay/lib/session-token.js, and
  // route-session-token.test.js for what it does when there IS a store). This
  // suite boots WITHOUT redis, which makes it the right place to pin the two
  // ways that credential must not weaken this gate.
  //
  // 1. A pst_-shaped Bearer with no store behind it is 503, not 200 and not a
  //    principal. Fail closed: "we cannot check this" may never read as "fine".
  const shaped = await srv.post('/v2/envelopes', {
    headers: { Authorization: `Bearer pst_${'a'.repeat(64)}` },
    body: { doc_hash: 'a'.repeat(64), parties: [{ label: 'Demo' }] },
  });
  assert.strictEqual(shaped.status, 503, `expected the store-unavailable 503, got ${shaped.status} ${shaped.text}`);
  assert.strictEqual(shaped.json.error, 'redis_unavailable');

  // 2. Anything that is NOT that exact shape is not a credential at all, so it
  //    falls straight through to the ordinary 401. In particular the ADMIN
  //    token as a Bearer stays an admin token and does not become a data-plane
  //    principal, and an api-key offered as a Bearer is still not an api-key.
  for (const value of [
    `Bearer pst_${'z'.repeat(64)}`,   // right prefix, not hex
    'Bearer pst_short',
    `Bearer ${LIVE_KEY}`,             // the api-key, in the wrong header
    `Bearer ${ADMIN}`,                // the admin token, in the wrong plane
    'Bearer',
  ]) {
    const r = await srv.post('/v2/envelopes', {
      headers: { Authorization: value },
      body: { doc_hash: 'a'.repeat(64), parties: [{ label: 'Demo' }] },
    });
    assert.strictEqual(r.status, 401, `${value} was treated as a credential (${r.status})`);
    assert.deepStrictEqual(r.json, { error: 'Invalid API key', hint: 'X-Api-Key: pgp_...' });
  }
  did();
});

test('a VALID key gets past the gate: the 503 behind it proves the gate opened', async () => {
  // No redis in this boot, so the envelope store is null (relay.js:5669). The
  // point of the assertion is the code, not the failure: 503 can only be
  // reached after the gate let the request through.
  const r = await srv.post('/v2/envelopes', {
    headers: { 'X-Api-Key': LIVE_KEY },
    body: { doc_hash: 'a'.repeat(64), parties: [{ label: 'A' }] },
  });
  assert.strictEqual(r.status, 503, `expected the store-unavailable 503, got ${r.status} ${r.text}`);
  assert.match(String(r.json && r.json.error), /Envelope store unavailable/);
  did();
});

// ── 2. the public recipient routes ───────────────────────────────────────────

test('the three envelope recipient routes are reachable without any key', async () => {
  // An external signer has no API key, so GET :id, POST :id/view and POST
  // :id/sign are public by design (relay.js:4201-4204). Public means "not
  // stopped by the gate": with no store behind them they answer 404/503, and
  // what matters is that none of them answers 401.
  const id = 'Zm9vYmFyZm9vYmFyZm9vYmFyZm9v';
  const probes = [
    ['GET', `/v2/envelopes/${id}`, undefined],
    ['POST', `/v2/envelopes/${id}/view`, { party_index: 0 }],
    ['POST', `/v2/envelopes/${id}/sign`, { party_index: 0, signer_public_key: 'AA==', signature: 'AA==' }],
  ];
  for (const [method, p, body] of probes) {
    const r = await srv.req(method, p, { body });
    assert.notStrictEqual(r.status, 401, `${method} ${p} must not be gated by X-Api-Key`);
  }
  did();
});

test('create is NOT in that public list: the trailing-slash prefix is what separates them', async () => {
  // isEnvelopePublic only matches paths that start with '/v2/envelopes/'.
  // '/v2/envelopes' (create) has no trailing slash, so it stays gated. This is
  // the single character the whole distinction rests on.
  const r = await srv.post('/v2/envelopes', { body: { doc_hash: 'a'.repeat(64), parties: [{ label: 'A' }] } });
  assert.strictEqual(r.status, 401);
  // And the neighbouring sub-routes that are NOT view/sign stay gated too.
  const doc = await srv.post(`/v2/envelopes/someid/document`, { body: {} });
  assert.strictEqual(doc.status, 401, 'POST :id/document is neither /view nor /sign, so it must stay gated');
  did();
});

// ── 3. admin routes ──────────────────────────────────────────────────────────

test('every admin route is 401 without a token', async () => {
  for (const p of ['/v2/admin/keys', '/v2/admin/usage', '/v2/admin/entitlements/acct_live']) {
    const r = await srv.get(p);
    assert.strictEqual(r.status, 401, `${p} without a token`);
    assert.deepStrictEqual(r.json, { error: 'ADMIN_TOKEN required for admin endpoints' });
  }
  const rev = await srv.post('/v2/admin/keys/revoke', { body: { key: LIVE_KEY } });
  assert.strictEqual(rev.status, 401);
  did();
});

test('a wrong admin token is 401, and the live API key is not an admin token', async () => {
  const wrong = await srv.get('/v2/admin/keys', { headers: { 'X-Admin-Token': ADMIN + 'x' } });
  assert.strictEqual(wrong.status, 401);
  // A tenant key, even an enterprise one, must never open an admin route.
  const asUser = await srv.get('/v2/admin/keys', { headers: { 'X-Admin-Token': LIVE_KEY } });
  assert.strictEqual(asUser.status, 401);
  const asApiKeyHeader = await srv.get('/v2/admin/keys', { headers: { 'X-Api-Key': LIVE_KEY } });
  assert.strictEqual(asApiKeyHeader.status, 401, 'X-Api-Key must not be accepted on an admin path');
  did();
});

test('with the admin token the route answers 200 and lists the keys masked', async () => {
  const r = await srv.get('/v2/admin/keys', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.ok, true);
  assert.strictEqual(r.json.masked, true);
  const listed = r.json.keys.map((k) => k.account_id);
  assert.ok(listed.includes('acct_live'), 'the active key is listed');
  assert.ok(!listed.includes('acct_dead'), 'an active:false key is never loaded, so it cannot be listed');
  // The masked listing must not hand back the secret.
  assert.ok(!r.text.includes(LIVE_KEY), 'the raw key must not appear in a masked listing');
  did();
});

test('the same token is accepted as a Bearer, and that is the only other form', async () => {
  const bearer = await srv.get('/v2/admin/keys', { headers: { Authorization: `Bearer ${ADMIN}` } });
  assert.strictEqual(bearer.status, 200);
  const basic = await srv.get('/v2/admin/keys', { headers: { Authorization: `Basic ${ADMIN}` } });
  assert.strictEqual(basic.status, 401, 'only the Bearer form is unwrapped');
  did();
});

test('the double-gated admin routes need X-Internal-Auth on top of the admin token', async () => {
  // update-plan / set-product-plan / entitlements were the first three. Since
  // 2026-09-06 the set is everything under /v2/admin that moves an entitlement
  // or mints a credential: set-parasign, mint-parasign, keys/erase and
  // keys/primary joined them. Which routes belong is asserted as a class in
  // admin-gate-parity.test.js; this is the behavioural half, on a booted relay.
  // The admin token alone must not do.
  const onlyAdmin = await srv.get('/v2/admin/entitlements/acct_live', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(onlyAdmin.status, 401);
  assert.deepStrictEqual(onlyAdmin.json, { error: 'unauthorized' });

  const both = await srv.get('/v2/admin/entitlements/acct_live', {
    headers: { 'X-Admin-Token': ADMIN, 'X-Internal-Auth': INTERNAL },
  });
  assert.strictEqual(both.status, 200, both.text);
  assert.strictEqual(both.json.ok, true);
  assert.strictEqual(both.json.account_id, 'acct_live');
  assert.ok(both.json.entitlements.parasend && both.json.entitlements.parasign);

  const wrongInternal = await srv.get('/v2/admin/entitlements/acct_live', {
    headers: { 'X-Admin-Token': ADMIN, 'X-Internal-Auth': INTERNAL + 'x' },
  });
  assert.strictEqual(wrongInternal.status, 401);

  // The route that MINTS. It used to stand behind the admin token alone, which
  // made one leaked secret enough to walk out with a working ParaSign key.
  const mintOne = await srv.post('/v2/admin/keys/mint-parasign', {
    headers: { 'X-Admin-Token': ADMIN }, body: { account_id: 'acct_live', test: true },
  });
  assert.strictEqual(mintOne.status, 401, 'mint-parasign answered on the admin token alone');
  assert.ok(!/psk_/.test(mintOne.text), 'a refused mint still leaked a key');
  did();
});

test('an unconfigured ADMIN_TOKEN fails CLOSED: no token in the env opens nothing', async () => {
  // The dangerous shape of this bug is a gate that treats "no token configured"
  // as "no token required". relay.js:4208 requires process.env.ADMIN_TOKEN to
  // be truthy, so an unconfigured relay answers 401 to everything, including an
  // empty header.
  for (const headers of [{}, { 'X-Admin-Token': '' }, { 'X-Admin-Token': 'anything' }]) {
    const r = await noAdmin.get('/v2/admin/keys', { headers });
    assert.strictEqual(r.status, 401, `unconfigured relay answered ${r.status} to ${JSON.stringify(headers)}`);
  }
  // Same rule on the internal gate: no INTERNAL_AUTH_TOKEN configured means the
  // user routes stay shut.
  const user = await noAdmin.get('/v2/user/history', { headers: { 'X-Internal-Auth': 'anything' } });
  assert.strictEqual(user.status, 401);
  did();
});

// ── 4. the key must not travel in the URL ────────────────────────────────────

test('an API key in the query string is refused before it is ever looked up', async () => {
  // relay.js:2155-2158. A key in ?k= lands in access logs, referrers and
  // browser history, so it is refused outright, with a 400, deliberately, and
  // before any auth decision, so the refusal cannot leak whether it was valid.
  const r = await srv.get(`/v2/audit?k=${LIVE_KEY}`);
  assert.strictEqual(r.status, 400);
  assert.match(String(r.json.error), /must be sent in the X-Api-Key header/);
  assert.ok(!r.text.includes(LIVE_KEY), 'the refusal must not echo the key back');
  did();
});

test('/health and /v2/capabilities stay public, and /health leaks nothing extra without the admin token', async () => {
  const h = await srv.get('/health');
  assert.strictEqual(h.status, 200);
  assert.strictEqual(h.json.ok, true);
  assert.strictEqual(h.json.uptime_s, undefined, 'the extended health fields are admin-only');
  const withAdmin = await srv.get('/health', { headers: { 'X-Admin-Token': ADMIN } });
  assert.strictEqual(withAdmin.status, 200);
  assert.notStrictEqual(Object.keys(withAdmin.json).length, Object.keys(h.json).length,
    'the admin view of /health must carry more than the public one');
  const cap = await srv.get('/v2/capabilities');
  assert.strictEqual(cap.status, 200);
  did();
});
