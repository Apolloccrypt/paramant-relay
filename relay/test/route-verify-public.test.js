'use strict';
// POST /v2/verify without an API key (hertest 2026-10-04, T3-12).
//
// /verify and /parasign promise that a signature can be checked "offline and
// without an account". For old v1/v2 envelopes the notary signature can only be
// checked by the relay, and POST /v2/verify answered a keyless caller 401
// "Invalid API key". The route is a pure function of the posted bytes (it stores
// nothing and reads no account), so it is public now, rate-limited per address.
// Run: node --test relay/test/route-verify-public.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, summary } = require('./_requires');

let srv = null;
let checks = 0;

before(async () => {
  if (!requireEngine()) return;
  srv = await boot({ tag: 'verify-public', users: { api_keys: [] } });
});
after(async () => { await killAll(); summary('route-verify-public', checks); });

test('a keyless caller gets a verdict, not a 401', async () => {
  if (!srv) return;
  const r = await srv.post('/v2/verify', { headers: { 'X-Real-IP': '10.7.0.1' }, body: { envelope: { version: 'paramant-sign-v1' } } });
  assert.notStrictEqual(r.status, 401, `still asks for a key: ${r.text}`);
  assert.ok(r.status === 422 || r.status === 400 || r.status === 200, `${r.status} ${r.text}`);
  assert.ok(!/Invalid API key/.test(r.text));
  checks++;
});

test('the public route is rate-limited per address', async () => {
  if (!srv) return;
  let last = 0;
  for (let i = 0; i < 25; i++) {
    const r = await srv.post('/v2/verify', { headers: { 'X-Real-IP': '10.7.0.9' }, body: { envelope: {} } });
    last = r.status;
    if (last === 429) break;
  }
  assert.strictEqual(last, 429, 'twenty-five keyless verifications a minute from one address must hit the limit');
  checks++;
});

test('other keyless POSTs stay closed', async () => {
  if (!srv) return;
  const r = await srv.post('/v2/envelopes', { headers: { 'X-Real-IP': '10.7.0.2' }, body: { doc_hash: 'a'.repeat(64), parties: [{ label: 'A' }] } });
  assert.strictEqual(r.status, 401);
  checks++;
});
