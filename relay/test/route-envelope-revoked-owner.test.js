'use strict';
// A revoked API key reads nothing of its envelopes any more.
//
// WHY THIS SUITE EXISTS. Review of PR #546 (MIDDEL). Every GET under
// /v2/envelopes/ passes the key gate as isEnvelopePublic, because an external
// signer has no key. A key revoked through /v2/admin/keys/revoke stays in
// apiKeys with active=false, so keyData is still truthy there. The owner
// routes checked `if (!keyData)` and not `keyData.active`: after the revoke the
// holder of a leaked pgp_ key still read party names, status, ink ciphertext
// (owner-view), the document capsule (owner-document), the ownership answer
// (owner-check) and the signed receipt. A gated route answered 401.
//
// NEEDS: a reachable redis (the envelope store is redis-only).
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-envelope-revoked-owner.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

const RUN = crypto.randomBytes(6).toString('hex');
const OWNER = `pgp_owner_key_for_the_revoked_suite_${RUN}`;
const ADMIN = `admin-token-revoked-suite-${RUN}`;
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';

let srv = null;
let rc = null;
let checks = 0;

before(async () => {
  rc = await requireRedis(DEFAULT_REDIS);
  if (!rc) return;
  srv = await boot({
    tag: 'revoked-owner',
    users: { api_keys: [{ key: OWNER, plan: 'business', active: true, parasign: true, email: 'owner@example.test', account_id: `acct_revoked_${RUN}` }] },
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS, ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: `internal-revoked-suite-${RUN}` },
  });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('route-envelope-revoked-owner', checks);
});

const H = { 'X-Api-Key': OWNER, 'X-Real-IP': '10.9.0.1' };

test('owner-view, owner-document, owner-check and receipt answer 401 once the key is revoked', async () => {
  if (!srv) return;
  const dh = crypto.createHash('sha3-256').update(crypto.randomBytes(32)).digest('hex');
  const c = await srv.post('/v2/envelopes', { headers: H, body: { doc_hash: dh, parties: [{ label: 'Alice' }, { label: 'Bob' }] } });
  assert.strictEqual(c.status, 200, `create: ${c.status} ${c.text}`);
  const id = c.json.envelope.id;
  const capsule = crypto.randomBytes(256);
  const up = await srv.post(`/v2/envelopes/${id}/document`, {
    headers: { ...H, 'Content-Type': 'application/octet-stream', 'X-Capsule-Sha256': crypto.createHash('sha256').update(capsule).digest('hex') },
    body: capsule,
  });
  assert.strictEqual(up.status, 200, `upload: ${up.status} ${up.text}`);

  // Before: the owner reads its own envelope.
  assert.strictEqual((await srv.get(`/v2/envelopes/${id}/owner-view`, { headers: H })).status, 200);
  const docBefore = await srv.get(`/v2/envelopes/${id}/owner-document`, { headers: H });
  assert.strictEqual(docBefore.status, 200);
  assert.ok(docBefore.buf.equals(capsule));
  assert.strictEqual((await srv.get(`/v2/envelopes/${id}/owner-check`, { headers: H })).status, 200);
  checks++;

  const rv = await srv.post('/v2/admin/keys/revoke', { headers: { 'X-Admin-Token': ADMIN }, body: { key: OWNER } });
  assert.strictEqual(rv.status, 200, `revoke: ${rv.status} ${rv.text}`);

  // A gated route already refused the revoked key.
  assert.strictEqual((await srv.post('/v2/envelopes', { headers: H, body: { doc_hash: dh, parties: [{ label: 'A' }] } })).status, 401);

  for (const route of ['owner-view', 'owner-document', 'owner-check', 'receipt']) {
    const r = await srv.get(`/v2/envelopes/${id}/${route}`, { headers: H });
    assert.strictEqual(r.status, 401, `${route} after revoke: ${r.status} ${r.text.slice(0, 120)}`);
    assert.ok(!r.buf.equals(capsule), `${route} must not hand out the capsule`);
  }
  checks++;

  try { await rc.del('env:' + id); await rc.del('envdoc:' + id); } catch (_) {}
});
