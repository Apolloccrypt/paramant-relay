'use strict';
// "Bekeken" only for the verified recipient (hertest 2026-10-04, T5-12).
//
// Opening a co-sign link anonymously, before signing in, set the party to
// status 'viewed' and wrote a viewed_at into the CT log: co-sign.js posts
// /view with only the invite token, and the token is in a mail that scanners,
// forwards and anyone at the screen also have. For an email-bound slot the
// view is now stamped only on a request the admin plane vouches for
// (X-Internal-Auth + the verified mailbox hash of that party), or when that
// verified person fetches the document. Open-mode envelopes have no mailbox to
// verify and keep the token rule.
//
// NEEDS: a reachable redis.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-envelope-view-verified.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');
const envelopeMod = require('../envelope');

const RUN = crypto.randomBytes(6).toString('hex');
const OWNER = `pgp_owner_key_for_the_view_suite_${RUN}`;
const INTERNAL = `internal-view-suite-${RUN}`;
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const EMAIL = `ontvanger-${RUN}@example.test`;

let srv = null;
let rc = null;
let checks = 0;

before(async () => {
  rc = await requireRedis(DEFAULT_REDIS);
  if (!rc) return;
  srv = await boot({
    tag: 'view-verified',
    users: { api_keys: [{ key: OWNER, plan: 'business', active: true, parasign: true, email: 'owner@example.test', account_id: `acct_view_${RUN}` }] },
    env: { REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS, INTERNAL_AUTH_TOKEN: INTERNAL },
  });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('route-envelope-view-verified', checks);
});

const H = { 'X-Api-Key': OWNER, 'X-Real-IP': '10.8.0.1' };

async function make(mode) {
  const dh = crypto.createHash('sha3-256').update(crypto.randomBytes(32)).digest('hex');
  const parties = mode === 'email' ? [{ label: 'Ontvanger', email: EMAIL }] : [{ label: 'Alice' }];
  const c = await srv.post('/v2/envelopes', { headers: H, body: { doc_hash: dh, parties, binding_mode: mode } });
  assert.strictEqual(c.status, 200, `create: ${c.status} ${c.text}`);
  return { id: c.json.envelope.id, token: c.json.envelope.party_links[0].invite_token };
}
const status0 = async (id) => rc.hGet('env:' + id, 'p0_status');
const view = (id, token, headers = {}) => srv.post(`/v2/envelopes/${id}/view`,
  { headers: { 'X-Real-IP': '10.8.0.2', ...headers }, body: { party_index: 0, token } });

test('an anonymous open of an email-bound link records no view', async () => {
  if (!srv) return;
  const { id, token } = await make('email');
  const before = await status0(id);
  const r = await view(id, token);
  assert.strictEqual(r.status, 200, 'the anonymous page still gets a 200');
  assert.strictEqual(r.json.recorded, false);
  assert.strictEqual(await status0(id), before, 'the slot must not read "viewed" after an anonymous open');
  assert.strictEqual(await rc.hGet('env:' + id, 'p0_viewed_at'), null);

  // A wrong mailbox, even with internal auth, records nothing either.
  const wrong = await view(id, token, { 'X-Internal-Auth': INTERNAL, 'X-Verified-Email-Hash': envelopeMod.partyEmailHash('ander@example.test') });
  assert.strictEqual(wrong.json.recorded, false);
  assert.strictEqual(await status0(id), before);

  // The verified recipient does.
  const ok = await view(id, token, { 'X-Internal-Auth': INTERNAL, 'X-Verified-Email-Hash': envelopeMod.partyEmailHash(EMAIL) });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(await status0(id), 'viewed');
  checks++;
  try { await rc.del('env:' + id); } catch (_) {}
});

test('an open-mode envelope keeps the token rule', async () => {
  if (!srv) return;
  const { id, token } = await make('open');
  const r = await view(id, token);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(await status0(id), 'viewed');
  checks++;
  try { await rc.del('env:' + id); } catch (_) {}
});
