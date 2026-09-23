'use strict';
// POST /v2/sends/precheck: the recipient ceiling, asked BEFORE the upload.
//
// The page used to seal and upload first and only learn at POST /v2/sends that
// a Community account may name one recipient. By then a transfer was counted,
// the blocks sat in memory, and the sender was left on "Sealing 0%". The
// precheck gives the same answer as the send would, with nothing uploaded.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { boot, killAll } = require('./_relay-server');
const { requireEngine } = require('./_requires');

const engineOk = requireEngine();
const PC_FIRM = 'pgp_precheck_firm_key_0001';
const PC_FREE = 'pgp_precheck_free_key_0001';
let srv = null;

before(async () => {
  if (!engineOk) return;
  srv = await boot({
    tag: 'precheck',
    env: { RELAY_MODE: 'full', MAIL_PROVIDER: 'dryrun' },
    users: { api_keys: [
      { key: PC_FIRM, active: true, plan: 'pro', plan_parasend: 'pro', label: 'firm',
        email: 'firm@example.com', account_id: 'acct_demo_firm' },
      { key: PC_FREE, active: true, plan: 'community', plan_parasend: 'community', label: 'free',
        email: 'free@example.com', account_id: 'acct_demo_free' },
    ] },
  });
});
after(killAll);

async function precheck(key, recipients) {
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers['X-Api-Key'] = key;
  const r = await fetch(srv.base + '/v2/sends/precheck', {
    method: 'POST', headers, body: JSON.stringify({ recipients }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

const addrs = (n) => Array.from({ length: n }, (_, i) => `r${i}@example.com`);

test('Community with one recipient: allowed, limit 1', { skip: !engineOk }, async () => {
  const r = await precheck(PC_FREE, addrs(1));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.limit, 1);
});

test('Community with two recipients: 403 over_limit, limit 1, asked 2', { skip: !engineOk }, async () => {
  const r = await precheck(PC_FREE, addrs(2));
  assert.equal(r.status, 403);
  assert.equal(r.body.error, 'over_limit');
  assert.equal(r.body.limit, 1);
  assert.equal(r.body.asked, 2);
  assert.equal(r.body.plan, 'community');
});

test('Firm with 30 is allowed and with 31 refused, naming 31', { skip: !engineOk }, async () => {
  assert.equal((await precheck(PC_FIRM, addrs(30))).status, 200);
  const r = await precheck(PC_FIRM, addrs(31));
  assert.equal(r.status, 403);
  assert.equal(r.body.limit, 30);
  assert.equal(r.body.asked, 31);
});

test('a bad address or an empty list is a 400 with the reason', { skip: !engineOk }, async () => {
  const bad = await precheck(PC_FIRM, ['not-an-address']);
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error, 'invalid_address');
  const empty = await precheck(PC_FIRM, []);
  assert.equal(empty.status, 400);
  assert.equal(empty.body.error, 'empty');
});

test('without a key: 401', { skip: !engineOk }, async () => {
  const r = await precheck(null, addrs(1));
  assert.equal(r.status, 401);
});
