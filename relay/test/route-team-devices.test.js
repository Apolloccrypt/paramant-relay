'use strict';
// SENDNAME-43: "add a device to the team (Firm or higher)" was promised and
// answered 403 "no team" to everyone, because team_id never reached a record.
// The team is the account now.
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const FIRM = 'pgp_' + crypto.randomBytes(32).toString('hex');
const FREE = 'pgp_' + crypto.randomBytes(32).toString('hex');
let checks = 0;
after(async () => { await killAll(); summary('route-team-devices', checks); });

test('a Firm account adds a device key to its own account; a free one is told why not', async () => {
  const srv = await boot({ tag: 'team', usersFile: true, users: { api_keys: [
    { key: FIRM, plan: 'pro', plan_parasend: 'pro', plan_parasign: 'pro', active: true, email: 'firm@example.test', account_id: 'acct_team_firm' },
    { key: FREE, plan: 'community', active: true, email: 'free@example.test', account_id: 'acct_team_free' },
  ] } });
  const add = await srv.post('/v2/team/add-device', { headers: { 'X-Api-Key': FIRM }, body: { label: 'balie-pc' } });
  assert.strictEqual(add.status, 201, add.text);
  assert.strictEqual(add.json.account_id, 'acct_team_firm');
  assert.match(add.json.key, /^pgp_[0-9a-f]{64}$/);
  const list = await srv.get('/v2/team/devices', { headers: { 'X-Api-Key': FIRM } });
  assert.strictEqual(list.json.count, 2);
  const onDisk = srv.readUsersFile().api_keys.find((k) => k.key === add.json.key);
  assert.ok(onDisk && onDisk.account_id === 'acct_team_firm', 'persisted under the account');
  const free = await srv.post('/v2/team/add-device', { headers: { 'X-Api-Key': FREE }, body: { label: 'x' } });
  assert.strictEqual(free.status, 403);
  assert.strictEqual(free.json.error, 'tier_upgrade_required');
  await srv.stop();
  checks++;
});
