'use strict';
// Deleting an account must remove the person, not only stop the key.
//
// Audit finding 5 of 2026-07-21: POST /admin/delete-account flipped every key to
// inactive and cleared Redis, and left the email address in users.json on all
// five sectors. An inactive record that still names someone is not erased, and
// article 17 GDPR asks for erasure.
//
// The line this draws: identity goes, financial fact stays. A payment has to
// remain traceable for the tax years it belongs to, so the tier and the paid
// period survive while the email address and the device label do not.
// Run: node relay/test/account-wissen.test.js (exits non-zero on failure).

const assert = require('assert');
const kt = require('../lib/keys-table');

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`ok   ${name}`); }
  catch (e) { console.error(`FAIL ${name}\n     ${e.message}`); process.exitCode = 1; }
}

function users() {
  return {
    accounts: [
      { account_id: 'acct_demo', email: 'demo@example.com', plan: 'pro', label: 'Acme' },
      { account_id: 'acct_other', email: 'other@example.com', plan: 'free' },
    ],
    api_keys: [
      { key: 'pgp_a', account_id: 'acct_demo', email: 'demo@example.com', label: 'laptop',
        active: true, plan_parasend: 'pro', paid_until_parasend: '2026-11-01T00:00:00.000Z' },
      { key: 'pgp_b', account_id: 'acct_demo', email: 'demo@example.com', active: true },
      { key: 'pgp_c', account_id: 'acct_other', email: 'other@example.com', active: true },
    ],
  };
}

// The whole point: after erasure the address must not be findable anywhere.
function contains(data, needle) {
  return JSON.stringify(data).includes(needle);
}

test('the email address is gone from every place it was stored', () => {
  const d = users();
  assert.ok(contains(d, 'demo@example.com'), 'fixture is wrong: the address was never there');
  kt.erasePersonalData(d, 'acct_demo');
  assert.ok(!contains(d, 'demo@example.com'), 'the address survived somewhere in users.json');
});

test('both storage places are covered, the summary and the key records', () => {
  const d = users();
  const out = kt.erasePersonalData(d, 'acct_demo');
  assert.strictEqual(out.accounts, 1);
  assert.strictEqual(out.keys, 2, 'both keys of this account should have been erased');
});

test('the device label goes too, it names a person just as well', () => {
  const d = users();
  kt.erasePersonalData(d, 'acct_demo');
  assert.ok(!contains(d, 'laptop'));
  assert.ok(!contains(d, 'Acme'));
});

test('what a payment must stay traceable by is kept', () => {
  const d = users();
  kt.erasePersonalData(d, 'acct_demo');
  const k = d.api_keys.find((x) => x.key === 'pgp_a');
  assert.strictEqual(k.plan_parasend, 'pro', 'the tier was thrown away with the person');
  assert.strictEqual(k.paid_until_parasend, '2026-11-01T00:00:00.000Z', 'the paid period was thrown away');
  assert.strictEqual(d.accounts.find((a) => a.account_id === 'acct_demo').plan, 'pro');
});

test('an erased key can no longer be used, even without a preceding revoke', () => {
  const d = users();
  kt.erasePersonalData(d, 'acct_demo');
  for (const k of d.api_keys.filter((x) => x.account_id === 'acct_demo')) {
    assert.strictEqual(k.active, false, 'an account with no owner kept a working key');
  }
});

test('another account is left completely alone', () => {
  const d = users();
  kt.erasePersonalData(d, 'acct_demo');
  assert.ok(contains(d, 'other@example.com'), 'erasing one account took another one with it');
  assert.strictEqual(d.api_keys.find((x) => x.key === 'pgp_c').active, true);
});

test('erasing twice is free, so a retry after an unreachable sector is safe', () => {
  const d = users();
  const first = kt.erasePersonalData(d, 'acct_demo');
  const second = kt.erasePersonalData(d, 'acct_demo');
  assert.ok(first.fields > 0);
  assert.deepStrictEqual(second, { accounts: 0, keys: 0, fields: 0 });
});

test('a key id works as well as an account id', () => {
  const d = users();
  const out = kt.erasePersonalData(d, 'pgp_a');
  assert.strictEqual(out.keys, 1);
  assert.ok(!contains(d.api_keys.find((x) => x.key === 'pgp_a'), 'demo@example.com'));
});

test('an erasure leaves a timestamp, so the record shows it was handled', () => {
  const d = users();
  kt.erasePersonalData(d, 'acct_demo');
  assert.ok(d.api_keys.find((x) => x.key === 'pgp_a').erased_at, 'no erased_at on the key');
  assert.ok(d.accounts.find((a) => a.account_id === 'acct_demo').erased_at, 'no erased_at on the account');
});

test('an unknown account changes nothing and does not throw', () => {
  const d = users();
  const before = JSON.stringify(d);
  const out = kt.erasePersonalData(d, 'acct_nope');
  assert.strictEqual(before, JSON.stringify(d));
  assert.strictEqual(out.fields, 0);
});

test('missing or malformed input is tolerated', () => {
  assert.deepStrictEqual(kt.erasePersonalData(null, 'acct_demo'), { accounts: 0, keys: 0, fields: 0 });
  assert.deepStrictEqual(kt.erasePersonalData({}, 'acct_demo'), { accounts: 0, keys: 0, fields: 0 });
  assert.deepStrictEqual(kt.erasePersonalData(users(), null), { accounts: 0, keys: 0, fields: 0 });
});

test('both delete routes in the admin call the erase endpoint', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '../../admin/server.js'), 'utf8');
  const hits = (src.match(/keys\/erase/g) || []).length;
  assert.strictEqual(hits, 2,
    `expected the admin route and the user route to erase, found ${hits} call(s)`);
});

console.log(`\n${passed} passed`);
