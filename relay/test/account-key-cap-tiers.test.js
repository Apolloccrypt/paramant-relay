'use strict';
// API-10-A: a paying account (ParaSign Pro + ParaSend Pro, as a payment sets
// them) kept the unified plan 'community' and so the five-key cap; its fifth
// key was refused. The cap follows the account's highest paid tier now.
const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const kt = require('../lib/keys-table');

test('computeOverLimit asks capForAccount, which sees the whole account', () => {
  const apiKeys = new Map(); const accountKeys = new Map([['acct', new Set()]]);
  for (let i = 0; i < 8; i++) { apiKeys.set('k' + i, { active: true, account_id: 'acct' }); accountKeys.get('acct').add('k' + i); }
  const accounts = new Map([['acct', { plan: 'community' }]]);
  const planOnly = kt.computeOverLimit(apiKeys, accounts, accountKeys, { capForPlan: () => 5 });
  assert.strictEqual(planOnly.size, 3, 'with the legacy plan alone three keys are over');
  const withAccount = kt.computeOverLimit(apiKeys, accounts, accountKeys, { capForPlan: () => 5, capForAccount: () => 100 });
  assert.strictEqual(withAccount.size, 0, 'a paying account is not over at eight');
});

test('relay.js routes every cap through accountKeyCap, and business has a row', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
  assert.match(src, /capForAccount: \(accountId, p\) => accountKeyCap\(accountId, p\)\.cap/);
  const block = src.slice(src.indexOf('const ACCOUNT_KEY_LIMIT = Object.freeze({'), src.indexOf('});', src.indexOf('const ACCOUNT_KEY_LIMIT')));
  assert.match(block, /business:/);
  assert.match(src, /function accountCapPlan\(accountId, legacyPlan\)[\s\S]{0,600}effectiveProductTier/);
  assert.doesNotMatch(src, /const _capPlan = tiers\.normalisePlan\(\(acct && acct\.plan\) \|\| plan\);/);
});
