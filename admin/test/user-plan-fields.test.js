'use strict';
// A paying customer must not be told he is on the free plan.
//
// The unified `plan` field cannot answer "is this customer paying". The Mollie
// webhook path calls setProductPlan (relay/relay.js), which delegates to
// applyProductTier in relay/lib/entitlements.js, and that function writes ONLY
// plan_parasign / plan_parasend and by design NEVER touches `plan`. So an
// account that buys ParaSign Pro self-serve keeps plan "community" forever.
// Before this change /api/user/me returned `plan` and nothing else, so the
// dashboard showed that customer the Community band and a badge reading
// Community. Measured on the branch, not inferred: the band was gated on the
// unified plan alone.
//
// Three endpoints answer this same question and the dashboard and the account
// page must not read two different truths, so they share one helper. This test
// pins both halves: the helper's shape, and the fact that all three response
// bodies spread it.
//
// Structural rather than behavioural, because reaching these handlers needs
// Redis, a session cookie and a live relay. What can go wrong here is a field
// quietly dropped from one of the three, and that is exactly what source
// inspection catches.
// Run: node --test admin/test/user-plan-fields.test.js

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SERVER = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

const REQUIRED = [
  'plan_parasign',
  'plan_parasend',
  'paid_until_parasign',
  'paid_until_parasend',
];

test('productPlanFields returns both product tiers and both paid-until dates', () => {
  const helper = /function productPlanFields\(rec\) \{[\s\S]*?\n\}/.exec(SERVER);
  assert.ok(helper, 'admin/server.js must define productPlanFields()');
  for (const field of REQUIRED) {
    assert.match(helper[0], new RegExp(`${field}:`), `productPlanFields must return ${field}`);
  }
  // Absent is null, never undefined: a missing key drops out of JSON entirely
  // and the client cannot tell "no tier recorded" from "field not implemented".
  assert.equal((helper[0].match(/\?\? null/g) || []).length, REQUIRED.length,
    'every field must fall back to null, not undefined');
});

test('the three endpoints a signed-in page reads all spread the same helper', () => {
  // /user/me backs the dashboard; /user/account and /user/billing/status back
  // the account page. #332 gates its free-plan copy on the latter two.
  for (const route of ['"/user/me"', '"/user/account"', '"/user/billing/status"']) {
    const start = SERVER.indexOf(`api.get(${route}`);
    assert.notEqual(start, -1, `admin/server.js must serve GET ${route}`);
    const body = SERVER.slice(start, start + 3000);
    const json = body.indexOf('res.json({');
    assert.notEqual(json, -1, `GET ${route} must answer with res.json({...})`);
    assert.match(body.slice(json, json + 1200), /\.\.\.productPlanFields\(/,
      `GET ${route} must spread productPlanFields(), or the dashboard and the account page read different truths`);
  }
});

test('the helper is defined before every use', () => {
  const def = SERVER.indexOf('function productPlanFields(rec)');
  assert.notEqual(def, -1);
  // Hoisting makes this safe at runtime; the check is here so a future move of
  // the helper into a conditional block (which does not hoist) is caught.
  assert.ok(/^function productPlanFields/m.test(SERVER),
    'productPlanFields must stay a top-level function declaration');
});
