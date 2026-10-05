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
    const payload = body.slice(json, json + 1200);
    // The helper may be spread straight into the body, or bound to a const
    // first when the handler also needs the values for something else (
    // /user/billing/status derives access_until from paid_until_*). Both are
    // the same guarantee, so both are accepted, but a spread through a const
    // only counts when that const really is the helper's result: a name that
    // holds something else would drop fields just as quietly as a missing
    // spread, which is the whole failure this test exists to catch.
    let spread = /\.\.\.productPlanFields\(/.test(payload);
    if (!spread) {
      for (const m of payload.matchAll(/\.\.\.([A-Za-z_$][\w$]*)\b/g)) {
        const bound = new RegExp(`(?:const|let|var)\\s+${m[1]}\\s*=\\s*productPlanFields\\(`);
        if (bound.test(body.slice(0, json))) { spread = true; break; }
      }
    }
    assert.ok(spread,
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

// ── The two usage endpoints ask the relay for the ceilings ──────────────────
//
// Same rule as above, one layer down: the unified `plan` may not decide a
// number a customer reads. /api/user/dashboard/overview and
// /api/user/developer/snapshot used to look the account up by email, take its
// `plan`, and run it through a tier table copied into admin/lib. That table had
// no `business` row and the field it was keyed on never moves on a purchase, so
// a ParaSign Pro customer was shown "2 signatures" where the relay grants 100.
//
// The relay owns the tiers and enforces them, so the relay is asked. This is a
// source-text test because reaching these handlers needs Redis, a session
// cookie and a live relay; what can go wrong is the lookup quietly reverting to
// the plan field, and that is what source inspection catches.
// admin/test/developer-snapshot.test.js pins the resulting numbers.
test('the usage endpoints read caps from the relay, not from a plan field', () => {
  for (const route of ['"/user/dashboard/overview"', '"/user/developer/snapshot"']) {
    const start = SERVER.indexOf(`api.get(${route}`);
    assert.notEqual(start, -1, `admin/server.js must serve GET ${route}`);
    const body = SERVER.slice(start, start + 1600);
    const handler = body.slice(0, body.indexOf('\n});') + 1);

    assert.match(handler, /readAccountEntitlements\(/,
      `GET ${route} must ask the relay for this account's entitlements`);
    assert.match(handler, /entitlements:\s*ents\b/,
      `GET ${route} must hand those entitlements to buildSnapshot`);
    assert.doesNotMatch(handler, /\bplan\s*[=:]/,
      `GET ${route} must not resolve a plan of its own; the caps come per product from the relay`);
    assert.match(handler, /entitlements_unavailable/,
      `GET ${route} must refuse rather than render a guessed cap when the relay cannot answer`);
  }
});

test('readAccountEntitlements reads the relay endpoint and returns null on failure', () => {
  const start = SERVER.indexOf('async function readAccountEntitlements(');
  assert.notEqual(start, -1, 'admin/server.js must define readAccountEntitlements()');
  const fn = SERVER.slice(start, start + 1200);
  assert.match(fn, /\/v2\/admin\/entitlements\//,
    'it must read GET /v2/admin/entitlements/:account_id, the relay\'s own entitlement answer');
  assert.match(fn, /return null/,
    'an unreachable or unhappy relay must yield null, so the caller can refuse instead of guess');
});
