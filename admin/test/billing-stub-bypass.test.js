'use strict';
// Proves the no-payment plan-grant bypass is closed. Two layers:
//   1) behavioral -- the shipped handler returns 410 and can grant nothing;
//   2) structural -- the live user-facing billing routes in server.js are wired
//      to that handler and no longer reach /v2/admin/keys/update-plan, while the
//      legitimate admin path is left intact.
// Run: node --test admin/test/billing-stub-bypass.test.js

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { billingStubGone } = require('../lib/billing-stub');

// Minimal express-style res double that records what the handler did.
function fakeRes() {
  const rec = { statusCode: null, body: null };
  return {
    _rec: rec,
    status(code) { rec.statusCode = code; return this; },
    json(obj) { rec.body = obj; return this; },
  };
}

test('stub confirm handler grants nothing and returns 410 Gone', () => {
  // A logged-in free user replaying the old confirm call: pretend they even
  // forged a completed checkout session in the body -- the handler ignores it.
  const req = {
    userSession: { user_id: 'pgp_victim', email: 'free@example.com' },
    params: { token: 'deadbeef' },
    body: { plan_id: 'pro', period: 'yearly' },
  };
  const res = fakeRes();
  billingStubGone(req, res);

  assert.strictEqual(res._rec.statusCode, 410, 'must answer 410 Gone');
  assert.strictEqual(res._rec.body.error, 'billing_stub_removed');
  // The handler signature is (req, res) only: it holds no relay/admin token and
  // exposes no code path that could call update-plan. Grant is impossible.
  assert.strictEqual(billingStubGone.length, 2, 'handler takes only (req, res)');
});

test('server.js wires the user billing routes to the disabled handler', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

  for (const route of [
    'api.post("/user/billing/checkout", authUser, billingStubGone);',
    'api.get("/user/billing/checkout/:token", authUser, billingStubGone);',
    'api.post("/user/billing/checkout/:token/confirm", authUser, billingStubGone);',
  ]) {
    assert.ok(src.includes(route), `route must be disabled: ${route}`);
  }

  // The old stub grant path must be gone from the user-facing region: no
  // async checkout/confirm handler bodies, no stub audit marker.
  assert.ok(
    !src.includes("api.post(\"/user/billing/checkout\", authUser, async"),
    'old async checkout handler body must be removed',
  );
  assert.ok(
    !src.includes("via: 'stub_checkout'"),
    'stub_checkout audit marker must be gone',
  );
});

test('legitimate admin change-plan path is left intact', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  // Admin-authenticated plan changes still use update-plan; we only killed the
  // user-facing stub, not the admin tool.
  assert.ok(
    src.includes("api.post('/admin/change-plan', authMiddleware"),
    'admin/change-plan endpoint must still exist',
  );
  assert.ok(
    src.includes("callRelay('/v2/admin/keys/update-plan', { key, plan: new_plan })"),
    'admin/change-plan must still reach update-plan',
  );
});
