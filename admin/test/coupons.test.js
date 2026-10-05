'use strict';
// The panel's three coupon routes, read as source.
//
// WHY SOURCE AND NOT HTTP. These handlers need a session, a redis and a live
// relay to reach, and the properties that matter here are structural rather
// than behavioural: they are the ones a later edit can quietly drop while every
// request still returns 200. Three of them:
//
//   1. authMiddleware on all three. A coupon raises a paid tier without a
//      payment, so minting one is the ability to give the product away. An
//      unauthenticated route here is worse than an unauthenticated /admin/audit.
//   2. the withdraw carries the code IN THE PATH and sends no body. The relay's
//      admin gate refuses an unauthenticated request before reading the body,
//      and a DELETE whose bytes are still on the wire desynchronises a
//      kept-alive connection: the NEXT request on it is answered by a socket
//      that has lost its place. Proved by hand against a booted relay while
//      this branch was open.
//   3. creating and withdrawing are written to the audit log. Every other plan
//      change is, and a gift is a plan change with no invoice behind it, so it
//      is the one that most needs a trail.
//
// Run: node --test admin/test/coupons.test.js

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

function routeSource(start, end) {
  const from = src.indexOf(start);
  assert.ok(from >= 0, `route marker missing: ${start}`);
  const to = src.indexOf(end, from + start.length);
  assert.ok(to > from, `end marker missing after ${start}: ${end}`);
  return src.slice(from, to);
}

test('all three coupon routes sit behind the admin session', () => {
  for (const decl of [
    "api.get('/admin/coupons', authMiddleware",
    "api.post('/admin/coupons', authMiddleware",
    "api.delete('/admin/coupons/:code', authMiddleware",
  ]) {
    assert.ok(src.includes(decl),
      `${decl} is not declared with authMiddleware; minting a code is the ability to give the product away`);
  }
});

test('the panel never holds ADMIN_TOKEN: every hop goes out on req.sessionToken', () => {
  const routes = routeSource("api.get('/admin/coupons'", "api.get(\"/admin/relay-detail\"");
  // Split rather than match: the DELETE hop interpolates encodeURIComponent(),
  // so a regex that stops at the first bracket reads half a call.
  const hops = routes.split('relayFetch(').slice(1).map((s) => s.slice(0, s.indexOf(');')));
  assert.strictEqual(hops.length, 3, `expected three relay hops, found ${hops.length}`);
  for (const hop of hops) {
    assert.ok(hop.includes('req.sessionToken'),
      `a coupon route calls the relay without the session's token: ${hop}`);
    assert.ok(hop.includes("'health'"),
      `a coupon route addresses a sector other than health: ${hop}. Coupons live in the shared redis, so one sector answers for all five and a fan-out would only invent five answers to a question with one`);
  }
});

test('the withdraw carries the code in the path and sends no body', () => {
  const route = routeSource("api.delete('/admin/coupons/:code'", 'api.get("/admin/relay-detail"');
  assert.match(route, /req\.params\.code/, 'the code must come out of the path');
  assert.match(route, /\/v2\/admin\/coupons\/\$\{encodeURIComponent\(code\)\}/,
    'the relay path must carry the code, encoded');
  // The fourth argument to relayFetch is the body. It has to be null here: a
  // DELETE body the relay refuses before reading leaves bytes on the wire.
  assert.match(route, /relayFetch\('health',[^,]+,\s*'DELETE',\s*null,/,
    'the withdraw must send no body; a refused DELETE body desynchronises the connection');
  assert.ok(!route.includes('req.body'),
    'the withdraw reads req.body; the code belongs in the path');
  // And a code that is not a code never reaches the relay at all.
  assert.match(route, /\[A-Z0-9-\]\{3,32\}/, 'the code shape must be checked before the hop');
});

test('creating and withdrawing a code are written to the audit log', () => {
  const create = routeSource("api.post('/admin/coupons'", "api.delete('/admin/coupons/:code'");
  assert.match(create, /logAuditEvent\('admin', 'admin_coupon_created'/,
    'a code that gives the product away must leave a trail');
  assert.match(create, /r\.status === 201/,
    'the audit line must only be written when the relay actually created it');

  const revoke = routeSource("api.delete('/admin/coupons/:code'", 'api.get("/admin/relay-detail"');
  assert.match(revoke, /logAuditEvent\('admin', 'admin_coupon_revoked'/);
  assert.match(revoke, /r\.status === 200/);
});

test('the two mutations are rate limited, like every other admin mutation', () => {
  for (const [marker, end] of [
    ["api.post('/admin/coupons'", "api.delete('/admin/coupons/:code'"],
    ["api.delete('/admin/coupons/:code'", 'api.get("/admin/relay-detail"'],
  ]) {
    const route = routeSource(marker, end);
    assert.match(route, /checkAdminRl\('coupons', 'admin', \d+\)/,
      `${marker} has no rate limit; a mint loop is a way to hand out the product`);
    assert.match(route, /rate_limited/);
  }
});
