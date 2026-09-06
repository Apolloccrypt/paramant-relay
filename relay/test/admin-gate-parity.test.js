'use strict';
// THE ADMIN GATE PARITY GATE. A /v2/admin route that MOVES an entitlement, or
// MINTS a credential, may not stand behind fewer gates than its neighbour.
//
// WHY THIS EXISTS. The 2026-09-05 hostile review filed it as an asymmetry with
// "no escalation": set-product-plan carried both ADMIN_TOKEN and X-Internal-Auth,
// mint-parasign carried only the first. Looked at again on 2026-09-06 the
// asymmetry was wider than filed (set-parasign was single-gated too) and the
// "no escalation" was too generous: mint-parasign passed `plan` from the body
// straight through, and on an account with no per-product plan on record
// {"plan":"enterprise"} minted an enterprise key with no paid_until, which the
// entitlement layer reads as never expiring.
//
// Neither half is interesting as a pair of individual bugs. What is interesting
// is that four routes doing the same kind of thing drifted into two different
// gate shapes over months, and nothing said so. Asserting "mint-parasign has
// _internalOk" catches the case. This catches the class:
//
//   ENUMERATE every POST handler under /v2/admin in relay.js.
//   CLASSIFY it as mutating if its body writes an entitlement or mints a key.
//   REQUIRE  every mutating one to carry _internalOk() and to leave an audit
//            trail, or to be named in ALLOW with a reason and an exact count.
//
// The exact count is the load-bearing part, as in authz-omission-gate.test.js:
// a fifth single-gated mutating admin route is then red on arrival rather than
// joining an established pattern.
//
// HOW TO ANSWER A RED
//   Add `if (!_internalOk()) return _internalReject();` as the first line of the
//   handler, and an auditAppend for what it changed. If the admin panel calls
//   the route, the caller must send the header too: callRelay in
//   admin/server.js always does, relayFetch only with its `withInternal` flag.
//   Adding a line to ALLOW is the last resort, and it needs a reason a reader
//   can check.
//
// Runs anywhere: no redis, no engine, plain fs.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

// A handler opens with the dispatch line and runs to the matching brace. The
// dispatch shape in relay.js is one long if-chain of exactly this form, so a
// regex finds the openings and a brace walk finds the ends.
const OPEN = /if \(path === '(\/v2\/admin\/[^']+)' && req\.method === '(POST|PUT|PATCH|DELETE)'\) \{/g;

function blockAfter(src, openBraceIdx) {
  let depth = 0;
  for (let i = openBraceIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return src.slice(openBraceIdx, i + 1); }
  }
  return src.slice(openBraceIdx);
}

function handlers() {
  const out = [];
  OPEN.lastIndex = 0;
  let m;
  while ((m = OPEN.exec(SRC)) !== null) {
    const brace = SRC.indexOf('{', m.index + m[0].length - 1);
    out.push({ route: `${m[2]} ${m[1]}`, body: blockAfter(SRC, brace) });
  }
  return out;
}

// What makes a handler MUTATING. Every name here writes an entitlement, a plan,
// an access flag, or mints a credential. A read-only admin route is not this
// class and is not flagged.
const MUTATES = /setProductPlan\(|mintParasignKey\(|_mutateUsersJson\(|\.parasign\s*=|applyProductTier\(|apiKeys\.set\(/;

// Routes allowed to be mutating with only the admin-path fence. Each needs a
// reason a reader can check, and `count` is exact: a route joining or leaving
// this list turns the gate red rather than passing quietly.
const ALLOW = [
  {
    route: 'POST /v2/admin/keys',
    reason: 'The key-issuance route. It predates the internal gate and the admin '
          + 'panel reaches it through relayFetch with the operator session token, '
          + 'not through callRelay. Giving it the second gate means moving four '
          + 'call sites in admin/server.js at once (lines around 322, 338), which '
          + 'is a change of its own and not a rider on a review round.',
  },
  {
    route: 'POST /v2/admin/keys/revoke',
    reason: 'Same caller and same reason as /v2/admin/keys. Revoking is the safe '
          + 'direction: worst case a leaked ADMIN_TOKEN turns a key off.',
  },
];

test('every mutating /v2/admin POST carries the second gate, or is named with a reason', () => {
  const found = handlers().filter((h) => MUTATES.test(h.body));
  assert.ok(found.length >= 4, `only ${found.length} mutating admin handlers found; the scanner is broken`);

  const allowed = new Set(ALLOW.map((a) => a.route));
  const offenders = [];
  for (const h of found) {
    if (/_internalOk\(\)/.test(h.body)) continue;
    if (allowed.has(h.route)) continue;
    offenders.push(h.route);
  }
  assert.deepStrictEqual(offenders, [], `mutating admin route(s) behind one gate only:\n  ${offenders.join('\n  ')}`);
});

test('the ALLOW list is exact: every entry still names a real single-gated route', () => {
  const found = handlers().filter((h) => MUTATES.test(h.body) && !/_internalOk\(\)/.test(h.body));
  const names = new Set(found.map((h) => h.route));
  const stale = ALLOW.filter((a) => !names.has(a.route)).map((a) => a.route);
  assert.deepStrictEqual(stale, [], `ALLOW names route(s) that are no longer single-gated; remove them:\n  ${stale.join('\n  ')}`);
  assert.strictEqual(found.length, ALLOW.length, `expected exactly ${ALLOW.length} single-gated mutating admin routes, found ${found.length}: ${[...names].join(', ')}`);
  for (const a of ALLOW) assert.ok(a.reason && a.reason.length > 40, `${a.route} has no usable reason`);
});

test('a route that mints a credential leaves an audit trail', () => {
  const minting = handlers().filter((h) => /mintParasignKey\(|apiKeys\.set\(/.test(h.body));
  assert.ok(minting.length >= 2, `only ${minting.length} minting admin handlers found`);
  const silent = minting.filter((h) => !/auditAppend\(|log\('info'/.test(h.body)).map((h) => h.route);
  assert.deepStrictEqual(silent, [], `admin route(s) mint a credential and record nothing:\n  ${silent.join('\n  ')}`);
});

test('mint-parasign does not take a tier from the request body', () => {
  // The specific shape behind the "no escalation" that was not quite true. A
  // mint route must derive the tier from what the account holds, never from
  // what the caller typed: there is no legitimate reason to mint a key above
  // the account, and set-product-plan (which validates against the ladder) is
  // the route for changing what the account holds.
  const h = handlers().find((x) => x.route === 'POST /v2/admin/keys/mint-parasign');
  assert.ok(h, 'mint-parasign handler not found');
  assert.doesNotMatch(h.body, /plan:\s*d\.plan/, 'mint-parasign passes a caller-supplied plan into the mint');
  assert.match(h.body, /_internalOk\(\)/);
});

test('self-test: the scanner really reads handler bodies, and can go red', () => {
  const all = handlers();
  assert.ok(all.length >= 10, `only ${all.length} admin write handlers found; the OPEN regex has drifted`);
  // Bodies must be balanced and non-trivial, otherwise MUTATES would match
  // nothing and every assertion above would pass over an empty set.
  for (const h of all) {
    assert.ok(h.body.length > 40, `${h.route} sliced to ${h.body.length} chars`);
    const opens = (h.body.match(/\{/g) || []).length;
    const closes = (h.body.match(/\}/g) || []).length;
    assert.strictEqual(opens, closes, `${h.route} brace walk unbalanced`);
  }
  // And the classifier separates: not everything is mutating, or the gate would
  // be asserting something about the whole file rather than about a class.
  const mutating = all.filter((h) => MUTATES.test(h.body)).length;
  assert.ok(mutating > 0 && mutating < all.length, `classifier picked ${mutating} of ${all.length}`);
});
