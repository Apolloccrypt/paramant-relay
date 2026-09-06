'use strict';
// THE KEYSPACE SCAN GATE. A route a customer can call must not make the shared
// Redis walk its whole keyspace.
//
// WHY THIS EXISTS. Finding 14 of the 2026-09-05 hostile review. Eight places in
// admin/server.js answered "which sessions belong to this user?" by scanning
// paramant:user:session:* across the entire keyspace and GETting every key that
// came back, filtering on user_id afterwards. One of them was
// GET /api/user/account, which the account screen calls on every load, behind no
// rate limit and no cache, against the Redis that all five relay sectors and the
// admin plane share. One free account plus a loop is a fleet-wide load
// generator, and the cost grows with the customer base rather than with the
// caller.
//
// It is also a privacy shape nobody chose. To show you your own two sessions,
// the process read every other customer's session blob -- their IP, their user
// agent -- and discarded them after the comparison.
//
// The repair is a per-user index (admin/lib/user-sessions.js). The gate is not
// "the session scan is gone": that catches the case, and the same shape is one
// commit away for audit events, for setup tokens, for whatever is indexed next.
//
// WHAT IT REQUIRES
//   S1  no wildcard SCAN sits in a handler reachable with a user session
//       (authUser) or with no authentication at all, unless it is named in
//       ALLOW with a reason and an exact count.
//   S2  GET /api/user/account in particular contains no wildcard MATCH. It is
//       the one a customer can call in a loop from a browser.
//
// An admin route (authMiddleware, ADMIN_TOKEN) may scan: the operator is not a
// threat model here and the routes are hand-driven, not polled.
//
// Runs anywhere: no redis, plain fs.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const LINES = SRC.split('\n');

// A scan over a pattern rather than over a known key.
// `[\s\S]{0,160}?` and not `[^)]*`: the first argument is usually `redis()`, so
// a pattern that cannot cross a closing paren never reaches the MATCH string and
// matches nothing at all -- which reads as a clean scan.
const WILDCARD = /(scanKeys|scanIterator|\.keys)\s*\([\s\S]{0,160}?['"`][^'"`]*\*/;

// Routes whose middleware chain is the operator's. Everything else in this file
// is either a customer route or an unauthenticated one.
const ADMIN_GUARD = /authMiddleware/;

// Module-level helpers that scan. A route that calls one of these is scanning
// too, and moving the loop out of the handler is exactly how a repair passes a
// naive gate: the setup-token scan of finding 15 ended up in issueSetupToken
// before this rule existed. One level of call graph, which is what these
// helpers are.
function scanningHelpers(lines = LINES) {
  const out = [];
  const decl = /^\s*(?:async\s+)?function\s+(\w+)\s*\(/;
  lines.forEach((l, i) => {
    const m = decl.exec(l);
    if (!m) return;
    let d = 0; let end = lines.length - 1;
    for (let j = i; j < lines.length; j++) {
      d += (lines[j].match(/\{/g) || []).length - (lines[j].match(/\}/g) || []).length;
      if (j > i && d <= 0) { end = j; break; }
    }
    if (WILDCARD.test(lines.slice(i, end + 1).join('\n'))) out.push(m[1]);
  });
  return out;
}

// Reachable by a customer or by nobody, and still scanning. Exact count.
const ALLOW = [];

function routes() {
  const out = [];
  const open = /^\s*api\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]\s*,?\s*(.*)$/;
  LINES.forEach((l, i) => {
    const m = open.exec(l);
    if (!m) return;
    // The handler runs to the line that closes it at the same indentation.
    let d = 0; let end = LINES.length - 1;
    for (let j = i; j < LINES.length; j++) {
      d += (LINES[j].match(/\(/g) || []).length - (LINES[j].match(/\)/g) || []).length;
      if (j > i && d <= 0) { end = j; break; }
    }
    const head = LINES.slice(i, Math.min(i + 3, LINES.length)).join(' ');
    out.push({
      name: `${m[1].toUpperCase()} ${m[2]}`,
      admin: ADMIN_GUARD.test(head),
      body: LINES.slice(i, end + 1).join('\n'),
      line: i + 1,
    });
  });
  return out;
}

test('the route scanner finds the routes at all', () => {
  const r = routes();
  assert.ok(r.length > 60, `only ${r.length} routes found; the scanner has drifted`);
  assert.ok(r.some((x) => x.name === 'GET /user/account'), 'the account route was not found');
  assert.ok(r.some((x) => x.admin), 'no admin-guarded route was recognised');
  assert.ok(r.some((x) => !x.admin), 'every route was classified as admin');
});

test('no customer-reachable route walks the whole keyspace', () => {
  const allowed = new Set(ALLOW.map((a) => a.route));
  const helpers = scanningHelpers();
  const offenders = [];
  for (const r of routes()) {
    if (r.admin) continue;
    const direct = WILDCARD.test(r.body);
    const viaHelper = helpers.find((h) => new RegExp(`\\b${h}\\s*\\(`).test(r.body));
    if (!direct && !viaHelper) continue;
    if (allowed.has(r.name)) continue;
    offenders.push(`admin/server.js:${r.line} ${r.name}${viaHelper ? ` (through ${viaHelper}())` : ''}`);
  }
  assert.deepStrictEqual(offenders, [], `a customer can make the shared redis walk its keyspace:\n  ${offenders.join('\n  ')}`);
});

test('the ALLOW list is exact and reasoned', () => {
  const helpers = scanningHelpers();
  const scanning = routes()
    .filter((r) => !r.admin && (WILDCARD.test(r.body) || helpers.some((h) => new RegExp(`\\b${h}\\s*\\(`).test(r.body))))
    .map((r) => r.name);
  assert.deepStrictEqual([...new Set(scanning)].sort(), ALLOW.map((a) => a.route).sort(),
    'the set of customer-reachable scanning routes has changed. Index it, or add it\n'
    + 'here with a reason; remove an entry that has been closed.');
  for (const a of ALLOW) assert.ok(a.reason && a.reason.length > 80, `${a.route} has no usable reason`);
});

test('the account screen holds no wildcard at all', () => {
  // The one a browser polls. Pinned separately from the class rule so moving it
  // between middleware chains cannot make it pass.
  const r = routes().find((x) => x.name === 'GET /user/account');
  assert.ok(r, 'GET /user/account is gone');
  assert.doesNotMatch(r.body, WILDCARD, 'the account screen scans the keyspace again');
  assert.match(r.body, /userSessions\.list\(/, 'the account screen no longer reads its sessions from the index');
});

test('every session write and delete goes through the index', () => {
  // A session written with a bare redis().set is invisible to its owner and
  // survives every revocation, which is worse than the scan it replaced.
  const bare = [];
  LINES.forEach((l, i) => {
    if (/paramant:user:session:/.test(l) && /redis\(\)\.(set|del)\(/.test(l)) {
      bare.push(`admin/server.js:${i + 1} ${l.trim().slice(0, 100)}`);
    }
  });
  assert.deepStrictEqual(bare, [], `a session written or deleted outside the index:\n  ${bare.join('\n  ')}`);
  assert.match(SRC, /userSessions\.remember\(/, 'nothing writes a session through the index');
  assert.match(SRC, /userSessions\.revokeAll\(/, 'nothing revokes through the index');
});

test('self-test: a scan hidden in a helper is still a scan', () => {
  // The rule that has to survive the next repair. Moving the loop out of the
  // handler and into a function is what happened to the setup-token scan while
  // finding 15 was being fixed, and a gate that only reads handler bodies would
  // have gone green on it.
  const synthetic = [
    'async function purgeTokens(userId) {',
    "  for await (const k of scanKeys(redis(), { MATCH: 'paramant:user:setup_token:*', COUNT: 100 })) {",
    '    await redis().del(k);',
    '  }',
    '}',
  ];
  assert.deepStrictEqual(scanningHelpers(synthetic), ['purgeTokens'], 'the helper detector missed a scanning helper');
  const clean = ['async function readOne(t) {', '  return redis().get(`paramant:user:setup_token:${t}`);', '}'];
  assert.deepStrictEqual(scanningHelpers(clean), [], 'the helper detector flags a plain get');
});

test('self-test: the wildcard pattern separates a scan from a plain get', () => {
  assert.strictEqual(WILDCARD.test("scanKeys(redis(), { MATCH: 'paramant:user:session:*', COUNT: 100 })"), true);
  assert.strictEqual(WILDCARD.test('scanKeys(r, { MATCH: match, COUNT: 100 })'), false, 'a variable pattern is not evidence either way');
  assert.strictEqual(WILDCARD.test('redis().get(`paramant:user:session:${token}`)'), false);
  assert.strictEqual(WILDCARD.test("redis().sMembers('paramant:user:sessions:acct')"), false);
});
