'use strict';
// THE COUNTER ATOMICITY GATE. A limit that is read, decided and then written is
// not a limit. It is a suggestion that holds until two people arrive together.
//
// WHY THIS EXISTS. The 2026-09-05 hostile review, finding 8. Both quota gates
// were written like this:
//
//     const cur = parseInt((await redisClient.get(signsKey(accountId))) || '0', 10);
//     if (cur >= limit) return { allowed: false, ... };
//     const n = await incrInWindow(redisClient, signsKey(accountId), MONTH_TTL_SECONDS);
//
// The counter stands at 1, the plan sells 2, ten requests arrive together. All
// ten read 1. All ten find room. All ten count. Eleven signatures on a plan that
// sells two, and nothing anywhere logs a complaint. On the live sign route the
// two halves were not even adjacent: the read and the increment sat 38 lines and
// a whole ML-DSA-65 verification apart, which is a window wide enough to hit by
// accident on a slow day.
//
// The house already knew. lib/coupon.js does cap, expiry, revocation, double-use
// and the tally in one Lua script, and the comment above it says, a month
// earlier, exactly what was wrong here: "A JavaScript version of this reads the
// count, decides, and writes, and two requests that read the same 99 both write
// a hundredth seat." The right answer was already in the building; the quota
// gates just never got it.
//
// WHAT MAKES THIS A CLASS. The bug is not "gateSign was wrong". It is a shape
// that reads as careful code, is invisible in any sequential test, and is one
// copy-paste away from the next counter someone adds. So this gate comes at it
// twice:
//
//   BEHAVIOUR  fire limit+N requests at a cap AT THE SAME TIME and count how
//              many got through. Sequential tests cannot see this bug at all,
//              which is why it survived a suite that already tested the cap.
//   SHAPE      scan lib/ for a counter that is read and later written in the
//              same function with an await in between. That catches the next
//              one before it ships, including on counters that have no route to
//              fire concurrent requests at yet.
//
// HOW TO ANSWER A RED
//   Do the deciding and the writing in one redis round trip. There is a worked
//   example in lib/coupon.js (CLAIM_LUA) and two more in lib/quota.js. If the
//   thing being counted can fail after the count, take the slot first and give
//   it back on failure, the way the sign route does with quota.releaseSign; do
//   not move the count back after the work, because that is this bug again.
//
// NEEDS a reachable redis (the counters are redis, and a fake one cannot race).
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/counter-atomicity-gate.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const quota = require('../lib/quota');
const { requireRedis, summary } = require('./_requires');

const ROOT = path.join(__dirname, '..');
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const RUN = crypto.randomBytes(6).toString('hex');

let rc = null;
let checks = 0;
const did = () => { checks++; };
const written = [];
let _n = 0;
const acct = () => { _n++; return `acct_atomic_${RUN}_${_n}`; };
const track = (...keys) => { written.push(...keys); };

before(async () => { rc = await requireRedis(DEFAULT_REDIS); });
after(async () => {
  if (rc) {
    for (const k of written) { try { await rc.del(k); } catch (_) {} }
    try { await rc.disconnect(); } catch (_) {}
  }
  summary('counter-atomicity-gate', checks);
});

// ── The property, stated once ────────────────────────────────────────────────
// Fire `attempts` gate calls with no await between them, so they are in flight
// together, and count the allows. A correct gate lets exactly `room` through no
// matter how many asked. A read-then-write gate lets nearly all of them
// through, because they all read the same starting number.
async function raceFor(gate, key, start, limit, attempts) {
  await rc.set(key, String(start));
  const results = await Promise.all(Array.from({ length: attempts }, () => gate()));
  const allowed = results.filter((r) => r.allowed).length;
  const counter = parseInt((await rc.get(key)) || '0', 10);
  return { allowed, counter };
}

test('concurrent signs cannot share one slot', async () => {
  if (!rc) return;
  const a = acct();
  const key = quota.signsKey(a);
  track(key);
  const LIMIT = 2;
  const START = 1;                 // one signature used, one left
  const ROOM = LIMIT - START;      // exactly one may get through
  const ATTEMPTS = 10;

  const { allowed, counter } = await raceFor(
    () => quota.gateSign(rc, a, LIMIT, null), key, START, LIMIT, ATTEMPTS);

  assert.strictEqual(allowed, ROOM,
    `${ATTEMPTS} requests arrived together with room for ${ROOM}, and ${allowed} were allowed. ` +
    'This is the whole finding: the cap is only a cap when the reading and the writing are one ' +
    'operation. See lib/coupon.js CLAIM_LUA for the shape that holds.'); did();
  assert.strictEqual(counter, LIMIT,
    `the counter finished at ${counter} for a limit of ${LIMIT}. A counter that overshoots its own ` +
    'cap is the receipt of the race, and it is what the customer is billed against next month.'); did();
});

test('concurrent transfers cannot share one slot', async () => {
  if (!rc) return;
  const a = acct();
  const key = quota.transfersKey(a);
  track(key);
  const LIMIT = 3;
  const START = 2;
  const ATTEMPTS = 12;
  // Distinct chunk hashes: a shared one would legitimately dedup, and dedup
  // passing is not the property under test here.
  let i = 0;
  const hashes = Array.from({ length: ATTEMPTS }, () => crypto.randomBytes(16).toString('hex'));
  for (const h of hashes) track(quota.seenKey(a, h));

  const { allowed, counter } = await raceFor(
    () => quota.gateTransfer(rc, a, hashes[i++], LIMIT, null), key, START, LIMIT, ATTEMPTS);

  assert.strictEqual(allowed, LIMIT - START,
    `${ATTEMPTS} uploads arrived together with room for ${LIMIT - START}, and ${allowed} were allowed`); did();
  assert.strictEqual(counter, LIMIT, 'the transfers counter must not overshoot its cap'); did();
});

test('a race at zero room lets nobody through', async () => {
  if (!rc) return;
  const a = acct();
  const key = quota.signsKey(a);
  track(key);
  const { allowed, counter } = await raceFor(() => quota.gateSign(rc, a, 2, null), key, 2, 2, 8);
  assert.strictEqual(allowed, 0, 'an account already at its cap gets nothing, however hard it asks'); did();
  assert.strictEqual(counter, 2, 'and a refusal does not count'); did();
});

// A reservation that is given back must not become a way to mint units: release
// under concurrency is the mirror of the same bug.
test('releases under concurrency give back exactly what was taken', async () => {
  if (!rc) return;
  const a = acct();
  const key = quota.signsKey(a);
  track(key);
  await rc.set(key, '5');
  await Promise.all(Array.from({ length: 5 }, () => quota.releaseSign(rc, a, null)));
  assert.strictEqual(parseInt(await rc.get(key), 10), 0, 'five releases against five units land on zero'); did();
  await Promise.all(Array.from({ length: 5 }, () => quota.releaseSign(rc, a, null)));
  assert.strictEqual(parseInt((await rc.get(key)) || '0', 10), 0,
    'and five more must not go negative, because a negative counter is free units for the next caller'); did();
});

// ── The shape, so the next counter does not have to be caught in production ──
// Narrow on purpose, in the spirit of authz-omission-gate.test.js: it looks for
// the exact thing that was written here, and a hit therefore means something.
// A read of a redis counter, and later in the SAME function a write to a key
// built the same way, with an await between them.
const COUNTER_READ = /(?:const|let)\s+\w+\s*=\s*(?:parseInt\()?\s*\(?\s*await\s+\w+\.get\(\s*(\w+Key)\s*\(/g;
const COUNTER_WRITE = /(?:await\s+\w+\.(?:incr|set|decr)\(|await\s+incrInWindow\()/;

// Files that hold a counter someone can spend. Not the whole tree: a gate that
// scans everything gets noisy, and noise is how a gate stops being read.
const SCAN = ['lib/quota.js', 'lib/coupon.js', 'lib/redis-counter.js', 'lib/rate-limit.js'];

// Known-good shapes that LOOK like the bug and are not. Exact counts, so a
// fourth copy of an allowed shape is a new finding rather than a free pass.
//
// EMPTY, and meant to stay empty. There is no counter left in these four files
// that reads, decides and writes as separate steps, so there is nothing here
// with a reason attached. readUsage() in lib/quota.js reads two counters and is
// the obvious candidate, but it decides nothing (it feeds the usage display and
// the 200 body) and it writes nothing, so the scan does not see it and it needs
// no entry. An entry appearing here is a deliberate exception and has to carry a
// reason a reader can check, not a note that it was inconvenient.
const ALLOW = [];

// The body of the function containing `idx`, by brace matching backwards to the
// nearest function head.
function enclosingFunction(code, idx) {
  const head = code.lastIndexOf('function ', idx);
  if (head === -1) return { name: '<top>', body: '' };
  const name = (code.slice(head + 9, code.indexOf('(', head)) || '').trim();
  const open = code.indexOf('{', code.indexOf('(', head));
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') { depth--; if (depth === 0) return { name, body: code.slice(open, i + 1), start: open }; }
  }
  return { name, body: code.slice(open), start: open };
}

// Comments and string bodies blanked, line count preserved, so a hit is code and
// a reported line number is usable. Same approach as the omission gate.
function stripNonCode(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, (m, p1) => p1 + ' '.repeat(m.length - p1.length))
    .replace(/`(?:[^`\\]|\\.)*`/g, (m) => m.replace(/[^\n]/g, ' '));
}

test('no counter is read, decided on, and written in three separate breaths', () => {
  const hits = [];
  const used = new Map();

  for (const rel of SCAN) {
    const raw = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const code = stripNonCode(raw);
    COUNTER_READ.lastIndex = 0;
    for (let m; (m = COUNTER_READ.exec(code)) !== null;) {
      const fn = enclosingFunction(code, m.index);
      const after = fn.body.slice(m.index - (fn.start || 0));
      if (!COUNTER_WRITE.test(after)) continue;
      const line = code.slice(0, m.index).split('\n').length;
      const rule = ALLOW.find((a) => a.file === rel && a.fn === fn.name);
      if (rule) { used.set(rule, (used.get(rule) || 0) + 1); continue; }
      hits.push(`  ${rel}:${line}  ${fn.name}()  reads ${m[1]}(...) and later writes it`);
    }
  }

  assert.deepStrictEqual(hits, [],
    'A counter is read, decided on and written as separate steps:\n' + hits.join('\n') +
    '\n\nTwo requests that read the same number both write the next one. Put the read, the ' +
    'comparison and the increment in one redis round trip: lib/coupon.js CLAIM_LUA is the worked ' +
    'example, and lib/quota.js GATE_SIGN_LUA is the smallest one. Only allowlist it above if the ' +
    'read genuinely decides nothing, and say so in a way a reader can check.');

  for (const rule of ALLOW) {
    const seen = used.get(rule) || 0;
    assert.strictEqual(seen, rule.count,
      `${rule.file}: ${rule.fn}() is allowlisted ${rule.count}x and now matches ${seen}x. ` +
      (seen > rule.count
        ? 'A new copy of an allowed shape is a new finding: check it, do not raise the count.'
        : 'It was fixed or moved: lower the count so the rest stays visible.'));
  }
});

test('the shape half fires on the pattern it is meant to catch, and not on the fix', () => {
  const broken = `
    async function gateSign(redisClient, accountId, limit) {
      const cur = parseInt((await redisClient.get(signsKey(accountId))) || '0', 10);
      if (cur >= limit) return { allowed: false };
      const n = await incrInWindow(redisClient, signsKey(accountId), 100);
      return { allowed: true, used: n };
    }
  `;
  const fixed = `
    async function gateSign(redisClient, accountId, limit) {
      const r = _gateResult(await redisClient.eval(GATE_SIGN_LUA, {
        keys: [signsKey(accountId)], arguments: [String(limit), '100'],
      }));
      if (r.status === 'over') return { allowed: false, used: r.used };
      return { allowed: true, used: r.used };
    }
  `;
  const scanSource = (src) => {
    const code = stripNonCode(src);
    const out = [];
    COUNTER_READ.lastIndex = 0;
    for (let m; (m = COUNTER_READ.exec(code)) !== null;) {
      const fn = enclosingFunction(code, m.index);
      if (COUNTER_WRITE.test(fn.body.slice(m.index - (fn.start || 0)))) out.push(fn.name);
    }
    return out;
  };
  assert.deepStrictEqual(scanSource(broken), ['gateSign'],
    'the gate must catch read-decide-write, which is the code that shipped');
  assert.deepStrictEqual(scanSource(fixed), [],
    'and must stay quiet on the one-round-trip version');
});
