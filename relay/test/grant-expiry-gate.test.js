'use strict';
// THE GRANT EXPIRY GATE. An entitlement that is stored as a flag must never be
// read without asking whether the period behind it is still running.
//
// WHY THIS EXISTS. Finding 11 of the 2026-09-05 hostile review: buy one month
// of ParaSign Pro, let it lapse, and POST /v2/user/parasign-keys keeps minting
// keys forever. Reproduced on 2026-09-06 against a booted relay with a term
// that ended five weeks ago: eight mints, and it survived a restart, because
// the flag is persisted.
//
// The shape is worth more than the case. `rec.parasign` is a CACHE of "the
// ParaSign tier is above the floor". entitlements.applyProductTier writes it on
// a purchase and clears it only on an explicit write down to the floor tier.
// Expiry, by design, is enforced on READ (effectiveProductTier) and never
// writes back -- which is the right design, and is exactly why a second copy of
// the same fact, stored as a boolean, goes stale the moment the term ends.
// The relay knew: the entitlements endpoint reported `free` for this account
// the whole time. The gate that decides simply did not ask.
//
// A cache of an expiring fact, read without the expiry, is the class. There is
// one such flag today. This gate is here so there is never a second one that
// nobody notices, and so the first one cannot quietly go back to being read raw.
//
// WHAT IT REQUIRES
//   E1  the two functions that gate on the flag resolve it through
//       parasignGrantLive, which consults effectiveProductTier.
//   E2  nowhere else in the relay or the admin server DECIDES a permission on
//       the raw flag. Reading it to write it (applyProductTier), to report it,
//       or to copy a record is not this bug and is not flagged. The expected
//       answer is an empty list and there is no allow list, because an entry
//       there would be a place where the term does not end.
//   E3  absence still means unbounded. A grant with no recorded period has no
//       term to run out, and reading absence as expiry would downgrade every
//       account from before billing existed.
//
// Runs anywhere: no redis, no engine, plain fs plus the pure functions.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const keysTable = require('../lib/keys-table');
const entitlements = require('../lib/entitlements');

const ROOT = path.join(__dirname, '..', '..');
const FILES = ['relay/relay.js', 'relay/lib/keys-table.js', 'relay/lib/entitlements.js', 'admin/server.js'];

const PAST = new Date(Date.now() - 40 * 86_400_000).toISOString();
const FUTURE = new Date(Date.now() + 40 * 86_400_000).toISOString();

// A read of the stored flag on a RECORD. Deliberately narrow:
//   (?<![)A-Z_])  not `getEntitlements(...).parasign` (that is the answer, not
//                 the cache) and not `PRODUCT_PAID_UNTIL_FIELD.parasign` (a
//                 constant map key).
//   (?![\w.])     not `plan_parasign`, not `ent.parasign.tier`.
//   (?!\s*=[^=])  not a write. Writing the flag is applyProductTier's job and
//                 the one thing that is allowed to treat it as state.
const RAW = /(?<![)A-Z_])\.parasign(?![\w.])(?!\s*=[^=])/;

// A block that DECIDES: it can refuse, or it answers a permission question.
// A read of the flag to copy it, report it, or derive a tier from it is not this
// bug and is not flagged. That is what keeps the gate narrow enough that a hit
// means something.
const DECIDES = /\b(40[123]|not_entitled|unauthorized|forbidden|allowed|entitled)\b/;

// The resolver is where the raw read belongs, and it is named so the gate does
// not flag the one function that is supposed to do this.
const RESOLVER = 'function parasignGrantLive(';

function blockAround(lines, idx) {
  let depth = 0; let start = idx;
  for (let i = idx; i >= 0; i--) {
    const l = lines[i];
    depth += (l.match(/\}/g) || []).length - (l.match(/\{/g) || []).length;
    if (depth < 0) { start = i; break; }
  }
  let d = 0; let end = lines.length - 1;
  for (let i = start; i < lines.length; i++) {
    const l = lines[i];
    d += (l.match(/\{/g) || []).length - (l.match(/\}/g) || []).length;
    if (i > start && d <= 0) { end = i; break; }
  }
  return lines.slice(start, end + 1).join('\n');
}

function decidingReads(src) {
  const lines = src.split('\n');
  const out = [];
  lines.forEach((l, i) => {
    const t = l.trim();
    if (t.startsWith('//') || t.startsWith('*')) return;
    if (!RAW.test(l)) return;
    const block = blockAround(lines, i);
    if (block.includes(RESOLVER)) return;
    if (!DECIDES.test(block)) return;
    out.push({ n: i + 1, text: t });
  });
  return out;
}

test('the two gates resolve the flag through the period, not raw', () => {
  const src = fs.readFileSync(path.join(ROOT, 'relay/lib/keys-table.js'), 'utf8');
  const resolver = src.slice(src.indexOf('function parasignGrantLive('), src.indexOf('function hasParaSignScope('));
  assert.match(resolver, /effectiveProductTier\(rec, 'parasign'/, 'parasignGrantLive does not consult the period');
  assert.match(resolver, /\.expired/, 'parasignGrantLive reads the tier but not the expiry');

  const scope = src.slice(src.indexOf('function hasParaSignScope('), src.indexOf('// Non-secret, stable key identifier'));
  assert.match(scope, /parasignGrantLive\(/, 'hasParaSignScope no longer goes through the resolver');

  const mintGate = src.slice(src.indexOf('function accountHasParasignEntitlement('));
  assert.match(mintGate, /parasignGrantLive\(/, 'the mint gate no longer goes through the resolver');
  assert.doesNotMatch(mintGate.slice(0, mintGate.indexOf('\n}')), /r\.parasign === true/, 'the mint gate reads the raw flag again');
});

test('no permission is decided on the raw flag anywhere', () => {
  const offenders = [];
  for (const f of FILES) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    for (const r of decidingReads(src)) offenders.push(`${f}:${r.n} ${r.text.slice(0, 100)}`);
  }
  // No ALLOW list, because the answer is genuinely zero and a list of exceptions
  // here would be a list of places the term does not end.
  assert.deepStrictEqual(offenders, [], `a permission decided on a cached, expiring flag:\n  ${offenders.join('\n  ')}`);
});

test('a lapsed grant is refused, a live one is not, an open one is not', () => {
  const lapsed = { parasign: true, plan_parasign: 'pro', paid_until_parasign: PAST };
  const live = { parasign: true, plan_parasign: 'pro', paid_until_parasign: FUTURE };
  const open = { parasign: true };
  const scoped = { scope: 'parasign' };

  assert.strictEqual(keysTable.hasParaSignScope(lapsed), false, 'a lapsed grant still opens the /v1 API');
  assert.strictEqual(keysTable.hasParaSignScope(live), true);
  assert.strictEqual(keysTable.hasParaSignScope(open), true, 'a grant with no term was read as expired');
  assert.strictEqual(keysTable.hasParaSignScope(scoped), true);
  assert.strictEqual(keysTable.hasParaSignScope(null), false);
  assert.strictEqual(keysTable.hasParaSignScope({}), false);

  assert.strictEqual(keysTable.accountHasParasignEntitlement([lapsed], 'community'), false, 'a lapsed account still mints');
  assert.strictEqual(keysTable.accountHasParasignEntitlement([live], 'community'), true);
  assert.strictEqual(keysTable.accountHasParasignEntitlement([open], 'community'), true);
  // The plan itself still carries the entitlement without any flag at all.
  assert.strictEqual(keysTable.accountHasParasignEntitlement([], 'pro'), true);
  assert.strictEqual(keysTable.accountHasParasignEntitlement([], 'community'), false);
});

test('the gate and the entitlements endpoint agree, which is what they did not before', () => {
  // The whole finding in one assertion: the relay reported `free` while the gate
  // said yes. Whatever effectiveProductTier calls expired, the gate must refuse,
  // for a record that carries the flag.
  const cases = [
    { parasign: true, plan_parasign: 'pro', paid_until_parasign: PAST },
    { parasign: true, plan_parasign: 'business', paid_until_parasign: PAST },
    { parasign: true, plan_parasign: 'pro', paid_until_parasign: FUTURE },
    { parasign: true, plan_parasign: 'enterprise' },
    { parasign: true },
  ];
  for (const rec of cases) {
    const eff = entitlements.effectiveProductTier(rec, 'parasign');
    assert.strictEqual(keysTable.hasParaSignScope(rec), !eff.expired,
      `gate and entitlements disagree for ${JSON.stringify(rec)}: gate=${keysTable.hasParaSignScope(rec)} expired=${eff.expired}`);
  }
});

test('self-test: the scanner can go red, so zero means zero', () => {
  // The whole risk of a gate whose expected answer is an empty list: if the
  // scanner breaks, it keeps returning the empty list and reports green over
  // anything. So it is driven over the shape it is meant to catch.
  const broken = [
    'function mayMint(rec) {',
    '  if (rec.parasign === true) return { allowed: true };',
    "  res.writeHead(403); return { error: 'not_entitled' };",
    '}',
  ].join('\n');
  assert.strictEqual(decidingReads(broken).length, 1, 'the scanner missed a permission decided on the raw flag');

  const fixed = [
    'function mayMint(rec) {',
    '  if (keysTable.parasignGrantLive(rec)) return { allowed: true };',
    "  res.writeHead(403); return { error: 'not_entitled' };",
    '}',
  ].join('\n');
  assert.strictEqual(decidingReads(fixed).length, 0, 'the scanner flags the repaired shape');

  // And the three forms it must NOT flag, or it would be noise and get muted.
  const innocent = [
    'const ent = entitlements.getEntitlements(rec).parasign;',
    'out.plan_parasign = derivePlanParasign(entry.plan, entry.parasign);',
    'if (v.parasign) acct.parasign = true;',
  ].join('\n');
  assert.strictEqual(decidingReads(`function copy() {\n${innocent}\n}`).length, 0, 'the scanner flags a copy or a derivation');

  // The pattern itself, at the character level.
  assert.strictEqual(RAW.test('rec.parasign = true'), false, 'the pattern matches an assignment');
  assert.strictEqual(RAW.test('if (r.parasign === true)'), true, 'the pattern misses a comparison');
  assert.strictEqual(RAW.test('v.plan_parasign'), false, 'the pattern matches the tier field');
  assert.strictEqual(RAW.test('ent.parasign.tier'), false, 'the pattern matches the entitlements object');
});
