'use strict';
// THE KEY MINT GATE. Every route that hands out an API key must bind it to an
// account, give it a scope, count it against a cap, and write it down.
//
// WHY THIS EXISTS. Findings 9 and 10 of the 2026-09-05 hostile review read as
// two bugs and are one class. Both are a mint that skipped part of what a mint
// has to do, and in both cases a correct mint stood twenty lines away:
//
//   9   POST /v2/team/add-device minted a pgp_ key with no account_id, no
//       scope, 16 bytes of entropy, no cap and no line in users.json. The
//       review read that as "no quota" -- wrong, a backfill above all routing
//       fills account_id in -- but the damage was worse than a skipped gate:
//       the device became its OWN account with its OWN fresh monthly bucket.
//       One paid seat, unlimited plans.
//   10  POST /v2/user/parasign-keys called mintParasignKey in a loop with no
//       cap at all. Measured on 2026-09-06 against a booted relay: fourteen
//       keys in a row on a Pro account, nine on a community account whose cap
//       is five, users.json from three entries to twenty-five in one loop.
//
// And in both cases /v2/admin/keys, the third mint, did it correctly. Repairing
// two routes and stopping there buys nothing: the fourth mint is one commit
// away and it will be written by reading one of the other three.
//
// So this scans for the SHAPE of a mint rather than for the routes. It is a
// linter, not a proof, and it is deliberately narrow so a hit means something.
//
// WHAT IT REQUIRES
//   M1  every apiKeys.set() whose value is a fresh record literal names
//       `account_id` and `scope`. A record without them is a key that answers
//       to nobody and may do anything: requireScope reads a missing scope as
//       'full'.
//   M2  every such site is inside a block that also checks ACCOUNT_KEY_LIMIT
//       and calls applyKeyLimitEnforcement().
//   M3  the key material is 32 bytes. 16 was the entropy add-device used.
//   M4  the mint is written down: _mutateUsersJson in the same block.
//
// Loading users.json is not minting and is not flagged: those sites REBUILD
// records that already exist and already carry their fields, and they are named
// in LOADERS with a reason.
//
// HOW TO ANSWER A RED
//   Do what /v2/admin/keys does, or call mintParasignKey, which now carries the
//   cap itself so the two ParaSign doors cannot drift. Adding a line to LOADERS
//   is for a site that reconstructs existing records, never for a new mint.
//
// Runs anywhere: no redis, no engine, plain fs.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
const LINES = SRC.split('\n');

// Sites that rebuild records read from storage rather than creating new key
// material. `count` is exact, so a mint that hides itself in a loader turns the
// gate red.
const LOADERS = [
  { line: 'try { const d = JSON.parse(process.env.USERS_JSON)', reason: 'loadUsers, USERS_JSON branch: rehydrates records that already exist, through keysTable.parseAccountFields.' },
  { line: 'if (k.active) apiKeys.set(k.key, {', reason: 'loadUsers, file branch: same rehydration, same parseAccountFields.' },
  { line: 'apiKeys.set(k.key, {', reason: 'loadTrialKeys: rehydrates trial records from their own store.' },
  { line: 'candidate.forEach((v, k) => apiKeys.set(k, v));', reason: '/v2/reload-users atomic swap: moves whole records from a freshly parsed table, creating none.' },
  { line: 'apiKeys.set(key, record);', reason: 'mintParasignKey itself. It IS the generator, and it carries the cap, the enforcement pass and the users.json write; asserted by name below rather than by proximity.' },
  { line: "apiKeys.set(k, { plan, label, email, active: true });", reason: 'the /v2/setup wizard mint. It runs only while the key table is empty (_setupModeOn), writes users.json in the same handler, and is the bootstrap that creates the first account there can be a cap against.' },
];

function siteLines() {
  const out = [];
  LINES.forEach((l, i) => { if (l.includes('apiKeys.set(')) out.push({ n: i + 1, text: l.trim() }); });
  return out;
}

function isLoader(text) {
  return LOADERS.some((l) => text.includes(l.line));
}

// The enclosing block of a line: walk back to the nearest line whose brace depth
// is one less, walk forward to where that block closes. Crude and good enough,
// because the shapes being judged are route handlers and short functions.
function enclosing(lineNo) {
  let start = lineNo - 1;
  let depth = 0;
  for (let i = lineNo - 1; i >= 0; i--) {
    const l = LINES[i];
    depth += (l.match(/\}/g) || []).length - (l.match(/\{/g) || []).length;
    if (depth < 0) { start = i; break; }
  }
  let d = 0; let end = LINES.length - 1;
  for (let i = start; i < LINES.length; i++) {
    const l = LINES[i];
    d += (l.match(/\{/g) || []).length - (l.match(/\}/g) || []).length;
    if (i > start && d <= 0) { end = i; break; }
  }
  return LINES.slice(start, end + 1).join('\n');
}

test('every fresh key record names an account and a scope', () => {
  const offenders = [];
  for (const s of siteLines()) {
    if (isLoader(s.text)) continue;
    if (!/account_id/.test(s.text)) offenders.push(`relay.js:${s.n} no account_id: ${s.text.slice(0, 90)}`);
    if (!/scope/.test(s.text)) offenders.push(`relay.js:${s.n} no scope: ${s.text.slice(0, 90)}`);
  }
  assert.deepStrictEqual(offenders, [], `a key that answers to nobody:\n  ${offenders.join('\n  ')}`);
});

test('every mint block checks a cap, records the key, and re-runs the enforcement pass', () => {
  const offenders = [];
  for (const s of siteLines()) {
    if (isLoader(s.text)) continue;
    const block = enclosing(s.n);
    if (!/ACCOUNT_KEY_LIMIT/.test(block)) offenders.push(`relay.js:${s.n} no cap check`);
    if (!/_mutateUsersJson/.test(block)) offenders.push(`relay.js:${s.n} not written to users.json`);
    if (!/applyKeyLimitEnforcement\(\)/.test(block)) offenders.push(`relay.js:${s.n} no enforcement pass after the mint`);
  }
  assert.deepStrictEqual(offenders, [], `an uncapped or unrecorded mint:\n  ${offenders.join('\n  ')}`);
});

test('key material is 32 bytes everywhere', () => {
  // add-device used randomBytes(16). Half the entropy of every other key in the
  // file, for a credential with the same authority.
  const weak = [];
  LINES.forEach((l, i) => {
    if (!/randomBytes\(\s*(\d+)\s*\)/.test(l)) return;
    if (!/'pgp_'|"pgp_"|psk_|newKey|apiKey/.test(l)) return;
    const n = parseInt(/randomBytes\(\s*(\d+)\s*\)/.exec(l)[1], 10);
    if (n < 32) weak.push(`relay.js:${i + 1} randomBytes(${n}): ${l.trim().slice(0, 90)}`);
  });
  assert.deepStrictEqual(weak, [], `key material under 32 bytes:\n  ${weak.join('\n  ')}`);
});

test('mintParasignKey is the single generator and it carries the cap itself', () => {
  // The cap lives in the generator rather than at the two routes, because that
  // is the only arrangement in which a third ParaSign door cannot forget it.
  const start = SRC.indexOf('function mintParasignKey(');
  assert.ok(start > 0, 'mintParasignKey not found');
  const body = SRC.slice(start, SRC.indexOf('\nfunction ', start + 10));
  assert.match(body, /ACCOUNT_KEY_LIMIT/, 'mintParasignKey does not check the per-account cap');
  assert.match(body, /LICENSE_MAX_KEYS/, 'mintParasignKey does not check the relay-total cap');
  assert.match(body, /applyKeyLimitEnforcement\(\)/, 'mintParasignKey does not re-run the enforcement pass');
  assert.match(body, /account_key_limit/, 'mintParasignKey has no typed refusal for the caller to turn into a 402');
  // And both callers must turn that refusal into a 402, not a 400 or a 500.
  const callers = SRC.split('\n').map((l, i) => ({ l, i })).filter((x) => /mintParasignKey\(/.test(x.l) && !/function mintParasignKey/.test(x.l));
  assert.strictEqual(callers.length, 2, `expected exactly 2 callers of mintParasignKey, found ${callers.length}`);
  for (const c of callers) {
    const block = enclosing(c.i + 1);
    assert.match(block, /keyCapReject\(/, `the mint caller at relay.js:${c.i + 1} does not answer a cap refusal with a 402`);
  }
});

test('the per-account cap is a number on every plan', () => {
  // pro and enterprise were Infinity, which is not a ceiling. A self-serve mint
  // plus Infinity is unbounded growth of users.json by design.
  const start = SRC.indexOf('const ACCOUNT_KEY_LIMIT = Object.freeze({');
  assert.ok(start > 0);
  const block = SRC.slice(start, SRC.indexOf('});', start));
  assert.doesNotMatch(block, /Infinity/, 'a plan still has an infinite per-account key cap');
  for (const plan of ['community', 'pro', 'enterprise']) {
    assert.match(block, new RegExp(`${plan}:`), `ACCOUNT_KEY_LIMIT has no ${plan} row`);
  }
});

test('the LOADERS list is exact and every entry carries a reason', () => {
  const sites = siteLines();
  assert.ok(sites.length >= 6, `only ${sites.length} apiKeys.set sites; the scanner has drifted`);
  const matched = LOADERS.filter((l) => sites.some((s) => s.text.includes(l.line)));
  assert.strictEqual(matched.length, LOADERS.length,
    `LOADERS names ${LOADERS.length} sites but ${matched.length} are present; remove what is gone`);
  for (const l of LOADERS) assert.ok(l.reason && l.reason.length > 40, `${l.line} has no usable reason`);
  const mints = sites.filter((s) => !isLoader(s.text));
  assert.ok(mints.length >= 2, `only ${mints.length} sites classified as mints; the LOADERS list is swallowing them`);
});

test('self-test: the block walker really finds an enclosing block', () => {
  const s = siteLines().find((x) => x.text.includes('apiKeys.set(newKey, { plan, label, email, active: true, account_id'));
  assert.ok(s, 'the /v2/admin/keys mint was not found; it is the reference shape');
  const block = enclosing(s.n);
  assert.ok(block.length > 400, `the reference mint sliced to ${block.length} chars`);
  assert.match(block, /ACCOUNT_KEY_LIMIT/);
  assert.match(block, /applyKeyLimitEnforcement\(\)/);
});
