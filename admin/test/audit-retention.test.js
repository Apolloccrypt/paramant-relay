'use strict';
// Proves the M2 privacy fix in lib/audit.js:
//  - operator IP in metadata is masked before it is stored
//  - the account email is preserved (admin traceability)
//  - retention is bounded by age (zRemRangeByScore with a cutoff), not just count
// and, since the 2026-09-05 review, the two failure modes of the write itself:
//  - a store that is down loses the entry loudly and never reaches the caller
//  - a missing user_id throws, because that one is the bug and not an outage

const Module = require('module');
const assert = require('assert');

const calls = { added: [], remByScore: [], remByRank: [] };
const fakeClient = {
  async zAdd(key, { value }) { calls.added.push({ key, value }); },
  async zRemRangeByRank(key, a, b) { calls.remByRank.push({ key, a, b }); },
  async zRemRangeByScore(key, min, max) { calls.remByScore.push({ key, min, max }); },
};

const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === './redis' || request.endsWith('/lib/redis')) {
    return { redis: () => fakeClient };
  }
  return origLoad.apply(this, arguments);
};

const { logAuditEvent } = require('../lib/audit');

function ok(name) { console.log('  ok - ' + name); }

(async () => {
  const before = Date.now();
  await logAuditEvent('user-1', 'admin_welcome_sent', {
    email: 'alice@example.com',
    admin_ip: '203.0.113.7',
  });

  // The per-user store received an entry.
  const userEntry = calls.added.find(a => a.key === 'paramant:user:audit:user-1');
  assert(userEntry, 'per-user audit entry written');
  const stored = JSON.parse(userEntry.value);

  assert.strictEqual(stored.metadata.admin_ip, '203.0.x.x', 'operator IP is masked');
  assert.strictEqual(stored.metadata.email, 'alice@example.com', 'account email preserved');
  ok('operator IP masked, account email preserved');

  // Retention trims by age as well as rank.
  assert(calls.remByRank.length >= 1, 'rank trim still applied');
  const scoreTrim = calls.remByScore.find(c => c.key === 'paramant:user:audit:user-1');
  assert(scoreTrim, 'age-based trim applied to the user key');
  assert.strictEqual(scoreTrim.min, 0, 'age trim starts at 0');
  const windowMs = 400 * 86400 * 1000;
  assert(scoreTrim.max <= before - windowMs + 5000 && scoreTrim.max >= before - windowMs - 5000,
    'age trim cutoff is ~now minus the retention window');
  ok('retention bounded by age (zRemRangeByScore cutoff ~= now - 400d)');

  // ── The write is a witness, never a gate ──────────────────────────────────
  // A store that is down is an availability event: the entry is lost, the
  // process log says so, and the request that triggered it still succeeds. This
  // matters because six call sites in admin/server.js wrapped this function in
  // `try { ... } catch {}` with no await, which caught nothing at all: with
  // Node's default of --unhandled-rejections=throw, a redis hiccup on any of
  // them ended the admin process.
  const goodZAdd = fakeClient.zAdd;
  fakeClient.zAdd = async () => { throw new Error('client not connected'); };
  const errs = [];
  const origError = console.error;
  console.error = (...a) => { errs.push(a.map(String).join(' ')); };
  try {
    await logAuditEvent('user-2', 'webauthn_login', { email: 'demo@example.com' });
  } finally {
    console.error = origError;
    fakeClient.zAdd = goodZAdd;
  }
  assert(errs.some(l => l.includes('[admin/audit]')), 'a lost audit write is reported on stderr');
  const reported = errs.join('\n');
  assert(reported.includes('webauthn_login'), 'the line names the event, so an outage can be sized');
  assert(!reported.includes('user-2'), 'and it carries no account id');
  assert(!reported.includes('demo@example.com'), 'and no metadata');
  ok('a store failure loses the entry loudly and never reaches the caller');

  // A missing user_id is the opposite: the first argument IS the redis key, so
  // an empty one writes an entry that no reader can ever fetch. That is a
  // programming error, and swallowing it is what hid six of them for months.
  for (const bad of [undefined, null, '', 0]) {
    let threw = null;
    try { await logAuditEvent(bad, 'webauthn_counter_regression', {}); } catch (e) { threw = e; }
    assert(threw, `user_id=${JSON.stringify(bad)} must throw, not be written under an empty key`);
    assert.strictEqual(threw.name, 'TypeError', 'and it is a TypeError, not a store error');
  }
  ok('a missing user_id is a programming error and is not swallowed');

  console.log('\nall audit-retention checks passed.');
  Module._load = origLoad;
})().catch(e => { console.error(e); process.exit(1); });
