'use strict';
// Proves the M2 privacy fix in lib/audit.js:
//  - operator IP in metadata is masked before it is stored
//  - the account email is preserved (admin traceability)
//  - retention is bounded by age (zRemRangeByScore with a cutoff), not just count

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

  console.log('\nall audit-retention checks passed.');
  Module._load = origLoad;
})().catch(e => { console.error(e); process.exit(1); });
